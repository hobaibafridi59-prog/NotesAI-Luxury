"""
NotesAI Authentication Module — User authentication and session management.

Provides:
- Password hashing (Werkzeug security, pbkdf2:sha256)
- JWT token generation and validation (HS256, manual implementation)
- User registration, login, logout
- Password reset flow with secure tokens
- @require_auth decorator for protected routes
- @require_admin decorator for admin routes
- Legacy Account management

Dependencies: werkzeug (already in Flask), hashlib, hmac, base64, json, datetime (all built-in)
"""

import os
import hashlib
import hmac
import base64
import json
import uuid
import secrets
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import request, jsonify, g

from werkzeug.security import generate_password_hash, check_password_hash

# Import database and models
import database
import models
import email_validation

# ============================================================================
# CONFIGURATION
# ============================================================================

# JWT secret key — auto-generate and persist if not set in .env
def _get_or_create_jwt_secret():
    """Get JWT secret from .env or environment. Auto-generate and persist if missing."""
    # Check .env file first
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    env_secret = None
    if os.path.exists(env_path):
        try:
            with open(env_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("NOTESAI_JWT_SECRET="):
                        env_secret = line.split("=", 1)[1].strip().strip(chr(39) + chr(34))
                        break
        except Exception:
            pass

    # Check environment variable
    if not env_secret:
        env_secret = os.environ.get("NOTESAI_JWT_SECRET", "").strip()

    # If found, use it
    if env_secret:
        return env_secret

    # Auto-generate and persist
    new_secret = secrets.token_hex(32)
    try:
        # Read existing .env content
        existing_lines = []
        if os.path.exists(env_path):
            with open(env_path, "r") as f:
                existing_lines = f.readlines()

        # Add the new secret
        # Check if NOTESAI_JWT_SECRET already exists (even if empty)
        found = False
        for i, line in enumerate(existing_lines):
            if line.strip().startswith("NOTESAI_JWT_SECRET="):
                existing_lines[i] = f"NOTESAI_JWT_SECRET={new_secret}\n"
                found = True
                break

        if not found:
            existing_lines.append(f"\n# Auto-generated JWT secret (do not share)\n")
            existing_lines.append(f"NOTESAI_JWT_SECRET={new_secret}\n")

        with open(env_path, "w") as f:
            f.writelines(existing_lines)
        try:
            os.chmod(env_path, 0o600)
        except Exception:
            pass

        # Also set in environment for current process
        os.environ["NOTESAI_JWT_SECRET"] = new_secret
        return new_secret
    except Exception:
        # Fallback to random (not persistent)
        return secrets.token_hex(32)

JWT_SECRET = _get_or_create_jwt_secret()
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRY_MINUTES = 15
REFRESH_TOKEN_EXPIRY_DAYS = 7
PASSWORD_RESET_EXPIRY_HOURS = 1
BCRYPT_COST = 12


# ============================================================================
# ADMIN SESSION (short-lived, scoped, HttpOnly cookie + CSRF)
# ============================================================================
ADMIN_SESSION_COOKIE = "notesai_admin_session"
ADMIN_CSRF_COOKIE = "notesai_admin_csrf"
ADMIN_SESSION_MAX_AGE = 30 * 60
_admin_session_signer = URLSafeTimedSerializer(
    f"{JWT_SECRET}|notesai-admin-session-v1", salt="notesai-admin-session"
)


def _admin_env_flag(name, default=False):
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _local_user_dev_allowed():
    """Loopback anonymous user access, only when explicitly enabled for dev."""
    if not _admin_env_flag("NOTESAI_ALLOW_LOCALHOST_USER"):
        return False
    from app import _is_local_request
    return _is_local_request()


def _admin_cookie_secure():
    return bool(request.is_secure or _admin_env_flag("NOTESAI_COOKIE_SECURE"))


def create_admin_session(user_id):
    """Create a server-backed admin session.

    Returns (signed_cookie_value, csrf_token). The signed cookie carries a
    random session id (jti) that is also stored in the database so logout can
    revoke it server-side, not just clear the browser cookie.
    """
    jti = uuid.uuid4().hex
    csrf = secrets.token_urlsafe(24)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=ADMIN_SESSION_MAX_AGE)
    token = _admin_session_signer.dumps(
        {"uid": str(user_id), "jti": jti, "csrf": csrf}
    )
    db = database.get_db()
    db.execute(
        "INSERT INTO admin_sessions (id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (jti, str(user_id), now.isoformat(), expires_at.isoformat()),
    )
    db.execute("DELETE FROM admin_sessions WHERE expires_at < ?", (now.isoformat(),))
    db.commit()
    return token, csrf


def decode_admin_session(token=""):
    if not token:
        return None
    try:
        data = _admin_session_signer.loads(token, max_age=ADMIN_SESSION_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    uid = str(data.get("uid") or "")
    jti = str(data.get("jti") or "")
    csrf = str(data.get("csrf") or "")
    return {"uid": uid, "jti": jti, "csrf": csrf} if uid and jti and csrf else None


def resolve_admin_session():
    """Resolve and validate the current admin session cookie."""
    data = decode_admin_session(request.cookies.get(ADMIN_SESSION_COOKIE, ""))
    if not data:
        return None
    try:
        db = database.get_db()
        row = db.execute(
            "SELECT id, user_id, expires_at, revoked_at FROM admin_sessions WHERE id = ?",
            (data["jti"],),
        ).fetchone()
        if not row or row["revoked_at"] or row["user_id"] != data["uid"]:
            return None
        expires_at = datetime.fromisoformat(str(row["expires_at"]).replace("Z", "+00:00"))
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > expires_at:
            return None
        user = models.get_user_by_id(db, data["uid"])
    except Exception:
        return None
    if not user or user.get("role") != "admin" or user.get("status") != "active":
        return None
    return {
        "user_id": data["uid"],
        "user": user,
        "csrf": data["csrf"],
        "jti": data["jti"],
    }


def revoke_current_admin_session():
    """Mark the current signed admin session as revoked in the database."""
    data = decode_admin_session(request.cookies.get(ADMIN_SESSION_COOKIE, ""))
    if not data:
        return False
    try:
        db = database.get_db()
        db.execute(
            "UPDATE admin_sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
            (datetime.now(timezone.utc).isoformat(), data["jti"]),
        )
        db.commit()
        return True
    except Exception:
        return False


def csrf_token_valid(session_data):
    """Check CSRF for state-changing requests under cookie auth."""
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return True
    supplied = request.headers.get("X-CSRF-Token", "") or request.form.get("csrf_token", "")
    if not supplied:
        payload = request.get_json(silent=True) or {}
        supplied = str(payload.get("csrf_token") or "")
    return bool(supplied) and hmac.compare_digest(str(supplied), session_data["csrf"])


def set_admin_session_cookies(response, user_id):
    token, csrf = create_admin_session(user_id)
    secure = _admin_cookie_secure()
    response.set_cookie(ADMIN_SESSION_COOKIE, token, max_age=ADMIN_SESSION_MAX_AGE,
                        httponly=True, secure=secure, samesite="Strict", path="/")
    response.set_cookie(ADMIN_CSRF_COOKIE, csrf, max_age=ADMIN_SESSION_MAX_AGE,
                        httponly=False, secure=secure, samesite="Strict", path="/")
    return response


def clear_admin_session_cookies(response):
    revoke_current_admin_session()
    secure = _admin_cookie_secure()
    response.delete_cookie(ADMIN_SESSION_COOKIE, path="/", samesite="Strict", secure=secure)
    response.delete_cookie(ADMIN_CSRF_COOKIE, path="/", samesite="Strict", secure=secure)
    return response


# ============================================================================
# JWT TOKEN UTILITIES (manual implementation, no external dependencies)
# ============================================================================

def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    """Base64url decode with padding restoration."""
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _create_jwt(payload: dict, secret: str = JWT_SECRET) -> str:
    """Create a JWT token (HS256)."""
    header = {"alg": JWT_ALGORITHM, "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}"
    signature = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    signature_b64 = _b64url_encode(signature)
    return f"{signing_input}.{signature_b64}"


def _verify_jwt(token: str, secret: str = JWT_SECRET) -> dict:
    """Verify and decode a JWT token. Returns payload dict or raises ValueError."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid token format")

    header_b64, payload_b64, signature_b64 = parts

    # Verify signature
    signing_input = f"{header_b64}.{payload_b64}"
    expected_signature = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    expected_b64 = _b64url_encode(expected_signature)

    if not hmac.compare_digest(signature_b64, expected_b64):
        raise ValueError("Invalid signature")

    # Decode payload
    payload = json.loads(_b64url_decode(payload_b64))

    # Check expiry
    if "exp" in payload:
        if datetime.now(timezone.utc).timestamp() > payload["exp"]:
            raise ValueError("Token expired")

    return payload


def create_access_token(user_id: str, email: str, role: str = "user") -> str:
    """Create an access token (15-minute expiry)."""
    now = datetime.now(timezone.utc)
    payload = {
        "user_id": user_id,
        "email": email,
        "role": role,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_EXPIRY_MINUTES)).timestamp()),
    }
    return _create_jwt(payload)


def create_refresh_token(user_id: str) -> tuple:
    """Create a refresh token (7-day expiry). Returns (token, token_id, expires_at)."""
    token_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=REFRESH_TOKEN_EXPIRY_DAYS)
    payload = {
        "user_id": user_id,
        "token_id": token_id,
        "type": "refresh",
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    token = _create_jwt(payload)
    return token, token_id, expires_at.isoformat()


def verify_access_token(token: str) -> dict:
    """Verify an access token. Returns payload or raises ValueError."""
    payload = _verify_jwt(token)
    if payload.get("type") != "access":
        raise ValueError("Not an access token")
    return payload


def verify_refresh_token(token: str) -> dict:
    """Verify a refresh token. Returns payload or raises ValueError."""
    payload = _verify_jwt(token)
    if payload.get("type") != "refresh":
        raise ValueError("Not a refresh token")
    return payload


# ============================================================================
# PASSWORD UTILITIES
# ============================================================================

def hash_password(password: str) -> str:
    """Hash a password using Werkzeug security (pbkdf2:sha256)."""
    return generate_password_hash(password, method="pbkdf2:sha256", salt_length=16)


def verify_password(password_hash: str, password: str) -> bool:
    """Verify a password against a hash."""
    return check_password_hash(password_hash, password)


def validate_password(password: str) -> tuple:
    """Validate password strength. Returns (is_valid, error_message)."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit."
    return True, ""


def validate_email(email: str) -> bool:
    """Validate email format."""
    import re
    return bool(re.match(r"^[^@]+@[^@]+\.[^@]+$", email.strip()))


# ============================================================================
# AUTHENTICATION DECORATORS
# ============================================================================

def require_auth(f):
    """Decorator: requires valid JWT access token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"ok": False, "error": "Authentication required", "code": "AUTH_REQUIRED"}), 401

        token = auth_header[7:].strip()
        try:
            payload = verify_access_token(token)
        except ValueError as e:
            return jsonify({"error": str(e), "code": "INVALID_TOKEN"}), 401

        # Load user from database
        db = database.get_db()
        user = models.get_user_by_id(db, payload["user_id"])
        if not user:
            return jsonify({"error": "User not found", "code": "USER_NOT_FOUND"}), 401
        if user.get("status") != "active":
            return jsonify({"error": "Account is not active", "code": "ACCOUNT_INACTIVE"}), 403

        if _local_user_dev_allowed():
            g.user_id = None
            g.user = None
            g.user_role = "user"
            return f(*args, **kwargs)

        g.user_id = payload["user_id"]
        g.user = user
        g.user_role = user.get("role", "user")
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    """Require a short-lived admin session or an admin JWT.

    Static admin tokens and anonymous loopback access are disabled by default.
    They can be re-enabled explicitly for migration via
    NOTESAI_ALLOW_ADMIN_TOKEN_HEADER / NOTESAI_ALLOW_LOCALHOST_ADMIN.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        session = resolve_admin_session()
        if session:
            if not csrf_token_valid(session):
                return jsonify({"ok": False, "error": "CSRF token missing or invalid", "code": "CSRF_INVALID"}), 403
            g.user_id = session["user_id"]
            g.user = session["user"]
            g.user_role = "admin"
            g.admin_session = session
            return f(*args, **kwargs)

        if _admin_env_flag("NOTESAI_ALLOW_ADMIN_TOKEN_HEADER"):
            from app import _admin_token_from_request
            supplied = _admin_token_from_request()
            configured = os.environ.get("NOTESAI_ADMIN_TOKEN", "").strip()
            if configured and supplied and hmac.compare_digest(supplied, configured):
                g.user_id = None
                g.user = None
                g.user_role = "admin"
                return f(*args, **kwargs)

        if _admin_env_flag("NOTESAI_ALLOW_LOCALHOST_ADMIN"):
            from app import _is_local_request
            if _is_local_request():
                g.user_id = None
                g.user = None
                g.user_role = "admin"
                return f(*args, **kwargs)

        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            try:
                payload = verify_access_token(token)
                db = database.get_db()
                user = models.get_user_by_id(db, payload["user_id"])
                if user and user.get("role") == "admin" and user.get("status") == "active":
                    g.user_id = payload["user_id"]
                    g.user = user
                    g.user_role = "admin"
                    return f(*args, **kwargs)
            except ValueError:
                pass

        return jsonify({"ok": False, "error": "Admin access required", "code": "ADMIN_REQUIRED"}), 403
    return decorated


def require_user_or_admin(f):
    """Require an admin session/JWT or a normal user JWT.

    Cookie-based admin access is CSRF-protected. Legacy static token and
    loopback bypass require explicit opt-in env flags.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        session = resolve_admin_session()
        if session:
            if not csrf_token_valid(session):
                return jsonify({"ok": False, "error": "CSRF token missing or invalid", "code": "CSRF_INVALID"}), 403
            g.user_id = session["user_id"]
            g.user = session["user"]
            g.user_role = "admin"
            g.admin_session = session
            return f(*args, **kwargs)

        if _admin_env_flag("NOTESAI_ALLOW_ADMIN_TOKEN_HEADER"):
            from app import _admin_token_from_request
            supplied = _admin_token_from_request()
            configured = os.environ.get("NOTESAI_ADMIN_TOKEN", "").strip()
            if configured and supplied and hmac.compare_digest(supplied, configured):
                g.user_id = None
                g.user = None
                g.user_role = "admin"
                return f(*args, **kwargs)

        if _admin_env_flag("NOTESAI_ALLOW_LOCALHOST_ADMIN"):
            from app import _is_local_request
            if _is_local_request():
                g.user_id = None
                g.user = None
                g.user_role = "admin"
                return f(*args, **kwargs)

        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            try:
                payload = verify_access_token(token)
                db = database.get_db()
                user = models.get_user_by_id(db, payload["user_id"])
                if user and user.get("status") == "active":
                    g.user_id = payload["user_id"]
                    g.user = user
                    g.user_role = user.get("role", "user")
                    return f(*args, **kwargs)
            except ValueError:
                pass

        if _local_user_dev_allowed():
            g.user_id = None
            g.user = None
            g.user_role = "user"
            return f(*args, **kwargs)

        return jsonify({"ok": False, "error": "Authentication required", "code": "AUTH_REQUIRED"}), 401
    return decorated


# ============================================================================
# AUTHENTICATION FUNCTIONS
# ============================================================================

def register_user(db, email, password, name, email_verified=True):
    """Register a new user. Returns (user, error_message)."""
    email = email.strip().lower()
    name = name.strip()

    if not validate_email(email):
        return None, "Invalid email format."

    real_email, email_error = email_validation.validate_real_email(email)
    if not real_email:
        return None, email_error

    is_valid, error = validate_password(password)
    if not is_valid:
        return None, error

    if not name:
        return None, "Name is required."

    # Check if email already exists
    existing = models.get_user_by_email(db, email)
    if existing:
        return None, "An account with this email already exists."

    # Hash password and create user
    password_hash = hash_password(password)
    user = models.create_user(db, email, password_hash, name, role="user",
                              email_verified=email_verified)
    return user, None


def issue_email_verification(db, user):
    """Create and store a fresh 6-digit OTP. Returns the plain code."""
    code = email_validation.generate_verification_code()
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    models.create_email_verification(
        db,
        user["id"],
        email_validation.hash_verification_code(code, user["email"]),
        expires_at,
    )
    return code


def verify_email_code(db, user, code):
    """Verify an OTP. Returns (ok, error_message)."""
    code = str(code or "").strip()
    if len(code) != 6 or not code.isdigit():
        return False, "Enter the 6-digit verification code."

    record = models.get_latest_email_verification(db, user["id"])
    if not record or record.get("verified_at"):
        return False, "This verification code is no longer valid. Request a new one."

    if int(record.get("attempts") or 0) >= 5:
        return False, "Too many incorrect attempts. Request a new verification code."

    try:
        expires_at = datetime.fromisoformat(str(record["expires_at"]).replace("Z", "+00:00"))
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return False, "This verification code is no longer valid. Request a new one."

    if datetime.now(timezone.utc) > expires_at:
        return False, "This verification code has expired. Request a new one."

    candidate = email_validation.hash_verification_code(code, user["email"])
    if not hmac.compare_digest(candidate, str(record["code_hash"])):
        models.increment_email_verification_attempt(db, record["id"])
        return False, "Incorrect verification code."

    models.mark_email_verification_verified(db, record["id"])
    models.update_user(db, user["id"], email_verified=1)
    user["email_verified"] = 1
    return True, None


def login_user(db, email, password):
    """Login a user. Returns (user, access_token, refresh_token, error_message)."""
    email = email.strip().lower()
    user = models.get_user_by_email(db, email)

    if not user:
        return None, None, None, "Invalid email or password."

    if user.get("status") != "active":
        return None, None, None, "Account is not active."

    if not verify_password(user["password_hash"], password):
        return None, None, None, "Invalid email or password."

    if not user.get("email_verified", 1):
        return None, None, None, "Please verify your email before signing in."

    # Update last login
    models.update_user(db, user["id"], last_login_at=datetime.now(timezone.utc).isoformat())

    # Create tokens
    access_token = create_access_token(user["id"], user["email"], user.get("role", "user"))
    refresh_token, token_id, expires_at = create_refresh_token(user["id"])

    # Store refresh token hash
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    models.create_refresh_token(db, user["id"], token_hash, expires_at)

    return user, access_token, refresh_token, None


def refresh_access_token(db, refresh_token):
    """Refresh an access token using a refresh token."""
    try:
        payload = verify_refresh_token(refresh_token)
    except ValueError as e:
        return None, None, str(e)

    user_id = payload["user_id"]
    token_id = payload["token_id"]

    # Check if refresh token is still valid in DB
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    stored_token = models.get_refresh_token(db, token_hash)
    if not stored_token:
        return None, None, "Refresh token has been revoked."

    # Check expiry
    expires_at = stored_token["expires_at"]
    if datetime.now(timezone.utc).isoformat() > expires_at:
        models.revoke_refresh_token(db, stored_token["id"])
        return None, None, "Refresh token has expired."

    # Load user
    user = models.get_user_by_id(db, user_id)
    if not user or user.get("status") != "active":
        return None, None, "User not found or inactive."

    # Revoke old refresh token (rotation)
    models.revoke_refresh_token(db, stored_token["id"])

    # Create new tokens
    new_access = create_access_token(user["id"], user["email"], user.get("role", "user"))
    new_refresh, new_token_id, new_expires = create_refresh_token(user["id"])
    new_token_hash = hashlib.sha256(new_refresh.encode()).hexdigest()
    models.create_refresh_token(db, user["id"], new_token_hash, new_expires)

    return new_access, new_refresh, None


def logout_user(db, refresh_token=None):
    """Logout a user by revoking their refresh token."""
    if refresh_token:
        token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
        stored = models.get_refresh_token(db, token_hash)
        if stored:
            models.revoke_refresh_token(db, stored["id"])
    return True


def logout_all_devices(db, user_id):
    """Revoke all refresh tokens for a user (logout all devices)."""
    models.revoke_all_user_tokens(db, user_id)
    return True


# ============================================================================
# PASSWORD RESET
# ============================================================================

def request_password_reset(db, email):
    """Request a password reset. Returns (token, error_message)."""
    email = email.strip().lower()
    user = models.get_user_by_email(db, email)
    if not user:
        # Don't reveal if email exists (security)
        return None, None

    # Generate reset token
    reset_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(reset_token.encode()).hexdigest()
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=PASSWORD_RESET_EXPIRY_HOURS)).isoformat()

    models.create_password_reset_token(db, user["id"], token_hash, expires_at)
    return reset_token, None


def reset_password(db, reset_token, new_password):
    """Reset password using a reset token. Returns (success, error_message)."""
    token_hash = hashlib.sha256(reset_token.encode()).hexdigest()
    token = models.get_password_reset_token(db, token_hash)

    if not token:
        return False, "Invalid or expired reset token."

    is_valid, error = validate_password(new_password)
    if not is_valid:
        return False, error

    # Update password
    password_hash = hash_password(new_password)
    models.update_user(db, token["user_id"], password_hash=password_hash)

    # Mark token as used
    models.mark_password_reset_used(db, token["id"])

    # Revoke all refresh tokens (force re-login)
    models.revoke_all_user_tokens(db, token["user_id"])

    return True, None


# ============================================================================
# LEGACY ACCOUNT
# ============================================================================

def create_legacy_account(db):
    """Create the legacy account for pre-migration data. Admin-only."""
    legacy_id = models.create_legacy_user(db)
    return legacy_id


def get_legacy_account_info(db):
    """Get legacy account info (admin only)."""
    legacy_id = models.get_legacy_user_id()
    user = models.get_user_by_id(db, legacy_id)
    if not user:
        return None
    stats = models.get_user_stats(db, legacy_id)
    return {
        "user": user,
        "stats": stats,
    }


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_current_user():
    """Get the current authenticated user from request context."""
    return getattr(g, "user", None)


def get_current_user_id():
    """Get the current authenticated user ID from request context."""
    return getattr(g, "user_id", None)


def is_admin():
    """Check if current user is admin."""
    return getattr(g, "user_role", None) == "admin"
