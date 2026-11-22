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
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import request, jsonify, g

from werkzeug.security import generate_password_hash, check_password_hash

# Import database and models
import database
import models

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
            return jsonify({"error": "Authentication required", "code": "AUTH_REQUIRED"}), 401

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

        g.user_id = payload["user_id"]
        g.user = user
        g.user_role = user.get("role", "user")
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    """Decorator: requires admin role or admin token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Check admin token first (existing mechanism)
        from app import _admin_token_from_request, _is_local_request
        supplied = _admin_token_from_request()
        configured = os.environ.get("NOTESAI_ADMIN_TOKEN", "").strip()
        if configured and supplied and hmac.compare_digest(supplied, configured):
            return f(*args, **kwargs)
        if _is_local_request() and not configured:
            return f(*args, **kwargs)

        # Check JWT admin role
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

        return jsonify({"error": "Admin access required", "code": "ADMIN_REQUIRED"}), 403
    return decorated


def require_user_or_admin(f):
    """Decorator: requires user auth (JWT) OR admin token OR localhost access.

    This allows:
    - Admin token (existing mechanism)
    - Localhost without token (existing web app behavior)
    - JWT access token (new, for Android app users)

    If none of these, returns 401.
    Sets g.user_id and g.user when JWT is present.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # 1. Check admin token (existing mechanism)
        from app import _admin_token_from_request, _is_local_request
        supplied = _admin_token_from_request()
        configured = os.environ.get("NOTESAI_ADMIN_TOKEN", "").strip()
        if configured and supplied and hmac.compare_digest(supplied, configured):
            g.user_id = None
            g.user = None
            g.user_role = "admin"
            return f(*args, **kwargs)
        if _is_local_request() and not configured:
            g.user_id = None
            g.user = None
            g.user_role = "admin"
            return f(*args, **kwargs)

        # 2. Check JWT token
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

        # 3. No valid auth found
        return jsonify({"error": "Authentication required", "code": "AUTH_REQUIRED"}), 401
    return decorated


# ============================================================================
# AUTHENTICATION FUNCTIONS
# ============================================================================

def register_user(db, email, password, name):
    """Register a new user. Returns (user, error_message)."""
    email = email.strip().lower()
    name = name.strip()

    if not validate_email(email):
        return None, "Invalid email format."

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
    user = models.create_user(db, email, password_hash, name, role="user")
    return user, None


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
