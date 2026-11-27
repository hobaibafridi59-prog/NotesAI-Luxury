"""
NotesAI Security Module — API security hardening.

Provides:
- Rate limiting (in-memory, no external dependencies)
- Input validation (email, IDs, filenames, etc.)
- CORS headers (approved origins only)
- HTTPS enforcement (HSTS header)
- Audit logging (JSON file, no secrets)
- File upload validation (MIME type, size, path traversal)

All features use only Python standard library and Flask built-ins.
No external packages required.
"""

import os
import time
import json
import re
import hashlib
import hmac
import mimetypes
from datetime import datetime, timezone
from functools import wraps
from collections import defaultdict
from threading import Lock

from flask import request, jsonify, g

# ============================================================================
# CONFIGURATION
# ============================================================================

# Rate limiting configuration
RATE_LIMITS = {
    "auth_login": {"max_requests": 5, "window_seconds": 900},       # 5 per 15 min
    "auth_register": {"max_requests": 3, "window_seconds": 3600},    # 3 per hour
    "auth_reset": {"max_requests": 3, "window_seconds": 3600},       # 3 per hour
    "api_general": {"max_requests": 60, "window_seconds": 60},       # 60 per minute
    "api_upload": {"max_requests": 20, "window_seconds": 60},        # 20 per minute
    "api_pdf": {"max_requests": 5, "window_seconds": 60},            # 5 per minute
    "api_ai": {"max_requests": 10, "window_seconds": 60},            # 10 per minute
    "api_admin": {"max_requests": 30, "window_seconds": 60},         # 30 per minute
}

# CORS allowed origins. Extra origins can be added with NOTESAI_CORS_ORIGINS
# (comma-separated) without editing source.
_DEFAULT_CORS_ORIGINS = [
    "http://localhost:3001",
    "http://127.0.0.1:3001",
    "https://hobaibafridi59.pythonanywhere.com",
    "https://notesai.app",
    "https://www.notesai.app",
]
_extra_origins = [o.strip() for o in os.getenv("NOTESAI_CORS_ORIGINS", "").split(",") if o.strip()]
CORS_ALLOWED_ORIGINS = _DEFAULT_CORS_ORIGINS + [
    o for o in _extra_origins if o not in _DEFAULT_CORS_ORIGINS
]

# File upload limits
MAX_FILE_SIZE = 20 * 1024 * 1024  # 20MB
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp", "bmp", "pdf"}
ALLOWED_MIME_TYPES = {
    "image/jpeg", "image/png", "image/webp", "image/bmp", "application/pdf",
}

# Audit log
AUDIT_LOG_FILE = os.path.join(os.path.dirname(__file__), "audit_log.json")
MAX_AUDIT_ENTRIES = 1000

# ============================================================================
# RATE LIMITING (In-memory, no external dependencies)
# ============================================================================

_rate_limit_store = defaultdict(list)
_rate_limit_lock = Lock()


def _get_client_ip():
    """Get client IP address."""
    return request.remote_addr or "unknown"


def _check_rate_limit(key, max_requests, window_seconds):
    """Check if request is within rate limit. Returns (allowed, retry_after)."""
    now = time.time()
    client_ip = _get_client_ip()
    rate_key = f"{key}:{client_ip}"

    with _rate_limit_lock:
        # Clean old entries
        _rate_limit_store[rate_key] = [
            ts for ts in _rate_limit_store[rate_key]
            if now - ts < window_seconds
        ]

        if len(_rate_limit_store[rate_key]) >= max_requests:
            oldest = _rate_limit_store[rate_key][0]
            retry_after = int(window_seconds - (now - oldest)) + 1
            return False, retry_after

        _rate_limit_store[rate_key].append(now)
        return True, 0


def rate_limit(key):
    """Decorator: apply rate limiting to an endpoint."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            config = RATE_LIMITS.get(key, RATE_LIMITS["api_general"])
            allowed, retry_after = _check_rate_limit(
                key, config["max_requests"], config["window_seconds"]
            )
            if not allowed:
                response = jsonify({
                    "error": "Rate limit exceeded. Please try again later.",
                    "code": "RATE_LIMITED",
                    "retry_after": retry_after,
                })
                response.status_code = 429
                response.headers["Retry-After"] = str(retry_after)
                return response
            return f(*args, **kwargs)
        return decorated
    return decorator


# ============================================================================
# INPUT VALIDATION
# ============================================================================

def validate_document_id(value):
    """Validate document ID format (32-char hex)."""
    if not value or not isinstance(value, str):
        return False
    return bool(re.fullmatch(r"[a-f0-9]{32}", value.strip()))


def validate_email(value):
    """Validate email format."""
    if not value or not isinstance(value, str):
        return False
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value.strip()))


def validate_filename(value):
    """Validate filename (no path traversal, safe characters)."""
    if not value or not isinstance(value, str):
        return False
    # No path separators
    if "/" in value or "\\" in value or ".." in value:
        return False
    # Only safe characters
    if not re.fullmatch(r"[a-zA-Z0-9_\-\.]+", value):
        return False
    # Reasonable length
    if len(value) > 255:
        return False
    return True


def validate_text_length(value, max_length=10000):
    """Validate text input length."""
    if value is None:
        return True
    if not isinstance(value, str):
        return False
    return len(value) <= max_length


def validate_integer(value, min_val=None, max_val=None):
    """Validate integer input."""
    try:
        v = int(value)
        if min_val is not None and v < min_val:
            return False
        if max_val is not None and v > max_val:
            return False
        return True
    except (TypeError, ValueError):
        return False


def validate_choice(value, choices):
    """Validate that value is in allowed choices."""
    return value in choices


def sanitize_string(value, max_length=255):
    """Sanitize a string input (strip, truncate)."""
    if not value:
        return ""
    return str(value).strip()[:max_length]


# ============================================================================
# CORS SECURITY
# ============================================================================

def add_cors_headers(response):
    """Add CORS headers to response (approved origins only)."""
    origin = request.headers.get("Origin", "")
    if origin in CORS_ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PATCH, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-CSRF-Token, X-NotesAI-Premium"
        response.headers["Access-Control-Max-Age"] = "3600"
    return response


# ============================================================================
# HTTPS ENFORCEMENT
# ============================================================================

def add_security_headers(response):
    """Add security headers to all responses."""
    # HSTS (only in production, not localhost)
    if request.host not in ("localhost", "127.0.0.1", "0.0.0.0"):
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Other security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# ============================================================================
# AUDIT LOGGING
# ============================================================================

_audit_lock = Lock()


def _load_audit_log():
    """Load audit log from file."""
    try:
        if os.path.exists(AUDIT_LOG_FILE):
            with open(AUDIT_LOG_FILE, 'r') as f:
                return json.load(f)
    except (json.JSONDecodeError, IOError):
        pass
    return []


def _save_audit_log(entries):
    """Save audit log to file (atomic write)."""
    try:
        tmp = AUDIT_LOG_FILE + ".tmp"
        with open(tmp, 'w') as f:
            json.dump(entries, f, indent=2)
        os.replace(tmp, AUDIT_LOG_FILE)
    except IOError:
        pass


def audit_log(event_type, details=None, user_id=None, ip=None, status="success"):
    """Log a security event to the audit log."""
    if details is None:
        details = {}

    # Never log secrets
    safe_details = {}
    for k, v in details.items():
        if any(secret in k.lower() for secret in ["password", "token", "secret", "key", "api_key"]):
            safe_details[k] = "***REDACTED***"
        else:
            safe_details[k] = v

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "status": status,
        "user_id": user_id,
        "ip": ip or _get_client_ip(),
        "details": safe_details,
    }

    with _audit_lock:
        entries = _load_audit_log()
        entries.append(entry)
        # Keep only last MAX_AUDIT_ENTRIES
        if len(entries) > MAX_AUDIT_ENTRIES:
            entries = entries[-MAX_AUDIT_ENTRIES:]
        _save_audit_log(entries)


def get_audit_log(limit=50, event_type=None):
    """Get recent audit log entries."""
    entries = _load_audit_log()
    if event_type:
        entries = [e for e in entries if e.get("event_type") == event_type]
    return entries[-limit:]


# ============================================================================
# FILE UPLOAD SECURITY
# ============================================================================

def validate_file_upload(file_storage):
    """Validate a file upload. Returns (is_valid, error_message)."""
    if not file_storage or not file_storage.filename:
        return False, "No file provided."

    filename = file_storage.filename
    # Check filename safety
    if not validate_filename(filename):
        return False, "Invalid filename."

    # Check extension
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"Unsupported file type: .{ext}"

    # Check file size
    file_storage.seek(0, 2)  # Seek to end
    size = file_storage.tell()
    file_storage.seek(0)  # Reset
    if size > MAX_FILE_SIZE:
        return False, f"File too large: {size} bytes (max {MAX_FILE_SIZE})"

    # Check MIME type (basic check)
    mime_type = file_storage.content_type or mimetypes.guess_type(filename)[0]
    if mime_type and mime_type not in ALLOWED_MIME_TYPES:
        return False, f"Unsupported MIME type: {mime_type}"

    # For images, verify they can be opened
    if ext in {"jpg", "jpeg", "png", "webp", "bmp"}:
        try:
            from PIL import Image
            file_storage.seek(0)
            with Image.open(file_storage) as img:
                img.load()
                width, height = img.size
                if width > 10000 or height > 10000:
                    file_storage.seek(0)
                    return False, f"Image too large: {width}x{height} (max 10000x10000)"
            file_storage.seek(0)
        except Exception:
            file_storage.seek(0)
            return False, "Invalid or corrupted image file."

    # For PDFs, verify header
    if ext == "pdf":
        file_storage.seek(0)
        header = file_storage.read(1024)
        file_storage.seek(0)
        if b"%PDF-" not in header:
            return False, "Invalid PDF file."

    return True, ""


# ============================================================================
# SECURITY MIDDLEWARE
# ============================================================================

def init_security(app):
    """Initialize security middleware on a Flask app."""
    # Add after_request handler for CORS and security headers
    @app.after_request
    def security_headers(response):
        response = add_cors_headers(response)
        response = add_security_headers(response)
        return response

    # Handle OPTIONS requests for CORS preflight
    @app.before_request
    def handle_preflight():
        if request.method == "OPTIONS":
            response = app.make_response("")
            response = add_cors_headers(response)
            response.status_code = 204
            return response


# ============================================================================
# HELPER: Get client IP for logging
# ============================================================================

def get_client_ip():
    """Get the request client IP.

    X-Forwarded-For is applied by Werkzeug ProxyFix only when
    NOTESAI_TRUST_PROXY_COUNT is explicitly configured.
    """
    return request.remote_addr or "unknown"
