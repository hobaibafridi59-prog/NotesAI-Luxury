"""
NotesAI User Isolation Module — Multi-user data ownership and access control.

Provides:
- Optional authentication for document endpoints (backward compatible)
- User ownership verification for documents
- Filtering documents by user_id
- Legacy document handling (documents without user_id are accessible to all)

This module is designed to work alongside the existing JSON-based storage
during the gradual migration to SQLite. It does NOT modify existing data.

Usage:
    from user_isolation import get_optional_user_id, filter_documents_by_user, verify_document_ownership
"""

import os
from flask import g, request

# Import auth module for token verification
try:
    from auth import verify_access_token, get_current_user_id
except ImportError:
    verify_access_token = None
    get_current_user_id = None


def get_optional_user_id():
    """
    Get the current user ID if authenticated, or None if not.
    Does NOT block access - just returns None for unauthenticated users.
    This allows backward compatibility with the existing web app.
    """
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        try:
            from auth import verify_access_token
            payload = verify_access_token(token)
            return payload.get("user_id")
        except Exception:
            return None
    return None


def get_optional_user():
    """
    Get the current user dict if authenticated, or None if not.
    """
    user_id = get_optional_user_id()
    if user_id:
        try:
            import database
            import models
            db = database.get_db()
            database.init_db()
            return models.get_user_by_id(db, user_id)
        except Exception:
            return None
    return None


def is_authenticated():
    """Check if the current request has a valid auth token."""
    return get_optional_user_id() is not None


def is_admin_request():
    """Check if the current request has admin privileges."""
    # Check admin token (existing mechanism)
    admin_token = request.headers.get("X-Admin-Token", "")
    configured = os.environ.get("NOTESAI_ADMIN_TOKEN", "").strip()
    if configured and admin_token and hmac.compare_digest(admin_token, configured):
        return True

    # Check localhost
    address = (request.remote_addr or "").strip().lower()
    if address in ("127.0.0.1", "::1", "localhost") and not configured:
        return True

    # Check JWT admin role
    user_id = get_optional_user_id()
    if user_id:
        try:
            import database
            import models
            db = database.get_db()
            database.init_db()
            user = models.get_user_by_id(db, user_id)
            if user and user.get("role") == "admin":
                return True
        except Exception:
            pass

    return False


def filter_documents_by_user(documents, user_id=None):
    """
    Filter documents by user_id.

    - If user_id is provided: return only documents owned by that user
      + legacy documents (without user_id) for backward compatibility
    - If user_id is None: return all documents (legacy behavior)
    """
    if user_id is None:
        return documents

    filtered = []
    for doc in documents:
        doc_user_id = doc.get("user_id")
        # Show documents owned by this user OR legacy documents (no user_id)
        if doc_user_id is None or doc_user_id == user_id:
            filtered.append(doc)
    return filtered


def verify_document_ownership(document, user_id):
    """
    Verify that a document belongs to the given user.

    Returns:
    - True if document has no user_id (legacy, accessible to all)
    - True if document.user_id == user_id
    - False otherwise
    """
    if document is None:
        return False
    doc_user_id = document.get("user_id")
    if doc_user_id is None:
        return True  # Legacy document, accessible to all
    return doc_user_id == user_id


def add_user_id_to_document(document, user_id):
    """
    Add user_id to a document record (for new documents).

    Only adds if user_id is provided and document doesn't already have one.
    Does NOT modify existing documents.
    """
    if user_id and not document.get("user_id"):
        document["user_id"] = user_id
    return document


def get_legacy_documents(documents):
    """Get documents that have no user_id (legacy documents)."""
    return [d for d in documents if not d.get("user_id")]


def get_user_documents(documents, user_id):
    """Get documents owned by a specific user."""
    return [d for d in documents if d.get("user_id") == user_id]


def is_legacy_document(document):
    """Check if a document is a legacy document (no user_id)."""
    return document is not None and not document.get("user_id")
