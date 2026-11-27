"""
NotesAI Data Models — Data access functions for SQLite database.

This module provides CRUD operations for all database tables.
All functions accept a database connection (from database.get_db()).

NOTE: In Phase 1, these functions are standalone and not yet integrated
with app.py. They will be connected in Phase 2 (User Authentication).
"""

import uuid
import json
from datetime import datetime


def now_iso():
    """Return current timestamp in ISO format (UTC)."""
    from datetime import timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ============================================================================
# USER MODEL
# ============================================================================

def _validate_email(email):
    """Basic email format validation."""
    import re
    return bool(re.match(r"^[^@]+@[^@]+\.[^@]+$", email))

def create_user(db, email, password_hash, name, role="user", email_verified=True):
    """Create a new user. Returns user dict."""
    email = email.lower().strip()
    if not _validate_email(email):
        raise ValueError("Invalid email format")
    if not name.strip():
        raise ValueError("Name cannot be empty")
    if not password_hash:
        raise ValueError("Password hash cannot be empty")
    user_id = uuid.uuid4().hex
    now = now_iso()
    db.execute(
        """INSERT INTO users (id, email, password_hash, name, role, status, email_verified, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)""",
        (user_id, email.lower().strip(), password_hash, name.strip(), role, 1 if email_verified else 0, now, now)
    )
    db.commit()
    return get_user_by_id(db, user_id)


def get_user_by_id(db, user_id):
    """Get user by ID."""
    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return dict(row) if row else None


def get_user_by_email(db, email):
    """Get user by email."""
    row = db.execute("SELECT * FROM users WHERE email = ?", (email.lower().strip(),)).fetchone()
    return dict(row) if row else None

def list_users(db, page=1, per_page=20, search=None, role=None, status=None):
    """List users with pagination and filters (admin use)."""
    conditions = []
    params = []
    if search:
        safe_search = search.replace("%", "\\%").replace("_", "\\_")
        conditions.append("(email LIKE ? ESCAPE '\\' OR name LIKE ? ESCAPE '\\')")
        params.extend([f"%{safe_search}%", f"%{safe_search}%"])
    if role:
        conditions.append("role = ?")
        params.append(role)
    if status:
        conditions.append("status = ?")
        params.append(status)

    where = " AND ".join(conditions) if conditions else "1=1"
    offset = (page - 1) * per_page
    query = f"SELECT id, email, name, role, status, created_at, last_login_at FROM users WHERE {where} ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([per_page, offset])
    rows = db.execute(query, params).fetchall()
    users = [dict(row) for row in rows]

    count_query = f"SELECT COUNT(*) as total FROM users WHERE {where}"
    total = db.execute(count_query, params[:-2]).fetchone()["total"]

    return {
        "items": users,
        "total": total,
        "page": page,
        "per_page": per_page,
        "has_more": (offset + len(users)) < total,
    }


def get_user_stats(db, user_id):
    """Get usage statistics for a user."""
    doc_count = db.execute("SELECT COUNT(*) as c FROM documents WHERE user_id = ? AND deleted_at IS NULL", (user_id,)).fetchone()["c"]
    deleted_count = db.execute("SELECT COUNT(*) as c FROM documents WHERE user_id = ? AND deleted_at IS NOT NULL", (user_id,)).fetchone()["c"]
    activity_count = db.execute("SELECT COUNT(*) as c FROM activity WHERE user_id = ?", (user_id,)).fetchone()["c"]
    study_count = db.execute("SELECT COUNT(*) as c FROM study_sets WHERE user_id = ?", (user_id,)).fetchone()["c"]
    storage = db.execute("SELECT COALESCE(SUM(size), 0) as s FROM documents WHERE user_id = ? AND deleted_at IS NULL", (user_id,)).fetchone()["s"]
    return {
        "documents": doc_count,
        "deleted_documents": deleted_count,
        "activity_entries": activity_count,
        "study_sets": study_count,
        "storage_bytes": storage,
    }



def update_user(db, user_id, **fields):
    """Update user fields. Allowed: name, role, status, last_login_at, password_hash, email_verified."""
    allowed = {"name", "role", "status", "last_login_at", "password_hash", "email_verified"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return False
    updates["updated_at"] = now_iso()
    # Use allowlist-based column mapping for safety
    _USER_COLUMNS = {"name", "role", "status", "last_login_at", "updated_at", "password_hash", "email_verified"}
    safe_updates = {k: v for k, v in updates.items() if k in _USER_COLUMNS}
    set_clause = ", ".join(f"{k} = ?" for k in safe_updates)
    values = list(safe_updates.values()) + [user_id]
    db.execute(f"UPDATE users SET {set_clause} WHERE id = ?", values)
    db.commit()
    return True


def delete_user(db, user_id):
    """Delete a user (cascade deletes all related data)."""
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()


# ============================================================================
# EMAIL VERIFICATION MODEL
# ============================================================================

def create_email_verification(db, user_id, code_hash, expires_at):
    """Store a new OTP record and invalidate older codes for this user."""
    verification_id = uuid.uuid4().hex
    now = now_iso()
    db.execute("UPDATE email_verifications SET verified_at = ? WHERE user_id = ? AND verified_at IS NULL",
               (now, user_id))
    db.execute(
        """INSERT INTO email_verifications (id, user_id, code_hash, expires_at, attempts, created_at)
           VALUES (?, ?, ?, ?, 0, ?)""",
        (verification_id, user_id, code_hash, expires_at, now)
    )
    db.commit()
    return get_email_verification_by_id(db, verification_id)


def get_email_verification_by_id(db, verification_id):
    row = db.execute("SELECT * FROM email_verifications WHERE id = ?", (verification_id,)).fetchone()
    return dict(row) if row else None


def get_latest_email_verification(db, user_id):
    """Return the newest OTP record for a user, including used codes."""
    row = db.execute(
        "SELECT * FROM email_verifications WHERE user_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1",
        (user_id,)
    ).fetchone()
    return dict(row) if row else None


def increment_email_verification_attempt(db, verification_id):
    db.execute(
        "UPDATE email_verifications SET attempts = attempts + 1 WHERE id = ?",
        (verification_id,)
    )
    db.commit()
    return True


def mark_email_verification_verified(db, verification_id):
    db.execute(
        "UPDATE email_verifications SET verified_at = ? WHERE id = ?",
        (now_iso(), verification_id)
    )
    db.commit()
    return True


def delete_email_verifications_for_user(db, user_id):
    db.execute("DELETE FROM email_verifications WHERE user_id = ?", (user_id,))
    db.commit()
    return True


# ============================================================================
# REFRESH TOKEN MODEL
# ============================================================================

def create_refresh_token(db, user_id, token_hash, expires_at):
    """Store a refresh token."""
    token_id = uuid.uuid4().hex
    db.execute(
        """INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        (token_id, user_id, token_hash, expires_at, now_iso())
    )
    db.commit()
    return token_id


def get_refresh_token(db, token_hash):
    """Get a refresh token by hash."""
    row = db.execute(
        "SELECT * FROM refresh_tokens WHERE token_hash = ? AND revoked_at IS NULL",
        (token_hash,)
    ).fetchone()
    return dict(row) if row else None


def revoke_refresh_token(db, token_id):
    """Revoke a refresh token."""
    db.execute("UPDATE refresh_tokens SET revoked_at = ? WHERE id = ?", (now_iso(), token_id))
    db.commit()


def revoke_all_user_tokens(db, user_id):
    """Revoke all refresh tokens for a user."""
    db.execute("UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
               (now_iso(), user_id))
    db.commit()


# ============================================================================
# DOCUMENT MODEL
# ============================================================================

def create_document(db, user_id, name, kind, size, filename, **extra):
    """Create a new document record. Returns document dict."""
    doc_id = uuid.uuid4().hex
    now = now_iso()
    db.execute(
        """INSERT INTO documents (id, user_id, name, type, kind, size, status, filename,
           created_at, updated_at, style, diagram_style, page_size, orientation, margin,
           folder, category, tags, favorite, pdf_options, text_content)
           VALUES (?, ?, ?, 'pdf', ?, ?, 'completed', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            doc_id, user_id, name, kind, size, filename, now, now,
            extra.get("style", "professional"),
            extra.get("diagram_style", "color"),
            extra.get("page_size", "A4"),
            extra.get("orientation", "P"),
            extra.get("margin", 12),
            extra.get("folder", ""),
            extra.get("category", ""),
            json.dumps(extra.get("tags", [])),
            1 if extra.get("favorite") else 0,
            json.dumps(extra.get("pdf_options", {})),
            extra.get("text", "")[:250000],
        )
    )
    db.commit()
    return get_document(db, doc_id, user_id=user_id)


def get_document(db, document_id, user_id, include_deleted=False):
    """Get a document by ID. If user_id provided, verify ownership."""
    query = "SELECT * FROM documents WHERE id = ?"
    params = [document_id]
    if user_id:
        query += " AND user_id = ?"
        params.append(user_id)
    if not include_deleted:
        query += " AND deleted_at IS NULL"
    row = db.execute(query, params).fetchone()
    if row:
        doc = dict(row)
        # Parse JSON fields
        try:
            doc["tags"] = json.loads(doc.get("tags", "[]"))
        except (json.JSONDecodeError, TypeError):
            doc["tags"] = []
        try:
            doc["pdf_options"] = json.loads(doc.get("pdf_options", "{}"))
        except (json.JSONDecodeError, TypeError):
            doc["pdf_options"] = {}
        doc["favorite"] = bool(doc.get("favorite"))
        return doc
    return None


def list_documents(db, user_id, status=None, kind=None, folder=None, tag=None,
                   search=None, sort="created_at", order="desc", include_deleted=False,
                   page=1, per_page=20):
    """List documents for a user with filters and pagination."""
    conditions = ["user_id = ?"]
    params = [user_id]
    if not include_deleted:
        conditions.append("deleted_at IS NULL")
    if status:
        conditions.append("status = ?")
        params.append(status)
    if kind:
        conditions.append("kind = ?")
        params.append(kind)
    if folder:
        conditions.append("folder = ?")
        params.append(folder)
    if tag:
        conditions.append("tags LIKE ?")
        params.append(f'%"{tag}"%')
    if search:
        # Escape SQL LIKE wildcards to prevent unexpected matches
        safe_search = search.replace("%", "\\%").replace("_", "\\_")
        conditions.append("(name LIKE ? ESCAPE '\\' OR text_content LIKE ? ESCAPE '\\')")
        params.extend([f"%{safe_search}%", f"%{safe_search}%"])

    where = " AND ".join(conditions)
    order_dir = "DESC" if order.lower() == "desc" else "ASC"
    # Map friendly sort names to actual column names
    sort_map = {"created": "created_at", "updated": "updated_at", "name": "name", "size": "size", "created_at": "created_at", "updated_at": "updated_at"}
    sort_col = sort_map.get(sort, "created_at")

    offset = (page - 1) * per_page
    query = f"SELECT * FROM documents WHERE {where} ORDER BY {sort_col} {order_dir} LIMIT ? OFFSET ?"
    params.extend([per_page, offset])

    rows = db.execute(query, params).fetchall()
    docs = []
    for row in rows:
        doc = dict(row)
        try:
            doc["tags"] = json.loads(doc.get("tags", "[]"))
        except (json.JSONDecodeError, TypeError):
            doc["tags"] = []
        try:
            doc["pdf_options"] = json.loads(doc.get("pdf_options", "{}"))
        except (json.JSONDecodeError, TypeError):
            doc["pdf_options"] = {}
        doc["favorite"] = bool(doc.get("favorite"))
        docs.append(doc)

    # Total count
    count_query = f"SELECT COUNT(*) as total FROM documents WHERE {where}"
    total = db.execute(count_query, params[:-2]).fetchone()["total"]

    return {
        "items": docs,
        "total": total,
        "page": page,
        "per_page": per_page,
        "has_more": (offset + len(docs)) < total,
    }


def update_document(db, document_id, user_id, **fields):
    """Update document fields. Returns updated document or None."""
    allowed = {"name", "folder", "category", "tags", "favorite"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return None

    # Verify ownership
    doc = get_document(db, document_id, user_id=user_id)
    if not doc:
        return None

    if "tags" in updates and isinstance(updates["tags"], list):
        updates["tags"] = json.dumps(updates["tags"])
    if "favorite" in updates:
        updates["favorite"] = 1 if updates["favorite"] else 0
    updates["updated_at"] = now_iso()

    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [document_id, user_id]
    db.execute(f"UPDATE documents SET {set_clause} WHERE id = ? AND user_id = ?", values)
    db.commit()
    return get_document(db, document_id, user_id=user_id)


def soft_delete_document(db, document_id, user_id):
    """Soft-delete a document (set deleted_at)."""
    doc = get_document(db, document_id, user_id=user_id)
    if not doc:
        return False
    db.execute("UPDATE documents SET deleted_at = ?, updated_at = ? WHERE id = ? AND user_id = ?",
               (now_iso(), now_iso(), document_id, user_id))
    db.commit()
    return True


def restore_document(db, document_id, user_id):
    """Restore a soft-deleted document."""
    doc = get_document(db, document_id, user_id=user_id, include_deleted=True)
    if not doc or not doc.get("deleted_at"):
        return False
    db.execute("UPDATE documents SET deleted_at = NULL, updated_at = ? WHERE id = ? AND user_id = ?",
               (now_iso(), document_id, user_id))
    db.commit()
    return True


def hard_delete_document(db, document_id, user_id):
    """Permanently delete a document."""
    doc = get_document(db, document_id, user_id=user_id, include_deleted=True)
    if not doc:
        return False
    db.execute("DELETE FROM documents WHERE id = ? AND user_id = ?", (document_id, user_id))
    db.commit()
    return True


# ============================================================================
# ACTIVITY MODEL
# ============================================================================

def add_activity(db, user_id, action, detail, status="completed", provider="", document_id=None):
    """Add an activity log entry."""
    db.execute(
        """INSERT INTO activity (user_id, action, detail, status, provider, document_id, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (user_id, action, detail, status, provider, document_id, now_iso())
    )
    db.commit()


def list_activity(db, user_id, limit=40):
    """List recent activity for a user."""
    rows = db.execute(
        "SELECT * FROM activity WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?",
        (user_id, limit)
    ).fetchall()
    return [dict(row) for row in rows]


def clear_activity(db, user_id):
    """Clear all activity for a user."""
    db.execute("DELETE FROM activity WHERE user_id = ?", (user_id,))
    db.commit()


# ============================================================================
# STUDY SET MODEL
# ============================================================================

def save_study_set(db, user_id, action, action_label, result, language="English",
                   provider="", model="", source_document_id=None, source_name="", title=""):
    """Save a study set."""
    set_id = uuid.uuid4().hex
    db.execute(
        """INSERT INTO study_sets (id, user_id, action, action_label, result, language,
           provider, model, source_document_id, source_name, title, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (set_id, user_id, action, action_label, result, language, provider, model,
         source_document_id, source_name, title, now_iso())
    )
    db.commit()
    return set_id


def list_study_sets(db, user_id):
    """List study sets for a user."""
    rows = db.execute(
        "SELECT * FROM study_sets WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,)
    ).fetchall()
    return [dict(row) for row in rows]


def delete_study_set(db, set_id, user_id):
    """Delete a study set (verify ownership)."""
    row = db.execute("SELECT id FROM study_sets WHERE id = ? AND user_id = ?", (set_id, user_id)).fetchone()
    if not row:
        return False
    db.execute("DELETE FROM study_sets WHERE id = ? AND user_id = ?", (set_id, user_id))
    db.commit()
    return True


# ============================================================================
# AI EXAM PLANNER MODEL
# ============================================================================

_PLANNER_JSON_COLUMNS = {"warnings_json", "schedule_json", "progress_json", "previous_schedule_json"}
_PLANNER_UPDATABLE = {
    "title", "exam_name", "exam_date", "today", "daily_hours", "days_remaining",
    "total_hours", "source_summary", "warnings_json", "schedule_json",
    "progress_json", "previous_schedule_json", "status", "version", "provider", "model",
}


def _decode_planner_json(value, fallback):
    """Decode a planner JSON column without ever raising on old/corrupt rows."""
    if value in (None, ""):
        return fallback
    parsed = value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError):
            return fallback
    if isinstance(fallback, dict) and not isinstance(parsed, dict):
        return fallback
    if isinstance(fallback, list) and not isinstance(parsed, list):
        return fallback
    return parsed


def _planner_from_row(row):
    if not row:
        return None
    item = dict(row)
    item["warnings"] = _decode_planner_json(item.get("warnings_json"), [])
    item["schedule"] = _decode_planner_json(item.get("schedule_json"), {})
    item["progress"] = _decode_planner_json(
        item.get("progress_json"), {"completed": {}, "missed_days": []}
    )
    item["previous_schedule"] = (
        _decode_planner_json(item.get("previous_schedule_json"), {})
        if item.get("previous_schedule_json") else None
    )
    return item


def create_planner(db, user_id, *, exam_name, exam_date, today, daily_hours,
                   days_remaining, total_hours, source_summary="", warnings=None,
                   schedule=None, progress=None, title="", provider="", model=""):
    """Create a planner owned by one user. Returns the full planner record."""
    planner_id = uuid.uuid4().hex
    now = now_iso()
    db.execute(
        """INSERT INTO exam_planners (
              id, user_id, title, exam_name, exam_date, today, daily_hours,
              days_remaining, total_hours, source_summary, warnings_json,
              schedule_json, progress_json, status, version, provider, model,
              created_at, updated_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', 1, ?, ?, ?, ?)""",
        (
            planner_id, user_id, str(title or "")[:200], str(exam_name or "")[:200],
            str(exam_date), str(today), float(daily_hours), int(days_remaining),
            float(total_hours), str(source_summary or "")[:1000],
            json.dumps(warnings or [], ensure_ascii=False),
            json.dumps(schedule or {}, ensure_ascii=False),
            json.dumps(progress or {"completed": {}, "missed_days": []}, ensure_ascii=False),
            str(provider or "")[:80], str(model or "")[:120], now, now,
        )
    )
    db.commit()
    return get_planner(db, planner_id, user_id)


def get_planner(db, planner_id, user_id):
    """Get a planner only when it belongs to user_id."""
    row = db.execute(
        "SELECT * FROM exam_planners WHERE id = ? AND user_id = ?",
        (str(planner_id), str(user_id)),
    ).fetchone()
    return _planner_from_row(row)


def list_planners(db, user_id, limit=100):
    """List the user's planners, newest first."""
    rows = db.execute(
        "SELECT * FROM exam_planners WHERE user_id = ? ORDER BY updated_at DESC, created_at DESC LIMIT ?",
        (str(user_id), int(limit)),
    ).fetchall()
    return [_planner_from_row(row) for row in rows]


def find_planner_by_exam(db, user_id, exam_name, exam_date):
    """Find an existing planner for the same exam name/date."""
    row = db.execute(
        """SELECT * FROM exam_planners
           WHERE user_id = ? AND LOWER(exam_name) = LOWER(?) AND exam_date = ?
           ORDER BY created_at DESC LIMIT 1""",
        (str(user_id), str(exam_name), str(exam_date)),
    ).fetchone()
    return _planner_from_row(row)


def update_planner(db, planner_id, user_id, fields, bump_version=False):
    """Update owned planner fields. Unknown keys are ignored for safety."""
    changes = []
    values = []
    for key, value in (fields or {}).items():
        if key not in _PLANNER_UPDATABLE:
            continue
        if key in _PLANNER_JSON_COLUMNS and not isinstance(value, str):
            value = json.dumps(value, ensure_ascii=False)
        changes.append(f"{key} = ?")
        values.append(value)
    if bump_version:
        changes.append("version = version + 1")
    if not changes:
        return get_planner(db, planner_id, user_id)
    changes.append("updated_at = ?")
    values.append(now_iso())
    values.extend([str(planner_id), str(user_id)])
    cursor = db.execute(
        "UPDATE exam_planners SET " + ", ".join(changes) + " WHERE id = ? AND user_id = ?",
        values,
    )
    db.commit()
    if cursor.rowcount <= 0:
        return None
    return get_planner(db, planner_id, user_id)


def delete_planner(db, planner_id, user_id):
    """Delete a planner only when it belongs to user_id."""
    cursor = db.execute(
        "DELETE FROM exam_planners WHERE id = ? AND user_id = ?",
        (str(planner_id), str(user_id)),
    )
    db.commit()
    return cursor.rowcount > 0


def save_planner_progress(db, planner_id, user_id, progress):
    """Persist real completion data for the user's planner."""
    return update_planner(
        db, planner_id, user_id,
        {"progress_json": progress or {"completed": {}, "missed_days": []}},
    )


# ============================================================================
# SUBSCRIPTION & BILLING MODEL
# ============================================================================

def get_user_subscription(db, user_id):
    """Get active subscription for a user."""
    row = db.execute(
        "SELECT * FROM subscriptions WHERE user_id = ? AND status = 'active' ORDER BY created_at DESC LIMIT 1",
        (user_id,)
    ).fetchone()
    return dict(row) if row else None


def create_subscription(db, user_id, plan_id):
    """Create a new subscription for a user."""
    sub_id = uuid.uuid4().hex
    now = now_iso()
    db.execute(
        """INSERT INTO subscriptions (id, user_id, plan_id, status, created_at, updated_at)
           VALUES (?, ?, ?, 'active', ?, ?)""",
        (sub_id, user_id, plan_id, now, now)
    )
    db.commit()
    return sub_id


def update_subscription(db, user_id, plan_id, status=None):
    """Update a user's subscription."""
    sub = get_user_subscription(db, user_id)
    if not sub:
        return create_subscription(db, user_id, plan_id)
    updates = {"plan_id": plan_id, "updated_at": now_iso()}
    if status:
        updates["status"] = status
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [sub["id"]]
    db.execute(f"UPDATE subscriptions SET {set_clause} WHERE id = ?", values)
    db.commit()


def get_user_plan(db, user_id):
    """Get the plan limits for a user."""
    sub = get_user_subscription(db, user_id)
    plan_id = sub["plan_id"] if sub else "free"
    row = db.execute("SELECT * FROM plans WHERE id = ?", (plan_id,)).fetchone()
    if row:
        return dict(row)
    return {"id": "free", "label": "Free workspace", "max_documents": 100, "max_storage_mb": 250}


def add_payment(db, user_id, amount, subscription_id=None, currency="USD",
                status="pending", payment_method=None, transaction_id=None):
    """Record a payment."""
    payment_id = uuid.uuid4().hex
    db.execute(
        """INSERT INTO payments (id, user_id, subscription_id, amount, currency, status,
           payment_method, transaction_id, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (payment_id, user_id, subscription_id, amount, currency, status,
         payment_method, transaction_id, now_iso())
    )
    db.commit()
    return payment_id


# ============================================================================
# USAGE MODEL
# ============================================================================

def get_usage(db, user_id, key):
    """Get a usage counter value."""
    row = db.execute("SELECT value FROM usage WHERE user_id = ? AND key = ?", (user_id, key)).fetchone()
    return row["value"] if row else 0


def set_usage(db, user_id, key, value):
    """Set a usage counter value."""
    db.execute(
        """INSERT INTO usage (user_id, key, value, updated_at) VALUES (?, ?, ?, ?)
           ON CONFLICT(user_id, key) DO UPDATE SET value = ?, updated_at = ?""",
        (user_id, key, value, now_iso(), value, now_iso())
    )
    db.commit()


def increment_usage(db, user_id, key, delta=1):
    """Increment a usage counter."""
    current = get_usage(db, user_id, key)
    new_value = max(0, current + delta)
    set_usage(db, user_id, key, new_value)
    return new_value


# ============================================================================
# PROVIDER SETTINGS MODEL
# ============================================================================

def get_provider_setting(db, user_id, provider):
    """Get provider settings for a user."""
    row = db.execute(
        "SELECT * FROM provider_settings WHERE user_id = ? AND provider = ?",
        (user_id, provider)
    ).fetchone()
    return dict(row) if row else None


def set_provider_setting(db, user_id, provider, api_key_encrypted=None, model=None):
    """Set or update provider settings for a user."""
    existing = get_provider_setting(db, user_id, provider)
    now = now_iso()
    if existing:
        _PROVIDER_COLUMNS = {"api_key_encrypted", "model", "updated_at"}
        updates = {"updated_at": now}
        if api_key_encrypted is not None:
            updates["api_key_encrypted"] = api_key_encrypted
        if model is not None:
            updates["model"] = model
        safe_updates = {k: v for k, v in updates.items() if k in _PROVIDER_COLUMNS}
        set_clause = ", ".join(f"{k} = ?" for k in safe_updates)
        values = list(safe_updates.values()) + [existing["id"]]
        db.execute(f"UPDATE provider_settings SET {set_clause} WHERE id = ?", values)
    else:
        setting_id = uuid.uuid4().hex
        db.execute(
            """INSERT INTO provider_settings (id, user_id, provider, api_key_encrypted, model, updated_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (setting_id, user_id, provider, api_key_encrypted, model, now)
        )
    db.commit()


# ============================================================================
# PASSWORD RESET MODEL
# ============================================================================

def create_password_reset_token(db, user_id, token_hash, expires_at):
    """Create a password reset token."""
    token_id = uuid.uuid4().hex
    db.execute(
        """INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        (token_id, user_id, token_hash, expires_at, now_iso())
    )
    db.commit()
    return token_id


def get_password_reset_token(db, token_hash):
    """Get a valid (unused, not expired) password reset token."""
    row = db.execute(
        """SELECT * FROM password_reset_tokens
           WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?""",
        (token_hash, now_iso())
    ).fetchone()
    return dict(row) if row else None


def mark_password_reset_used(db, token_id):
    """Mark a password reset token as used."""
    db.execute("UPDATE password_reset_tokens SET used_at = ? WHERE id = ?", (now_iso(), token_id))
    db.commit()


# ============================================================================
# LEGACY DATA MIGRATION HELPERS
# ============================================================================

def create_legacy_user(db):
    """Create the legacy user account for pre-migration data."""
    import secrets
    legacy_id = "legacy" + "0" * 28  # Fixed ID for easy identification
    # Check if already exists
    existing = get_user_by_id(db, legacy_id)
    if existing:
        return legacy_id
    db.execute(
        """INSERT INTO users (id, email, password_hash, name, role, status, created_at, updated_at)
           VALUES (?, ?, ?, ?, 'legacy', 'active', ?, ?)""",
        (legacy_id, 'legacy@notesai.local', secrets.token_hex(32), 'Legacy Data', now_iso(), now_iso())
    )
    db.commit()
    return legacy_id


def get_legacy_user_id():
    """Return the fixed legacy user ID."""
    return "legacy" + "0" * 28
