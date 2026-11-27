"""
NotesAI Database Layer — SQLite schema and connection management.

This module provides the database schema and connection management for NotesAI.
It is designed to be used alongside the existing JSON-based storage during
a gradual migration period.

Environment:
    USE_DATABASE=1  — Enable database mode (default: False, uses JSON)
    DATABASE_PATH    — Path to SQLite database file (default: notesai.db)

Usage:
    from database import get_db, init_db, close_db
    db = get_db()
    # use db connection
    close_db(db)
"""

import os
import sqlite3
import threading
from pathlib import Path

# Database configuration
PROJECT_ROOT = Path(__file__).resolve().parent
DATABASE_PATH = os.environ.get("DATABASE_PATH", str(PROJECT_ROOT / "notesai.db"))
USE_DATABASE = os.environ.get("USE_DATABASE", "0").strip().lower() in {"1", "true", "yes", "on"}

# Thread-local connection storage
_local = threading.local()


def get_db():
    """Get a thread-local database connection."""
    if not hasattr(_local, "connection") or _local.connection is None:
        _local.connection = sqlite3.connect(DATABASE_PATH, timeout=30)
        _local.connection.row_factory = sqlite3.Row
        _local.connection.execute("PRAGMA foreign_keys = ON")
        _local.connection.execute("PRAGMA journal_mode = WAL")
        _local.connection.execute("PRAGMA busy_timeout = 5000")
    return _local.connection


def close_db(conn=None):
    """Close the database connection for the current thread."""
    if conn is None:
        conn = getattr(_local, "connection", None)
    if conn is not None:
        conn.close()
        _local.connection = None


def init_db():
    """Initialize the database schema. Safe to call multiple times (idempotent)."""
    db = get_db()
    db.executescript(SCHEMA_SQL)

    # Forward-only migration for databases created before email verification.
    columns = {row[1] for row in db.execute("PRAGMA table_info(users)")}
    if "email_verified" not in columns:
        db.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 1")

    db.commit()
    return db


def reset_db(confirm=False):
    """Drop all tables and recreate. USE ONLY FOR TESTING.

    Requires confirm=True to prevent accidental production use.
    """
    if not confirm:
        raise ValueError("reset_db() requires confirm=True to prevent accidental data loss.")
    db = get_db()
    # Get all table names
    cursor = db.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    for table in tables:
        if table != "sqlite_sequence":
            db.execute(f"DROP TABLE IF EXISTS {table}")
    db.commit()
    init_db()
    return db


# ============================================================================
# SCHEMA DEFINITION
# ============================================================================

SCHEMA_SQL = """
-- ============================================================================
-- USERS
-- ============================================================================
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT DEFAULT 'user' CHECK(role IN ('user', 'admin', 'legacy')),
    status TEXT DEFAULT 'active' CHECK(status IN ('active', 'suspended', 'deleted')),
    email_verified INTEGER DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_login_at TEXT
);

-- ============================================================================
-- REFRESH TOKENS (for JWT revocation)
-- ============================================================================
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
    token_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked_at TEXT
);

-- ============================================================================
-- DOCUMENTS
-- ============================================================================
CREATE TABLE IF NOT EXISTS documents (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
    name TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'pdf',
    kind TEXT NOT NULL DEFAULT 'professional',
    size INTEGER NOT NULL DEFAULT 0,
    status TEXT DEFAULT 'completed' CHECK(status IN ('completed', 'failed', 'processing')),
    provider TEXT DEFAULT '',
    model TEXT DEFAULT '',
    style TEXT DEFAULT 'professional',
    diagram_style TEXT DEFAULT 'color',
    page_size TEXT DEFAULT 'A4',
    orientation TEXT DEFAULT 'P',
    margin INTEGER DEFAULT 12,
    pages INTEGER,
    folder TEXT DEFAULT '',
    category TEXT DEFAULT '',
    tags TEXT DEFAULT '[]',
    favorite INTEGER DEFAULT 0,
    deleted_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    filename TEXT NOT NULL,
    text_content TEXT,
    pdf_options TEXT
);

-- ============================================================================
-- ACTIVITY LOG
-- ============================================================================
CREATE TABLE IF NOT EXISTS activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
    action TEXT NOT NULL,
    detail TEXT NOT NULL,
    status TEXT DEFAULT 'completed' CHECK(status IN ('completed', 'failed', 'cancelled')),
    provider TEXT DEFAULT '',
    document_id TEXT,
    timestamp TEXT NOT NULL
);

-- ============================================================================
-- STUDY SETS
-- ============================================================================
CREATE TABLE IF NOT EXISTS study_sets (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
    action TEXT NOT NULL,
    action_label TEXT NOT NULL,
    result TEXT NOT NULL,
    language TEXT DEFAULT 'English',
    provider TEXT DEFAULT '',
    model TEXT DEFAULT '',
    source_document_id TEXT,
    source_name TEXT DEFAULT '',
    title TEXT DEFAULT '',
    created_at TEXT NOT NULL
);

-- ============================================================================
-- PLANS
-- ============================================================================
CREATE TABLE IF NOT EXISTS plans (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    max_documents INTEGER NOT NULL,
    max_storage_mb INTEGER NOT NULL
);

-- ============================================================================
-- SUBSCRIPTIONS
-- ============================================================================
CREATE TABLE IF NOT EXISTS subscriptions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
    plan_id TEXT NOT NULL REFERENCES plans(id),
    status TEXT DEFAULT 'active' CHECK(status IN ('active', 'cancelled', 'expired', 'suspended')),
    renewal_date TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- ============================================================================
-- PAYMENTS
-- ============================================================================
CREATE TABLE IF NOT EXISTS payments (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
    subscription_id TEXT REFERENCES subscriptions(id) ON DELETE SET NULL,
    amount REAL NOT NULL,
    currency TEXT DEFAULT 'USD',
    status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'completed', 'failed', 'refunded')),
    payment_method TEXT,
    transaction_id TEXT,
    created_at TEXT NOT NULL
);

-- ============================================================================
-- USAGE TRACKING
-- ============================================================================
CREATE TABLE IF NOT EXISTS usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
    key TEXT NOT NULL,
    value INTEGER DEFAULT 0,
    updated_at TEXT NOT NULL,
    UNIQUE(user_id, key)
);

-- ============================================================================
-- PROVIDER SETTINGS (per user, optional)
-- ============================================================================
CREATE TABLE IF NOT EXISTS provider_settings (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
    provider TEXT NOT NULL CHECK(provider IN ('gemini', 'openrouter')),
    api_key_encrypted TEXT,
    model TEXT,
    updated_at TEXT NOT NULL,
    UNIQUE(user_id, provider)
);

-- ============================================================================
-- PASSWORD RESET TOKENS
-- ============================================================================
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
    token_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT NOT NULL
);

-- ============================================================================
-- INDEXES
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_documents_user_id ON documents(user_id);
CREATE INDEX IF NOT EXISTS idx_documents_deleted_at ON documents(deleted_at);
CREATE INDEX IF NOT EXISTS idx_documents_created ON documents(created_at);
CREATE INDEX IF NOT EXISTS idx_documents_status ON documents(status);
CREATE INDEX IF NOT EXISTS idx_documents_folder ON documents(folder);
CREATE INDEX IF NOT EXISTS idx_activity_user_id ON activity(user_id);
CREATE INDEX IF NOT EXISTS idx_activity_timestamp ON activity(timestamp);
CREATE INDEX IF NOT EXISTS idx_study_sets_user_id ON study_sets(user_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_user_id ON subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_payments_user_id ON payments(user_id);
CREATE INDEX IF NOT EXISTS idx_usage_user_id ON usage(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_password_reset_user_id ON password_reset_tokens(user_id);

-- ============================================================================
-- AI EXAM PLANNER
-- ============================================================================
CREATE TABLE IF NOT EXISTS exam_planners (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    title TEXT NOT NULL DEFAULT '',
    exam_name TEXT NOT NULL,
    exam_date TEXT NOT NULL,
    today TEXT NOT NULL,
    daily_hours REAL NOT NULL,
    days_remaining INTEGER NOT NULL,
    total_hours REAL NOT NULL,
    source_summary TEXT NOT NULL DEFAULT '',
    warnings_json TEXT NOT NULL DEFAULT '[]',
    schedule_json TEXT NOT NULL,
    progress_json TEXT NOT NULL DEFAULT '{"completed": {}, "missed_days": []}',
    previous_schedule_json TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    version INTEGER NOT NULL DEFAULT 1,
    provider TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_exam_planners_user_id ON exam_planners(user_id);
CREATE INDEX IF NOT EXISTS idx_exam_planners_user_exam ON exam_planners(user_id, exam_date);

-- ============================================================================
-- EMAIL VERIFICATION (OTP)
-- ============================================================================
CREATE TABLE IF NOT EXISTS email_verifications (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
    code_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    attempts INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    verified_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_email_verifications_user_id ON email_verifications(user_id);
CREATE INDEX IF NOT EXISTS idx_email_verifications_user_created ON email_verifications(user_id, created_at);

-- ============================================================================
-- SCHEMA VERSION
-- ============================================================================
CREATE TABLE IF NOT EXISTS schema_version (
    version TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL
);

INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES ('1.0.0', datetime('now'));
INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES ('1.1.0', datetime('now'));
INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES ('1.2.0', datetime('now'));

-- ============================================================================
-- DEFAULT DATA
-- ============================================================================
INSERT OR IGNORE INTO plans (id, label, max_documents, max_storage_mb) VALUES
    ('free', 'Free workspace', 100, 250),
    ('pro', 'Professional workspace', 500, 2048);
"""




def table_exists(table_name):
    """Check if a table exists in the database."""
    db = get_db()
    cursor = db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,)
    )
    return cursor.fetchone() is not None


def get_table_names():
    """Return list of all table names in the database."""
    db = get_db()
    cursor = db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    return [row[0] for row in cursor.fetchall()]


_ALLOWED_TABLES = {
    "users", "refresh_tokens", "documents", "activity", "study_sets",
    "plans", "subscriptions", "payments", "usage", "provider_settings",
    "password_reset_tokens", "schema_version", "exam_planners", "email_verifications",
}

def _validate_table_name(table_name):
    if table_name not in _ALLOWED_TABLES:
        raise ValueError(f"Unknown table: {table_name}")

def get_table_info(table_name):
    """Return column info for a table."""
    _validate_table_name(table_name)
    db = get_db()
    cursor = db.execute(f"PRAGMA table_info({table_name})")
    columns = []
    for row in cursor.fetchall():
        columns.append({
            "cid": row[0],
            "name": row[1],
            "type": row[2],
            "notnull": bool(row[3]),
            "default": row[4],
            "pk": bool(row[5]),
        })
    return columns


def get_foreign_keys(table_name):
    """Return foreign key info for a table."""
    _validate_table_name(table_name)
    db = get_db()
    cursor = db.execute(f"PRAGMA foreign_key_list({table_name})")
    fks = []
    for row in cursor.fetchall():
        fks.append({
            "id": row[0],
            "seq": row[1],
            "table": row[2],
            "from": row[3],
            "to": row[4],
            "on_update": row[5],
            "on_delete": row[6],
        })
    return fks


def get_indexes(table_name):
    """Return index info for a table."""
    _validate_table_name(table_name)
    db = get_db()
    cursor = db.execute(f"PRAGMA index_list({table_name})")
    indexes = []
    for row in cursor.fetchall():
        indexes.append({
            "seq": row[0],
            "name": row[1],
            "unique": bool(row[2]),
            "origin": row[3],
            "partial": bool(row[4]),
        })
    return indexes

def backup_db(destination_path):
    """Create a safe online backup of the database."""
    import shutil
    db = get_db()
    # Use SQLite backup API for safe online backup
    backup_conn = sqlite3.connect(destination_path)
    db.backup(backup_conn)
    backup_conn.close()
    return destination_path


def vacuum_db():
    """Run maintenance: optimize and vacuum the database."""
    db = get_db()
    db.execute("PRAGMA optimize")
    db.commit()
    db.execute("VACUUM")
    db.commit()


def get_schema_version():
    """Return the current schema version."""
    db = get_db()
    try:
        row = db.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
        return row["version"] if row else "unknown"
    except Exception:
        return "unknown"

