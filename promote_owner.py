"""One-time, idempotent server-side owner promotion for NotesAI.

This script is intentionally CLI-only. It is never exposed as an HTTP route.

Target:
    hobaibafridi59@gmail.com

It verifies the existing registered account, requires explicit typed
confirmation, creates a timestamped backup, updates only role/status, then
verifies that identity, password hash and user data were preserved.
"""

import hashlib
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

OWNER_EMAIL = "hobaibafridi59@gmail.com"
CONFIRMATION = "PROMOTE " + OWNER_EMAIL


def load_project_env():
    """Mirror WSGI .env loading so the same database is used."""
    env_path = Path(".env")
    if env_path.exists():
        for line in env_path.read_text(errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip())

    # This is a DB-only administrative tool. Never let a stale USE_DATABASE=0
    # silently point it at an in-memory database.
    os.environ["USE_DATABASE"] = "1"


def mask_email(email):
    local, _, domain = email.partition("@")
    prefix = local[:2] if local else "**"
    return f"{prefix}***@{domain}" if domain else f"{prefix}***"


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def data_counts(db, user_id):
    return {
        "users": int(db.execute("SELECT COUNT(*) FROM users").fetchone()[0]),
        "documents": int(db.execute(
            "SELECT COUNT(*) FROM documents WHERE user_id = ?", (user_id,)
        ).fetchone()[0]),
        "activity": int(db.execute(
            "SELECT COUNT(*) FROM activity WHERE user_id = ?", (user_id,)
        ).fetchone()[0]),
        "study_sets": int(db.execute(
            "SELECT COUNT(*) FROM study_sets WHERE user_id = ?", (user_id,)
        ).fetchone()[0]),
        "email_matches": int(db.execute(
            "SELECT COUNT(*) FROM users WHERE email = ?", (OWNER_EMAIL,)
        ).fetchone()[0]),
    }


def user_snapshot(user):
    return {
        "id": user["id"],
        "email": user["email"],
        "password_hash": user["password_hash"],
        "name": user["name"],
        "role": user["role"],
        "status": user["status"],
        "email_verified": user["email_verified"],
        "created_at": user["created_at"],
    }


def create_backup(database_path, before, counts):
    """Create a consistent DB snapshot plus a single-row rollback record."""
    backup_root = Path(
        os.getenv(
            "NOTESAI_PROMOTION_BACKUP_DIR",
            str(Path(database_path).resolve().parent / ".s1-backup"),
        )
    ).resolve()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "-" + uuid.uuid4().hex[:6]
    backup_dir = backup_root / f"owner-promotion-{stamp}"
    backup_dir.mkdir(parents=True, exist_ok=True)

    snapshot_path = backup_dir / "notesai.db"
    source = sqlite3.connect(f"file:{Path(database_path).resolve()}?mode=ro", uri=True)
    destination = sqlite3.connect(str(snapshot_path))
    try:
        source.backup(destination)
    finally:
        destination.close()
        source.close()

    rollback = {
        "email": OWNER_EMAIL,
        "user_id": before["id"],
        "previous_role": before["role"],
        "previous_status": before["status"],
        "counts_before": counts,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "note": "Contains no password, token or secret.",
    }
    rollback_path = backup_dir / "rollback.json"
    rollback_path.write_text(
        json.dumps(rollback, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    hashes = [
        f"notesai.db sha256: {file_sha256(snapshot_path)}",
        f"rollback.json sha256: {file_sha256(rollback_path)}",
    ]
    env_path = Path(".env")
    if env_path.exists():
        # Store only the hash. Never copy .env into a backup directory.
        hashes.append(f".env sha256: {file_sha256(env_path)} (not copied)")
    (backup_dir / "SHA256SUMS.txt").write_text("\n".join(hashes) + "\n", encoding="utf-8")
    return backup_dir


def verify_after_update(db, models, user_id, before, counts_before):
    updated = models.get_user_by_id(db, user_id)
    if not updated:
        return False, "USER_MISSING_AFTER_UPDATE"

    checks = {
        "same_id": updated["id"] == before["id"],
        "same_email": updated["email"] == OWNER_EMAIL,
        "same_password_hash": updated["password_hash"] == before["password_hash"],
        "same_name": updated["name"] == before["name"],
        "same_created_at": updated["created_at"] == before["created_at"],
        "same_email_verified": updated["email_verified"] == before["email_verified"],
        "role_admin": updated["role"] == "admin",
        "status_active": updated["status"] == "active",
        "counts_unchanged": data_counts(db, user_id) == counts_before,
    }
    failed = [name for name, ok in checks.items() if not ok]
    return (not failed), ",".join(failed)


def main():
    load_project_env()

    import database
    import models

    database.init_db()
    db = database.get_db()
    user = models.get_user_by_email(db, OWNER_EMAIL)

    if not user:
        print("NOT_FOUND: no account with the configured owner email. No changes made.")
        raise SystemExit(2)

    before = user_snapshot(user)
    counts_before = data_counts(db, user["id"])

    if before["role"] == "admin" and before["status"] == "active":
        print("ALREADY_ADMIN:", mask_email(before["email"]), "no changes made.")
        return

    print("TARGET:", mask_email(before["email"]))
    print("CURRENT:", "role=" + before["role"], "status=" + before["status"])

    confirmation = input("Type " + CONFIRMATION + " to continue: ").strip()
    if confirmation != CONFIRMATION:
        print("CANCELLED: confirmation did not match. No changes made.")
        raise SystemExit(1)

    backup_dir = create_backup(database.DATABASE_PATH, before, counts_before)
    print("BACKUP:", str(backup_dir))

    # Allowlisted update: role and status only.
    models.update_user(db, user["id"], role="admin", status="active")

    ok, reason = verify_after_update(db, models, user["id"], before, counts_before)
    if not ok:
        try:
            models.update_user(
                db,
                user["id"],
                role=before["role"],
                status=before["status"],
            )
            print("VERIFICATION_FAILED:", reason, "ROLLED_BACK")
        except Exception:
            print("VERIFICATION_FAILED:", reason, "MANUAL_ROLLBACK_REQUIRED")
        raise SystemExit(3)

    after = models.get_user_by_id(db, user["id"])
    print(
        "PROMOTED:",
        after["id"][:8] + "...",
        mask_email(after["email"]),
        "role=" + after["role"],
        "status=" + after["status"],
    )
    print("PRESERVED_ID:", after["id"] == before["id"])
    print("PRESERVED_EMAIL:", after["email"] == before["email"])
    print("PRESERVED_PASSWORD_HASH:", after["password_hash"] == before["password_hash"])
    print("PRESERVED_NAME:", after["name"] == before["name"])
    print("PRESERVED_CREATED_AT:", after["created_at"] == before["created_at"])
    print("PRESERVED_EMAIL_VERIFIED:", after["email_verified"] == before["email_verified"])
    print("USER_DATA_UNCHANGED:", data_counts(db, user["id"]) == counts_before)
    print("NO_DUPLICATE:", counts_before["email_matches"] == 1 and counts_before["users"] == data_counts(db, user["id"])["users"])
    print("NEXT: sign out and sign in again so fresh admin cookies are issued.")


if __name__ == "__main__":
    main()
