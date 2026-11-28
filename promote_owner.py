"""One-time server-side admin bootstrap for an existing NotesAI account.

Run this only in the PythonAnywhere console (or another trusted server shell):

    cd /home/hobaibafridi59/notesai-deploy
    source /home/hobaibafridi59/.virtualenvs/notesai-venv/bin/activate
    python promote_owner.py

It never exposes passwords or tokens, never creates a duplicate account, and
only changes the role/status of one already-registered email. Documents,
activity, study sets, billing data and all other user rows are untouched.
"""

import os
from pathlib import Path


def load_project_env():
    """Mirror the WSGI .env loading so the same database is used."""
    env_path = Path(".env")
    if env_path.exists():
        for line in env_path.read_text(errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip())
    os.environ.setdefault("USE_DATABASE", "1")


def mask_email(email):
    local, _, domain = email.partition("@")
    prefix = local[:2] if local else "**"
    return f"{prefix}***@{domain}" if domain else f"{prefix}***"


def main():
    load_project_env()

    import database
    import models

    email = input("Registered owner email: ").strip().lower()
    if not email or "@" not in email:
        raise SystemExit("Invalid email. No changes made.")

    database.init_db()
    db = database.get_db()
    user = models.get_user_by_email(db, email)

    if not user:
        raise SystemExit("No account found with that email. No changes made.")

    print(
        "Found:", mask_email(email),
        "| role:", user["role"],
        "| status:", user["status"],
    )

    if user["role"] == "admin" and user["status"] == "active":
        raise SystemExit("Already an active admin. No changes made.")

    confirm = input("Type PROMOTE to continue: ").strip()
    if confirm != "PROMOTE":
        raise SystemExit("Cancelled. No changes made.")

    # Allowlisted update: role and status only. password_hash, email_verified,
    # documents, activity, study sets and every other row remain untouched.
    models.update_user(db, user["id"], role="admin", status="active")
    updated = models.get_user_by_id(db, user["id"])

    print(
        "PROMOTED:", updated["id"][:8] + "...",
        mask_email(updated["email"]),
        updated["role"],
        updated["status"],
    )
    print("Now sign out and sign in again so fresh admin cookies are issued.")


if __name__ == "__main__":
    main()
