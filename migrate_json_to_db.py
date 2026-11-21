"""
NotesAI JSON-to-SQLite Migration Script (DRY-RUN ONLY).

This script reads existing JSON data files and prepares them for migration
to the SQLite database. It does NOT modify any JSON files or create any
database records.

Usage:
    python migrate_json_to_db.py --dry-run     # Show what would be migrated
    python migrate_json_to_db.py --verify      # Verify data integrity only
    python migrate_json_to_db.py --execute     # Execute migration (requires --confirm)

Safety:
    - Original JSON files are NEVER modified
    - All operations are read-only by default
    - Real migration requires explicit --confirm flag
    - Idempotent: can be run multiple times without duplicating data
"""

import os
import json
import hashlib
import argparse
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
LEGACY_USER_ID = "legacy" + "0" * 28


def load_json_safe(path):
    """Load a JSON file safely, returning None on error."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as e:
        print(f"  ERROR: Invalid JSON in {path}: {e}")
        return None


def classify_data():
    """Classify all JSON data into user-specific, legacy, global, and system categories."""
    classification = {
        "user_specific": [],
        "legacy": [],
        "global": [],
        "system": [],
        "files": {},
    }

    # documents.json -> legacy (all existing docs become legacy-owned)
    docs = load_json_safe(PROJECT_ROOT / "documents.json")
    if docs is not None:
        classification["legacy"].append({
            "source": "documents.json",
            "count": len(docs),
            "target_table": "documents",
            "owner": LEGACY_USER_ID,
            "note": "All existing documents assigned to Legacy Account",
        })
        classification["files"]["documents.json"] = {
            "exists": True,
            "count": len(docs),
            "size_bytes": os.path.getsize(PROJECT_ROOT / "documents.json"),
            "keys": list(docs[0].keys()) if docs else [],
        }

    # activity.json -> legacy
    activity = load_json_safe(PROJECT_ROOT / "activity.json")
    if activity is not None:
        classification["legacy"].append({
            "source": "activity.json",
            "count": len(activity),
            "target_table": "activity",
            "owner": LEGACY_USER_ID,
            "note": "All existing activity assigned to Legacy Account",
        })
        classification["files"]["activity.json"] = {
            "exists": True,
            "count": len(activity),
            "size_bytes": os.path.getsize(PROJECT_ROOT / "activity.json"),
            "keys": list(activity[0].keys()) if activity else [],
        }

    # billing.json -> global (single workspace billing, not user-specific)
    billing = load_json_safe(PROJECT_ROOT / "billing.json")
    if billing is not None:
        classification["global"].append({
            "source": "billing.json",
            "target_table": "subscriptions + payments",
            "note": "Global billing becomes Legacy Account subscription",
            "data": {k: (v if k != "payments" else f"{len(v)} payments") for k, v in billing.items()},
        })
        classification["files"]["billing.json"] = {
            "exists": True,
            "count": 1,
            "size_bytes": os.path.getsize(PROJECT_ROOT / "billing.json"),
            "keys": list(billing.keys()),
        }

    # stats.json -> system (global counters)
    stats = load_json_safe(PROJECT_ROOT / "stats.json")
    if stats is not None:
        classification["system"].append({
            "source": "stats.json",
            "target_table": "usage",
            "note": "Global stats become Legacy Account usage counters",
            "data": stats,
        })
        classification["files"]["stats.json"] = {
            "exists": True,
            "count": len(stats),
            "size_bytes": os.path.getsize(PROJECT_ROOT / "stats.json"),
            "keys": list(stats.keys()),
        }

    # provider_status.json -> global (system-wide provider status)
    provider_status = load_json_safe(PROJECT_ROOT / "provider_status.json")
    if provider_status is not None:
        classification["global"].append({
            "source": "provider_status.json",
            "target_table": "provider_settings",
            "note": "Global provider status (not user-specific, stays as system default)",
            "data": {k: v.get("status", "unknown") for k, v in provider_status.items()},
        })
        classification["files"]["provider_status.json"] = {
            "exists": True,
            "count": len(provider_status),
            "size_bytes": os.path.getsize(PROJECT_ROOT / "provider_status.json"),
            "keys": list(provider_status.keys()),
        }

    # study_sets.json (if exists)
    study_sets_path = PROJECT_ROOT / "study_sets.json"
    if study_sets_path.exists():
        study_sets = load_json_safe(study_sets_path)
        if study_sets is not None:
            classification["legacy"].append({
                "source": "study_sets.json",
                "count": len(study_sets),
                "target_table": "study_sets",
                "owner": LEGACY_USER_ID,
                "note": "All existing study sets assigned to Legacy Account",
            })
            classification["files"]["study_sets.json"] = {
                "exists": True,
                "count": len(study_sets),
                "size_bytes": os.path.getsize(study_sets_path),
                "keys": list(study_sets[0].keys()) if study_sets else [],
            }
    else:
        classification["files"]["study_sets.json"] = {"exists": False}

    return classification


def verify_data_integrity():
    """Verify integrity of all JSON data files."""
    issues = []

    docs = load_json_safe(PROJECT_ROOT / "documents.json")
    if docs is not None:
        # Check for duplicate IDs
        ids = [d.get("id") for d in docs]
        if len(ids) != len(set(ids)):
            dupes = [x for x in ids if ids.count(x) > 1]
            issues.append(f"Duplicate document IDs: {set(dupes)}")

        # Check for missing required fields
        required = {"id", "name", "type", "kind", "size", "created", "filename"}
        for d in docs:
            missing = required - set(d.keys())
            if missing:
                issues.append(f"Document {d.get('id', '?')[:8]} missing fields: {missing}")

        # Check filename format
        import re
        for d in docs:
            fname = d.get("filename", "")
            if not re.fullmatch(r"[a-f0-9]{32}\.pdf", fname):
                issues.append(f"Document {d.get('id', '?')[:8]} has invalid filename: {fname}")

        # Check file existence
        missing_files = []
        for d in docs:
            fpath = PROJECT_ROOT / "documents" / d.get("filename", "")
            if not fpath.exists():
                missing_files.append(d.get("filename", "?"))
        if missing_files:
            issues.append(f"Missing PDF files: {len(missing_files)} files")

    activity = load_json_safe(PROJECT_ROOT / "activity.json")
    if activity is not None:
        # Check for required fields
        required = {"action", "detail", "status", "timestamp"}
        for a in activity:
            missing = required - set(a.keys())
            if missing:
                issues.append(f"Activity entry missing fields: {missing}")

    return issues


def dry_run():
    """Show what would be migrated without making any changes."""
    print("=" * 60)
    print("NOTESAI JSON-TO-SQLITE MIGRATION — DRY RUN")
    print("=" * 60)
    print()

    classification = classify_data()

    print("FILE CLASSIFICATION:")
    print("-" * 40)
    for fname, info in classification["files"].items():
        if info.get("exists"):
            print(f"  {fname}: {info['count']} records, {info['size_bytes']} bytes")
        else:
            print(f"  {fname}: NOT FOUND")

    print()
    print("DATA CLASSIFICATION:")
    print("-" * 40)

    print("\n  LEGACY (assigned to Legacy Account):")
    for item in classification["legacy"]:
        print(f"    {item['source']}: {item['count']} records → {item['target_table']}")

    print("\n  GLOBAL (system-wide, not user-specific):")
    for item in classification["global"]:
        print(f"    {item['source']}: → {item['target_table']}")
        if "data" in item:
            for k, v in item["data"].items():
                print(f"      {k}: {v}")

    print("\n  SYSTEM (counters and stats):")
    for item in classification["system"]:
        print(f"    {item['source']}: → {item['target_table']}")
        if "data" in item:
            for k, v in item["data"].items():
                print(f"      {k}: {v}")

    print()
    print("INTEGRITY CHECK:")
    print("-" * 40)
    issues = verify_data_integrity()
    if issues:
        for issue in issues:
            print(f"  ⚠️  {issue}")
    else:
        print("  ✅ No integrity issues found")

    print()
    print("LEGACY USER:")
    print(f"  ID: {LEGACY_USER_ID}")
    print(f"  Email: legacy@notesai.local")
    print(f"  Role: legacy (cannot login)")

    print()
    print("MIGRATION PLAN (NOT EXECUTED):")
    print("-" * 40)
    print("  1. Create notesai.db with schema")
    print("  2. Create Legacy User account")
    print("  3. Insert 74 documents with user_id = legacy")
    print("  4. Insert 122 activity entries with user_id = legacy")
    print("  5. Insert billing as Legacy subscription")
    print("  6. Insert stats as Legacy usage counters")
    print("  7. Verify record counts match")
    print("  8. Verify file integrity")
    print()
    print("  Status: DRY RUN ONLY — no data was modified")
    print("=" * 60)


def verify_only():
    """Verify data integrity only."""
    print("DATA INTEGRITY VERIFICATION")
    print("-" * 40)
    issues = verify_data_integrity()
    if issues:
        for issue in issues:
            print(f"  ⚠️  {issue}")
    else:
        print("  ✅ No integrity issues found")

    classification = classify_data()
    print()
    print("FILE SUMMARY:")
    for fname, info in classification["files"].items():
        if info.get("exists"):
            print(f"  {fname}: {info['count']} records, {info['size_bytes']} bytes")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NotesAI JSON-to-SQLite Migration")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be migrated")
    parser.add_argument("--verify", action="store_true", help="Verify data integrity only")
    parser.add_argument("--execute", action="store_true", help="Execute migration (requires --confirm)")
    parser.add_argument("--confirm", action="store_true", help="Confirm migration execution")

    args = parser.parse_args()

    if args.dry_run:
        dry_run()
    elif args.verify:
        verify_only()
    elif args.execute:
        if not args.confirm:
            print("ERROR: --execute requires --confirm flag")
            print("Usage: python migrate_json_to_db.py --execute --confirm")
        else:
            print("ERROR: Real migration not yet implemented.")
            print("Migration will be available after Phase 3 approval.")
    else:
        print("Usage:")
        print("  python migrate_json_to_db.py --dry-run   # Show migration plan")
        print("  python migrate_json_to_db.py --verify    # Verify data integrity")
        print("  python migrate_json_to_db.py --execute --confirm  # Execute (not yet available)")
