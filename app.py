from flask import Flask, render_template_string, request, jsonify, send_file, abort, g
import io
import tempfile
import json
import os
import base64
import re
import hmac
import threading
import time
import urllib.parse
import uuid
import subprocess
import hashlib
import shutil
import zipfile
from functools import wraps
from pathlib import Path
from PIL import Image
from fpdf import FPDF
from watermark_engine import WatermarkedFPDF, WATERMARK_ENABLED, WATERMARK_TEXT
import database
import models
import user_isolation
import security
from auth import (register_user, login_user, refresh_access_token, logout_user,
    logout_all_devices, request_password_reset, reset_password, require_auth,
    require_admin as require_admin_auth, create_legacy_account, get_legacy_account_info,
    hash_password, verify_password, validate_password, validate_email,
    get_current_user, get_current_user_id, is_admin, require_user_or_admin)
from fpdf.enums import XPos, YPos
from datetime import datetime, timedelta
from markupsafe import escape
import requests

from notesai_schema import (
    analysis_has_arabic,
    clean_text,
    analysis_to_structured,
    analysis_to_text,
    iter_diagrams,
    normalise_analysis,
    normalise_diagram,
)
from notesai_diagrams import (
    DiagramRenderError,
    normalise_diagram_style,
    render_diagram_svg,
    svg_dimensions,
)

from notesai_trace import trace_data_url, TraceQualityError

# Watermark configuration constants
WATERMARK_TEXT = "Lucky's 59"
WATERMARK_ENABLED = True

# Sync constants to watermark_engine module
import watermark_engine
watermark_engine.sync_constants(WATERMARK_TEXT, WATERMARK_ENABLED)


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024

# Initialize security middleware
security.init_security(app)


@app.teardown_appcontext
def _close_db_connection(exception=None):
    """Close database connection at end of request."""
    try:
        import database
        database.close_db()
    except Exception:
        pass


@app.after_request
def _no_cache_provider_ui(response):
    """Prevent stale provider status/UI after a switch or server restart."""
    if request.path in {"/settings", "/api/provider-status"}:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

import gzip as _gzip

@app.after_request
def _gzip_compress(response):
    """Gzip text responses for faster transfer (performance)."""
    try:
        if response.direct_passthrough:
            return response
        if response.status_code < 200 or response.status_code >= 300:
            return response
        if "Content-Encoding" in response.headers:
            return response
        ctype = (response.headers.get("Content-Type") or "").lower()
        if not any(t in ctype for t in ("text/", "application/json", "application/javascript", "application/xml")):
            return response
        ae = (request.headers.get("Accept-Encoding") or "").lower()
        if "gzip" not in ae:
            return response
        data = response.get_data()
        if len(data) < 512:
            return response
        gz = _gzip.compress(data, compresslevel=6)
        if len(gz) >= len(data):
            return response
        response.set_data(gz)
        response.headers["Content-Encoding"] = "gzip"
        response.headers["Content-Length"] = str(len(gz))
        response.headers["Vary"] = "Accept-Encoding"
    except Exception:
        pass
    return response


def _ai_error_code(status):
    """Map an upstream provider status to a stable client-facing code."""
    if status == 429:
        return "RATE_LIMITED"
    if status in (401, 403):
        return "PROVIDER_AUTH_FAILED"
    if status >= 500:
        return "AI_UNAVAILABLE"
    return "AI_REQUEST_FAILED"


def _error_response(message, status=400, code="REQUEST_FAILED", retryable=None):
    """Return the shared error envelope.

    ``error`` remains the human-readable message used by the existing UI.
    ``code`` and ``retryable`` are additive so older clients keep working.
    """
    payload = {"error": str(message), "code": str(code)}
    if retryable is not None:
        payload["retryable"] = bool(retryable)
    return jsonify(payload), status


def _ai_failure_response(status, message, provider="", model="", extra_headers=None, code=None):
    """Build the shared AI failure envelope used by extraction and generation."""
    response = jsonify(
        error=str(message or "The AI request failed."),
        code=code or _ai_error_code(status),
        retryable=bool(status == 429 or status >= 500),
        provider=provider,
        model=model,
    )
    if provider:
        response.headers["X-NotesAI-Provider"] = provider
    if model:
        response.headers["X-NotesAI-Model"] = model
    for key, value in (extra_headers or {}).items():
        response.headers[key] = value
    return response, status


def _provider_error(message, status=400, code="PROVIDER_REQUEST_FAILED", retryable=None, provider=None):
    """Additive error metadata for the provider settings/test UI.

    The existing ``ok``/``error`` keys are preserved for compatibility.
    """
    if retryable is None:
        retryable = status == 429 or status >= 500
    payload = {
        "ok": False,
        "error": str(message),
        "code": str(code),
        "retryable": bool(retryable),
    }
    if provider:
        payload["provider"] = str(provider)
    return jsonify(payload), status


@app.errorhandler(413)
def _request_too_large(_error):
    return _error_response(
        "File is too large. Each upload must be 20 MB or smaller.",
        413, "FILE_TOO_LARGE", retryable=False,
    )


@app.errorhandler(500)
def _server_error(error):
    app.logger.error("Unhandled server error", exc_info=True)
    if request.path.startswith("/api/") or request.path in {"/extract-text", "/generate-pdf"}:
        return _error_response(
            "The server could not complete this request. Please retry.",
            500, "SERVER_ERROR", retryable=True,
        )
    return "The server could not complete this request.", 500


@app.errorhandler(404)
def _not_found(error):
    """Keep API failures machine-readable; leave HTML navigation untouched."""
    if request.path.startswith("/api/"):
        return _error_response("API endpoint not found.", 404, "NOT_FOUND", retryable=False)
    return error


@app.errorhandler(405)
def _method_not_allowed(error):
    if request.path.startswith("/api/") or request.path in {"/extract-text", "/generate-pdf"}:
        return _error_response(
            "This action is not allowed for the requested endpoint.", 405,
            "METHOD_NOT_ALLOWED", retryable=False,
        )
    return error


PROJECT_ROOT = Path(__file__).resolve().parent
ENV_PATH = PROJECT_ROOT / ".env"
PROVIDER_STATUS_FILE = PROJECT_ROOT / "provider_status.json"

# Gemini is the default provider. The model below was verified against the
# live Google API (text + image). It can be overridden with GEMINI_MODEL.
GEMINI_MODEL_DEFAULT = "gemini-3.1-flash-lite"
GEMINI_MODEL_CANDIDATES = (
    "gemini-3.8-flash",
    "gemini-flash-latest",
    "gemini-3.6-flash",
    "gemini-3.5-flash",
    "gemini-3.1-flash-lite",
    "gemini-2.5-flash-lite",
)

# OpenRouter is the manual alternate provider. Only zero-priced, image-input,
# text-output models ending in ":free" are ever selected.
OPENROUTER_API_BASE_DEFAULT = "https://openrouter.ai/api/v1"
OPENROUTER_ALLOWED_HOSTS = {"openrouter.ai"}
OPENROUTER_FREE_MODEL_PREFERENCE = (
    "dots-studio/dots-3-note-preview:free",
    "nvidia/nemotron-3.5-super-vl:free",
    "google/gemma-4-31b-it:free",
    "google/gemma-4-26b-a4b-it:free",
    "particle-ai/particle-1:free",
    "thinkingmachines/inkling-2-small:free",
    "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free",
)
OPENROUTER_MODELS_TTL_SECONDS = 6 * 60 * 60

# Stats/activity storage (persisted to files). User data is never rewritten
# destructively: unknown keys are preserved and counters are clamped at zero.
STATS_FILE = PROJECT_ROOT / "stats.json"
ACTIVITY_FILE = PROJECT_ROOT / "activity.json"

# Lightweight, file-based document history. No external database is required.
# PDF files live in documents/ and metadata (never API keys) lives in
# documents.json. Both are private to the local user.
DOCUMENTS_DIR = PROJECT_ROOT / "documents"
DOCUMENTS_FILE = PROJECT_ROOT / "documents.json"
MAX_STORED_DOCUMENTS = 100
STUDY_SETS_FILE = PROJECT_ROOT / "study_sets.json"
BILLING_FILE = PROJECT_ROOT / "billing.json"
MAX_STUDY_SETS = 100
PLAN_LIMITS = {
    "free": {"label": "Free workspace", "max_documents": 100, "max_storage_mb": 250},
    "pro": {"label": "Professional workspace", "max_documents": 500, "max_storage_mb": 2048},
}
STUDY_ACTIONS = {
    "summarize": ("Summarize", "Create a concise, faithful summary with the main ideas and conclusions."),
    "rewrite": ("Rewrite & improve", "Rewrite the text clearly and professionally without changing its meaning."),
    "translate": ("Translate", "Translate the text into the requested language. Preserve headings, lists, and technical terms."),
    "key_points": ("Key points", "Extract the most important facts as short, revision-ready bullet points."),
    "headings": ("Headings & structure", "Organize the text with clear headings, subheadings, and logical order."),
    "organize": ("Organize content", "Reorganize the text into a clean study-note structure without losing information."),
    "qa": ("Questions & answers", "Create useful study questions with accurate answers grounded in the text."),
    "mcq": ("MCQs", "Create multiple-choice questions with four options and mark the correct answer."),
    "short_questions": ("Short questions", "Create short-answer exam questions with concise model answers."),
    "long_questions": ("Long questions", "Create long-answer exam questions with structured model answers."),
    "flashcards": ("Flashcards", "Create revision flashcards with a prompt on one side and a concise answer."),
    "quiz": ("Quiz", "Create a mixed quiz with a clear answer key."),
    "exam_topics": ("Exam topics", "Identify the most likely exam-worthy topics and explain why they matter."),
    "chapter_summary": ("Chapter summary", "Write a chapter-style summary with key definitions and examples."),
    "explain": ("Explain simply", "Explain the difficult ideas in simple language with small examples."),
    "revision": ("Revision sheet", "Create a compact revision sheet with facts, definitions, formulas, and quick checks."),
}
_STUDY_LOCK = threading.RLock()
_BILLING_LOCK = threading.RLock()
DEFAULT_BILLING = {
    "plan": "free",
    "status": "active",
    "renewal": None,
    "payments": [],
    "updated_at": None,
}

# Smart page understanding is intentionally bounded: it keeps free-tier usage
# predictable and prevents one huge upload from becoming an unbounded AI bill.
SMART_MAX_PAGES = 10
SMART_MAX_DIAGRAMS = 30
PREMIUM_CODE_ENV = "NOTESAI_PREMIUM_CODE"
PREMIUM_OPEN_ENV = "NOTESAI_PREMIUM_OPEN"
# Temporarily free while Smart Recreated PDF is being completed and tested.
# Set this to False and re-add the route checks to restore the paid gate.
SMART_FREE_MODE = True
_DIAGRAM_CAPABILITY_LOCK = threading.RLock()
_DIAGRAM_CAPABILITY_CACHE = {}

DEFAULT_STATS = {"total_documents": 0, "in_progress": 0, "completed": 0, "failed": 0}

_STATS_LOCK = threading.RLock()
_ACTIVITY_LOCK = threading.RLock()
_DOCUMENTS_LOCK = threading.RLock()
_JOB_LOCK = threading.Lock()
_PROVIDER_LOCK = threading.RLock()
_OPENROUTER_MODELS_LOCK = threading.RLock()
_OPENROUTER_MODELS_CACHE = {"ts": 0.0, "models": []}
_RECENT_JOBS = {}
JOB_TTL_SECONDS = 600
JOB_CACHE_LIMIT = 500
_ACTIVE_JOBS = {}
_ACTIVE_JOBS_LOCK = threading.Lock()
ACTIVE_JOB_TTL_SECONDS = 15 * 60
ACTIVE_JOB_LIMIT = 500


def load_stats():
    stats = dict(DEFAULT_STATS)
    if STATS_FILE.exists():
        try:
            data = json.loads(STATS_FILE.read_text())
            if isinstance(data, dict):
                # Preserve any extra keys while normalising the known counters.
                for key, value in data.items():
                    stats[key] = value
                for key in DEFAULT_STATS:
                    try:
                        stats[key] = max(0, int(stats.get(key, 0)))
                    except (TypeError, ValueError):
                        stats[key] = 0
        except Exception:
            pass
    return stats


def save_stats(stats):
    with _STATS_LOCK:
        STATS_FILE.write_text(json.dumps(stats))


def load_activity():
    if ACTIVITY_FILE.exists():
        try:
            parsed = json.loads(ACTIVITY_FILE.read_text())
            if isinstance(parsed, list):
                return [item for item in parsed if isinstance(item, dict)]
        except Exception:
            pass
    return []


def save_activity(activity):
    with _ACTIVITY_LOCK:
        ACTIVITY_FILE.write_text(json.dumps(activity[-200:]))  # Keep a useful recent history


def add_activity(action, detail, status="completed", **extra):
    with _ACTIVITY_LOCK:
        activity = load_activity()
        entry = {
            "action": action,
            "detail": detail,
            "status": status,
            "timestamp": datetime.now().isoformat()
        }
        entry.update({key: value for key, value in extra.items() if value is not None})
        activity.insert(0, entry)
        save_activity(activity[:200])


def _save_json_private(path, payload, lock, limit=None):
    with lock:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        data = payload
        if limit is not None:
            data = payload[:limit]
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass


def load_study_sets():
    if not STUDY_SETS_FILE.is_file():
        return []
    try:
        parsed = json.loads(STUDY_SETS_FILE.read_text())
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict) and item.get("id")]
    except Exception:
        pass
    return []


def save_study_sets(items):
    _save_json_private(STUDY_SETS_FILE, items, _STUDY_LOCK, MAX_STUDY_SETS)


def load_billing():
    billing = dict(DEFAULT_BILLING)
    if BILLING_FILE.is_file():
        try:
            parsed = json.loads(BILLING_FILE.read_text())
            if isinstance(parsed, dict):
                billing.update(parsed)
        except Exception:
            pass
    plan = str(billing.get("plan") or "free").lower()
    billing["plan"] = plan if plan in PLAN_LIMITS else "free"
    if not isinstance(billing.get("payments"), list):
        billing["payments"] = []
    billing["limits"] = PLAN_LIMITS[billing["plan"]]
    return billing


def save_billing(billing):
    payload = dict(DEFAULT_BILLING)
    payload.update(billing or {})
    payload.pop("limits", None)
    payload["payments"] = payload.get("payments")[-100:]
    payload["updated_at"] = datetime.now().isoformat(timespec="seconds")
    _save_json_private(BILLING_FILE, payload, _BILLING_LOCK)


def _document_text_for_study(document):
    """Return readable text from a stored document without exposing paths.

    Professional and Smart documents store structured JSON for regeneration,
    so the raw stored text must be flattened before sending it to the Study
    assistant. Text/plain documents are returned unchanged.
    """
    text = str((document or {}).get("text") or "").strip()
    if not text:
        return ""
    kind = str((document or {}).get("kind") or "")
    if kind not in {"smart", "smart-regenerated", "professional", "regenerated"}:
        return text
    try:
        parsed = json.loads(text)
    except Exception:
        return text
    if not isinstance(parsed, dict):
        return text

    parts = []
    title = str(parsed.get("title") or "").strip()
    subtitle = str(parsed.get("subtitle") or "").strip()
    if title:
        parts.append(title)
    if subtitle:
        parts.append(subtitle)

    for section in parsed.get("sections") or []:
        if not isinstance(section, dict):
            continue
        heading = str(section.get("heading") or "").strip()
        content = str(section.get("content") or "").strip()
        if heading:
            parts.append(heading)
        if content:
            parts.append(content)

    blocks = list(parsed.get("blocks") or [])
    for page in parsed.get("pages") or []:
        if not isinstance(page, dict):
            continue
        page_title = str(page.get("title") or "").strip()
        page_subtitle = str(page.get("subtitle") or "").strip()
        if page_title and page_title not in parts:
            parts.append(page_title)
        if page_subtitle and page_subtitle not in parts:
            parts.append(page_subtitle)
        blocks.extend(page.get("blocks") or [])
    for block in blocks:
        if not isinstance(block, dict):
            continue
        for key in ("text", "title", "label", "question", "answer", "formula", "caption", "description"):
            value = str(block.get(key) or "").strip()
            if value:
                parts.append(value)
        for item in block.get("items") or []:
            parts.append("- " + str(item))
        columns = block.get("columns") or []
        if columns:
            parts.append(" | ".join(str(value) for value in columns))
        for row in block.get("rows") or []:
            if isinstance(row, (list, tuple)):
                parts.append(" | ".join(str(value) for value in row))
        for step in block.get("steps") or []:
            parts.append("- " + str(step))
    return "\n".join(part for part in parts if part).strip()


def _public_study_set(item):
    keys = ("id", "title", "action", "language", "result", "created",
            "provider", "model", "source_document_id", "source_name")
    return {key: item.get(key) for key in keys if key in item}


def save_study_set(action, result, source_document=None, language="English",
                   provider="", model="", title=""):
    study_id = uuid.uuid4().hex
    action_label = STUDY_ACTIONS.get(action, ("Study result", ""))[0]
    source_name = (source_document or {}).get("name") or ""
    record = {
        "id": study_id,
        "title": (str(title or "").strip() or f"{action_label}{' — ' + source_name if source_name else ''}")[:160],
        "action": action,
        "language": language,
        "result": str(result or "")[:120000],
        "created": datetime.now().isoformat(timespec="seconds"),
        "provider": provider,
        "model": model,
        "source_document_id": (source_document or {}).get("id") or "",
        "source_name": source_name,
    }
    with _STUDY_LOCK:
        items = load_study_sets()
        items.insert(0, record)
        save_study_sets(items)
    return _public_study_set(record)


def _safe_display_name(value, fallback="NotesAI Document"):
    name = str(value or "").replace("\\", "/").split("/")[-1]
    name = re.sub(r"[\x00-\x1f\x7f]+", " ", name).strip()
    name = re.sub(r"\s+", " ", name)
    return (name or fallback)[:120]


def _valid_document_id(value):
    return bool(re.fullmatch(r"[a-f0-9]{32}", str(value or "")))


def _load_documents():
    if not DOCUMENTS_FILE.is_file():
        return []
    try:
        parsed = json.loads(DOCUMENTS_FILE.read_text())
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict) and _valid_document_id(item.get("id"))]
    except Exception:
        pass
    return []


def _plan_max_documents():
    try:
        plan = load_billing().get("plan", "free")
        return PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])["max_documents"]
    except Exception:
        return MAX_STORED_DOCUMENTS


def _save_documents(documents):
    DOCUMENTS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(DOCUMENTS_DIR, 0o700)
    except Exception:
        pass
    tmp = DOCUMENTS_FILE.with_name(DOCUMENTS_FILE.name + ".tmp")
    tmp.write_text(json.dumps(documents, ensure_ascii=False, indent=2) + "\n")
    os.replace(tmp, DOCUMENTS_FILE)
    try:
        os.chmod(DOCUMENTS_FILE, 0o600)
    except Exception:
        pass


def _document_defaults(document):
    """Return a document record with backward-compatible management fields."""
    record = dict(document or {})
    record["folder"] = str(record.get("folder") or "")[:80]
    record["category"] = str(record.get("category") or "")[:80]
    raw_tags = record.get("tags")
    if not isinstance(raw_tags, list):
        raw_tags = []
    record["tags"] = [str(value).strip()[:32] for value in raw_tags if str(value).strip()][:12]
    favorite = record.get("favorite")
    record["favorite"] = favorite is True or str(favorite).lower() in {"1", "true", "yes", "on"}
    record.setdefault("deleted_at", None)
    record.setdefault("retention_days", None)
    record.setdefault("expires_at", None)
    record.setdefault("service_option", "standard")
    if not record.get("updated_at"):
        record["updated_at"] = record.get("created")
    if not isinstance(record.get("tags"), list):
        record["tags"] = [str(record.get("tags"))] if record.get("tags") else []
    record["tags"] = [str(tag).strip()[:32] for tag in record["tags"] if str(tag).strip()][:12]
    return record


def _public_document(document):
    """Metadata safe to send to the browser (never includes file paths)."""
    record = _document_defaults(document)
    keys = ("id", "name", "type", "kind", "size", "created", "updated_at", "status",
            "provider", "model", "style", "diagram_style", "page_size",
            "orientation", "margin", "pages", "folder", "category", "tags",
            "favorite", "deleted_at", "retention_days", "expires_at", "service_option")
    return {key: record.get(key) for key in keys if key in record}


def save_generated_document(pdf_bytes, name, kind, options=None, text="", provider="", model="", pages=None, retention_days=None):
    """Persist a generated PDF plus non-secret metadata for history/download."""
    if not pdf_bytes:
        return None
    options = options or {}
    if retention_days is None:
        retention_days = options.get("retentionDays") or options.get("retention_days")
    document_id = uuid.uuid4().hex
    filename = f"{document_id}.pdf"
    DOCUMENTS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(DOCUMENTS_DIR, 0o700)
    except Exception:
        pass
    path = DOCUMENTS_DIR / filename
    path.write_bytes(pdf_bytes)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass
    created = datetime.now().isoformat(timespec="seconds")
    # Temporary PDF retention: 3 / 7 / 30 days (None = keep forever)
    try:
        rd = int(retention_days) if retention_days is not None else None
    except (TypeError, ValueError):
        rd = None
    if rd not in (3, 7, 30):
        rd = None
    expires_at = None
    if rd:
        expires_at = (datetime.now() + timedelta(days=rd)).isoformat(timespec="seconds")
    # Add user_id if authenticated (Phase 3 multi-user support)
    user_id = None
    try:
        user_id = user_isolation.get_optional_user_id()
    except Exception:
        pass

    record = {
        "id": document_id,
        "name": _safe_display_name(name),
        "type": "pdf",
        "kind": kind,
        "size": len(pdf_bytes),
        "created": created,
        "updated_at": created,
        "status": "completed",
        "provider": provider or "",
        "model": model or "",
        "style": options.get("style", "professional"),
        "diagram_style": normalise_diagram_style(options.get("diagramStyle", "color")),
        "page_size": options.get("pageSize", "A4"),
        "orientation": options.get("orientation", "P"),
        "margin": options.get("margin", 12),
        "pages": pages,
        "folder": str(options.get("folder") or "")[:80],
        "category": str(options.get("category") or "")[:80],
        "tags": [str(value).strip()[:32] for value in options.get("tags") or [] if str(value).strip()][:12]
        if isinstance(options.get("tags"), list) else [],
        "favorite": bool(options.get("favorite")),
        "user_id": user_id,
        "deleted_at": None,
        "retention_days": rd,
        "expires_at": expires_at,
        "service_option": str(options.get("serviceOption") or "standard"),
        "pdf_options": {
            key: options.get(key) for key in (
                "title", "subtitle", "headerText", "footerText", "accentColor",
                "includeToc", "showPageNumbers", "coverPage", "fontSize", "style",
            ) if key in options
        },
        "filename": filename,
        # Stored for the Regenerate action; it is local-only user content and
        # is never returned by the public documents API.
        "text": (text or "")[:250000],
    }
    with _DOCUMENTS_LOCK:
        documents = _load_documents()
        active_count = sum(
            1 for item in documents
            if not _document_defaults(item).get("deleted_at")
        )
        if active_count >= _plan_max_documents():
            # Keep the generated PDF downloadable but do not evict an older
            # document from the local library just to make room.
            try:
                path.unlink()
            except Exception:
                pass
            app.logger.warning(
                "Document library is at its plan limit (%s); PDF not added to history.",
                _plan_max_documents(),
            )
            return None
        documents.insert(0, record)
        _save_documents(documents)
    return _public_document(record)


def get_document(document_id, include_deleted=False):
    if not _valid_document_id(document_id):
        return None
    with _DOCUMENTS_LOCK:
        for document in _load_documents():
            if document.get("id") == document_id:
                record = _document_defaults(document)
                if record.get("deleted_at") and not include_deleted:
                    return None
                return record
    return None


def document_file_path(document):
    if not document:
        return None
    if document.get("deleted_at"):
        return None
    filename = str(document.get("filename") or "")
    if not re.fullmatch(r"[a-f0-9]{32}\.pdf", filename):
        return None
    path = DOCUMENTS_DIR / filename
    return path if path.is_file() else None

def cleanup_expired_documents():
    """Delete PDFs whose retention period (3/7/30 days) has elapsed."""
    now = datetime.now()
    removed = 0
    with _DOCUMENTS_LOCK:
        documents = _load_documents()
        kept = []
        for doc in documents:
            rec = _document_defaults(doc)
            expires = rec.get("expires_at")
            if expires:
                try:
                    if datetime.fromisoformat(expires) <= now:
                        # delete file
                        fn = rec.get("filename")
                        if fn and re.fullmatch(r"[a-f0-9]{32}\.pdf", str(fn)):
                            try:
                                (DOCUMENTS_DIR / fn).unlink(missing_ok=True)
                            except Exception:
                                pass
                        removed += 1
                        continue
                except (ValueError, TypeError):
                    pass
            kept.append(doc)
        if removed:
            _save_documents(kept)
    return removed


def increment_stat(key, delta=1):
    """Atomically adjust a counter, never letting it go below zero."""
    with _STATS_LOCK:
        stats = load_stats()
        try:
            current = int(stats.get(key, 0))
        except (TypeError, ValueError):
            current = 0
        stats[key] = max(0, current + int(delta))
        save_stats(stats)
        return stats[key]


def _job_is_duplicate(action, job_id):
    """Return True when this (action, job_id) pair was already counted.

    Duplicate browser retries/double-clicks must not inflate statistics.
    Entries expire after JOB_TTL_SECONDS and the cache is size-bounded.
    """
    if not job_id:
        return False
    key = f"{action}:{job_id}"
    now = time.monotonic()
    with _JOB_LOCK:
        for stale in [k for k, ts in _RECENT_JOBS.items() if now - ts > JOB_TTL_SECONDS]:
            _RECENT_JOBS.pop(stale, None)
        if key in _RECENT_JOBS:
            _RECENT_JOBS[key] = now
            return True
        _RECENT_JOBS[key] = now
        while len(_RECENT_JOBS) > JOB_CACHE_LIMIT:
            _RECENT_JOBS.pop(next(iter(_RECENT_JOBS)), None)
    return False


def _begin_active_job(action, job_id):
    """Reserve one (action, job id) while its request is running.

    Returns an opaque handle, ``None`` when no job id was supplied, or
    ``False`` when the same job is already running.
    """
    if not job_id:
        return None
    key = f"{action}:{job_id}"
    now = time.monotonic()
    token = uuid.uuid4().hex
    with _ACTIVE_JOBS_LOCK:
        for stale, (_token, started) in list(_ACTIVE_JOBS.items()):
            if now - started > ACTIVE_JOB_TTL_SECONDS:
                _ACTIVE_JOBS.pop(stale, None)
        if key in _ACTIVE_JOBS:
            return False
        _ACTIVE_JOBS[key] = (token, now)
        while len(_ACTIVE_JOBS) > ACTIVE_JOB_LIMIT:
            _ACTIVE_JOBS.pop(next(iter(_ACTIVE_JOBS)), None)
    return (key, token)


def _end_active_job(handle):
    """Release an in-flight reservation only when it still belongs to us."""
    if not handle or handle is False:
        return
    key, token = handle
    with _ACTIVE_JOBS_LOCK:
        current = _ACTIVE_JOBS.get(key)
        if current and current[0] == token:
            _ACTIVE_JOBS.pop(key, None)


def _single_flight(action):
    """Prevent the same browser job from running twice on this server."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            job_id = (request.form.get("jobId") or "").strip()[:80]
            handle = _begin_active_job(action, job_id)
            if handle is False:
                response = _error_response(
                    "This request is already running. Please wait for it to finish, then retry.",
                    409, "REQUEST_IN_PROGRESS", retryable=True,
                )
                response[0].headers["Retry-After"] = "3"
                return response
            try:
                return view(*args, **kwargs)
            finally:
                _end_active_job(handle)
        return wrapped
    return decorator


def note_extraction_success(job_id=None):
    """A document extraction finished: it is now 'in progress'."""
    if _job_is_duplicate("extract", job_id):
        return False
    increment_stat("in_progress")
    return True


def note_extraction_failure(job_id=None):
    """A document extraction failed: count it once, never as in-progress."""
    if _job_is_duplicate("extract_failed", job_id):
        return False
    increment_stat("failed")
    return True


def note_document_created(job_id=None):
    """A PDF was produced: one completed document, one less in progress."""
    if _job_is_duplicate("document", job_id):
        return False
    increment_stat("total_documents")
    increment_stat("completed")
    increment_stat("in_progress", -1)
    return True


# Initialize stats if empty
if not STATS_FILE.exists():
    save_stats(dict(DEFAULT_STATS))


# ============================================================
# ENV / PROVIDER HELPERS
# ============================================================
def _read_env_file():
    data = {}
    if not ENV_PATH.is_file():
        return data
    try:
        for line in ENV_PATH.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            data[k.strip()] = v.strip().strip("'\"")
    except Exception:
        pass
    return data


def _write_env_file(updates):
    """Read-modify-write the project .env without dropping unrelated keys."""
    data = _read_env_file()
    for k, v in updates.items():
        if v is None or v == "":
            data.pop(k, None)
        else:
            data[k] = v
    lines = [f"{k}={v}" for k, v in data.items()]
    ENV_PATH.write_text("\n".join(lines) + ("\n" if lines else ""))
    try:
        os.chmod(ENV_PATH, 0o600)
    except Exception:
        pass


def get_env_key(*names):
    """Read provider keys from the project .env first, then process env.

    The project file wins so an unrelated parent-folder .env (for example
    ~/.env from another project) can never silently override NotesAI config.
    """
    env = _read_env_file()
    for name in names:
        val = env.get(name)
        if val:
            return val.strip()
    for name in names:
        val = os.getenv(name)
        if val:
            return val.strip()
    return ""


def get_gemini_config():
    api_key = get_env_key("GEMINI_API_KEY", "GOOGLE_API_KEY")
    model = get_env_key("GEMINI_MODEL") or GEMINI_MODEL_DEFAULT
    return {"api_key": api_key, "model": model}


def get_openrouter_config():
    api_key = get_env_key("OPENROUTER_API_KEY")
    model = get_env_key("OPENROUTER_FREE_MODEL")
    base = OPENROUTER_API_BASE_DEFAULT
    return {"api_key": api_key, "model": model, "base_url": base}


def get_active_provider():
    provider = (get_env_key("AI_PROVIDER") or "gemini").strip().lower()
    return provider if provider in {"gemini", "openrouter"} else "gemini"


def set_active_provider(provider):
    provider = (provider or "").strip().lower()
    if provider not in {"gemini", "openrouter"}:
        raise ValueError("Invalid provider.")
    _write_env_file({"AI_PROVIDER": provider})
    return provider


def _default_provider_status():
    return {
        "gemini": {"status": "not_tested", "message": "", "model": "", "checked_at": None},
        "openrouter": {"status": "not_tested", "message": "", "model": "", "checked_at": None},
    }


def load_provider_status():
    """Load non-secret connection status. Never stores API keys."""
    with _PROVIDER_LOCK:
        data = _default_provider_status()
        if not PROVIDER_STATUS_FILE.is_file():
            return data
        try:
            parsed = json.loads(PROVIDER_STATUS_FILE.read_text())
            if isinstance(parsed, dict):
                for provider in ("gemini", "openrouter"):
                    entry = parsed.get(provider)
                    if isinstance(entry, dict):
                        for key in ("status", "message", "model", "checked_at"):
                            if key in entry:
                                data[provider][key] = entry[key]
        except Exception:
            pass
        return data


def save_provider_status(provider, status, message="", model=None):
    """Persist a non-secret status entry atomically (mode 600)."""
    if provider not in {"gemini", "openrouter"}:
        return
    with _PROVIDER_LOCK:
        data = load_provider_status()
        entry = data.get(provider) or {}
        entry.update({
            "status": status,
            "message": (message or "")[:300],
            "checked_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        })
        if model is not None:
            entry["model"] = model
        data[provider] = entry
        tmp = PROVIDER_STATUS_FILE.with_name(PROVIDER_STATUS_FILE.name + ".tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        os.replace(tmp, PROVIDER_STATUS_FILE)
        try:
            os.chmod(PROVIDER_STATUS_FILE, 0o600)
        except Exception:
            pass


# ============================================================
# SECURITY HELPERS (admin auth, SSRF guard, runtime config)
# ============================================================
ADMIN_TOKEN_ENV = "NOTESAI_ADMIN_TOKEN"
LOCALHOST_ADDRESSES = {"127.0.0.1", "::1", "localhost"}
MODEL_NAME_RE = re.compile(r"^[A-Za-z0-9._:/@+-]{1,120}$")


def _env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def premium_configured():
    """True when Smart Recreated PDF is available without a paid gate."""
    if SMART_FREE_MODE:
        return True
    return bool(get_env_key(PREMIUM_CODE_ENV)) or get_env_key(PREMIUM_OPEN_ENV).strip().lower() in {"1", "true", "yes", "on"}


def premium_open_for_local_development():
    return SMART_FREE_MODE or get_env_key(PREMIUM_OPEN_ENV).strip().lower() in {"1", "true", "yes", "on"}


def premium_authorized():
    """Smart Recreated PDF is temporarily free; no code is required."""
    if SMART_FREE_MODE:
        return True
    configured = get_env_key(PREMIUM_CODE_ENV)
    if not configured:
        return False
    supplied = (
        request.headers.get("X-NotesAI-Premium", "")
        or request.form.get("premiumCode", "")
        or ""
    ).strip()
    return bool(supplied) and hmac.compare_digest(supplied, configured)


def premium_error_response():
    if not premium_configured():
        return jsonify(
            error="Smart Diagram Recreation is a premium feature. Configure NOTESAI_PREMIUM_CODE on the server or unlock it with a premium access code."
        ), 402
    return jsonify(error="Premium access required for Smart Diagram Recreation."), 402


def _is_local_request():
    """True when the request originates from this machine (loopback)."""
    address = (request.remote_addr or "").strip().lower()
    return address in LOCALHOST_ADDRESSES


def _admin_token_from_request():
    header_token = request.headers.get("X-Admin-Token", "")
    if header_token:
        return header_token.strip()
    data = request.get_json(silent=True) or {}
    return str(data.get("admin_token") or "").strip()


def _admin_error(message, code):
    """Keep admin failures in the shared UI envelope without breaking clients."""
    return jsonify({
        "ok": False,
        "error": str(message),
        "code": str(code),
        "retryable": False,
    }), 403


def require_admin():
    """Block unauthorized callers from changing server configuration.

    Local (loopback) requests are always allowed. Remote requests must present
    NOTESAI_ADMIN_TOKEN via the X-Admin-Token header or an ``admin_token``
    JSON field. When no token is configured, remote access stays blocked
    (fail-closed) instead of silently allowing anonymous changes.
    """
    expected = os.getenv(ADMIN_TOKEN_ENV, "").strip()
    supplied = _admin_token_from_request()
    if expected and supplied and hmac.compare_digest(supplied, expected):
        return None
    if _is_local_request():
        return None
    if not expected:
        return _admin_error(
            "Admin token is not configured on the server. Set NOTESAI_ADMIN_TOKEN to allow remote changes.",
            "ADMIN_TOKEN_MISSING",
        )
    return _admin_error("Unauthorized. Provide a valid admin token.", "ADMIN_AUTH_REQUIRED")


def validate_openrouter_base_url(base_url):
    """Return the official OpenRouter API URL or None when it is not allowed.

    Only HTTPS requests to ``openrouter.ai/api/v1`` are accepted. Client
    supplied base URLs are never trusted, which prevents SSRF.
    """
    candidate = (base_url or "").strip()
    if not candidate:
        return None
    try:
        parsed = urllib.parse.urlsplit(candidate)
    except ValueError:
        return None
    if parsed.scheme != "https":
        return None
    if parsed.username or parsed.password:
        return None
    host = (parsed.hostname or "").lower()
    if host not in OPENROUTER_ALLOWED_HOSTS:
        return None
    if parsed.port not in (None, 443):
        return None
    if parsed.path.rstrip("/") != "/api/v1":
        return None
    if parsed.query or parsed.fragment:
        return None
    return candidate.rstrip("/")


def prepare_image_data_url(file_storage, max_edge=2048, quality=85, max_bytes=18 * 1024 * 1024):
    """Read, validate, resize/compress image and return data URL for vision API."""
    try:
        file_storage.stream.seek(0)
        with Image.open(file_storage.stream) as source:
            source.load()
            image = source.convert("RGB")
    except Exception:
        return None
    w, h = image.size
    if max(w, h) > max_edge:
        scale = max_edge / float(max(w, h))
        image = image.resize((max(1, int(w * scale)), max(1, int(h * scale))), Image.LANCZOS)
    buf = io.BytesIO()
    image.save(buf, format="JPEG", quality=quality, optimize=True)
    data = buf.getvalue()
    # reduce quality if still too large
    q = quality
    while len(data) > max_bytes and q > 40:
        q -= 10
        buf = io.BytesIO()
        image.save(buf, format="JPEG", quality=q, optimize=True)
        data = buf.getvalue()
    b64 = base64.b64encode(data).decode("ascii")
    return f"data:image/jpeg;base64,{b64}"


def get_files_for_vision(files):
    """Return (image_data_urls, pdf_parts_info, error). For now only images supported for vision."""
    mime_types = {"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png", "webp": "image/webp", "bmp": "image/bmp"}
    urls = []
    for uploaded in files:
        ext = uploaded.filename.rsplit(".", 1)[-1].lower() if "." in uploaded.filename else ""
        if ext == "pdf":
            return [], [], "PDF extraction via vision is not supported in this flow. Upload images for AI extraction."
        if ext not in mime_types:
            return [], [], "Supported files: JPG, PNG, WEBP, BMP."
        data_url = prepare_image_data_url(uploaded)
        if not data_url:
            return [], [], f"Could not read image: {uploaded.filename}"
        urls.append(data_url)
    return urls, [], None


EXTRACTION_PROMPT = (
    "Analyze the handwritten document images and extract the text content. "
    "Return a JSON object with this exact structure:\n"
    "{\n"
    "  \"title\": \"Main document title (detect from content)\",\n"
    "  \"sections\": [\n"
    "    {\"heading\": \"Section heading\", \"level\": 1, \"content\": \"Paragraph text...\"},\n"
    "    {\"heading\": \"Subsection heading\", \"level\": 2, \"content\": \"Paragraph text...\"}\n"
    "  ]\n"
    "}\n\n"
    "Rules:\n"
    "1. Detect the main document title from the content (first line, or largest text)\n"
    "2. Identify headings and subheadings (level 1 = main sections, level 2 = subsections, level 3 = sub-subsections)\n"
    "3. Group related paragraphs under appropriate headings\n"
    "4. Detect numbered lists and bullet points, include them in content\n"
    "5. Preserve original language (Urdu, Arabic, English, etc.)\n"
    "6. Mark genuinely unclear text as [unclear]\n"
    "7. Do NOT translate, summarize, or invent content\n"
    "8. Do NOT create unnecessary headings - only where structure naturally exists\n"
    "9. For every table, preserve the real rows and columns. Put each row on its own line with cells separated by ' | '. "
    "Include a header row exactly as written. Never flatten a table into one paragraph and never invent missing cells.\n"
    "10. Keep the original order: heading, table/chart, formula, tip, example, question/answer. Do not move content to another section.\n"
    "11. Keep formulas, arrows, numbered lists, comparison charts, and highlighted tips in their own section content. "
    "Use 'Trick : ...', 'Remember : ...' or 'Note : ...' for a highlighted tip when the source has one.\n"
    "12. Do not turn a diagram into prose. If the page contains a diagram, describe only its visible labels and structure in the section content; "
    "do not invent scientific facts or new labels.\n"
    "13. Return ONLY the JSON object, no extra text or markdown formatting\n"
)


SMART_ANALYSIS_PROMPT = (
    "You are NotesAI's educational page understanding and diagram reconstruction engine. "
    "Analyze this ONE uploaded page visually. Return ONLY one valid JSON object, no markdown fences.\n\n"
    "Schema:\n"
    "{\n"
    "  \"schema_version\": 2,\n"
    "  \"title\": \"page/document title\",\n"
    "  \"subtitle\": \"optional subtitle\",\n"
    "  \"blocks\": [\n"
    "    {\"id\":\"b1\",\"type\":\"heading\",\"level\":1,\"text\":\"Heading\"},\n"
    "    {\"id\":\"b2\",\"type\":\"paragraph\",\"text\":\"Exact text\"},\n"
    "    {\"id\":\"b3\",\"type\":\"list\",\"ordered\":true,\"items\":[\"item\"]},\n"
    "    {\"id\":\"b4\",\"type\":\"table\",\"title\":\"GK Questions\",\"columns\":[\"No.\",\"Question\",\"Answer\"],\"rows\":[[\"1\",\"...\",\"...\"]]},\n"
    "    {\"id\":\"b5\",\"type\":\"callout\",\"label\":\"Remember\",\"text\":\"...\"},\n"
    "    {\"id\":\"b6\",\"type\":\"question\",\"question\":\"...\",\"answer\":\"...\"},\n"
    "    {\"id\":\"b7\",\"type\":\"formula\",\"text\":\"...\"},\n"
    "    {\"id\":\"b8\",\"type\":\"flow\",\"title\":\"Present\",\"steps\":[\"Do\",\"Doing\",\"Done\"]},\n"
    "    {\"id\":\"b9\",\"type\":\"diagram\",\"diagram_id\":\"d1\"},\n"
    "    {\"id\":\"b10\",\"type\":\"uncertain\",\"text\":\"...\",\"reason\":\"...\"}\n"
    "  ],\n"
    "  \"diagrams\": [\n"
    "    {\n"
    "      \"id\":\"d1\",\"category\":\"astronomy|biology|chemistry|physics|mathematics|geography|engineering|flowchart|chart|education|other\",\n"
    "      \"type\":\"solar_system|flowchart|geometry|circuit|molecule|chart|heart|cell|map|labelled_figure|other\",\n"
    "      \"title\":\"Diagram title\",\"confidence\":0.0,\n"
    "      \"placement\":{\"anchor_block_id\":\"b1\",\"position\":\"after\"},\n"
    "      \"source_bbox\":[0,0,1000,1000],\n"
    "      \"labels\":[{\"text\":\"label\",\"source_text\":\"original label\",\"confidence\":0.0}],\n"
    "      \"template_data\":{},\n"
    "      \"scene\":{\"canvas\":[1000,700],\"elements\":[]},\n"
    "      \"uncertain\":[],\"review_required\":false\n"
    "    }\n"
    "  ]\n"
    "}\n\n"
    "Rules:\n"
    "1. Read the page as a visual document, not just OCR. Preserve the logical order.\n"
    "2. Identify every real diagram/illustration and its labels, arrows, connections, numbering, and related text. "
    "Do NOT treat a table, bullet list, formula card, highlighted tip, callout box, heading, or ordinary text as a diagram. "
    "Only use a diagram when the page contains actual pictorial shapes, arrows, or an illustration. If there is no diagram, return diagrams: []. "
    "Text inside a highlighted memory-trick/formula card must be a callout or list block, never a diagram. "
    "Include every line of that card, including the numbered rule, total, and every arrow explanation line; do not stop after the first two lines.\n"
    "3. Place a diagram block immediately after its related heading/paragraph/question. Never move a diagram to the end. "
    "Every visible line of text must appear in a block. diagram.labels are only short labels on a picture; they must never replace body text, "
    "a memory trick, a formula, a table, or a list.\n"
    "4. source_bbox uses normalized coordinates: x,y,width,height in 0..1000 relative to this page.\n"
    "5. Recreate only the diagram that is actually visible on this page. Choose the closest supported type. "
    "Never add a Solar System, chart, or any other diagram that is not present in the source. "
    "Solar System is just one optional template when the page really contains one.\n"
    "6. Use template_data only when the chosen type has a matching deterministic template. "
    "For any other diagram use scene with canvas [w,h] and elements. Allowed element kinds: shape, connector, text. "
    "Allowed shapes: rect, circle, ellipse, line, polyline, polygon, path, arrow. "
    "A connector has from/to ids, optional arrow, and optional label. Coordinates should approximate the source layout. "
    "Use soft, simple educational colors and neat lines; do not add 3D decoration.\n"
    "6a. For a real chart, use type chart and template_data like "
    "{\"chart_type\":\"bar|line|pie\",\"labels\":[\"A\",\"B\"],\"values\":[10,20]}. "
    "Read labels and numbers only when they are visibly printed. If values are unclear, do not invent them: "
    "use the original crop / review_required instead. Never convert an ordinary table into a chart; tables stay table blocks.\n"
    "6b. For biology, human body, heart, cell, plant, map and other labelled figures, always return a scene with "
    "at least one shape for each visible structure and a text element for each visible label. Approximate the "
    "positions from the source_bbox. A clean schematic is better than an empty scene. If you truly cannot "
    "represent it, set review_required true and use_original true instead of inventing anatomy.\n"
    "6c. A labels-only diagram is INVALID. If you return labels, you must also return scene.elements with "
    "a text element for every label and shape/connector elements for the visible structure. "
    "Each text element must include a bbox [x,y,w,h]. Example: "
    "{\"kind\":\"text\",\"id\":\"t1\",\"text\":\"PARIETAL BONE\",\"bbox\":[60,40,180,40]}, "
    "{\"kind\":\"shape\",\"id\":\"s1\",\"shape\":\"path\",\"d\":\"M...\",\"bbox\":[120,80,500,520]}, "
    "{\"kind\":\"connector\",\"id\":\"c1\",\"from\":\"t1\",\"to\":\"s1\",\"arrow\":false}. "
    "For anatomy, trace the outer silhouette and major internal boundaries with polygon/path shapes, and use "
    "a separate shape for each labelled part. Add leader connectors with points [x1,y1,x2,y2] from each "
    "label to the named part. Do not connect every label to one central point. Do not return only labels and "
    "do not invent missing parts.\n"
    "7. Preserve original labels. Correct only an obvious spelling typo and note it. "
    "Never invent missing labels, scientific facts, values, or connections.\n"
    "8. Mark unclear content as type uncertain or add it to diagram.uncertain. Lower confidence when unsure.\n"
    "9. Use table blocks for every grid/table/chart-like layout. Keep exact columns and rows; never flatten a table into a paragraph. "
    "Use flow blocks for arrow sequences and formula blocks for formulas. Questions and answers must remain paired.\n"
    "10. Use callout blocks for highlighted tips, memory tricks and important notes; use list blocks for real lists. "
    "Preserve the original logical order instead of converting everything to paragraphs.\n"
    "11. Preserve language and script. Do not translate, summarize, or add facts.\n"
    "12. Return ONLY JSON. Page number in this request: {{PAGE}}.\n"
)


DIAGRAM_SCENE_REPAIR_PROMPT = (
    "You are NotesAI's diagram geometry repair engine. The attached image is one diagram crop. "
    "Return ONLY one valid JSON object, no markdown fences. Do not add, remove, rename, or translate labels. "
    "Build a safe vector scene that follows the visible structure: outer silhouette, internal boundaries, "
    "arrows, leader lines, repeated parts, and the exact label positions. Do not invent anatomy or science.\n\n"
    "Schema:\n"
    "{\"diagrams\":[{\"id\":\"d1\",\"scene\":{\"canvas\":[1000,1000],\"elements\":["
    "{\"id\":\"s1\",\"kind\":\"shape\",\"shape\":\"polygon\",\"points\":[x,y,x,y,...],\"bbox\":[x,y,w,h]},"
    "{\"id\":\"s2\",\"kind\":\"shape\",\"shape\":\"path\",\"d\":\"M...\",\"bbox\":[x,y,w,h]},"
    "{\"id\":\"t1\",\"kind\":\"text\",\"text\":\"EXACT LABEL\",\"bbox\":[x,y,w,h]},"
    "{\"id\":\"c1\",\"kind\":\"connector\",\"from\":\"t1\",\"to\":\"s1\",\"points\":[x1,y1,x2,y2],\"arrow\":false}"
    "]},\"review_required\":true,\"reason\":\"\"}]}\n\n"
    "Rules:\n"
    "1. Allowed element kinds: shape, connector, text. Allowed shapes: rect, circle, ellipse, line, "
    "polyline, polygon, path, arrow. Coordinates are 0..1000 relative to the attached crop.\n"
    "2. Use only the detected labels listed below. Every label must appear as a text element with its exact text. "
    "Do not add any new label or scientific fact. If a label is unreadable, omit it and mention it in reason.\n"
    "3. Draw the visible outline and major internal boundaries with polygon or path shapes. Create a SEPARATE "
    "shape for every labelled part, not one shape for the whole diagram. The outer silhouette may be one "
    "additional shape. Each label must connect to the shape for the part it names.\n"
    "3a. Every connector must include points [x1,y1,x2,y2] following the visible leader line from the label "
    "to the named part. from/to ids may also be included. Never connect all labels to one central point.\n"
    "3b. Keep shapes simple: a polygon with 4-12 points or a short path is enough. Do not trace every pencil "
    "stroke. Approximate the visible region, but keep the correct position and relationship.\n"
    "4. If the crop is too unclear to recreate safely, return an empty elements list and review_required true "
    "with a short reason. Never invent a structure.\n"
    "5. Return every requested diagram id exactly once. Detected diagrams:\n{{DIAGRAMS}}\n"
)


def extract_with_openrouter(image_data_urls, api_key, model, base_url, prompt=EXTRACTION_PROMPT,
                            max_tokens=4096, timeout=(15, 120)):
    """Extract text with an OpenRouter free vision model (OpenAI-compatible)."""
    messages = [{
        "role": "user",
        "content": [{"type": "text", "text": prompt}] + [
            {"type": "image_url", "image_url": {"url": url, "detail": "high"}} for url in image_data_urls
        ]
    }]
    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0,
        "max_tokens": max_tokens,
        # Some free vision models spend the whole completion budget on hidden
        # reasoning and return content=None with finish_reason="length".
        # Disabling reasoning keeps latency and token use predictable.
        "reasoning": {"enabled": False},
    }
    url = base_url.rstrip("/") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost",
        "X-Title": "NotesAI",
    }
    resp = requests.post(url, json=payload, headers=headers, timeout=timeout)
    if resp.status_code == 401:
        raise ValueError("INVALID_API_KEY")
    if resp.status_code == 402:
        raise ValueError("INSUFFICIENT_CREDITS")
    if resp.status_code == 403:
        raise ValueError("FORBIDDEN")
    if resp.status_code == 404:
        raise ValueError("MODEL_NOT_FOUND")
    if resp.status_code == 429:
        raise ValueError("RATE_LIMITED")
    if resp.status_code >= 500:
        raise RuntimeError(f"PROVIDER_ERROR:{resp.status_code}")
    if not resp.ok:
        try:
            err = resp.json().get("error", {})
            msg = err.get("message") if isinstance(err, dict) else str(err)
        except Exception:
            msg = resp.text[:200]
        raise RuntimeError(f"API_ERROR:{resp.status_code}:{msg}")
    data = resp.json()
    choices = data.get("choices") or []
    if not choices:
        raise RuntimeError("EMPTY_CHOICES")
    choice = choices[0] or {}
    msg = choice.get("message") or {}
    content = msg.get("content") or ""
    if isinstance(content, list):
        content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
    content = content.strip() if isinstance(content, str) else ""
    if not content and choice.get("finish_reason") == "length":
        raise RuntimeError("TOKEN_LIMIT")
    return content


def extract_with_gemini(file_storages, api_key, model, prompt=EXTRACTION_PROMPT, max_output_tokens=None):
    from google import genai
    from google.genai import types
    mime_types = {"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png", "webp": "image/webp", "bmp": "image/bmp", "pdf": "application/pdf"}
    parts = []
    for uploaded in file_storages:
        ext = uploaded.filename.rsplit(".", 1)[-1].lower() if "." in uploaded.filename else ""
        if ext not in mime_types:
            raise ValueError("Unsupported file type for Gemini.")
        uploaded.stream.seek(0)
        data = uploaded.read()
        if not data:
            continue
        parts.append(types.Part.from_bytes(data=data, mime_type=mime_types[ext]))
    if not parts:
        return ""
    client = genai.Client(api_key=api_key, http_options=types.HttpOptions(timeout=60000))
    config_kwargs = {"temperature": 0}
    if max_output_tokens:
        config_kwargs["max_output_tokens"] = int(max_output_tokens)
    response = client.models.generate_content(
        model=model,
        contents=[prompt, *parts],
        config=types.GenerateContentConfig(**config_kwargs)
    )
    return (response.text or "").strip()


def extract_with_gemini_images(image_items, api_key, model, prompt=EXTRACTION_PROMPT, max_output_tokens=None):
    """Extract from already-prepared (bytes, mime_type) page images."""
    from google import genai
    from google.genai import types
    parts = [
        types.Part.from_bytes(data=data, mime_type=mime_type)
        for data, mime_type in image_items
        if data
    ]
    if not parts:
        return ""
    client = genai.Client(api_key=api_key, http_options=types.HttpOptions(timeout=90000))
    config_kwargs = {"temperature": 0}
    if max_output_tokens:
        config_kwargs["max_output_tokens"] = int(max_output_tokens)
    response = client.models.generate_content(
        model=model,
        contents=[prompt, *parts],
        config=types.GenerateContentConfig(**config_kwargs)
    )
    return (response.text or "").strip()


def sanitize_provider_message(message, *secrets):
    """Return a short, key-free message safe for JSON responses/logs."""
    text = str(message or "")
    for secret in secrets:
        if secret:
            text = text.replace(secret, "<redacted>")
    text = re.sub(r"sk-or-[A-Za-z0-9_\-]+", "<redacted>", text)
    text = re.sub(r"AIza[0-9A-Za-z_\-]{10,}", "<redacted>", text)
    return text[:300]


def _is_free_vision_model(model):
    """Strict free + vision + text-output check for OpenRouter models."""
    model_id = str(model.get("id") or "")
    if not model_id.endswith(":free"):
        return False
    if model_id.startswith("openrouter/") or ":online" in model_id:
        return False
    pricing = model.get("pricing") or {}
    try:
        prompt_price = float(pricing.get("prompt") or 0)
        completion_price = float(pricing.get("completion") or 0)
    except (TypeError, ValueError):
        return False
    if prompt_price != 0 or completion_price != 0:
        return False
    architecture = model.get("architecture") or {}
    inputs = architecture.get("input_modalities") or []
    outputs = architecture.get("output_modalities") or []
    if "image" not in inputs or "text" not in outputs:
        return False
    if "audio" in outputs:
        return False
    return True


def _openrouter_rank(model):
    model_id = str(model.get("id") or "")
    try:
        preferred_index = OPENROUTER_FREE_MODEL_PREFERENCE.index(model_id)
    except ValueError:
        preferred_index = len(OPENROUTER_FREE_MODEL_PREFERENCE)
    return (preferred_index, -(model.get("context_length") or 0), model_id)


def discover_openrouter_free_models(force=False):
    """Return a cached, ranked list of verified free vision models."""
    now = time.time()
    with _OPENROUTER_MODELS_LOCK:
        cached = list(_OPENROUTER_MODELS_CACHE["models"])
        fresh = (now - _OPENROUTER_MODELS_CACHE["ts"]) < OPENROUTER_MODELS_TTL_SECONDS
        if cached and fresh and not force:
            return cached
        try:
            resp = requests.get(
                OPENROUTER_API_BASE_DEFAULT + "/models",
                timeout=(10, 30),
                headers={"HTTP-Referer": "http://localhost", "X-Title": "NotesAI"},
            )
            resp.raise_for_status()
            payload = resp.json()
            models = [m for m in (payload.get("data") or []) if _is_free_vision_model(m)]
            models.sort(key=_openrouter_rank)
            if models:
                _OPENROUTER_MODELS_CACHE["models"] = models
                _OPENROUTER_MODELS_CACHE["ts"] = now
                return list(models)
        except Exception as exc:
            app.logger.warning("OpenRouter model discovery failed: %s", type(exc).__name__)
        return cached


def select_openrouter_free_model():
    """Return (model_id, ranked_models) using only verified free vision models."""
    models = discover_openrouter_free_models()
    if not models:
        return None, []
    available_ids = [m.get("id") for m in models]
    override = (get_openrouter_config().get("model") or "").strip()
    if override and override in available_ids:
        return override, models
    return available_ids[0], models


def test_openrouter_model(api_key, model, base_url, timeout=(10, 30)):
    """Verify key/model access with one tiny free-model request."""
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "Reply with exactly: OK"}],
        "temperature": 0,
        "max_tokens": 10,
        "reasoning": {"enabled": False},
    }
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost",
        "X-Title": "NotesAI",
    }
    try:
        resp = requests.post(base_url.rstrip("/") + "/chat/completions", json=payload, headers=headers, timeout=timeout)
    except requests.Timeout:
        return False, 504, "OpenRouter request timed out."
    except Exception as exc:
        return False, 502, f"OpenRouter connection failed: {type(exc).__name__}"
    if resp.status_code == 200:
        return True, None, ""
    if resp.status_code == 401:
        return False, 401, "Invalid OpenRouter API key."
    if resp.status_code == 402:
        return False, 402, "This model is not free. Paid models are blocked."
    if resp.status_code == 403:
        return False, 403, "OpenRouter denied access to this model."
    if resp.status_code == 404:
        return False, 404, "OpenRouter model is unavailable."
    if resp.status_code == 429:
        return False, 429, "OpenRouter free-tier rate limit reached."
    return False, 502, f"OpenRouter returned HTTP {resp.status_code}."


def _gemini_client(api_key, timeout_ms=60000):
    from google import genai
    from google.genai import types
    return genai.Client(api_key=api_key, http_options=types.HttpOptions(timeout=timeout_ms))


def gemini_error_details(exc):
    """Extract (http_code, status, message) from a google-genai exception."""
    code = getattr(exc, "code", None)
    if not isinstance(code, int):
        match = re.search(r"\b(\d{3})\b", str(exc))
        code = int(match.group(1)) if match else None
    status = getattr(exc, "status", None) or ""
    message = getattr(exc, "message", None) or str(exc)
    return code, str(status), str(message)


def gemini_model_candidates(configured=None):
    candidates = []
    for model in (configured, GEMINI_MODEL_DEFAULT, *GEMINI_MODEL_CANDIDATES):
        model = (model or "").strip()
        if model and model not in candidates:
            candidates.append(model)
    return candidates


def test_gemini_model(api_key, model, timeout_ms=60000):
    """Make one tiny Gemini call. Returns (ok, code, message)."""
    try:
        from google.genai import types
        client = _gemini_client(api_key, timeout_ms)
        client.models.generate_content(
            model=model,
            contents="Reply with exactly: OK",
            config=types.GenerateContentConfig(temperature=0),
        )
        return True, None, ""
    except Exception as exc:
        code, _status, message = gemini_error_details(exc)
        return False, code, sanitize_provider_message(message, api_key)


def select_working_gemini_model(api_key, configured=None, timeout_ms=60000):
    """Pick a working Gemini model, trying alternates only on model-not-found."""
    last_code, last_message = None, ""
    for model in gemini_model_candidates(configured):
        ok, code, message = test_gemini_model(api_key, model, timeout_ms)
        if ok:
            return model, None, ""
        last_code, last_message = code, message
        if code != 404:
            break
    return None, last_code, last_message or "No supported Gemini vision model is available."


def resolve_extraction_provider(requested=None):
    """Return the manually selected provider, or None when it is not configured.

    There is deliberately no automatic cross-provider fallback.
    """
    provider = get_active_provider()
    if provider == "gemini" and get_gemini_config()["api_key"]:
        return "gemini"
    if provider == "openrouter" and get_openrouter_config()["api_key"]:
        return "openrouter"
    return None


def generate_text_with_provider(prompt, max_tokens=3072):
    """Generate study text with the active provider.

    Returns (text, provider, model, status, error). There is no cross-provider
    fallback and OpenRouter remains restricted to verified free models.
    """
    provider = get_active_provider()
    if provider == "gemini":
        config = get_gemini_config()
        if not config["api_key"]:
            return "", provider, "", 503, "No Gemini API key is configured on the server."
        model = config["model"]
        try:
            from google.genai import types
            client = _gemini_client(config["api_key"], timeout_ms=120000)
            response = client.models.generate_content(
                model=model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.35,
                    max_output_tokens=max(256, min(8192, int(max_tokens))),
                ),
            )
            text = (response.text or "").strip()
            if not text:
                return "", provider, model, 502, "Gemini returned an empty response. Please retry."
            return text, provider, model, 200, ""
        except Exception as exc:
            code, _status, message = gemini_error_details(exc)
            status = 429 if code == 429 else 404 if code == 404 else 504 if code in (408, 504) else 502
            return "", provider, model, status, sanitize_provider_message(message, config["api_key"])
    if provider == "openrouter":
        config = get_openrouter_config()
        if not config["api_key"]:
            return "", provider, "", 503, "No OpenRouter API key is configured on the server."
        model, models = select_openrouter_free_model()
        if not model:
            return "", provider, "", 503, "No free OpenRouter text-capable model is available right now. Try again later or switch to Gemini."
        try:
            text = extract_with_openrouter(
                [], config["api_key"], model, config["base_url"],
                prompt=prompt, max_tokens=max(256, min(8192, int(max_tokens))),
                timeout=(15, 180),
            )
            if not text:
                return "", provider, model, 502, "The free OpenRouter model returned an empty response. Please retry."
            return text, provider, model, 200, ""
        except ValueError as exc:
            reason = str(exc)
            status = 401 if reason == "INVALID_API_KEY" else 402 if reason == "INSUFFICIENT_CREDITS" else 403 if reason == "FORBIDDEN" else 404 if reason == "MODEL_NOT_FOUND" else 429 if reason == "RATE_LIMITED" else 502
            return "", provider, model, status, sanitize_provider_message(reason, config["api_key"])
        except requests.Timeout:
            return "", provider, model, 504, "The free OpenRouter model timed out. Please retry."
        except Exception as exc:
            return "", provider, model, 502, sanitize_provider_message(str(exc), config["api_key"])
    return "", provider, "", 503, "No AI provider is configured."


def build_study_prompt(action, text, language="English", count=8, prompt=""):
    """Build a bounded, instruction-safe study prompt from user content."""
    label, instruction = STUDY_ACTIONS[action]
    try:
        count = max(1, min(30, int(count)))
    except (TypeError, ValueError):
        count = 8
    language = (language or "English").strip()[:60]
    extra = (prompt or "").strip()[:1200]
    return (
        "You are NotesAI Study Assistant. Work only from the supplied notes. "
        "Do not invent facts or add material that is not supported by the notes. "
        "Keep the user's language unless translation is requested. "
        "Use clean Markdown with short headings and readable lists. "
        "For Urdu or Arabic, write natural right-to-left text and preserve English technical terms.\n\n"
        f"Task: {label}\n{instruction}\n"
        f"Language: {language}\n"
        f"Requested item count: {count}\n"
        + (f"Extra instruction: {extra}\n" if extra else "")
        + "\nNOTES:\n" + str(text or "").strip()[:30000]
    )


# ============================================================
# FONTS / URDU & ARABIC TEXT SHAPING
# ============================================================
BUNDLED_FONT_DIR = PROJECT_ROOT / "fonts"
SYSTEM_FONT_DIRS = (
    Path("/usr/share/fonts"),
    Path("/usr/local/share/fonts"),
    Path.home() / ".fonts",
    Path.home() / ".local/share/fonts",
    Path("/data/data/com.termux/files/usr/share/fonts"),
)

LATIN_FONT_FILES = ("NotoSans-Regular.ttf", "DejaVuSans.ttf")
LATIN_BOLD_FONT_FILES = ("NotoSans-Bold.ttf", "DejaVuSans-Bold.ttf")
ARABIC_FONT_FILES = ("NotoNaskhArabic-Regular.ttf", "NotoNaskhArabic-Regular.otf")
ARABIC_BOLD_FONT_FILES = ("NotoNaskhArabic-Bold.ttf", "NotoNaskhArabic-Bold.otf")
# The bundled merged fonts contain both the Latin and Arabic glyphs. Using one
# family avoids fpdf2's fallback-font + text-colour glyph corruption bug while
# keeping Latin and Urdu together in the same paragraph.
MERGED_FONT_FILES = ("NotesAIMerged-Regular.ttf",)
MERGED_BOLD_FONT_FILES = ("NotesAIMerged-Bold.ttf",)

ARABIC_SCRIPT_RE = re.compile(r"[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF]")

_shaping_backend = None
_merged_fonts_attempted = False


class PdfCapabilityError(RuntimeError):
    """Raised when a PDF cannot be produced correctly (font/shaping missing)."""


def _find_font_file(filenames):
    search_dirs = []
    custom_dir = os.getenv("NOTESAI_FONT_DIR", "").strip()
    if custom_dir:
        search_dirs.append(Path(custom_dir).expanduser())
    search_dirs.append(BUNDLED_FONT_DIR)
    search_dirs.append(PROJECT_ROOT)
    search_dirs.extend(SYSTEM_FONT_DIRS)
    for directory in search_dirs:
        for name in filenames:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None


def _ensure_merged_pdf_fonts():
    """Build the merged Latin+Arabic families once when they are missing.

    The merged files are checked in with the project. This helper keeps a
    fresh checkout working when only the original Noto files are present.
    fontTools is already a transitive dependency of fpdf2.
    """
    global _merged_fonts_attempted
    if _merged_fonts_attempted:
        return
    _merged_fonts_attempted = True
    if _find_font_file(MERGED_FONT_FILES) and _find_font_file(MERGED_BOLD_FONT_FILES):
        return
    latin = _find_font_file(LATIN_FONT_FILES)
    latin_bold = _find_font_file(LATIN_BOLD_FONT_FILES)
    arabic = _find_font_file(ARABIC_FONT_FILES)
    arabic_bold = _find_font_file(ARABIC_BOLD_FONT_FILES)
    if not all((latin, latin_bold, arabic, arabic_bold)):
        return
    try:
        from fontTools.merge import Merger
        BUNDLED_FONT_DIR.mkdir(parents=True, exist_ok=True)
        for target_name, paths in (
            (MERGED_FONT_FILES[0], (latin, arabic)),
            (MERGED_BOLD_FONT_FILES[0], (latin_bold, arabic_bold)),
        ):
            target = BUNDLED_FONT_DIR / target_name
            merged = Merger().merge([str(path) for path in paths])
            temp = target.with_name(target.name + ".tmp")
            merged.save(str(temp))
            os.replace(temp, target)
            try:
                os.chmod(target, 0o600)
            except Exception:
                pass
    except Exception as exc:
        app.logger.warning("Could not build merged PDF fonts: %s", exc)


def resolve_pdf_fonts():
    """Locate portable fonts: bundled project fonts first, system fonts second.

    The merged family is preferred because it renders Latin and Arabic runs
    reliably together. The separate families remain a fallback for older
    installations that do not yet have the generated merged font files.
    """
    _ensure_merged_pdf_fonts()
    merged = _find_font_file(MERGED_FONT_FILES)
    merged_bold = _find_font_file(MERGED_BOLD_FONT_FILES)
    if merged and merged_bold:
        return {
            "latin": merged, "latin_bold": merged_bold,
            "arabic": merged, "arabic_bold": merged_bold,
            "merged": True,
        }
    latin = _find_font_file(LATIN_FONT_FILES)
    if not latin:
        raise PdfCapabilityError("PDF_FONT_MISSING")
    latin_bold = _find_font_file(LATIN_BOLD_FONT_FILES) or latin
    arabic = _find_font_file(ARABIC_FONT_FILES)
    arabic_bold = _find_font_file(ARABIC_BOLD_FONT_FILES) or arabic
    return {"latin": latin, "latin_bold": latin_bold,
            "arabic": arabic, "arabic_bold": arabic_bold, "merged": False}


def _harfbuzz_available():
    try:
        import uharfbuzz  # noqa: F401
        return True
    except Exception:
        return False


def _reshaper_available():
    try:
        import arabic_reshaper  # noqa: F401
        from bidi.algorithm import get_display  # noqa: F401
        return True
    except Exception:
        return False


def detect_shaping_backend():
    """Return the available shaping backend: 'harfbuzz', 'reshaper' or ''."""
    global _shaping_backend
    if _shaping_backend is not None:
        return _shaping_backend
    if _harfbuzz_available():
        _shaping_backend = "harfbuzz"
    elif _reshaper_available():
        _shaping_backend = "reshaper"
    else:
        _shaping_backend = ""
    return _shaping_backend


def contains_arabic(text):
    return bool(ARABIC_SCRIPT_RE.search(text or ""))


def bidi_base_direction(text, default="L"):
    """Return the Unicode-style base direction from the first strong character.

    Using the first strong character (rather than counting letters) keeps a
    mixed Urdu-first paragraph right-to-left while an English-first sentence
    containing an Urdu word stays left-to-right.
    """
    value = "" if text is None else str(text)
    for char in value:
        if ARABIC_SCRIPT_RE.match(char):
            return "R"
        if ("A" <= char <= "Z") or ("a" <= char <= "z"):
            return "L"
    return default


def text_is_rtl_dominant(text):
    """True when the paragraph's base direction is right-to-left."""
    value = "" if text is None else str(text)
    if not contains_arabic(value):
        return False
    return bidi_base_direction(value, "L") == "R"


def shape_text_for_pdf(text):
    """Return text ready for rendering.

    With uharfbuzz, fpdf2 performs full OpenType shaping + bidi itself.
    Without it, arabic-reshaper + python-bidi produce presentation forms.
    If neither is available, fail loudly instead of emitting broken glyphs.
    """
    value = "" if text is None else str(text)
    # The bundled Latin font does not include every Unicode arrow glyph. Keep
    # the meaning and avoid a missing-glyph warning; flow diagrams draw real
    # arrow shapes separately.
    value = value.replace("→", "->").replace("←", "<-").replace("➜", "->").replace("➡", "->")
    if not contains_arabic(value):
        return value
    backend = detect_shaping_backend()
    if backend == "harfbuzz":
        return value
    if backend == "reshaper":
        import arabic_reshaper
        from bidi.algorithm import get_display
        shaped_lines = []
        # Anchor sentence-final punctuation to a preceding Latin run so it is
        # not stranded at the visual start of an RTL paragraph.
        lrm = "\u200e"
        for line in value.split("\n"):
            if contains_arabic(line):
                base = bidi_base_direction(line, "R")
                if base == "R" and re.search(r"[A-Za-z]", line):
                    line = re.sub(r"([A-Za-z])([.!?])", r"\1\2" + lrm, line)
                shaped_lines.append(get_display(arabic_reshaper.reshape(line), base_dir=base))
            else:
                shaped_lines.append(line)
        return "\n".join(shaped_lines)
    raise PdfCapabilityError("SHAPING_UNAVAILABLE")


def document_has_arabic(structured_data):
    """True when any title/heading/content contains Arabic-script text."""
    if not isinstance(structured_data, dict):
        return False
    if contains_arabic(structured_data.get("title", "")):
        return True
    if contains_arabic(structured_data.get("subtitle", "")):
        return True
    for section in structured_data.get("sections", []) or []:
        if not isinstance(section, dict):
            continue
        if contains_arabic(section.get("heading", "")) or contains_arabic(section.get("content", "")):
            return True
    return False


def register_pdf_fonts(pdf, fonts):
    """Register the PDF family.

    A merged Latin+Arabic font is used when available. Otherwise the separate
    Arabic family is registered as a fallback for older installations.
    """
    global _shaping_backend
    pdf.add_font("NotesAI", "", str(fonts["latin"]))
    pdf.add_font("NotesAI", "B", str(fonts["latin_bold"]))
    if not fonts.get("merged") and fonts.get("arabic"):
        pdf.add_font("NotesAIUrdu", "", str(fonts["arabic"]))
        pdf.add_font("NotesAIUrdu", "B", str(fonts["arabic_bold"]))
        pdf.set_fallback_fonts(["NotesAIUrdu"], exact_match=False)
    if detect_shaping_backend() == "harfbuzz":
        try:
            pdf.set_text_shaping(True)
        except Exception:
            # Never emit broken Urdu text: degrade to the pure-Python shaper,
            # or fail loudly when no shaper is available at all.
            app.logger.warning("uharfbuzz failed to initialise; using reshaper fallback.")
            if _reshaper_available():
                _shaping_backend = "reshaper"
            else:
                _shaping_backend = ""
                raise PdfCapabilityError("SHAPING_UNAVAILABLE")


def pdf_capability_error_response(exc):
    """User-facing error for missing fonts / text shaping support."""
    code = str(exc)
    if code == "SHAPING_UNAVAILABLE":
        return _error_response(
            "Urdu/Arabic text shaping is not available on this server, so this PDF was not generated. "
            "Install 'uharfbuzz' (recommended) or 'arabic-reshaper' + 'python-bidi' and retry.",
            501, "PDF_SHAPING_UNAVAILABLE", retryable=False,
        )
    if code == "PDF_FONT_MISSING":
        return _error_response(
            "PDF fonts are missing. Restore the bundled 'fonts/' directory "
            "(Noto Sans + Noto Naskh Arabic) and retry.",
            500, "PDF_FONT_MISSING", retryable=False,
        )
    app.logger.error("PDF capability error: %s", code)
    return _error_response(
        "PDF generation is not available on this server.",
        500, "PDF_UNAVAILABLE", retryable=False,
    )


# ============================================================
# PROFESSIONAL PDF GENERATION HELPER
# ============================================================
def _clean_pdf_text(value):
    """Normalise whitespace without changing the user's wording."""
    text = "" if value is None else str(value)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    return text.strip()


def _strip_emphasis_markers(value):
    """Headings/titles are already bold in the PDF; drop literal ** markers."""
    return re.sub(r"\*\*(.+?)\*\*", r"\1", str(value or ""), flags=re.DOTALL)


def _pdf_hex_color(value, fallback=None):
    match = re.fullmatch(r"#?([0-9a-fA-F]{6})", str(value or "").strip())
    if not match:
        return fallback
    raw = match.group(1)
    return tuple(int(raw[index:index + 2], 16) for index in (0, 2, 4))


def normalise_pdf_options(payload):
    """Read optional PDF Studio controls without changing existing defaults."""
    payload = payload or {}
    options = {}
    for key, limit in (("title", 200), ("subtitle", 300), ("headerText", 120), ("footerText", 160)):
        if key in payload:
            options[key] = str(payload.get(key) or "").strip()[:limit]
    accent_value = str(payload.get("accentColor") or "").strip().lower()
    use_accent = str(payload.get("useAccentColor") or "").lower() in {"1", "true", "yes", "on"}
    # Keep each document style's own colours unless the user actively picks a
    # custom accent (or explicitly asks to override with the default navy).
    if use_accent or accent_value not in {"", "#1e3a8a"}:
        accent = _pdf_hex_color(payload.get("accentColor"), None)
        if accent:
            options["accentColor"] = "#" + "".join(f"{part:02x}" for part in accent)
    if "includeToc" in payload:
        options["includeToc"] = str(payload.get("includeToc")).lower() in {"1", "true", "yes", "on"}
    if "showPageNumbers" in payload:
        options["showPageNumbers"] = str(payload.get("showPageNumbers")).lower() in {"1", "true", "yes", "on"}
    if "coverPage" in payload:
        options["coverPage"] = str(payload.get("coverPage")).lower() in {"1", "true", "yes", "on"}
    return options


def _normalise_heading_key(value):
    """Comparison key used only to remove genuinely duplicated headings."""
    text = _clean_pdf_text(value).casefold()
    text = re.sub(r"[^\w\u0600-\u06FF]+", " ", text, flags=re.UNICODE)
    return re.sub(r"\s+", " ", text).strip()


def _prepare_structured_for_pdf(structured_data):
    """Remove duplicate title/heading text and merge repeated sections.

    The extraction model sometimes repeats the document title as the first
    section heading. We keep the title once, remove the duplicate heading and
    merge consecutive sections with the same heading. Content is otherwise
    preserved exactly.
    """
    if not isinstance(structured_data, dict):
        structured_data = {}
    title = _strip_emphasis_markers(_clean_pdf_text(structured_data.get("title", "")))
    subtitle = _strip_emphasis_markers(_clean_pdf_text(structured_data.get("subtitle", "")))
    title_key = _normalise_heading_key(title)
    sections = []

    for raw in structured_data.get("sections", []) or []:
        if not isinstance(raw, dict):
            continue
        heading = _strip_emphasis_markers(_clean_pdf_text(raw.get("heading", "")))
        content = _clean_pdf_text(raw.get("content", ""))
        try:
            level = max(1, min(3, int(raw.get("level", 1))))
        except (TypeError, ValueError):
            level = 1

        # Remove a section heading that merely repeats the document title.
        heading_for_strip = heading
        if heading and title_key and _normalise_heading_key(heading) == title_key:
            heading = ""

        # Some models put "Heading: body" (or the title again) at the start of
        # the content. Remove that redundant prefix only when it is followed
        # by a separator or a line break; otherwise a body sentence that
        # happens to start with the same word would lose that word.
        if heading_for_strip and content:
            escaped = re.escape(heading_for_strip)
            content = re.sub(
                r"^\s*\*{0,2}" + escaped + r"\*{0,2}(?:\s*[:：\-–—]\s*|\s*\n\s*)",
                "", content, count=1, flags=re.IGNORECASE | re.UNICODE,
            ).strip()

        if not heading and not content:
            continue

        # Merge a repeated heading into the previous section instead of
        # printing the same heading twice.
        if sections and heading and _normalise_heading_key(heading) == _normalise_heading_key(sections[-1]["heading"]):
            previous = sections[-1]
            if content:
                previous["content"] = (previous["content"] + "\n\n" + content).strip()
            previous["level"] = min(previous["level"], level)
            continue

        sections.append({"heading": heading, "level": level, "content": content})

    return {"title": title, "subtitle": subtitle, "sections": sections}


def _generate_professional_pdf_legacy(structured_data, options=None):
    """
    Legacy paragraph-only professional PDF renderer.

    Kept for reference and rollback; the public generate_professional_pdf()
    wrapper below uses the structured block renderer so tables, charts, lists,
    formulas and callouts are real PDF elements.

    structured_data: dict with keys:
        - title: str (main document title)
        - subtitle: str (optional)
        - sections: list of {heading: str, level: int, content: str}
    options: dict with page_size, orientation, margin, font_size, style
    """
    if options is None:
        options = {}

    page_size = options.get('pageSize', 'A4')
    orientation = options.get('orientation', 'P')
    try:
        margin = max(6, min(25, int(options.get('margin', 12))))
    except (TypeError, ValueError):
        margin = 12
    try:
        font_size = max(8, min(16, int(options.get('fontSize', 11))))
    except (TypeError, ValueError):
        font_size = 11
    style = options.get('style', 'professional')
    if style not in {'professional', 'academic', 'minimal', 'modern'}:
        style = 'professional'

    data = _prepare_structured_for_pdf(structured_data)
    title = data["title"]
    subtitle = data["subtitle"]
    sections = data["sections"]

    # Style configurations: each style changes typography and layout, not just
    # colour. The wording of the document itself is never shortened.
    styles = {
        'professional': {
            'title_color': (30, 58, 138),
            'heading1_color': (30, 58, 138),
            'heading2_color': (51, 65, 85),
            'heading3_color': (71, 85, 105),
            'text_color': (15, 23, 42),
            'muted_color': (100, 116, 139),
            'line_color': (30, 58, 138),
            'title_size': font_size + 11,
            'title_line': 10.5,
            'subtitle_size': font_size + 1,
            'heading_sizes': (font_size + 4, font_size + 2, font_size + 1),
            'body_line': 6.2,
            'paragraph_gap': 3.4,
            'section_gap': 5.0,
            'title_rule': 'short',
            'header_rule': True,
            'accent_bar': False,
            'body_align': 'J',
            'heading_rule': True,
        },
        'academic': {
            'title_color': (15, 23, 42),
            'heading1_color': (15, 23, 42),
            'heading2_color': (30, 58, 138),
            'heading3_color': (51, 65, 85),
            'text_color': (15, 23, 42),
            'muted_color': (100, 116, 139),
            'line_color': (15, 23, 42),
            'title_size': font_size + 9,
            'title_line': 10,
            'subtitle_size': font_size,
            'heading_sizes': (font_size + 3, font_size + 1.5, font_size),
            'body_line': 6.0,
            'paragraph_gap': 3.0,
            'section_gap': 4.5,
            'title_rule': 'full',
            'header_rule': True,
            'accent_bar': False,
            'body_align': 'J',
            'heading_rule': False,
        },
        'minimal': {
            'title_color': (51, 65, 85),
            'heading1_color': (51, 65, 85),
            'heading2_color': (71, 85, 105),
            'heading3_color': (100, 116, 139),
            'text_color': (51, 65, 85),
            'muted_color': (148, 163, 184),
            'line_color': (203, 213, 225),
            'title_size': font_size + 8,
            'title_line': 9.5,
            'subtitle_size': font_size,
            'heading_sizes': (font_size + 2, font_size + 1, font_size),
            'body_line': 6.4,
            'paragraph_gap': 4.2,
            'section_gap': 6.5,
            'title_rule': None,
            'header_rule': False,
            'accent_bar': False,
            'body_align': 'L',
            'heading_rule': False,
        },
        'modern': {
            'title_color': (30, 58, 138),
            'heading1_color': (30, 58, 138),
            'heading2_color': (59, 130, 246),
            'heading3_color': (96, 165, 250),
            'text_color': (30, 41, 59),
            'muted_color': (100, 116, 139),
            'line_color': (30, 58, 138),
            'title_size': font_size + 13,
            'title_line': 11,
            'subtitle_size': font_size + 1,
            'heading_sizes': (font_size + 5, font_size + 2.5, font_size + 1),
            'body_line': 6.4,
            'paragraph_gap': 3.8,
            'section_gap': 6.0,
            'title_rule': 'accent',
            'header_rule': True,
            'accent_bar': True,
            'body_align': 'J',
            'heading_rule': False,
        },
    }
    style_config = styles[style]

    class ProfessionalPDF(WatermarkedFPDF):
        def header(self):
            # Subtle running header on continuation pages; page 1 keeps a clean
            # title area while still showing the top rule.
            line_y = max(3, margin - 3)
            if style_config['header_rule']:
                self.set_draw_color(*style_config['line_color'])
                self.set_line_width(0.35)
                self.line(margin, line_y, self.w - margin, line_y)
            if self.page_no() > 1 and title and margin >= 10:
                self.set_y(max(2, margin - 9))
                self.set_font('NotesAI', size=8)
                self.set_text_color(*style_config['muted_color'])
                header_text = shape_text_for_pdf(title)
                if len(header_text) > 80:
                    header_text = header_text[:77].rstrip() + "..."
                self.cell(0, 5, header_text, align='R' if text_is_rtl_dominant(title) else 'L')
            self.set_y(margin)

        def footer(self):
            self.set_y(-max(10, margin))
            self.set_font('NotesAI', size=8)
            self.set_text_color(*style_config['muted_color'])
            self.cell(0, 8, f"Page {self.page_no()} of {{nb}}", align='C')

    fonts = resolve_pdf_fonts()
    if document_has_arabic(data) and not fonts["arabic"]:
        raise PdfCapabilityError("PDF_FONT_MISSING")
    pdf = ProfessionalPDF(orientation=orientation, unit="mm", format=page_size)
    # Apply the selected margin to the body as well as the header/footer.
    pdf.set_margins(margin, margin, margin)
    pdf.set_auto_page_break(auto=True, margin=margin + 12)
    register_pdf_fonts(pdf, fonts)
    pdf.alias_nb_pages()

    def ensure_space(needed):
        if pdf.get_y() + needed > pdf.h - pdf.b_margin - 12:
            pdf.add_page()

    pdf.add_page()

    # Title
    if title:
        title_text = shape_text_for_pdf(title)
        title_align = 'R' if text_is_rtl_dominant(title) else 'C'
        title_size = style_config['title_size']
        if len(title_text) > 70:
            title_size = max(font_size + 5, title_size - 4)
        if len(title_text) > 120:
            title_size = max(font_size + 3, title_size - 3)
        pdf.set_font('NotesAI', 'B', size=title_size)
        pdf.set_text_color(*style_config['title_color'])
        pdf.multi_cell(w=0, h=style_config['title_line'], text=title_text, align=title_align)
        pdf.ln(4)

        rule = style_config['title_rule']
        if rule:
            pdf.set_draw_color(*style_config['line_color'])
            pdf.set_line_width(1.6 if rule == 'accent' else (0.8 if rule == 'short' else 0.45))
            if rule == 'short':
                rule_width = 34
            elif rule == 'accent':
                rule_width = 26
            else:
                rule_width = pdf.w - 2 * margin
            if title_align == 'R':
                rule_x = pdf.w - margin - rule_width
            elif title_align == 'L':
                rule_x = margin
            else:
                rule_x = (pdf.w - rule_width) / 2
            pdf.line(rule_x, pdf.get_y(), rule_x + rule_width, pdf.get_y())
            pdf.ln(8 if rule == 'short' else 7)

    if subtitle:
        pdf.set_font('NotesAI', size=style_config['subtitle_size'])
        pdf.set_text_color(*style_config['muted_color'])
        subtitle_align = 'R' if contains_arabic(subtitle) and not re.search(r"[A-Za-z]", subtitle) else 'C'
        pdf.multi_cell(w=0, h=6.5, text=shape_text_for_pdf(subtitle), align=subtitle_align)
        pdf.ln(7)

    # Process sections
    for section in sections:
        level = section.get('level', 1)
        heading = section.get('heading', '')
        content = section.get('content', '')

        if heading:
            heading_size = style_config['heading_sizes'][level - 1]
            heading_line = max(6.2, heading_size * 0.55)
            # Avoid an orphan heading at the bottom of a page.
            ensure_space(heading_line + style_config['body_line'] * 2 + 3)
            pdf.ln(style_config['section_gap'] if pdf.get_y() > margin + 2 else 0)
            raw_heading = heading
            heading_text = shape_text_for_pdf(raw_heading)
            heading_align = 'R' if contains_arabic(raw_heading) else 'L'
            if level == 1:
                color = style_config['heading1_color']
            elif level == 2:
                color = style_config['heading2_color']
            else:
                color = style_config['heading3_color']
            pdf.set_font('NotesAI', 'B', size=heading_size)
            pdf.set_text_color(*color)

            if style_config['accent_bar'] and level == 1:
                bar_top = pdf.get_y()
                pdf.set_fill_color(*style_config['line_color'])
                if heading_align == 'R':
                    pdf.rect(pdf.w - margin - 1.8, bar_top + 0.5, 1.8, heading_line + 1.5, style='F')
                    pdf.set_x(margin)
                    pdf.multi_cell(w=pdf.w - 2 * margin - 5, h=heading_line, text=heading_text, align=heading_align)
                else:
                    pdf.rect(margin, bar_top + 0.5, 1.8, heading_line + 1.5, style='F')
                    pdf.set_x(margin + 5)
                    pdf.multi_cell(w=pdf.w - 2 * margin - 5, h=heading_line, text=heading_text, align=heading_align)
            else:
                pdf.multi_cell(w=0, h=heading_line, text=heading_text, align=heading_align)

            if style_config['heading_rule'] and level == 1:
                pdf.set_draw_color(*style_config['line_color'])
                pdf.set_line_width(0.25)
                pdf.line(margin, pdf.get_y() + 1.5, pdf.w - margin, pdf.get_y() + 1.5)
                pdf.ln(2.5)
            else:
                pdf.ln(2)

        if content:
            pdf.set_font('NotesAI', size=font_size)
            pdf.set_text_color(*style_config['text_color'])
            paragraphs = content.split('\n\n')
            for para in paragraphs:
                para = para.strip()
                if not para:
                    continue
                paragraph_text = shape_text_for_pdf(para)
                align = 'R' if contains_arabic(para) else style_config['body_align']
                is_list = bool(re.match(r"^(?:[•\-*·]|\d+[.)])\s+", para))
                # Preserve the editor's **bold** formatting using fpdf2's
                # markdown renderer. Enable it only when paired markers exist so
                # ordinary asterisks/bullets are never reinterpreted.
                use_markdown = bool(re.search(r"\*\*.+?\*\*", para, flags=re.DOTALL))
                # Keep a short paragraph from leaving a single orphan line.
                ensure_space(style_config['body_line'] * 2)
                if is_list:
                    pdf.set_x(margin + 5)
                    pdf.multi_cell(w=pdf.w - 2 * margin - 5, h=style_config['body_line'],
                                   text=paragraph_text, align=align, markdown=use_markdown)
                else:
                    pdf.multi_cell(w=0, h=style_config['body_line'], text=paragraph_text,
                                   align=align, markdown=use_markdown)
                pdf.ln(style_config['paragraph_gap'])

    output = pdf.output()
    if isinstance(output, str):
        output = output.encode("latin-1")
    return bytes(output)


def generate_professional_pdf(structured_data, options=None):
    """Render the Professional PDF with the structured block engine.

    The old renderer treated every section body as a paragraph, so model output
    such as ``Tense | Formula | Example`` became pipe-separated text. The shared
    block renderer converts those bodies into real tables, lists, callouts,
    formulas and flows. Diagrams are intentionally disabled here; they belong
    to the premium Smart Recreated PDF.
    """
    if isinstance(structured_data, dict) and (
        structured_data.get('pages') or structured_data.get('blocks')
    ):
        analysis = normalise_analysis(structured_data)
    else:
        data = _prepare_structured_for_pdf(structured_data)
        analysis = normalise_analysis(data)
    pdf_bytes, _warnings = generate_smart_pdf(
        analysis, options, source_pages=None, include_diagrams=False,
    )
    return pdf_bytes


def _smart_style_config(font_size, style):
    base = {
        'title_color': (30, 58, 138),
        'heading1_color': (30, 58, 138),
        'heading2_color': (51, 65, 85),
        'heading3_color': (71, 85, 105),
        'text_color': (15, 23, 42),
        'muted_color': (100, 116, 139),
        'line_color': (30, 58, 138),
        'title_size': font_size + 11,
        'title_line': 10.5,
        'subtitle_size': font_size + 1,
        'heading_sizes': (font_size + 4, font_size + 2, font_size + 1),
        'body_line': max(5.2, round(font_size * 0.56, 1)),
        'paragraph_gap': max(2.0, round(font_size * 0.25, 1)),
        'section_gap': max(3.2, round(font_size * 0.41, 1)),
        'body_align': 'J',
        'header_rule': True,
        'footer_rule': True,
        'footer_brand': 'NotesAI',
    }
    if style == 'academic':
        base.update({
            'title_color': (15, 23, 42), 'heading1_color': (15, 23, 42),
            'heading2_color': (30, 58, 138), 'line_color': (15, 23, 42),
            'title_size': font_size + 9, 'heading_sizes': (font_size + 3, font_size + 1.5, font_size),
            'body_line': 6.0, 'paragraph_gap': 3.0, 'section_gap': 4.5,
        })
    elif style == 'minimal':
        base.update({
            'title_color': (51, 65, 85), 'heading1_color': (51, 65, 85),
            'heading2_color': (71, 85, 105), 'heading3_color': (100, 116, 139),
            'line_color': (203, 213, 225), 'title_size': font_size + 8,
            'heading_sizes': (font_size + 2, font_size + 1, font_size),
            'body_line': 6.4, 'paragraph_gap': 4.2, 'section_gap': 6.5,
            'body_align': 'L', 'header_rule': False,
        })
    elif style == 'modern':
        base.update({
            'heading2_color': (59, 130, 246), 'heading3_color': (96, 165, 250),
            'title_size': font_size + 13, 'title_line': 11,
            'heading_sizes': (font_size + 5, font_size + 2.5, font_size + 1),
            'body_line': 6.4, 'paragraph_gap': 3.2, 'section_gap': 5.5,
        })
    return base


def generate_smart_pdf(analysis, options=None, source_pages=None, include_diagrams=True):
    """Generate a smart-reconstruction PDF from schema-v2 analysis.

    Returns (pdf_bytes, warnings). Diagram specs are rendered locally to SVG;
    if that is unsafe or unsupported, the original page crop is preserved.
    ``include_diagrams=False`` is used by Professional PDF mode so the shared
    block engine can render tables/callouts without premium diagrams.
    """
    if options is None:
        options = {}
    analysis = normalise_analysis(analysis)
    page_size = options.get('pageSize', 'A4')
    orientation = options.get('orientation', 'P')
    try:
        margin = max(6, min(25, int(options.get('margin', 12))))
    except (TypeError, ValueError):
        margin = 12
    try:
        font_size = max(8, min(16, int(options.get('fontSize', 11))))
    except (TypeError, ValueError):
        font_size = 11
    style = options.get('style', 'professional')
    if style not in {'professional', 'academic', 'minimal', 'modern'}:
        style = 'professional'
    diagram_style = normalise_diagram_style(options.get('diagramStyle', 'color'))
    style_config = _smart_style_config(font_size, style)
    accent = _pdf_hex_color(options.get('accentColor'), None)
    if accent:
        style_config['title_color'] = accent
        style_config['heading1_color'] = accent
        style_config['line_color'] = accent
        if style == 'modern':
            style_config['heading2_color'] = accent
    title = str(options.get('title') or analysis.get('title') or 'Converted Document').strip()
    subtitle = str(options.get('subtitle') or analysis.get('subtitle') or '').strip()
    header_label = str(options.get('headerText') or title or '').strip()[:120]
    footer_label = str(options.get('footerText') or 'NotesAI').strip()[:160]
    show_page_numbers = options.get('showPageNumbers', True) is not False
    heading_blocks = [
        block for page in (analysis.get('pages') or [])
        for block in (page.get('blocks') or [])
        if isinstance(block, dict) and block.get('type') == 'heading' and str(block.get('text') or '').strip()
    ]
    toc_enabled = bool(options.get('includeToc')) and len(heading_blocks) >= 2
    diagrams_by_id = {diagram['id']: diagram for diagram in iter_diagrams(analysis)}
    source_pages = source_pages or []
    warnings = []
    last_heading_text = ''

    def heading_key(value):
        text = re.sub(r"^\s*\d+[.)]\s*", "", str(value or ""))
        return re.sub(r"[^\w\u0600-\u06FF]+", " ", text.casefold(), flags=re.UNICODE).strip()

    def same_heading(first, second):
        first_key, second_key = heading_key(first), heading_key(second)
        if not first_key or not second_key:
            return False
        return first_key == second_key or first_key.endswith(second_key) or second_key.endswith(first_key)

    fonts = resolve_pdf_fonts()
    if analysis_has_arabic(analysis) and not fonts["arabic"]:
        raise PdfCapabilityError("PDF_FONT_MISSING")

    class SmartPDF(WatermarkedFPDF):
        def header(self):
            line_y = max(3, margin - 4)
            if style_config['header_rule']:
                self.set_draw_color(*style_config['line_color'])
                self.set_line_width(0.35)
                self.line(margin, line_y, self.w - margin, line_y)
            if self.page_no() > 1 and margin >= 10:
                self.set_y(max(2, margin - 10))
                self.set_font('NotesAI', size=8)
                self.set_text_color(*style_config['muted_color'])
                header_text = shape_text_for_pdf(header_label)
                if len(header_text) > 80:
                    header_text = header_text[:77].rstrip() + "..."
                self.cell(0, 5, header_text, align='R' if text_is_rtl_dominant(header_label) else 'L')
            self.set_y(margin)

        def footer(self):
            footer_y = self.h - max(10, margin)
            if style_config['footer_rule']:
                self.set_draw_color(*style_config['muted_color'])
                self.set_line_width(0.25)
                self.line(margin, footer_y - 3.5, self.w - margin, footer_y - 3.5)
            self.set_y(footer_y)
            self.set_x(margin)
            self.set_font('NotesAI', size=8)
            self.set_text_color(*style_config['muted_color'])
            self.cell(0, 6, shape_text_for_pdf(footer_label), align='L')
            if show_page_numbers:
                self.set_y(footer_y)
                self.set_x(margin)
                self.cell(0, 6, f"Page {self.page_no()} of {{nb}}", align='C')

    pdf = SmartPDF(orientation=orientation, unit="mm", format=page_size)
    pdf.set_margins(margin, margin, margin)
    pdf.set_auto_page_break(auto=True, margin=margin + 12)
    register_pdf_fonts(pdf, fonts)
    pdf.alias_nb_pages()
    # Searchable, professional PDF metadata. Wrapped because older fpdf2
    # builds may not expose every setter.
    try:
        pdf.set_title(_clean_pdf_text(title)[:200] or "NotesAI Document")
        pdf.set_subject(_clean_pdf_text(subtitle)[:200])
        pdf.set_author("NotesAI")
        pdf.set_creator("NotesAI")
        pdf.set_producer("NotesAI")
        pdf.set_keywords("NotesAI, converted notes")
    except Exception:
        app.logger.debug("PDF metadata setters unavailable", exc_info=True)

    def ensure_space(needed):
        if pdf.get_y() + needed > pdf.h - pdf.b_margin - 2:
            pdf.add_page()

    def embed_image(image, caption, suffix='.png', source_label=''):
        nonlocal warnings
        try:
            width, height = image.size
        except Exception:
            width, height = 1000, 700
        max_w = pdf.epw
        max_h = max(35, pdf.h - pdf.b_margin - 8)
        scale = min(max_w / max(1, width), max_h / max(1, height))
        draw_w, draw_h = width * scale, height * scale
        ensure_space(draw_h + 14)
        path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp:
                if suffix == '.svg':
                    temp.write(image if isinstance(image, bytes) else image.read())
                else:
                    image.save(temp, format='PNG')
                path = temp.name
            y = pdf.get_y()
            pdf.image(path, x=(pdf.w - draw_w) / 2, y=y, w=draw_w, h=draw_h)
            pdf.set_y(y + draw_h + 2)
            if caption:
                pdf.set_font('NotesAI', size=8)
                pdf.set_text_color(*style_config['muted_color'])
                pdf.multi_cell(w=0, h=4.5, text=shape_text_for_pdf(caption), align='C')
            pdf.ln(3)
        except Exception as exc:
            warnings.append(f"{source_label or 'Diagram'} could not be embedded: {sanitize_provider_message(str(exc))}")
            raise
        finally:
            if path:
                try:
                    os.unlink(path)
                except OSError:
                    pass

    def render_placeholder(diagram, reason):
        nonlocal warnings
        warnings.append(f"{diagram.get('title') or diagram.get('id') or 'Diagram'}: {reason}")
        ensure_space(28)
        y = pdf.get_y()
        pdf.set_draw_color(203, 213, 225)
        pdf.set_fill_color(248, 250, 252)
        pdf.rect(margin, y, pdf.epw, 24, style='DF')
        pdf.set_xy(margin + 3, y + 4)
        pdf.set_font('NotesAI', 'B', size=9)
        pdf.set_text_color(100, 116, 139)
        pdf.multi_cell(w=pdf.epw - 6, h=5, text="Diagram could not be recreated safely.")
        pdf.set_x(margin + 3)
        pdf.set_font('NotesAI', size=8)
        pdf.multi_cell(w=pdf.epw - 6, h=4.5, text=shape_text_for_pdf(reason))
        pdf.set_y(y + 27)

    def render_original_crop(diagram):
        nonlocal warnings
        page_index = int(diagram.get('page_index') or 0)
        if page_index < 0 or page_index >= len(source_pages):
            data_url = str(diagram.get('source_preview') or '')
            if data_url.startswith('data:image/'):
                try:
                    import base64 as _base64
                    payload = data_url.split(',', 1)[1]
                    crop = Image.open(io.BytesIO(_base64.b64decode(payload))).convert('RGB')
                    caption = (diagram.get('title') or 'Diagram') + " — source diagram preserved for accuracy."
                    embed_image(crop, caption, suffix='.jpg', source_label=diagram.get('title'))
                    return
                except Exception:
                    app.logger.warning("Could not embed saved source diagram preview")
            render_placeholder(diagram, "The original page image is unavailable. Please re-upload the source and regenerate.")
            return
        page_image = source_pages[page_index]
        bbox = diagram.get('source_bbox') or [0, 0, 1000, 1000]
        try:
            x, y, w, h = [float(value) for value in bbox]
        except (TypeError, ValueError):
            x, y, w, h = 0, 0, 1000, 1000
        if w <= 1 or h <= 1:
            x, y, w, h = 0, 0, 1000, 1000
        left = max(0, min(page_image.width - 1, int(x / 1000 * page_image.width)))
        top = max(0, min(page_image.height - 1, int(y / 1000 * page_image.height)))
        right = max(left + 1, min(page_image.width, int((x + w) / 1000 * page_image.width)))
        bottom = max(top + 1, min(page_image.height, int((y + h) / 1000 * page_image.height)))
        crop = page_image.crop((left, top, right, bottom))
        caption = (diagram.get('title') or 'Diagram') + " — source diagram preserved for accuracy."
        try:
            embed_image(crop, caption, suffix='.png', source_label=diagram.get('title'))
        except Exception:
            render_placeholder(diagram, "The original crop could not be embedded.")

    def render_diagram(diagram_id):
        diagram = diagrams_by_id.get(diagram_id)
        if not diagram or diagram.get('excluded'):
            return
        if diagram.get('use_original'):
            warnings.append(
                f"{diagram.get('title') or diagram.get('id') or 'Diagram'}: source diagram preserved for accuracy; an AI recreation is available for review."
            )
            render_original_crop(diagram)
            return
        try:
            render_spec = diagram
            diagram_title = diagram.get('title') or ''
            if diagram_title and (same_heading(diagram_title, last_heading_text) or same_heading(diagram_title, title)):
                render_spec = dict(diagram)
                render_spec['title'] = ''
            svg_bytes = render_diagram_svg(render_spec, style=diagram_style)
            svg_w, svg_h = svg_dimensions(svg_bytes)
            max_w = pdf.epw * 0.92
            max_h = max(35, pdf.h - pdf.b_margin - 8)
            scale = min(max_w / max(1, svg_w), max_h / max(1, svg_h))
            draw_w, draw_h = svg_w * scale, svg_h * scale
            ensure_space(draw_h + 16)
            y = pdf.get_y()
            path = None
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix='.svg') as temp:
                    temp.write(svg_bytes)
                    path = temp.name
                pdf.image(path, x=(pdf.w - draw_w) / 2, y=y, w=draw_w, h=draw_h)
                pdf.set_y(y + draw_h + 2)
            finally:
                if path:
                    try:
                        os.unlink(path)
                    except OSError:
                        pass
            if diagram.get('recreation_mode') == 'trace':
                match = diagram.get('quality', {}).get('structural_match')
                match_text = f"{match:.0%}" if isinstance(match, (int, float)) else ""
                caption = (diagram.get('title') or 'Diagram') + (
                    f" — vector-traced from the source; structure preserved{'.' if not match_text else f' — structural match {match_text}.'}"
                )
            else:
                caption = (diagram.get('title') or 'Diagram') + " — digitally recreated from the source; illustrative, not to scale."
                if diagram.get('review_required'):
                    caption += " Review recommended."
            pdf.set_font('NotesAI', size=8)
            pdf.set_text_color(*style_config['muted_color'])
            pdf.multi_cell(w=0, h=4.5, text=shape_text_for_pdf(caption), align='C')
            pdf.ln(3)
            for uncertainty in diagram.get('uncertain') or []:
                pdf.set_font('NotesAI', size=8)
                pdf.set_text_color(180, 83, 9)
                pdf.multi_cell(w=0, h=4.5, text=shape_text_for_pdf("Uncertain: " + str(uncertain)), align='L')
                pdf.ln(1)
        except Exception as exc:
            warnings.append(f"{diagram.get('title') or diagram.get('id') or 'Diagram'}: {sanitize_provider_message(str(exc))}")
            render_original_crop(diagram)

    def cell_height(text, width):
        pdf.set_font('NotesAI', size=8.6)
        try:
            height = pdf.multi_cell(width - 2.4, 4.4, text, dry_run=True, output="HEIGHT")
            return max(5.0, float(height) + 2.0)
        except Exception:
            return max(5.0, 4.4 * max(1, len(text) // max(8, int(width / 1.6)) + 1))

    def draw_table(block):
        columns = [str(item) for item in (block.get('columns') or [])]
        rows = [[str(cell) for cell in row] for row in (block.get('rows') or [])]
        if not columns and rows:
            columns = [f"Column {index + 1}" for index in range(max(len(row) for row in rows))]
        if not columns:
            return
        # Preserve all extracted table content: do not drop columns or rows.
        # Pad short rows so every row has a cell for each column.
        col_count = len(columns)
        rows = [(list(row) + [''] * max(0, col_count - len(row)))[:col_count] for row in rows]
        table_title = block.get('title') or ''
        if table_title and same_heading(table_title, last_heading_text):
            table_title = ''
        longest = []
        for index, column in enumerate(columns):
            lengths = [len(column)] + [len(row[index]) for row in rows]
            longest.append(max(6, min(44, max(lengths) * 1.45)))
        total = sum(longest) or 1
        widths = [max(6, item * pdf.epw / total) for item in longest]
        # Keep the table within the printable width; scale down if too many
        # columns would otherwise overflow the page.
        cur = sum(widths)
        if cur > pdf.epw:
            scale = pdf.epw / cur
            widths = [max(6, w * scale) for w in widths]
        widths[-1] += pdf.epw - sum(widths)
        if widths[-1] < 6:
            widths[-1] = 6
        line_h = 4.4
        align = block.get('align') or []
        start_x = margin

        # Measure before drawing the title so a title can never be stranded at
        # the bottom of a page while its table starts on the next page.
        header_height = max(cell_height(column, widths[index]) for index, column in enumerate(columns))
        row_heights = [
            max(cell_height(cell, widths[index]) for index, cell in enumerate(row))
            for row in rows
        ]
        table_height = header_height + sum(row_heights) + 2
        available_height = pdf.h - pdf.b_margin - pdf.get_y() - 2
        title_height = 0
        if table_title:
            pdf.set_font('NotesAI', 'B', size=font_size)
            try:
                title_height = float(pdf.multi_cell(
                    pdf.epw, 6, shape_text_for_pdf(table_title), dry_run=True, output="HEIGHT",
                ))
            except Exception:
                title_height = 6
        page_body_height = pdf.h - 2 * pdf.b_margin
        if table_title and table_height + title_height + 2 <= page_body_height:
            # Short table: keep the title and the whole table on one page.
            if table_height + title_height + 2 > available_height:
                pdf.add_page()
        elif table_title:
            # Long table: at minimum keep the title with the header row.
            ensure_space(title_height + header_height + 2)
        elif table_height <= page_body_height and table_height > available_height:
            pdf.add_page()

        if table_title:
            pdf.set_font('NotesAI', 'B', size=font_size)
            pdf.set_text_color(*style_config['heading2_color'])
            pdf.multi_cell(
                w=0, h=6, text=shape_text_for_pdf(table_title),
                align='R' if text_is_rtl_dominant(table_title) else 'L',
            )
            pdf.ln(2)

        def draw_row(cells, is_header=False):
            heights = [cell_height(cell, widths[index]) for index, cell in enumerate(cells)]
            row_h = max(heights)
            page_body_height = pdf.h - pdf.b_margin - pdf.t_margin - 4
            if row_h > page_body_height:
                warnings.append(
                    "A table row is taller than the available page area; "
                    "split it into shorter rows if the layout looks cramped."
                )
            if pdf.get_y() + row_h > pdf.h - pdf.b_margin - 2:
                pdf.add_page()
                if not is_header:
                    if table_title:
                        pdf.set_font('NotesAI', 'B', size=font_size)
                        pdf.set_text_color(*style_config['heading2_color'])
                        continued = f"{table_title} (continued)"
                        pdf.multi_cell(
                            w=0, h=6, text=shape_text_for_pdf(continued),
                            align='R' if text_is_rtl_dominant(table_title) else 'L',
                        )
                        pdf.ln(1)
                    draw_row(columns, True)
            start_y = pdf.get_y()
            for index, cell in enumerate(cells):
                x = start_x + sum(widths[:index])
                pdf.set_xy(x, start_y)
                pdf.set_font('NotesAI', 'B' if is_header else '', size=8.6)
                if is_header:
                    pdf.set_fill_color(*style_config['line_color'])
                    pdf.set_text_color(255, 255, 255)
                else:
                    pdf.set_fill_color(248, 250, 252)
                    pdf.set_text_color(*style_config['text_color'])
                cell_align = str(align[index]).lower() if index < len(align) else 'L'
                if cell_align not in {'l', 'c', 'r'}:
                    cell_align = 'L' if not text_is_rtl_dominant(cell) else 'R'
                pdf.multi_cell(
                    widths[index], line_h, shape_text_for_pdf(cell), border=1,
                    align=cell_align, fill=True, new_x=XPos.RIGHT, new_y=YPos.TOP,
                    padding=1,
                )
            pdf.set_y(start_y + row_h)

        draw_row(columns, True)
        for row in rows:
            draw_row(row, False)
        pdf.ln(4)

    def render_callout(block):
        text = block.get('text') or ''
        label = block.get('label') or 'Note'
        pdf.set_font('NotesAI', 'B', size=9)
        label_text = shape_text_for_pdf(label)
        pdf.set_font('NotesAI', size=font_size - 1)
        body_text = shape_text_for_pdf(text)
        pdf.set_font('NotesAI', size=font_size - 1)
        try:
            body_h = float(pdf.multi_cell(pdf.epw - 8, 5.2, body_text, dry_run=True, output="HEIGHT"))
        except Exception:
            body_h = 5.2
        box_h = body_h + 13
        ensure_space(box_h + 3)
        y = pdf.get_y()
        pdf.set_fill_color(239, 246, 255)
        pdf.set_draw_color(191, 219, 254)
        pdf.rect(margin, y, pdf.epw, box_h, style='DF')
        pdf.set_xy(margin + 4, y + 3)
        pdf.set_font('NotesAI', 'B', size=9)
        pdf.set_text_color(30, 64, 175)
        pdf.multi_cell(
            w=pdf.epw - 8, h=5, text=label_text,
            align='R' if text_is_rtl_dominant(label) else 'L',
        )
        pdf.set_x(margin + 4)
        pdf.set_font('NotesAI', size=font_size - 1)
        pdf.set_text_color(*style_config['text_color'])
        pdf.multi_cell(
            w=pdf.epw - 8, h=5.2, text=body_text,
            align='R' if text_is_rtl_dominant(text) else 'L',
            markdown=bool(re.search(r"\*\*.+?\*\*", body_text, flags=re.DOTALL)),
        )
        pdf.set_y(y + box_h + 3)

    def render_uncertain(block):
        nonlocal warnings
        warnings.append(block.get('text') or 'Unclear content')
        ensure_space(16)
        y = pdf.get_y()
        pdf.set_fill_color(255, 251, 235)
        pdf.set_draw_color(253, 230, 138)
        pdf.rect(margin, y, pdf.epw, 14, style='DF')
        pdf.set_xy(margin + 4, y + 3)
        pdf.set_font('NotesAI', 'B', size=8.5)
        pdf.set_text_color(180, 83, 9)
        pdf.multi_cell(
            w=pdf.epw - 8, h=4.8,
            text="Review required: " + shape_text_for_pdf(block.get('text') or ''),
            align='R' if text_is_rtl_dominant(block.get('text') or '') else 'L',
        )
        pdf.set_y(y + 17)

    def render_heading(block):
        nonlocal last_heading_text
        last_heading_text = block.get('text') or ''
        level = max(1, min(3, int(block.get('level', 1))))
        heading_size = style_config['heading_sizes'][level - 1]
        heading_line = max(6.2, heading_size * 0.55)
        ensure_space(heading_line + style_config['body_line'] * 2 + 3)
        if toc_enabled and str(block.get('text') or '').strip():
            pdf.start_section(str(block.get('text')), level=level - 1, strict=False)
        pdf.ln(style_config['section_gap'] if pdf.get_y() > margin + 2 else 0)
        text = shape_text_for_pdf(block.get('text') or '')
        align = 'R' if text_is_rtl_dominant(block.get('text') or '') else 'L'
        color = (style_config['heading1_color'] if level == 1 else
                 style_config['heading2_color'] if level == 2 else style_config['heading3_color'])
        pdf.set_font('NotesAI', 'B', size=heading_size)
        pdf.set_text_color(*color)
        pdf.multi_cell(w=0, h=heading_line, text=text, align=align)
        pdf.ln(2)

    def render_paragraph(block):
        text = block.get('text') or ''
        pdf.set_font('NotesAI', size=font_size)
        pdf.set_text_color(*style_config['text_color'])
        for para in text.split('\n\n'):
            para = para.strip()
            if not para:
                continue
            paragraph_text = shape_text_for_pdf(para)
            align = 'R' if text_is_rtl_dominant(para) else style_config['body_align']
            use_markdown = bool(re.search(r"\*\*.+?\*\*", para, flags=re.DOTALL))
            # Keep a short paragraph fully together rather than leaving one or
            # two lines stranded at the bottom of a page.
            try:
                para_height = float(pdf.multi_cell(
                    pdf.epw, style_config['body_line'], paragraph_text,
                    dry_run=True, output="HEIGHT",
                ))
            except Exception:
                para_height = 0
            page_body_height = pdf.h - 2 * pdf.b_margin
            available_height = pdf.h - pdf.b_margin - pdf.get_y() - 2
            if (
                para_height
                and para_height <= style_config['body_line'] * 5
                and para_height <= page_body_height
                and para_height > available_height
            ):
                pdf.add_page()
            # Reserve three body lines so a paragraph never starts with a
            # single orphaned line at the bottom of a page.
            ensure_space(style_config['body_line'] * 3)
            if re.match(r"^(?:[•\-*·]|\d+[.)])\s+", para):
                pdf.set_x(margin + 5)
                pdf.multi_cell(w=pdf.epw - 5, h=style_config['body_line'], text=paragraph_text,
                               align=align, markdown=use_markdown)
            else:
                pdf.multi_cell(w=0, h=style_config['body_line'], text=paragraph_text,
                               align=align, markdown=use_markdown)
            pdf.ln(style_config['paragraph_gap'])

    def render_list(block):
        ordered = bool(block.get('ordered'))
        items = block.get('items') or []
        if not items:
            return
        # Keep a short list together instead of leaving one bullet on the
        # previous page and the rest on the next page.
        heights = []
        for index, item in enumerate(items):
            marker = f"{index + 1}." if ordered else "•"
            text = shape_text_for_pdf(f"{marker} {item}")
            pdf.set_font('NotesAI', size=font_size)
            # Estimate height from character count. fpdf2's width/dry-run
            # measurement can corrupt the glyph mapping of a later mixed
            # Latin/Arabic line when a fallback font is registered, so this
            # deliberately avoids touching the font state before drawing.
            chars_per_line = max(18, int((pdf.epw - 5.0) / max(2.0, font_size * 0.52)))
            lines = max(1, (len(text) + chars_per_line - 1) // chars_per_line)
            heights.append(max(style_config['body_line'], lines * style_config['body_line']) + 1.2)
        total_height = sum(heights) + 2
        available_height = pdf.h - pdf.b_margin - pdf.get_y() - 2
        if total_height <= pdf.h - 2 * pdf.b_margin and total_height > available_height:
            pdf.add_page()
        for index, item in enumerate(items):
            marker = f"{index + 1}." if ordered else "•"
            text = shape_text_for_pdf(f"{marker} {item}")
            ensure_space(style_config['body_line'] * 2)
            pdf.set_font('NotesAI', size=font_size)
            pdf.set_text_color(*style_config['text_color'])
            rtl_item = text_is_rtl_dominant(item)
            pdf.set_x(margin if rtl_item else margin + 4)
            pdf.multi_cell(w=pdf.epw - 4, h=style_config['body_line'], text=text,
                           align='R' if rtl_item else 'L')
            pdf.ln(1.2)
        pdf.ln(2)

    def render_question(block):
        ensure_space(14)
        pdf.set_font('NotesAI', 'B', size=font_size)
        pdf.set_text_color(*style_config['heading2_color'])
        pdf.multi_cell(
            w=0, h=6, text=shape_text_for_pdf("Q: " + (block.get('question') or '')),
            align='R' if text_is_rtl_dominant(block.get('question') or '') else 'L',
        )
        if block.get('answer'):
            pdf.set_font('NotesAI', size=font_size)
            pdf.set_text_color(*style_config['text_color'])
            pdf.multi_cell(
                w=0, h=style_config['body_line'],
                text=shape_text_for_pdf("A: " + block['answer']),
                align='R' if text_is_rtl_dominant(block['answer']) else 'L',
            )
        pdf.ln(3)

    def render_formula(block):
        ensure_space(16)
        text = shape_text_for_pdf(block.get('text') or '')
        pdf.set_fill_color(248, 250, 252)
        pdf.set_draw_color(226, 232, 240)
        pdf.set_font('NotesAI', size=font_size)
        pdf.set_text_color(*style_config['text_color'])
        try:
            h = float(pdf.multi_cell(pdf.epw - 8, 6, text, dry_run=True, output="HEIGHT"))
        except Exception:
            h = 6
        y = pdf.get_y()
        pdf.rect(margin, y, pdf.epw, h + 5, style='DF')
        pdf.set_xy(margin + 4, y + 3)
        pdf.multi_cell(w=pdf.epw - 8, h=6, text=text, align='C')
        pdf.set_y(y + h + 8)

    def render_flow(block):
        """Draw arrow-connected cards for step-by-step processes."""
        raw_steps = [step for step in (block.get('steps') or []) if isinstance(step, dict)]
        if not raw_steps:
            return
        arrow_re = re.compile(r"(?:->|→|=>|➜|➡)")
        groups = []
        if any(arrow_re.search(step.get('text') or '') for step in raw_steps):
            # A model may put all arrow rows into one flow block, for example
            # "Present: Do -> Doing" / "Past: Did -> ...". Render each as its
            # own labelled row so the cards stay readable.
            for step in raw_steps:
                text = step.get('text') or ''
                label = step.get('label') or ''
                match = re.match(r"^([^:]{1,50}):\s*(.+)$", text)
                if match:
                    label = match.group(1).strip() or label
                    text = match.group(2).strip()
                parts = [part.strip() for part in arrow_re.split(text) if part.strip()]
                if len(parts) >= 2:
                    groups.append({
                        "title": label,
                        "steps": [{"label": "", "text": part} for part in parts],
                    })
                else:
                    groups.append({
                        "title": label,
                        "steps": [{"label": "", "text": text}],
                    })
        if not groups:
            groups = [{"title": block.get('title') or "", "steps": raw_steps}]

        block_title = block.get('title') or ''
        if block_title and same_heading(block_title, last_heading_text):
            block_title = ""
        # Reserve enough room for the whole flow (including its title) so rows
        # are not orphaned from the heading.
        ensure_space(len(groups) * 24 + (10 if block_title else 4))
        if block_title:
            pdf.set_font('NotesAI', 'B', size=9.2)
            pdf.set_text_color(*style_config['heading2_color'])
            pdf.multi_cell(
                w=0, h=5.2, text=shape_text_for_pdf(block_title),
                align='R' if text_is_rtl_dominant(block_title) else 'L',
            )
            pdf.ln(1.5)
        line_h = 4.2
        for group_index, group in enumerate(groups):
            steps = group.get("steps") or []
            if not steps:
                continue
            title = group.get("title") or ""
            if title and (same_heading(title, last_heading_text) or same_heading(title, block_title)):
                title = ""
            if title:
                pdf.set_font('NotesAI', 'B', size=8.8)
                pdf.set_text_color(*style_config['heading2_color'])
                pdf.multi_cell(
                    w=0, h=4.8, text=shape_text_for_pdf(title),
                    align='R' if text_is_rtl_dominant(title) else 'L',
                )
                pdf.ln(1.2)
            per_row = min(4, len(steps))
            gap = 6.0
            box_w = (pdf.epw - gap * (per_row - 1)) / per_row
            heights = []
            for step in steps:
                label = step.get('label') or ''
                text = step.get('text') or ''
                combined = (label + "\n" if label else "") + text
                pdf.set_font('NotesAI', size=8.4)
                try:
                    height = float(pdf.multi_cell(box_w - 4, line_h, shape_text_for_pdf(combined), dry_run=True, output="HEIGHT"))
                except Exception:
                    height = line_h * 2
                heights.append(max(10.0, height + 3.0))
            row_h = max(heights) if heights else 10.0
            rows = (len(steps) + per_row - 1) // per_row
            for row_index in range(rows):
                row_steps = steps[row_index * per_row:(row_index + 1) * per_row]
                ensure_space(row_h + 4)
                y = pdf.get_y()
                x = margin
                for step_index, step in enumerate(row_steps):
                    pdf.set_fill_color(248, 250, 252)
                    pdf.set_draw_color(*style_config['line_color'])
                    pdf.set_line_width(0.35)
                    pdf.rect(x, y, box_w, row_h, style='DF')
                    pdf.set_xy(x + 2, y + 2)
                    label = step.get('label') or ''
                    if label:
                        pdf.set_font('NotesAI', 'B', size=8.0)
                        pdf.set_text_color(*style_config['heading2_color'])
                        pdf.multi_cell(
                            w=box_w - 4, h=4.0, text=shape_text_for_pdf(label),
                            align='R' if text_is_rtl_dominant(label) else 'C',
                        )
                        pdf.set_x(x + 2)
                    pdf.set_font('NotesAI', size=8.4)
                    pdf.set_text_color(*style_config['text_color'])
                    pdf.multi_cell(
                        w=box_w - 4, h=line_h,
                        text=shape_text_for_pdf(step.get('text') or ''),
                        align='R' if text_is_rtl_dominant(step.get('text') or '') else 'C',
                    )
                    if step_index < len(row_steps) - 1:
                        ax1 = x + box_w + 0.9
                        ax2 = x + box_w + gap - 0.9
                        ay = y + row_h / 2
                        pdf.set_draw_color(*style_config['line_color'])
                        pdf.set_line_width(0.7)
                        pdf.line(ax1, ay, ax2, ay)
                        pdf.line(ax2, ay, ax2 - 1.8, ay - 1.2)
                        pdf.line(ax2, ay, ax2 - 1.8, ay + 1.2)
                    x += box_w + gap
                pdf.set_y(y + row_h + 3)
                if row_index < rows - 1:
                    cx = pdf.w / 2
                    pdf.set_draw_color(*style_config['line_color'])
                    pdf.set_line_width(0.7)
                    pdf.line(cx, pdf.get_y(), cx, pdf.get_y() + 3)
                    pdf.line(cx, pdf.get_y() + 3, cx - 1.2, pdf.get_y() + 1.4)
                    pdf.line(cx, pdf.get_y() + 3, cx + 1.2, pdf.get_y() + 1.4)
                    pdf.ln(5)
            if group_index < len(groups) - 1:
                pdf.ln(4)
        pdf.ln(3)

    def render_block(block):
        block_type = block.get('type')
        if block_type == 'heading':
            render_heading(block)
        elif block_type == 'paragraph':
            render_paragraph(block)
        elif block_type == 'list':
            render_list(block)
        elif block_type == 'table':
            draw_table(block)
        elif block_type == 'callout':
            render_callout(block)
        elif block_type == 'question':
            render_question(block)
        elif block_type == 'formula':
            render_formula(block)
        elif block_type == 'flow':
            render_flow(block)
        elif block_type == 'diagram':
            if include_diagrams:
                render_diagram(block.get('diagram_id'))
        elif block_type == 'uncertain':
            render_uncertain(block)
        elif block_type == 'page_break':
            pdf.add_page()

    pdf.add_page()
    if title:
        title_text = shape_text_for_pdf(title)
        title_align = 'R' if text_is_rtl_dominant(title) else 'C'
        title_size = style_config['title_size']
        if len(title_text) > 70:
            title_size = max(font_size + 5, title_size - 4)
        if len(title_text) > 120:
            title_size = max(font_size + 3, title_size - 3)
        pdf.set_font('NotesAI', 'B', size=title_size)
        pdf.set_text_color(*style_config['title_color'])
        pdf.multi_cell(w=0, h=style_config['title_line'], text=title_text, align=title_align)
        pdf.ln(4)
        pdf.set_draw_color(*style_config['line_color'])
        pdf.set_line_width(0.8)
        rule_width = 34
        rule_x = (pdf.w - rule_width) / 2
        if title_align == 'R':
            rule_x = pdf.w - margin - rule_width
        elif title_align == 'L':
            rule_x = margin
        pdf.line(rule_x, pdf.get_y(), rule_x + rule_width, pdf.get_y())
        pdf.ln(7)
    if subtitle:
        pdf.set_font('NotesAI', size=style_config['subtitle_size'])
        pdf.set_text_color(*style_config['muted_color'])
        pdf.multi_cell(w=0, h=6.5, text=shape_text_for_pdf(subtitle), align='C')
        pdf.ln(6)

    if options.get('coverPage'):
        pdf.add_page()

    if toc_enabled:
        def render_toc(toc_pdf, outline):
            toc_title = "فہرست" if text_is_rtl_dominant(title) else "Contents"
            toc_pdf.set_font('NotesAI', 'B', size=font_size + 4)
            toc_pdf.set_text_color(*style_config['title_color'])
            toc_pdf.set_x(margin)
            toc_pdf.cell(toc_pdf.epw, 9, shape_text_for_pdf(toc_title), align='R' if text_is_rtl_dominant(toc_title) else 'L', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            toc_pdf.ln(4)
            for section in outline:
                indent = min(18, max(0, int(section.level)) * 4)
                toc_pdf.set_x(margin + indent)
                toc_pdf.set_font('NotesAI', size=max(9, font_size - 1))
                toc_pdf.set_text_color(*style_config['text_color'])
                label = shape_text_for_pdf(section.name)
                available = toc_pdf.epw - indent - 14
                toc_pdf.cell(available, 6, label, align='R' if text_is_rtl_dominant(section.name) else 'L')
                toc_pdf.cell(14, 6, str(section.page_number), align='R', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                toc_pdf.set_draw_color(*style_config['line_color'])
                toc_pdf.set_line_width(0.15)
                toc_pdf.line(margin + indent, toc_pdf.get_y() - 0.5, toc_pdf.w - margin, toc_pdf.get_y() - 0.5)
        if not options.get('coverPage'):
            pdf.add_page()
        pdf.insert_toc_placeholder(render_toc, pages=1, reset_page_indices=False)

    for page_index, page in enumerate(analysis.get('pages') or []):
        # Content flows continuously across extracted source pages. We no
        # longer force a page break for every source page, which previously
        # left large unused areas on short pages. Page breaks happen only when
        # content genuinely needs more room (ensure_space) or via an explicit
        # page_break block.
        page_blocks = page.get('blocks') or []
        for block_index, block in enumerate(page_blocks):
            # Keep a flow heading together with its arrow cards. Without this
            # the heading can stay at the bottom of one page while the cards
            # start on the next page.
            if (
                block.get('type') == 'heading'
                and block_index + 1 < len(page_blocks)
                and page_blocks[block_index + 1].get('type') == 'flow'
            ):
                flow_count = 0
                for following in page_blocks[block_index + 1:]:
                    if following.get('type') != 'flow':
                        break
                    steps = [step for step in (following.get('steps') or []) if isinstance(step, dict)]
                    grouped = any(re.search(r"(?:->|→|=>|➜|➡)", step.get('text') or '') for step in steps)
                    flow_count += len(steps) if grouped else 1
                ensure_space(12 + max(1, flow_count) * 24)
            elif (
                block.get('type') == 'heading'
                and block_index + 1 < len(page_blocks)
                and page_blocks[block_index + 1].get('type') in {'list', 'table', 'callout', 'formula', 'question'}
            ):
                next_type = page_blocks[block_index + 1].get('type')
                ensure_space(52 if next_type == 'list' else 34)
            render_block(block)

    output = pdf.output()
    if isinstance(output, str):
        output = output.encode("latin-1")
    return bytes(output), warnings


def parse_gemini_structured_response(text):
    """
    Parse Gemini's structured response into our document format.
    Expected format from enhanced prompt:
    {
        "title": "Document Title",
        "sections": [
            {"heading": "Introduction", "level": 1, "content": "..."},
            {"heading": "Benefits", "level": 2, "content": "..."}
        ]
    }
    """
    import json

    # Models sometimes wrap JSON in markdown code fences.
    cleaned = (text or "").strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[A-Za-z0-9_-]*\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned).strip()

    # Try to parse as JSON first
    try:
        data = json.loads(cleaned)
        if isinstance(data, dict) and (
            ('title' in data and 'sections' in data)
            or data.get('blocks')
            or data.get('pages')
        ):
            return data
    except (json.JSONDecodeError, TypeError):
        pass

    # Fallback: parse markdown-like structure without losing paragraphs.
    lines = cleaned.split('\n')
    structured = {'title': '', 'sections': []}
    current_section = None
    current_content = []

    def flush_section():
        nonlocal current_section, current_content
        if current_section is not None:
            body = '\n'.join(current_content).strip()
            body = re.sub(r'\n{3,}', '\n\n', body)
            current_section['content'] = body
            structured['sections'].append(current_section)
        elif any(line.strip() for line in current_content):
            # Text after the title but before the first heading is still the
            # user's document body; keep it instead of silently dropping it.
            body = '\n'.join(current_content).strip()
            body = re.sub(r'\n{3,}', '\n\n', body)
            structured['sections'].append({'heading': '', 'level': 1, 'content': body})
        current_section = None
        current_content = []

    for line in lines:
        line = line.rstrip()
        stripped = line.strip()
        if stripped.startswith('# '):
            flush_section()
            if not structured['title']:
                structured['title'] = stripped[2:].strip()
            else:
                current_section = {'heading': stripped[2:].strip(), 'level': 1, 'content': ''}
        elif stripped.startswith('## '):
            flush_section()
            current_section = {'heading': stripped[3:].strip(), 'level': 1, 'content': ''}
        elif stripped.startswith('### '):
            flush_section()
            current_section = {'heading': stripped[4:].strip(), 'level': 2, 'content': ''}
        elif stripped.startswith('#### '):
            flush_section()
            current_section = {'heading': stripped[5:].strip(), 'level': 3, 'content': ''}
        else:
            current_content.append(line)

    flush_section()

    # If no title found, promote the first non-empty heading to the title.
    # Keep that section's body as an untitled section so no content is lost.
    if not structured['title'] and structured['sections'] and structured['sections'][0]['heading']:
        first = structured['sections'].pop(0)
        structured['title'] = first['heading']
        if (first.get('content') or '').strip():
            structured['sections'].insert(0, {
                'heading': '', 'level': first.get('level', 1),
                'content': first.get('content', ''),
            })

    if not structured['title']:
        structured['title'] = 'Converted Document'

    return structured


def _gemini_http_error(code, message):
    message = sanitize_provider_message(message)
    if code == 401:
        return 401, "Invalid Gemini API key. Check GEMINI_API_KEY in the server .env."
    if code == 403:
        return 403, "Gemini permission denied for this key/model. " + message
    if code == 404:
        return 400, "Gemini model is not available for this key. Set GEMINI_MODEL to a supported vision model. " + message
    if code == 429:
        return 429, "Gemini rate limit or free-tier quota reached. Please retry later."
    if code == 503:
        return 503, "Gemini is currently busy (high demand). Please retry shortly."
    if code == 504:
        return 504, "Gemini request timed out. Please retry."
    return 502, "Gemini extraction failed. " + message


def _reset_streams(files):
    for uploaded in files:
        try:
            uploaded.stream.seek(0)
        except Exception:
            pass


def extract_text_with_provider(files, provider, prompt=EXTRACTION_PROMPT, max_tokens=4096):
    """Extract raw text using exactly one selected provider.

    Returns (text, model_used, http_status, error_message). No cross-provider
    fallback is performed. OpenRouter retries at most one other verified free
    vision model on model failure.
    """
    if provider == "gemini":
        gemini = get_gemini_config()
        api_key = gemini["api_key"]
        configured = gemini["model"]
        model = configured
        try:
            _reset_streams(files)
            text = extract_with_gemini(files, api_key, model, prompt=prompt, max_output_tokens=max_tokens)
            if text:
                return text, model, None, None
            return "", model, 502, "Gemini returned no text. Try a clearer image."
        except Exception as exc:
            code, _status, message = gemini_error_details(exc)
            if code == 404:
                selected, _sel_code, sel_message = select_working_gemini_model(api_key, configured=configured)
                if selected and selected != configured:
                    try:
                        _write_env_file({"GEMINI_MODEL": selected})
                        _reset_streams(files)
                        text = extract_with_gemini(files, api_key, selected, prompt=prompt, max_output_tokens=max_tokens)
                        if text:
                            return text, selected, None, None
                        return "", selected, 502, "Gemini returned no text. Try a clearer image."
                    except Exception as retry_exc:
                        r_code, _r_status, r_message = gemini_error_details(retry_exc)
                        status, error = _gemini_http_error(
                            r_code, sanitize_provider_message(r_message, api_key)
                        )
                        return "", selected, status, error
                status, error = _gemini_http_error(
                    code, sanitize_provider_message(sel_message or message, api_key)
                )
                return "", model, status, error
            status, error = _gemini_http_error(
                code, sanitize_provider_message(message, api_key)
            )
            return "", model, status, error

    if provider == "openrouter":
        openrouter = get_openrouter_config()
        api_key = openrouter["api_key"]
        urls, _pdf_parts, err = get_files_for_vision(files)
        if err:
            return "", "", 400, err
        if not urls:
            return "", "", 400, "No valid images to extract."
        selected, models = select_openrouter_free_model()
        if not selected:
            return "", "", 503, "No free vision-capable OpenRouter models are available right now. Try again later or switch to Gemini."
        candidates = [selected] + [m.get("id") for m in models if m.get("id") != selected][:1]
        last_status, last_error, last_model = 502, "OpenRouter extraction failed.", selected
        for model in candidates:
            last_model = model
            try:
                text = extract_with_openrouter(
                    urls, api_key, model, openrouter["base_url"],
                    prompt=prompt, max_tokens=max_tokens,
                )
                if text:
                    return text, model, None, None
                last_status, last_error = 502, "OpenRouter returned no text. Try a clearer image."
            except ValueError as exc:
                code = str(exc)
                if code == "INVALID_API_KEY":
                    return "", model, 401, "Invalid OpenRouter API key. Check OPENROUTER_API_KEY in the server .env."
                if code == "INSUFFICIENT_CREDITS":
                    last_status, last_error = 402, "This OpenRouter model is not free. Paid models are blocked."
                    continue
                if code == "MODEL_NOT_FOUND":
                    last_status, last_error = 404, "OpenRouter free model is unavailable. Refreshing the free model list may help."
                    continue
                if code == "RATE_LIMITED":
                    last_status, last_error = 429, "OpenRouter free-tier rate limit reached. Please retry later."
                    continue
                if code == "FORBIDDEN":
                    last_status, last_error = 403, "OpenRouter denied access to this free model."
                    continue
                last_status, last_error = 502, "OpenRouter request failed."
            except RuntimeError as exc:
                last_status = 502
                if str(exc) == "TOKEN_LIMIT":
                    last_error = "The free model used its full token budget before answering. Retrying another verified free model."
                else:
                    last_error = sanitize_provider_message(str(exc), api_key)
            except Exception as exc:
                last_status = 502
                last_error = sanitize_provider_message(str(exc), api_key)
        return "", last_model, last_status, last_error

    return "", "", 503, "No AI provider is configured."


def extract_structured_for_pdf(files):
    """Return (structured, (http_status, error_message)) for professional PDF."""
    provider = resolve_extraction_provider()
    if not provider:
        return None, (503, "No AI provider configured. Add GEMINI_API_KEY or OPENROUTER_API_KEY in the server .env.")
    text, model, status, error = extract_text_with_provider(files, provider)
    g.notesai_provider = provider
    g.notesai_model = model or ""
    app.logger.info(
        "Professional PDF AI extraction provider=%s model=%s files=%d status=%s",
        provider, model or "", len(files), "failed" if status else "ok",
    )
    if status:
        return None, (status, error)
    return parse_gemini_structured_response(text), None


def auto_extract_and_structure(files, api_key=None, model=None):
    """Compatibility wrapper: return structured data or None."""
    structured, _error = extract_structured_for_pdf(files)
    return structured


def _image_png_bytes(image):
    buffer = io.BytesIO()
    image.convert("RGB").save(buffer, format="PNG", optimize=True)
    return buffer.getvalue()


def pil_image_to_data_url(image, max_edge=2048, quality=85, max_bytes=18 * 1024 * 1024):
    """Prepare an in-memory page image for an OpenAI-compatible vision call."""
    source = image.convert("RGB")
    width, height = source.size
    if max(width, height) > max_edge:
        scale = max_edge / float(max(width, height))
        source = source.resize((max(1, int(width * scale)), max(1, int(height * scale))), Image.LANCZOS)
    buffer = io.BytesIO()
    source.save(buffer, format="JPEG", quality=quality, optimize=True)
    data = buffer.getvalue()
    quality_now = quality
    while len(data) > max_bytes and quality_now > 40:
        quality_now -= 10
        buffer = io.BytesIO()
        source.save(buffer, format="JPEG", quality=quality_now, optimize=True)
        data = buffer.getvalue()
    return "data:image/jpeg;base64," + base64.b64encode(data).decode("ascii")


def _natural_page_sort(path):
    match = re.search(r"(\d+)$", path.stem)
    return int(match.group(1)) if match else 0


def prepare_source_pages(files):
    """Return ordered PIL page images for images and PDFs.

    PDFs are rendered locally with poppler's pdftoppm. This keeps OpenRouter's
    image-only constraint and Gemini's page-level diagram analysis consistent.
    """
    if len(files) > SMART_MAX_PAGES:
        raise ValueError(f"Smart mode supports up to {SMART_MAX_PAGES} pages per request. Split the document or use Professional Text PDF for larger files.")
    pages = []
    for uploaded in files:
        filename = uploaded.filename or "page"
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        try:
            uploaded.stream.seek(0)
            if ext == "pdf":
                data = uploaded.read()
                if not data:
                    continue
                with tempfile.TemporaryDirectory() as temp_dir:
                    source_path = Path(temp_dir) / "source.pdf"
                    source_path.write_bytes(data)
                    prefix = Path(temp_dir) / "page"
                    try:
                        info = subprocess.run(
                            ["pdfinfo", str(source_path)],
                            check=False, timeout=20,
                            capture_output=True, text=True,
                        )
                        page_match = re.search(r"^Pages:\s+(\d+)", info.stdout or "", re.MULTILINE)
                        if page_match and int(page_match.group(1)) > SMART_MAX_PAGES:
                            raise ValueError(
                                f"Smart mode supports up to {SMART_MAX_PAGES} pages per request. "
                                "Split the PDF or use Professional Text PDF for larger documents."
                            )
                    except FileNotFoundError:
                        pass
                    try:
                        subprocess.run(
                            ["pdftoppm", "-r", "200", "-png", "-f", "1", "-l", str(SMART_MAX_PAGES),
                             str(source_path), str(prefix)],
                            check=True, timeout=120,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        )
                    except FileNotFoundError:
                        raise ValueError("PDF page rendering is unavailable on this server. Upload page images instead.")
                    except subprocess.TimeoutExpired:
                        raise ValueError("PDF page rendering timed out.")
                    for page_path in sorted(Path(temp_dir).glob("page-*.png"), key=_natural_page_sort):
                        with Image.open(page_path) as page_image:
                            page_image.load()
                            pages.append(page_image.convert("RGB").copy())
            elif ext in {"jpg", "jpeg", "png", "webp", "bmp"}:
                with Image.open(uploaded.stream) as page_image:
                    page_image.load()
                    pages.append(page_image.convert("RGB").copy())
            else:
                raise ValueError(f"Unsupported file type: {filename}")
        except ValueError:
            raise
        except Exception:
            raise ValueError(f"Could not read page: {filename}")
        if len(pages) >= SMART_MAX_PAGES:
            break
    if not pages:
        raise ValueError("No readable page images were found.")
    return pages[:SMART_MAX_PAGES]


def _parse_json_object(text):
    """Parse a model JSON object, tolerating markdown fences and wrappers."""
    cleaned = (text or "").strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[A-Za-z0-9_-]*\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned).strip()
    try:
        data = json.loads(cleaned)
        if isinstance(data, dict):
            return data
    except (json.JSONDecodeError, TypeError):
        pass
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start >= 0 and end > start:
        try:
            data = json.loads(cleaned[start:end + 1])
            if isinstance(data, dict):
                return data
        except (json.JSONDecodeError, TypeError):
            pass
    return None


def _diagram_capability_key(provider, model):
    return f"{provider}:{model or ''}"


def _record_diagram_capability(provider, model, ok, message=""):
    with _DIAGRAM_CAPABILITY_LOCK:
        _DIAGRAM_CAPABILITY_CACHE[_diagram_capability_key(provider, model)] = {
            "ok": bool(ok),
            "message": sanitize_provider_message(message),
            "ts": time.time(),
        }


def _diagram_capability_error(provider, model):
    with _DIAGRAM_CAPABILITY_LOCK:
        entry = _DIAGRAM_CAPABILITY_CACHE.get(_diagram_capability_key(provider, model))
    if entry and not entry.get("ok") and time.time() - entry.get("ts", 0) < 180:
        return entry.get("message") or "The selected model did not return a usable diagram specification."
    return ""


def _smart_provider_page(page_bytes, provider, page_index):
    """One vision request for one page. Returns (text, model, status, error)."""
    prompt = SMART_ANALYSIS_PROMPT.replace("{{PAGE}}", str(page_index))
    return _provider_vision_request(page_bytes, provider, prompt)


def _provider_vision_request(page_bytes, provider, prompt, max_output_tokens=8192):
    """One vision request with an arbitrary prompt. Returns (text, model, status, error)."""
    if provider == "gemini":
        gemini = get_gemini_config()
        api_key = gemini["api_key"]
        model = gemini["model"]
        try:
            text = extract_with_gemini_images(
                [(page_bytes, "image/png")], api_key, model,
                prompt=prompt, max_output_tokens=max_output_tokens,
            )
            if text:
                return text, model, None, None
            return "", model, 502, "Gemini returned no page analysis."
        except Exception as exc:
            code, _status, message = gemini_error_details(exc)
            if code == 404:
                selected, _sel_code, sel_message = select_working_gemini_model(api_key, configured=model)
                if selected and selected != model:
                    try:
                        _write_env_file({"GEMINI_MODEL": selected})
                        text = extract_with_gemini_images(
                            [(page_bytes, "image/png")], api_key, selected,
                            prompt=prompt, max_output_tokens=max_output_tokens,
                        )
                        if text:
                            return text, selected, None, None
                        return "", selected, 502, "Gemini returned no page analysis."
                    except Exception as retry_exc:
                        r_code, _r_status, r_message = gemini_error_details(retry_exc)
                        status, error = _gemini_http_error(r_code, sanitize_provider_message(r_message, api_key))
                        return "", selected, status, error
                status, error = _gemini_http_error(code, sanitize_provider_message(sel_message or message, api_key))
                return "", model, status, error
            status, error = _gemini_http_error(code, sanitize_provider_message(message, api_key))
            return "", model, status, error

    if provider == "openrouter":
        openrouter = get_openrouter_config()
        api_key = openrouter["api_key"]
        selected, models = select_openrouter_free_model()
        if not selected:
            return "", "", 503, "No free vision-capable OpenRouter models are available right now. Try again later or switch to Gemini."
        # Same-provider, free-only resilience: the first ranked model can be
        # rate-limited or time out. Try at most one other verified free vision
        # model. Never leave OpenRouter and never try a paid model.
        candidates = []
        for candidate in [{"id": selected}] + list(models or []):
            model_id = candidate.get("id") if isinstance(candidate, dict) else str(candidate)
            if model_id and model_id not in candidates:
                candidates.append(model_id)
        candidates = candidates[:2]
        last_status, last_error, last_model = 502, "OpenRouter page analysis failed.", selected
        try:
            with Image.open(io.BytesIO(page_bytes)) as image:
                image.load()
                data_url = pil_image_to_data_url(image.convert("RGB"))
        except Exception as exc:
            return "", selected, 400, sanitize_provider_message(str(exc), api_key)
        for model in candidates:
            last_model = model
            try:
                text = extract_with_openrouter(
                    [data_url], api_key, model, openrouter["base_url"],
                    prompt=prompt, max_tokens=max_output_tokens, timeout=(15, 120),
                )
                if text:
                    if _parse_json_object(text):
                        return text, model, None, None
                    last_status, last_error = 422, "The selected OpenRouter free model returned invalid page JSON. Trying another free vision model."
                    continue
                last_status, last_error = 502, "OpenRouter returned no page analysis."
            except ValueError as exc:
                code = str(exc)
                if code == "INVALID_API_KEY":
                    return "", model, 401, "Invalid OpenRouter API key. Check OPENROUTER_API_KEY in the server .env."
                if code == "INSUFFICIENT_CREDITS":
                    last_status, last_error = 402, "This OpenRouter model is not free. Paid models are blocked."
                elif code == "MODEL_NOT_FOUND":
                    last_status, last_error = 404, "OpenRouter free model is unavailable. Refresh the free model list or switch to Gemini."
                elif code == "RATE_LIMITED":
                    last_status, last_error = 429, "OpenRouter free-tier rate limit reached. Please retry later."
                elif code == "FORBIDDEN":
                    last_status, last_error = 403, "OpenRouter denied access to this free model."
                else:
                    last_status, last_error = 502, "OpenRouter page analysis failed."
            except RuntimeError as exc:
                last_status = 502
                if str(exc) == "TOKEN_LIMIT":
                    last_error = "The free model used its full token budget before answering. Retrying another verified free model."
                else:
                    last_error = sanitize_provider_message(str(exc), api_key)
            except Exception as exc:
                last_status = 502
                last_error = sanitize_provider_message(str(exc), api_key)
        return "", last_model, last_status, last_error

    return "", "", 503, "No AI provider is configured."


def _diagram_source_preview(page_image, diagram, max_side=900):
    """Return a compact data URL of the source diagram crop for review."""
    if page_image is None:
        return ""
    bbox = diagram.get("source_bbox") or [0, 0, 1000, 1000]
    try:
        x, y, w, h = [float(value) for value in bbox]
    except (TypeError, ValueError):
        x, y, w, h = 0, 0, 1000, 1000
    if w <= 1 or h <= 1:
        x, y, w, h = 0, 0, 1000, 1000
    left = max(0, min(page_image.width - 1, int(x / 1000 * page_image.width)))
    top = max(0, min(page_image.height - 1, int(y / 1000 * page_image.height)))
    right = max(left + 1, min(page_image.width, int((x + w) / 1000 * page_image.width)))
    bottom = max(top + 1, min(page_image.height, int((y + h) / 1000 * page_image.height)))
    try:
        crop = page_image.crop((left, top, right, bottom)).convert("RGB")
        crop.thumbnail((max_side, max_side), Image.LANCZOS)
        buffer = io.BytesIO()
        crop.save(buffer, format="JPEG", quality=84, optimize=True)
        return "data:image/jpeg;base64," + base64.b64encode(buffer.getvalue()).decode("ascii")
    except Exception:
        app.logger.warning("Could not build source diagram preview")
        return ""


MAX_DIAGRAM_REPAIRS_PER_PAGE = 3
MAX_DIAGRAM_REPAIRS_TOTAL = 6


def _diagram_label_key(value):
    text = clean_text(value, 500).casefold()
    text = re.sub(r"[^0-9a-z\u0600-\u06ff]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _diagram_crop_for_repair(page_image, diagram, max_side=1400):
    if page_image is None:
        return None
    bbox = diagram.get("source_bbox") or [0, 0, 1000, 1000]
    try:
        x, y, w, h = [float(value) for value in bbox]
    except (TypeError, ValueError):
        x, y, w, h = 0, 0, 1000, 1000
    if w <= 1 or h <= 1:
        x, y, w, h = 0, 0, 1000, 1000
    left = max(0, min(page_image.width - 1, int(x / 1000 * page_image.width)))
    top = max(0, min(page_image.height - 1, int(y / 1000 * page_image.height)))
    right = max(left + 1, min(page_image.width, int((x + w) / 1000 * page_image.width)))
    bottom = max(top + 1, min(page_image.height, int((y + h) / 1000 * page_image.height)))
    crop = page_image.crop((left, top, right, bottom)).convert("RGB")
    if max(crop.size) > max_side:
        crop.thumbnail((max_side, max_side), Image.LANCZOS)
    return crop


def _scene_shape_has_geometry(element):
    shape = str(element.get("shape") or "").lower()
    points = element.get("points") or []
    if shape in {"polygon", "polyline"}:
        return len(points) >= 4
    if shape == "path":
        return bool(element.get("d"))
    bbox = element.get("bbox") or [0, 0, 0, 0]
    try:
        return len(bbox) == 4 and (float(bbox[2]) > 0 or float(bbox[3]) > 0)
    except (TypeError, ValueError):
        return False


def _validate_repaired_scene(raw_scene, diagram):
    """Normalise and safety-check a model-returned scene.

    Returns (scene, matched_label_keys, missing_label_texts). The scene is
    rejected when it has no real geometry or too few matching labels. Text that
    is not one of the detected labels/title is removed so the model cannot
    invent labels.
    """
    if not isinstance(raw_scene, dict):
        return None, [], []
    labels = [clean_text(item.get("text"), 500) for item in diagram.get("labels") or [] if isinstance(item, dict)]
    labels = [text for text in labels if text]
    allowed = {_diagram_label_key(text): text for text in labels}
    title_key = _diagram_label_key(diagram.get("title"))
    temp = {
        "id": "repair",
        "type": diagram.get("type") or "labelled_figure",
        "category": diagram.get("category") or "other",
        "title": diagram.get("title") or "",
        "labels": diagram.get("labels") or [],
        "scene": raw_scene,
        "template_data": {},
    }
    normalized = normalise_diagram(temp)
    if not normalized:
        return None, [], labels
    scene = normalized.get("scene") or {}
    elements = scene.get("elements") or []
    cleaned = []
    matched = set()
    shape_count = 0
    text_count = 0
    for element in elements:
        kind = str(element.get("kind") or "").lower()
        if kind == "text":
            key = _diagram_label_key(element.get("text"))
            if key not in allowed and key != title_key:
                continue
            bbox = element.get("bbox") or [0, 0, 0, 0]
            has_position = bool(bbox and (float(bbox[2] or 0) > 0 or float(bbox[3] or 0) > 0))
            if not has_position:
                try:
                    has_position = element.get("x") is not None and element.get("y") is not None
                except Exception:
                    has_position = False
            if not has_position:
                continue
            if key in allowed:
                matched.add(key)
                text_count += 1
            cleaned.append(element)
        elif kind == "shape":
            if not _scene_shape_has_geometry(element):
                continue
            label_key = _diagram_label_key(element.get("label"))
            if label_key and label_key not in allowed:
                element["label"] = ""
            shape_count += 1
            cleaned.append(element)
        elif kind == "connector":
            label_key = _diagram_label_key(element.get("label"))
            if label_key and label_key not in allowed:
                element["label"] = ""
            cleaned.append(element)
    ids = {element.get("id") for element in cleaned if element.get("id")}
    cleaned = [
        element for element in cleaned
        if element.get("kind") != "connector"
        or len(element.get("points") or []) >= 4
        or (element.get("from") in ids and element.get("to") in ids)
    ]
    minimum_text = max(2, min(3, len(labels)))
    if shape_count < 1 or text_count < minimum_text:
        return None, [], labels
    scene["elements"] = cleaned
    missing = [text for text in labels if _diagram_label_key(text) not in matched]
    return scene, sorted(matched), missing


def _scene_quality(scene):
    elements = (scene or {}).get("elements") or []
    shapes = sum(1 for item in elements if item.get("kind") == "shape")
    texts = sum(1 for item in elements if item.get("kind") == "text")
    connectors = sum(1 for item in elements if item.get("kind") == "connector")
    return shapes, texts, connectors


def _repair_diagram_scene(page_image, diagram, provider):
    """Ask the active provider for diagram geometry using the source crop.

    This is a focused second pass, not a full-page re-analysis. It runs only
    when the first pass returned labels but no scene/template geometry. If the
    first response is only a single outline, a second line-art attempt asks for
    an outer silhouette plus internal boundary paths for the visible parts.
    """
    crop = _diagram_crop_for_repair(page_image, diagram)
    if crop is None:
        return None, "", "Could not crop the source diagram."
    canvas_w = 1000
    canvas_h = max(300, min(2000, int(round(1000 * crop.height / max(1, crop.width)))))
    labels = [
        {"text": item.get("text"), "source_text": item.get("source_text") or item.get("text")}
        for item in diagram.get("labels") or []
        if isinstance(item, dict) and item.get("text")
    ]
    spec = {
        "id": diagram.get("id") or "d1",
        "type": diagram.get("type") or "labelled_figure",
        "category": diagram.get("category") or "other",
        "title": diagram.get("title") or "",
        "canvas": [canvas_w, canvas_h],
        "labels": labels,
    }
    prompt = DIAGRAM_SCENE_REPAIR_PROMPT.replace(
        "{{DIAGRAMS}}", json.dumps([spec], ensure_ascii=False, indent=2)
    )
    min_shapes = max(1, min(6, len(labels) // 2 + 1))
    lineart_prompt = prompt + (
        "\n\nIMPORTANT: Return a traced line drawing, not a block diagram. "
        "Use ONE outer silhouette path plus internal boundary paths for the visible parts and sutures. "
        "Use SVG path elements with d (curves and lines). Do NOT use rectangles and do NOT use a separate "
        "box for every label. Do NOT simplify the figure into a grid of rectangles. Every label must have "
        "a text element and a connector with points [x1,y1,x2,y2] that ends on the actual named part. "
        f"The scene must contain at least {min_shapes} shape elements. "
        "If the image is too unclear, return an empty scene and a reason instead of inventing shapes."
    )
    scaffold_elements = []
    for index, item in enumerate(labels, 1):
        label_text = item.get("text") or ""
        scaffold_elements.extend([
            {"id": f"s{index}", "kind": "shape", "shape": "path", "d": "M 0 0",
             "bbox": [0, 0, 0, 0], "label": label_text},
            {"id": f"t{index}", "kind": "text", "text": label_text, "bbox": [0, 0, 0, 0]},
            {"id": f"c{index}", "kind": "connector", "from": f"t{index}", "to": f"s{index}",
             "points": [0, 0, 0, 0], "arrow": False},
        ])
    scaffold = {"canvas": [canvas_w, canvas_h], "elements": scaffold_elements}
    scaffold_prompt = prompt + (
        "\n\nUse this exact scaffold. Fill every bbox, path and connector point. Return exactly one shape, "
        "one text element and one connector per detected label. Do not omit elements. A single outline is "
        "invalid. Use path shapes that follow the visible part (M/L/C/Q/Z). Do not use rectangles or generic "
        "boxes. Each path should be a simple 4-12 point outline of the named part. Every connector must end "
        "on its part. If the image is too unclear, return an empty scene and a reason.\nSCAFFOLD:\n"
        + json.dumps(scaffold, ensure_ascii=False, indent=2)
    )
    page_bytes = _image_png_bytes(crop)
    last_model = ""
    last_error = "The model did not return a usable diagram scene."
    best = None
    best_shapes = 0
    required_shapes = min_shapes
    for attempt in range(3):
        attempt_prompt = (prompt, lineart_prompt, scaffold_prompt)[attempt]
        text, model, status, error = _provider_vision_request(
            page_bytes, provider, attempt_prompt, max_output_tokens=8192 if attempt == 2 else 6144
        )
        last_model = model or last_model
        if status:
            last_error = error or last_error
            if status in {401, 402, 403, 429}:
                break
            continue
        data = _parse_json_object(text)
        if not data:
            last_error = "The model returned invalid diagram geometry JSON."
            continue
        entries = data.get("diagrams")
        if not isinstance(entries, list):
            entries = [data]
        entry = next(
            (item for item in entries if isinstance(item, dict) and str(item.get("id") or "") == str(spec["id"])),
            entries[0] if entries and isinstance(entries[0], dict) else None,
        )
        if not entry:
            last_error = "The model did not return geometry for this diagram."
            continue
        scene, matched, missing = _validate_repaired_scene(entry.get("scene"), diagram)
        if scene:
            shapes, texts, connectors = _scene_quality(scene)
            candidate = {
                "scene": scene,
                "matched": matched,
                "missing": missing,
                "model": model or last_model,
            }
            if best is None or shapes > best_shapes:
                best = candidate
                best_shapes = shapes
            if shapes >= required_shapes and (attempt == 0 or len(matched) >= len(labels)):
                return candidate, model or last_model, ""
            if attempt == 2 and shapes >= required_shapes and len(matched) >= len(labels):
                return candidate, model or last_model, ""
        last_error = "The model returned labels but no usable vector shapes."
    if best is not None and best_shapes >= required_shapes:
        return best, best.get("model") or last_model, ""
    return None, last_model, last_error


def _scene_curved_shape_count(scene):
    count = 0
    for element in (scene or {}).get("elements") or []:
        if element.get("kind") != "shape":
            continue
        shape = str(element.get("shape") or "").lower()
        if shape in {"circle", "ellipse"}:
            count += 1
        elif shape == "path" and re.search(r"[CcQqAaSsTt]", str(element.get("d") or "")):
            count += 1
    return count


def _apply_repaired_scene(diagram, repair):
    diagram["scene"] = repair["scene"]
    diagram["review_required"] = True
    labels = diagram.get("labels") or []
    shape_count, _text_count, _connector_count = _scene_quality(repair["scene"])
    min_shapes = max(1, min(6, len(labels) // 2 + 1))
    category = str(diagram.get("category") or "").lower()
    diagram_type = str(diagram.get("type") or "").lower()
    organic = category in {"biology", "anatomy", "human_body", "heart", "cell", "plant"} or diagram_type in {
        "heart", "cell", "plant", "human_body", "anatomy", "brain", "eye", "ear", "kidney",
        "lungs", "skeleton", "muscle",
    }
    curved_count = _scene_curved_shape_count(repair["scene"])
    curved_required = max(2, min(5, len(labels) // 2 + 1))
    simplified = shape_count < min_shapes or (organic and curved_count < curved_required)
    diagram["use_original"] = bool(simplified)
    old_warnings = [
        warning for warning in diagram.get("warnings") or []
        if "No safe vector specification" not in warning
        and "Only labels were detected" not in warning
        and "original diagram crop will be preserved" not in warning
        and "source diagram is preserved for accuracy" not in warning
        and "visible structure was incomplete" not in warning
        and "The AI recreation is simplified" not in warning
        and "This recreation uses fewer shapes" not in warning
        and "Diagram geometry reconstructed from the source image" not in warning
    ]
    new_warnings = []
    if simplified:
        new_warnings.append(
            "The AI recreation is simplified, so the source crop is preserved by default. "
            "Use recreation only after comparing it with the source crop."
        )
    else:
        new_warnings.append(
            "Diagram geometry reconstructed from the source image. Review labels and leader lines before approving."
        )
    if shape_count < len(labels):
        new_warnings.append(
            "This recreation uses fewer shapes than labels; compare it with the source crop before approving."
        )
    missing = repair.get("missing") or []
    if missing:
        new_warnings.append("Missing labels in the recreated scene: " + ", ".join(missing[:20]))
    diagram["warnings"] = old_warnings + new_warnings
    diagram.setdefault("corrections", []).append({
        "field": "scene",
        "action": "reconstructed",
        "detail": f"{len(repair.get('matched') or [])} label(s) matched from the source crop.",
    })


def _diagram_needs_repair(diagram):
    """True when a detected diagram has labels but no reliable renderable scene."""
    if not isinstance(diagram, dict) or diagram.get("excluded"):
        return False
    labels = diagram.get("labels") or []
    if not labels or diagram.get("template_data"):
        return False
    if str(diagram.get("type") or "").lower() in {"chart", "flowchart", "solar_system"}:
        return False
    elements = (diagram.get("scene") or {}).get("elements") or []
    if not elements:
        return True
    shape_count = sum(
        1 for element in elements
        if element.get("kind") == "shape" and _scene_shape_has_geometry(element)
    )
    required_shapes = max(1, min(6, len(labels) // 2 + 1))
    if shape_count < required_shapes:
        return True
    try:
        render_diagram_svg(diagram, style="color")
    except Exception:
        return True
    return False


def _repair_label_only_diagrams(pages, page_results, provider):
    repaired_total = 0
    for page in page_results:
        try:
            page_index = int(page.get("page_index") or 0)
        except (TypeError, ValueError):
            page_index = 0
        page_image = pages[page_index] if 0 <= page_index < len(pages) else None
        repaired_page = 0
        for diagram in page.get("diagrams") or []:
            if repaired_total >= MAX_DIAGRAM_REPAIRS_TOTAL or repaired_page >= MAX_DIAGRAM_REPAIRS_PER_PAGE:
                break
            if not isinstance(diagram, dict) or diagram.get("excluded"):
                continue
            if not _diagram_needs_repair(diagram):
                continue
            repair, model, error = _repair_diagram_scene(page_image, diagram, provider)
            if repair:
                _apply_repaired_scene(diagram, repair)
                repaired_total += 1
                repaired_page += 1
                app.logger.info(
                    "Diagram scene repaired provider=%s model=%s diagram=%s labels=%d matched=%d missing=%d",
                    provider, model or "", diagram.get("id") or "", len(diagram.get("labels") or []),
                    len(repair.get("matched") or []), len(repair.get("missing") or []),
                )
            else:
                app.logger.warning(
                    "Diagram scene repair failed provider=%s model=%s diagram=%s reason=%s",
                    provider, model or "", diagram.get("id") or "", sanitize_provider_message(error),
                )
    return repaired_total


def analyze_smart_pages(files, provider, diagram_style="color"):
    """Analyze each page and return (analysis, model, status, error, previews)."""
    try:
        pages = prepare_source_pages(files)
    except ValueError as exc:
        return None, "", 400, str(exc), {}
    page_results = []
    model_used = ""
    for index, page_image in enumerate(pages):
        page_bytes = _image_png_bytes(page_image)
        text, model, status, error = _smart_provider_page(page_bytes, provider, index + 1)
        model_used = model or model_used
        if status:
            _record_diagram_capability(provider, model_used, False, error)
            return None, model_used, status, error, {}
        data = _parse_json_object(text)
        if not data:
            _record_diagram_capability(provider, model_used, False, "The selected model did not return valid JSON page analysis.")
            return None, model_used, 422, (
                "The selected model did not return a usable page/diagram specification. "
                "Switch to Gemini or retry with a more capable free vision model."
            ), {}
        page_doc = normalise_analysis(data, index)
        page = page_doc["pages"][0]
        page["page_index"] = index
        page_results.append(page)

    repaired = _repair_label_only_diagrams(pages, page_results, provider)
    if repaired:
        app.logger.info("Diagram scene repair completed provider=%s repaired=%d", provider, repaired)

    title = next((page.get("title") for page in page_results if page.get("title")), "")
    subtitle = next((page.get("subtitle") for page in page_results if page.get("subtitle")), "")
    if not title:
        for page in page_results:
            heading = next((block.get("text") for block in page.get("blocks", []) if block.get("type") == "heading" and block.get("text")), "")
            if heading:
                title = heading
                break
    analysis = normalise_analysis({"title": title, "subtitle": subtitle, "pages": page_results})
    _record_diagram_capability(provider, model_used, True, "")
    app.logger.info(
        "Smart page analysis provider=%s model=%s pages=%d diagrams=%d",
        provider, model_used or "", len(pages), len(iter_diagrams(analysis)),
    )

    previews = {}
    diagram_style = normalise_diagram_style(diagram_style)
    for diagram in iter_diagrams(analysis, normalise=False):
        try:
            page_index = int(diagram.get("page_index") or 0)
        except (TypeError, ValueError):
            page_index = 0
        page_image = pages[page_index] if 0 <= page_index < len(pages) else None
        preview = {}
        source_preview = _diagram_source_preview(page_image, diagram)
        if source_preview:
            preview["original_data_url"] = source_preview
            diagram["source_preview"] = source_preview
        diagram_type = str(diagram.get("type") or "").lower()
        has_scene = bool((diagram.get("scene") or {}).get("elements"))
        has_template = bool(diagram.get("template_data"))
        if (
            diagram_type not in {"chart", "flowchart", "solar_system"}
            and not has_template
            and diagram.get("source_preview")
        ):
            try:
                trace_svg, trace_quality = trace_data_url(
                    diagram["source_preview"], style=diagram_style
                )
                if trace_quality.get("accepted"):
                    diagram["recreation_mode"] = "trace"
                    diagram["quality"] = trace_quality
                    diagram["use_original"] = False
                    diagram["confidence"] = trace_quality.get("structural_match", 0.0)
                    diagram["review_required"] = True
                    # The trace is source-accurate; clear the "source preserved" warnings.
                    diagram["warnings"] = [
                        w for w in (diagram.get("warnings") or [])
                        if "source crop" not in w and "source diagram" not in w
                    ]
            except TraceQualityError:
                app.logger.info(
                    "Diagram trace rejected diagram=%s",
                    diagram.get("id") or "",
                )
        if (diagram.get("scene") or {}).get("elements") or diagram.get("template_data") or diagram.get("recreation_mode") == "trace":
            try:
                preview["svg"] = render_diagram_svg(diagram, style=diagram_style).decode("utf-8")
            except Exception as exc:
                preview["error"] = sanitize_provider_message(str(exc))
        if diagram.get("use_original"):
            preview["source_note"] = (
                "Source diagram preserved for accuracy. An AI recreation is available for review."
            )
        elif diagram.get("recreation_mode") == "trace":
            match = diagram.get("quality", {}).get("structural_match")
            match_text = f"{match:.0%}" if isinstance(match, (int, float)) else ""
            preview["source_note"] = (
                f"Vector-traced from the source; structure and labels preserved{'.' if not match_text else f' — structural match {match_text}.'}"
            )
        elif not preview.get("svg"):
            preview["source_note"] = (
                "Source diagram will be preserved because a reliable vector preview is not available."
            )
        previews[diagram["id"]] = preview
    return analysis, model_used, None, None, previews

HTML = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<!-- PWA Meta Tags -->
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#1e3a8a">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="NotesAI">
<link rel="apple-touch-icon" href="/static/icons/icon-192x192.png">
<meta name="mobile-web-app-capable" content="yes">
<meta name="application-name" content="NotesAI">
<meta name="msapplication-TileColor" content="#1e3a8a">
<meta name="msapplication-TileImage" content="/static/icons/icon-144x144.png">
<title>NotesAI — Premium Workspace</title>
<script>
(function () {
  try {
    var saved = localStorage.getItem('theme') || 'premium';
    document.documentElement.setAttribute('data-theme', saved);
  } catch (error) {}
})();
</script>
<script>
  window.__ADMIN_TOKEN__ = {{ admin_token|tojson }};
  (function() {
    if (!window.__ADMIN_TOKEN__) return;
    const _origFetch = window.fetch.bind(window);
    window.fetch = function(input, init) {
      init = init || {};
      const headers = new Headers(init.headers || {});
      if (!headers.has('X-Admin-Token')) headers.set('X-Admin-Token', window.__ADMIN_TOKEN__);
      init.headers = headers;
      return _origFetch(input, init);
    };
  })();
</script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
/* ============================================================
   DESIGN SYSTEM — ROYAL BLUE / WHITE / SILVER
   ============================================================ */
:root {
  /* Primary Brand */
  --royal-blue: #1e3a8a;
  --royal-blue-600: #1e40af;
  --royal-blue-500: #3b82f6;
  --royal-blue-400: #60a5fa;
  --royal-blue-100: #dbeafe;
  --royal-blue-50: #eff6ff;

  /* Dark Navy for Text */
  --navy-900: #0f172a;
  --navy-800: #1e293b;
  --navy-700: #334155;
  --navy-600: #475569;
  --navy-500: #64748b;
  --navy-400: #94a3b8;
  --navy-300: #cbd5e1;
  --navy-200: #e2e8f0;
  --navy-100: #f1f5f9;
  --navy-50: #f8fafc;

  /* Pure White */
  --white: #ffffff;

  /* Soft Silver */
  --silver-100: #e2e8f0;
  --silver-200: #cbd5e1;
  --silver-300: #94a3b8;
  --silver-400: #64748b;

  /* Semantic */
  --bg-primary: var(--navy-50);
  --bg-secondary: var(--white);
  --bg-tertiary: var(--navy-100);
  --text-primary: var(--navy-900);
  --text-secondary: var(--navy-600);
  --text-muted: var(--navy-400);
  --border-light: var(--navy-200);
  --border-medium: var(--navy-300);
  --accent-primary: var(--royal-blue);
  --accent-hover: var(--royal-blue-600);
  --accent-light: var(--royal-blue-100);
  --surface: var(--white);
  --surface-2: var(--navy-50);
  --success: #059669;
  --success-light: #d1fae5;
  --warning: #d97706;
  --warning-light: #fef3c7;
  --error: #dc2626;
  --error-light: #fee2e2;

  /* Gradients */
  --grad-primary: linear-gradient(135deg, var(--royal-blue) 0%, var(--royal-blue-500) 100%);
  --grad-primary-hover: linear-gradient(135deg, var(--royal-blue-600) 0%, var(--royal-blue) 100%);
  --grad-surface: linear-gradient(145deg, var(--white) 0%, var(--navy-50) 100%);
  --grad-glass: linear-gradient(135deg, rgba(255,255,255,0.95) 0%, rgba(248,250,252,0.85) 100%);
  --grad-hero: linear-gradient(135deg, var(--royal-blue) 0%, #312e81 50%, var(--royal-blue-600) 100%);
  --grad-card: linear-gradient(145deg, rgba(255,255,255,0.9) 0%, rgba(248,250,252,0.7) 100%);

  /* 3D Shadows — Layered Depth */
  --shadow-xs: 0 1px 2px rgba(15,23,42,0.03);
  --shadow-sm: 0 1px 3px rgba(15,23,42,0.05), 0 1px 2px rgba(15,23,42,0.04);
  --shadow-md: 0 4px 6px -1px rgba(15,23,42,0.07), 0 2px 4px -2px rgba(15,23,42,0.05);
  --shadow-lg: 0 10px 15px -3px rgba(15,23,42,0.08), 0 4px 6px -4px rgba(15,23,42,0.06);
  --shadow-xl: 0 20px 25px -5px rgba(15,23,42,0.1), 0 8px 10px -6px rgba(15,23,42,0.08);
  --shadow-2xl: 0 25px 50px -12px rgba(15,23,42,0.15);
  --shadow-3d: 0 4px 24px rgba(15,23,42,0.06), 0 0 0 1px rgba(15,23,42,0.03), 0 1px 0 rgba(255,255,255,0.5) inset;
  --shadow-3d-hover: 0 12px 40px rgba(15,23,42,0.1), 0 0 0 1px rgba(15,23,42,0.05), 0 1px 0 rgba(255,255,255,0.5) inset;
  --shadow-3d-press: 0 2px 8px rgba(15,23,42,0.08), 0 0 0 1px rgba(15,23,42,0.04), 0 1px 0 rgba(255,255,255,0.3) inset;
  --shadow-inner: inset 0 2px 4px rgba(15,23,42,0.04);
  --shadow-glow: 0 0 0 3px var(--accent-light);

  /* Glassmorphism */
  --glass-bg: rgba(255,255,255,0.88);
  --glass-bg-strong: rgba(255,255,255,0.95);
  --glass-border: rgba(148,163,184,0.18);
  --glass-border-strong: rgba(148,163,184,0.28);
  --glass-blur: blur(20px);
  --glass-blur-strong: blur(30px);

  /* Border Radius */
  --radius-xs: 6px;
  --radius-sm: 8px;
  --radius-md: 12px;
  --radius-lg: 16px;
  --radius-xl: 20px;
  --radius-2xl: 24px;
  --radius-full: 9999px;

  /* Transitions */
  --transition-fast: 120ms cubic-bezier(0.4, 0, 0.2, 1);
  --transition-base: 200ms cubic-bezier(0.4, 0, 0.2, 1);
  --transition-slow: 300ms cubic-bezier(0.4, 0, 0.2, 1);
  --transition-bounce: 350ms cubic-bezier(0.34, 1.56, 0.64, 1);

  /* Z-index */
  --z-dropdown: 100;
  --z-sticky: 200;
  --z-fixed: 300;
  --z-modal: 400;
  --z-toast: 500;

  /* Layout */
  --sidebar-width: 260px;
  --sidebar-collapsed: 72px;
  --header-height: 64px;
  --mobile-nav-height: 72px;

  /* Luxury Glass & Depth — added surfaces, sheen and elevation tiers.
     These extend (never replace) the existing design tokens. All themes
     keep working because values derive from --glass-bg / --glass-border etc. */
  --glass-sheen: rgba(255,255,255,0.55);
  --glass-highlight: rgba(255,255,255,0.9);
  --glass-ring: rgba(30,58,138,0.14);
  --depth-line: 0 0 0 1px rgba(15,23,42,0.06);
  --elev-1: 0 1px 3px rgba(15,23,42,0.06), 0 1px 2px rgba(15,23,42,0.04);
  --elev-2: 0 4px 12px rgba(15,23,42,0.07), 0 1px 3px rgba(15,23,42,0.05);
  --elev-3: 0 10px 30px rgba(15,23,42,0.09), 0 2px 6px rgba(15,23,42,0.06);
  --elev-4: 0 20px 50px rgba(15,23,42,0.12), 0 4px 12px rgba(15,23,42,0.08);

  /* Animation easing for micro-interactions */
  --ease-3d: cubic-bezier(0.23, 1, 0.32, 1);
}

/* ============================================================
   THEMES — applied instantly from Settings
   ============================================================ */
[data-theme="light"] {
  --bg-primary: #ffffff;
  --bg-secondary: #ffffff;
  --bg-tertiary: #f8fafc;
  --surface: #ffffff;
  --surface-2: #f8fafc;
  --border-light: #e8edf3;
  --border-medium: #d5dde7;
  --grad-surface: linear-gradient(145deg, #ffffff 0%, #f8fafc 100%);
}

[data-theme="ocean"] {
  --royal-blue: #0f766e;
  --royal-blue-600: #0d9488;
  --royal-blue-500: #14b8a6;
  --royal-blue-400: #2dd4bf;
  --royal-blue-100: #ccfbf1;
  --royal-blue-50: #f0fdfa;
  --bg-primary: #f0fdfa;
  --bg-secondary: #ffffff;
  --bg-tertiary: #ccfbf1;
  --surface: #ffffff;
  --surface-2: #f0fdfa;
  --accent-primary: #0f766e;
  --accent-hover: #0d9488;
  --accent-light: #ccfbf1;
  --grad-primary: linear-gradient(135deg, #0f766e 0%, #14b8a6 100%);
  --grad-primary-hover: linear-gradient(135deg, #0d9488 0%, #0f766e 100%);
  --grad-surface: linear-gradient(145deg, #ffffff 0%, #f0fdfa 100%);
  --grad-card: linear-gradient(145deg, rgba(255,255,255,0.94) 0%, rgba(240,253,250,0.78) 100%);
  --grad-hero: linear-gradient(135deg, #0f766e 0%, #115e59 50%, #0d9488 100%);
}

[data-theme="graphite"],
[data-theme="dark"] {
  --white: #0f172a;
  --navy-50: #0b1120;
  --navy-100: #111827;
  --navy-200: #1f2937;
  --navy-300: #334155;
  --navy-400: #94a3b8;
  --navy-500: #cbd5e1;
  --navy-600: #e2e8f0;
  --navy-700: #f1f5f9;
  --navy-800: #f8fafc;
  --navy-900: #ffffff;
  --bg-primary: #070b14;
  --bg-secondary: #0f172a;
  --bg-tertiary: #111827;
  --surface: #0f172a;
  --surface-2: #111827;
  --text-primary: #f8fafc;
  --text-secondary: #cbd5e1;
  --text-muted: #94a3b8;
  --border-light: #1f2937;
  --border-medium: #334155;
  --accent-primary: #60a5fa;
  --accent-hover: #93c5fd;
  --accent-light: #1e3a8a;
  --grad-primary: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);
  --grad-primary-hover: linear-gradient(135deg, #1e40af 0%, #1e3a8a 100%);
  --grad-surface: linear-gradient(145deg, #0f172a 0%, #111827 100%);
  --grad-glass: linear-gradient(135deg, rgba(15,23,42,0.96) 0%, rgba(17,24,39,0.9) 100%);
  --grad-card: linear-gradient(145deg, rgba(15,23,42,0.96) 0%, rgba(17,24,39,0.86) 100%);
  --grad-hero: linear-gradient(135deg, #1e3a8a 0%, #312e81 50%, #1e40af 100%);
  --glass-bg: rgba(15,23,42,0.9);
  --glass-bg-strong: rgba(15,23,42,0.97);
  --glass-border: rgba(148,163,184,0.16);
  --glass-border-strong: rgba(148,163,184,0.26);
  --shadow-xs: 0 1px 2px rgba(0,0,0,0.3);
  --shadow-sm: 0 1px 3px rgba(0,0,0,0.35);
  --shadow-md: 0 4px 10px rgba(0,0,0,0.35);
  --shadow-lg: 0 12px 24px rgba(0,0,0,0.38);
  --shadow-xl: 0 22px 44px rgba(0,0,0,0.42);
  --shadow-2xl: 0 30px 60px rgba(0,0,0,0.48);
  --shadow-3d: 0 4px 24px rgba(0,0,0,0.3), 0 0 0 1px rgba(148,163,184,0.08);
  --shadow-3d-hover: 0 12px 40px rgba(0,0,0,0.38), 0 0 0 1px rgba(148,163,184,0.14);
}

[data-theme="graphite"] {
  --accent-primary: #f59e0b;
  --accent-hover: #fbbf24;
  --accent-light: #3f2d0f;
  --royal-blue: #b45309;
  --royal-blue-600: #d97706;
  --royal-blue-500: #f59e0b;
  --royal-blue-400: #fbbf24;
  --royal-blue-100: #3f2d0f;
  --royal-blue-50: #1c1917;
  --grad-primary: linear-gradient(135deg, #b45309 0%, #f59e0b 100%);
  --grad-primary-hover: linear-gradient(135deg, #d97706 0%, #b45309 100%);
}

[data-theme="dark"] .diagram-preview,
[data-theme="graphite"] .diagram-preview { background: #f8fafc; }

[data-theme="dark"] .diagram-warning,
[data-theme="graphite"] .diagram-warning { background: #2a2110; border-color: #5b4213; color: #fbbf24; }

/* Reduced Motion */
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
  }
}

/* ============================================================
   RESET & BASE
   ============================================================ */
*, *::before, *::after { box-sizing: border-box; }
* { margin: 0; }

html { -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale; text-rendering: optimizeLegibility; }
.icon-sprite { position: absolute; width: 0; height: 0; overflow: hidden; }

body {
  margin: 0;
  min-height: 100vh;
  background: var(--bg-primary);
  color: var(--text-primary);
  font-family: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
  font-size: 14px;
  line-height: 1.6;
  letter-spacing: -0.01em;
}

a { color: inherit; text-decoration: none; }
button { font: inherit; color: inherit; background: none; border: none; cursor: pointer; }
input, select, textarea { font: inherit; color: inherit; }
img { max-width: 100%; height: auto; display: block; }
/* Performance & smoothness */
html { scroll-behavior: smooth; }
*, *::before, *::after { -webkit-tap-highlight-color: transparent; }
.panel, .card, .stat-card, .dashboard-card, .modal, .toast {
  will-change: transform, opacity;
  transform: translateZ(0);
  backface-visibility: hidden;
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; }
}

/* Keyboard skip link */
.skip-link {
  position: fixed;
  top: 10px;
  left: 10px;
  z-index: calc(var(--z-toast) + 10);
  padding: 10px 16px;
  border-radius: var(--radius-md);
  background: var(--accent-primary);
  color: var(--white);
  font-size: 13px;
  font-weight: 700;
  box-shadow: var(--shadow-xl);
  transform: translateY(-160%);
  transition: transform var(--transition-fast);
}
.skip-link:focus-visible { transform: translateY(0); }

/* Focus Visible */
:focus:not(:focus-visible) { outline: none; }
:focus-visible {
  outline: none;
  box-shadow: var(--shadow-glow);
  border-radius: var(--radius-sm);
}

/* Scrollbar */
::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--navy-300); border-radius: var(--radius-full); border: 2px solid transparent; background-clip: content-box; }
::-webkit-scrollbar-thumb:hover { background: var(--navy-400); }

/* Selection */
::selection { background: var(--accent-light); color: var(--accent-primary); }

/* ============================================================
   3D CARD SYSTEM
   ============================================================ */
.card-3d {
  background: var(--grad-surface);
  border: 1px solid var(--border-light);
  border-radius: var(--radius-xl);
  box-shadow: var(--shadow-3d);
  transition: box-shadow var(--transition-base), transform var(--transition-base);
}
.card-3d:hover { box-shadow: var(--shadow-3d-hover); transform: translateY(-2px); }
.card-3d:active { box-shadow: var(--shadow-3d-press); transform: translateY(0); }

.card-glass {
  background: var(--glass-bg);
  backdrop-filter: var(--glass-blur);
  -webkit-backdrop-filter: var(--glass-blur);
  border: 1px solid var(--glass-border);
  border-radius: var(--radius-xl);
  box-shadow: var(--shadow-lg);
}
.card-glass-strong {
  background: var(--glass-bg-strong);
  backdrop-filter: var(--glass-blur-strong);
  -webkit-backdrop-filter: var(--glass-blur-strong);
  border: 1px solid var(--glass-border-strong);
  border-radius: var(--radius-xl);
  box-shadow: var(--shadow-xl);
}

.card-elevated {
  background: var(--white);
  border: 1px solid var(--border-light);
  border-radius: var(--radius-xl);
  box-shadow: var(--shadow-lg);
  transition: box-shadow var(--transition-base), transform var(--transition-base);
}
.card-elevated:hover { box-shadow: var(--shadow-xl); transform: translateY(-4px); }

/* 3D Button System */
.btn-3d {
  position: relative;
  overflow: hidden;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  padding: 14px 24px;
  font-size: 14px;
  font-weight: 600;
  line-height: 1.4;
  border-radius: var(--radius-lg);
  border: 1px solid transparent;
  transition: all var(--transition-fast);
  white-space: nowrap;
  box-shadow: var(--elev-1), var(--depth-line);
}
.btn-3d::before {
  content: '';
  position: absolute; inset: 0; border-radius: inherit; pointer-events: none; z-index: 0;
  background: linear-gradient(135deg, transparent 45%, rgba(255,255,255,0.45) 50%, transparent 55%);
  opacity: 0; transition: transform var(--transition-base), opacity var(--transition-base);
}
.btn-3d:hover::before { opacity: 1; transform: translateX(-110%) translateY(-60%); }
.btn-3d:active { transform: scale(0.985); box-shadow: var(--shadow-3d-press); }
.btn-3d:disabled { opacity: 0.5; cursor: not-allowed; transform: none; box-shadow: none; }

.btn-primary {
  background: var(--grad-primary);
  color: var(--white);
  border-color: var(--royal-blue-500);
  box-shadow: 0 4px 14px rgba(30,58,138,0.3), 0 0 0 1px rgba(30,58,138,0.1) inset;
}
.btn-primary:hover:not(:disabled) {
  background: var(--grad-primary-hover);
  box-shadow: 0 8px 24px rgba(30,58,138,0.4), 0 0 0 1px rgba(30,58,138,0.15) inset;
  transform: translateY(-2px);
}

.btn-secondary {
  background: var(--white);
  color: var(--text-primary);
  border-color: var(--border-medium);
  box-shadow: var(--shadow-sm);
}
.btn-secondary:hover:not(:disabled) {
  background: var(--navy-50);
  border-color: var(--navy-400);
  box-shadow: var(--shadow-md);
  transform: translateY(-1px);
}

.btn-ghost {
  background: transparent;
  color: var(--text-secondary);
  border-color: transparent;
}
.btn-ghost:hover:not(:disabled) {
  background: var(--navy-100);
  color: var(--text-primary);
}

.btn-outline {
  background: var(--white);
  color: var(--accent-primary);
  border: 1px solid var(--accent-primary);
}
.btn-outline:hover:not(:disabled) {
  background: var(--accent-light);
  border-color: var(--accent-hover);
}

.btn-destructive {
  background: var(--white);
  color: var(--error);
  border-color: var(--error);
}
.btn-destructive:hover:not(:disabled) {
  background: var(--error-light);
  border-color: var(--error);
}

/* Icon Button */
.btn-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 40px;
  height: 40px;
  border-radius: var(--radius-md);
  color: var(--text-secondary);
  background: transparent;
  border: 1px solid transparent;
  transition: all var(--transition-fast);
}
.btn-icon:hover { background: var(--navy-100); color: var(--text-primary); }
.btn-icon:active { transform: scale(0.95); }

/* Form Elements */
.form-label {
  display: block;
  font-size: 12px;
  font-weight: 600;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: 8px;
}
.form-select, .form-input, .form-textarea {
  position: relative;
  width: 100%;
  padding: 12px 14px;
  font-size: 14px;
  line-height: 1.5;
  color: var(--text-primary);
  background: var(--glass-bg-strong);
  backdrop-filter: var(--glass-blur-strong);
  -webkit-backdrop-filter: var(--glass-blur-strong);
  border: 1px solid var(--glass-border);
  border-radius: var(--radius-md);
  box-shadow: var(--elev-1);
  transition: border-color var(--transition-fast), box-shadow var(--transition-fast), background var(--transition-fast);
}
.form-select:hover, .form-input:hover, .form-textarea:hover { border-color: var(--navy-400); box-shadow: var(--elev-2); }
.form-select:focus, .form-input:focus, .form-textarea:focus {
  border-color: var(--accent-primary);
  box-shadow: var(--elev-2), 0 0 0 4px var(--accent-light);
  outline: none;
}
.form-select { cursor: pointer; appearance: none; background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='20' height='20' viewBox='0 0 24 24' fill='none' stroke='%2364748b' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 12px center; padding-right: 40px; }
.form-textarea { resize: vertical; min-height: 160px; font-family: 'Inter', monospace; }

/* ============================================================
   LAYOUT
   ============================================================ */
.app {
  min-height: 100vh;
  display: grid;
  grid-template-columns: var(--sidebar-width) 1fr;
  transition: grid-template-columns var(--transition-base);
}

/* Sidebar */
.sidebar {
  position: fixed;
  top: 0;
  left: 0;
  height: 100vh;
  width: var(--sidebar-width);
  background: var(--grad-surface);
  border-right: 1px solid var(--border-light);
  display: flex;
  flex-direction: column;
  padding: 20px 16px;
  z-index: var(--z-fixed);
  overflow-y: auto;
  transition: width var(--transition-base), transform var(--transition-base);
}
.sidebar::before {
  content: '';
  position: absolute;
  top: 0; right: 0; bottom: 0; left: 0;
  background: linear-gradient(180deg, rgba(30,58,138,0.02) 0%, transparent 50%);
  pointer-events: none;
}

/* Collapsed Sidebar (Tablet) */
@media (max-width: 1024px) {
  .sidebar { width: var(--sidebar-collapsed); padding: 16px 8px; }
  .sidebar .brand-copy, .sidebar .nav-label, .sidebar .nav-text, .sidebar .side-bottom { display: none; }
  .sidebar .brand { justify-content: center; padding-bottom: 24px; }
  .sidebar .nav a { justify-content: center; padding: 12px; }
  .sidebar .nav-icon { font-size: 20px; }
  .app { grid-template-columns: var(--sidebar-collapsed) 1fr; }
}

/* Mobile - Sidebar becomes drawer */
@media (max-width: 640px) {
  .sidebar {
    transform: translateX(-100%);
    width: 280px;
    box-shadow: var(--shadow-2xl);
    border-radius: 0 var(--radius-2xl) var(--radius-2xl) 0;
    border-right: none;
  }
  .sidebar.open { transform: translateX(0); }
  .app { grid-template-columns: 1fr; }
  .main { margin-left: 0; }
}

/* Sidebar Overlay */
.sidebar-overlay {
  display: block;
  position: fixed;
  inset: 0;
  background: rgba(15,23,42,0.4);
  backdrop-filter: blur(4px);
  z-index: calc(var(--z-fixed) - 1);
  opacity: 0;
  visibility: hidden;
  pointer-events: none;
  transition: opacity var(--transition-base), visibility var(--transition-base);
}
.sidebar-overlay.visible {
  opacity: 1;
  visibility: visible;
  pointer-events: auto;
}

/* Brand */
.brand {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 8px 4px 28px;
}
.logo {
  width: 44px;
  height: 44px;
  border-radius: var(--radius-lg);
  display: grid;
  place-items: center;
  font-size: 22px;
  font-weight: 700;
  color: var(--white);
  background: var(--grad-primary);
  box-shadow: 0 4px 16px rgba(30,58,138,0.35), 0 0 0 1px rgba(30,58,138,0.1) inset;
  flex-shrink: 0;
}
.brand-copy { display: flex; flex-direction: column; min-width: 0; }
.brand-copy strong { font-size: 16px; font-weight: 700; color: var(--text-primary); letter-spacing: -0.02em; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.brand-copy small { font-size: 10px; font-weight: 500; color: var(--accent-primary); letter-spacing: 0.1em; text-transform: uppercase; margin-top: 2px; white-space: nowrap; }

/* Navigation */
.nav-label {
  font-size: 10px;
  font-weight: 600;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.1em;
  padding: 16px 8px 8px;
}
.nav { display: flex; flex-direction: column; gap: 4px; }
.nav a {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 12px;
  border-radius: var(--radius-lg);
  font-size: 14px;
  font-weight: 500;
  color: var(--text-secondary);
  transition: all var(--transition-fast);
  position: relative;
}
.nav a:hover { background: var(--navy-100); color: var(--text-primary); }
.nav a.active {
  background: linear-gradient(90deg, var(--accent-light), transparent);
  color: var(--accent-primary);
  font-weight: 600;
  box-shadow: inset 0 0 0 1px rgba(30,58,138,0.08);
}
.nav a::before {
  content: '';
  position: absolute;
  left: 0; top: 22%; bottom: 22%;
  width: 3px;
  background: var(--accent-primary);
  border-radius: 0 var(--radius-xs) var(--radius-xs) 0;
  transform: scaleY(0);
  transform-origin: center;
  transition: transform var(--transition-base);
}
.nav a.active::before { transform: scaleY(1); }
.nav-icon {
  width: 20px;
  height: 20px;
  flex-shrink: 0;
  transition: transform var(--transition-fast), color var(--transition-fast);
}
.nav a:hover .nav-icon { transform: translateY(-1px) scale(1.04); }
.nav-text { white-space: nowrap; }

/* Side Bottom */
.side-bottom {
  margin-top: auto;
  padding: 16px;
  background: var(--grad-card);
  border: 1px solid var(--glass-border);
  border-radius: var(--radius-lg);
  backdrop-filter: var(--glass-blur);
}
.side-bottom .premium-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 11px;
  font-weight: 600;
  color: var(--accent-primary);
  margin-bottom: 8px;
}
.side-bottom p { font-size: 12px; line-height: 1.6; color: var(--text-muted); }

/* Main Content */
.main {
  margin-left: var(--sidebar-width);
  min-height: 100vh;
  padding: 20px clamp(20px, 3.5vw, 40px);
  max-width: calc(100% - var(--sidebar-width));
  transition: margin-left var(--transition-base), max-width var(--transition-base), padding var(--transition-base);
}
@media (max-width: 1024px) {
  .main { margin-left: var(--sidebar-collapsed); max-width: calc(100% - var(--sidebar-collapsed)); }
}
@media (max-width: 640px) {
  .main {
    margin-left: 0;
    max-width: 100%;
    /* Clear the fixed mobile menu button, then the bottom navigation and
       device home-indicator safe area. */
    padding: 72px 14px calc(26px + var(--mobile-nav-height) + env(safe-area-inset-bottom, 0px));
    scroll-padding-bottom: calc(var(--mobile-nav-height) + env(safe-area-inset-bottom, 0px));
  }
}

/* Header / Topbar */
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 24px;
  margin-bottom: 32px;
  flex-wrap: wrap;
}
.topbar-left { display: flex; flex-direction: column; gap: 4px; }
.eyebrow {
  font-size: 11px;
  font-weight: 600;
  color: var(--accent-primary);
  text-transform: uppercase;
  letter-spacing: 0.15em;
}
.topbar h1 {
  font-size: clamp(26px, 3.5vw, 36px);
  font-weight: 700;
  letter-spacing: -0.03em;
  color: var(--text-primary);
  line-height: 1.2;
}
.avatar {
  width: 44px;
  height: 44px;
  border-radius: var(--radius-full);
  display: grid;
  place-items: center;
  font-size: 18px;
  font-weight: 700;
  color: var(--white);
  background: var(--grad-primary);
  box-shadow: 0 4px 14px rgba(30,58,138,0.25), 0 0 0 1px rgba(30,58,138,0.1) inset;
  flex-shrink: 0;
}

/* Welcome Section */
.welcome {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 24px;
  margin-bottom: 24px;
  padding: 24px;
  background: var(--grad-hero);
  border-radius: var(--radius-2xl);
  color: var(--white);
  position: relative;
  overflow: hidden;
}
.welcome::before {
  content: '';
  position: absolute;
  top: -50%; right: -20%;
  width: 60%; height: 200%;
  background: radial-gradient(ellipse, rgba(255,255,255,0.08) 0%, transparent 70%);
  pointer-events: none;
}
.welcome-content { position: relative; z-index: 1; max-width: 600px; }
.welcome h2 {
  font-size: clamp(22px, 3vw, 28px);
  font-weight: 700;
  letter-spacing: -0.02em;
  line-height: 1.3;
  margin-bottom: 10px;
}
.welcome h2 span { color: var(--royal-blue-100); }
.welcome p { font-size: 14px; line-height: 1.7; opacity: 0.9; }
.welcome-action { position: relative; z-index: 1; flex-shrink: 0; }

/* Stats Grid */
.stats {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 16px;
  margin-bottom: 24px;
  perspective: 1200px;
}
@media (max-width: 700px) { .stats { grid-template-columns: repeat(2, 1fr); } }
@media (max-width: 420px) { .stats { grid-template-columns: 1fr; } }

.stat-card {
  position: relative;
  overflow: hidden;
  padding: 20px;
  background: var(--glass-bg-strong);
  backdrop-filter: var(--glass-blur-strong);
  -webkit-backdrop-filter: var(--glass-blur-strong);
  border: 1px solid var(--glass-border);
  border-radius: var(--radius-xl);
  box-shadow: var(--elev-2), var(--depth-line);
  transition: box-shadow var(--transition-base), transform var(--transition-base);
}
.stat-card::before {
  content: '';
  position: absolute; top: 0; left: 0; right: 0; height: 3px;
  background: var(--grad-primary);
  opacity: 0; transition: opacity var(--transition-base);
}
.stat-card { perspective: 1000px; transform-style: preserve-3d; }
.stat-card:hover { box-shadow: var(--elev-3), var(--depth-line); transform: translateY(-4px) rotateX(2deg) translateZ(8px); }
.stat-card:hover::before { opacity: 1; }
.stat-card::after {
  content: '';
  position: absolute; inset: 0; border-radius: inherit; pointer-events: none; z-index: 0;
  background: linear-gradient(135deg, transparent 45%, var(--glass-sheen) 50%, transparent 55%);
  opacity: 0; transition: transform var(--transition-base), opacity var(--transition-base);
}
.stat-card:hover::after { opacity: 1; transform: translateX(-110%) translateY(-60%); }
.stat-card > * { position: relative; z-index: 1; }

.stat-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }
.stat-label { font-size: 12px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }
.stat-icon {
  width: 40px;
  height: 40px;
  border-radius: var(--radius-lg);
  display: grid;
  place-items: center;
  font-size: 20px;
  background: var(--accent-light);
  color: var(--accent-primary);
  flex-shrink: 0;
}
.stat-value { font-size: 32px; font-weight: 700; letter-spacing: -0.03em; color: var(--text-primary); line-height: 1.1; margin-bottom: 4px; }
.stat-desc { font-size: 12px; color: var(--text-muted); }

@media (max-width: 700px) {
  .stat-card { padding: 16px; border-radius: var(--radius-lg); }
  .stat-value { font-size: 26px; }
}

/* Section Head */
.section-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  margin: 6px 0 20px;
  flex-wrap: wrap;
}
.section-head h2 { font-size: 20px; font-weight: 700; letter-spacing: -0.02em; color: var(--text-primary); }
.section-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 6px 12px;
  font-size: 11px;
  font-weight: 600;
  color: var(--accent-primary);
  background: var(--accent-light);
  border-radius: var(--radius-full);
}

/* Workspace Grid */
.workspace {
  display: grid;
  grid-template-columns: 1fr;
  gap: 22px;
}

/* Panels */
.panel {
  position: relative;
  overflow: hidden;
  padding: 24px;
  background: var(--glass-bg-strong);
  backdrop-filter: var(--glass-blur-strong);
  -webkit-backdrop-filter: var(--glass-blur-strong);
  border: 1px solid var(--glass-border);
  border-radius: var(--radius-xl);
  box-shadow: var(--elev-2), var(--depth-line);
  transition: box-shadow var(--transition-base), transform var(--transition-base), border-color var(--transition-base);
}
.panel:hover { box-shadow: var(--elev-3), var(--depth-line); transform: translateY(-2px); }
.panel::before {
  content: '';
  position: absolute; inset: 0; border-radius: inherit; pointer-events: none; z-index: 0;
  background: linear-gradient(135deg, transparent 45%, var(--glass-sheen) 50%, transparent 55%);
  opacity: 0; transition: transform var(--transition-base), opacity var(--transition-base);
}
.panel:hover::before { opacity: 1; transform: translateX(-110%) translateY(-60%); }
.panel > * { position: relative; z-index: 1; }
.panel-header { margin-bottom: 20px; }
.panel-eyebrow {
  font-size: 11px;
  font-weight: 600;
  color: var(--accent-primary);
  text-transform: uppercase;
  letter-spacing: 0.1em;
  margin-bottom: 8px;
}
.panel h3 { font-size: 18px; font-weight: 700; color: var(--text-primary); letter-spacing: -0.02em; }
.panel p { font-size: 14px; color: var(--text-secondary); line-height: 1.6; margin-top: 4px; }

/* Dropzone */
.dropzone {
  position: relative;
  min-height: 160px;
  border: 2px dashed var(--border-medium);
  border-radius: var(--radius-xl);
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  padding: 32px 24px;
  background: var(--white);
  transition: all var(--transition-base);
  cursor: pointer;
}
.dropzone:hover, .dropzone.drag-active {
  border-color: var(--accent-primary);
  background: var(--accent-light);
}
.dropzone.drag-active { transform: scale(1.01); box-shadow: var(--shadow-glow); }
.dropzone-icon {
  width: 56px;
  height: 56px;
  border-radius: var(--radius-xl);
  display: grid;
  place-items: center;
  font-size: 24px;
  background: var(--accent-light);
  color: var(--accent-primary);
  margin-bottom: 16px;
  transition: transform var(--transition-bounce);
}
.dropzone:hover .dropzone-icon { transform: rotate(-6deg) scale(1.05); }
.dropzone strong { display: block; font-size: 15px; font-weight: 600; color: var(--text-primary); margin-bottom: 6px; }
.dropzone p { font-size: 13px; color: var(--text-muted); margin-bottom: 20px; }
.dropzone .btn-outline { padding: 12px 24px; font-size: 13px; }

/* File Preview */
.file-preview {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
  gap: 12px;
  width: 100%;
  margin-top: 16px;
}
.file-preview > p { grid-column: 1 / -1; text-align: center; color: var(--text-muted); font-size: 13px; padding: 16px; }
.file-item {
  padding: 12px;
  background: var(--white);
  border: 1px solid var(--border-light);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-sm);
  transition: box-shadow var(--transition-fast), transform var(--transition-fast);
  min-width: 0;
}
.file-item:hover { box-shadow: var(--shadow-md); transform: translateY(-2px); }
.file-item img, .pdf-preview-frame {
  display: block; width: 100%; height: 100px; object-fit: cover; border-radius: var(--radius-md); margin-bottom: 10px; background: var(--navy-100);
}
.pdf-preview-frame { border: none; }
.file-item strong { display: block; font-size: 11px; font-weight: 600; color: var(--text-primary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; margin-bottom: 4px; }
.file-item small { display: block; font-size: 10px; color: var(--text-muted); }

/* Upload Settings */
.upload-settings {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 14px;
  margin-top: 20px;
}
@media (max-width: 640px) { .upload-settings { grid-template-columns: 1fr; } }

/* PDF output mode cards */
.visually-hidden {
  position: absolute !important;
  width: 1px !important;
  height: 1px !important;
  padding: 0 !important;
  margin: -1px !important;
  overflow: hidden !important;
  clip: rect(0 0 0 0) !important;
  white-space: nowrap !important;
  border: 0 !important;
}
.mode-settings { grid-template-columns: 1fr; align-items: start; }
.mode-field { min-width: 0; }
.mode-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
}
.mode-card {
  position: relative;
  display: flex;
  flex-direction: column;
  justify-content: flex-start;
  gap: 6px;
  min-height: 104px;
  padding: 14px 14px 13px;
  border: 1px solid var(--border-medium);
  border-radius: var(--radius-md);
  background: var(--white);
  cursor: pointer;
  transition: border-color var(--transition-fast), background var(--transition-fast), box-shadow var(--transition-fast), transform var(--transition-fast);
}
.mode-card:hover { border-color: var(--accent-primary); box-shadow: var(--shadow-sm); transform: translateY(-1px); }
.mode-card:focus-within { outline: 2px solid var(--accent-primary); outline-offset: 2px; }
.mode-card input { position: absolute; opacity: 0; width: 1px; height: 1px; margin: 0; pointer-events: none; }
.mode-card.selected {
  border-color: var(--accent-primary);
  background: var(--accent-light);
  box-shadow: 0 0 0 2px rgba(37, 99, 235, 0.16);
}
.mode-card-title {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px;
  font-size: 13px;
  font-weight: 700;
  line-height: 1.35;
  color: var(--text-primary);
}
.mode-card-desc {
  display: block;
  font-size: 11.5px;
  line-height: 1.45;
  color: var(--text-muted);
}
.free-badge {
  display: inline-flex;
  align-items: center;
  min-height: 18px;
  padding: 2px 6px;
  border-radius: var(--radius-full);
  background: var(--success);
  color: var(--white);
  font-size: 9px;
  font-weight: 800;
  letter-spacing: 0.06em;
}
.mode-style { max-width: 320px; margin-top: 4px; }
@media (max-width: 900px) {
  .mode-grid { grid-template-columns: 1fr; }
  .mode-card { min-height: 104px; }
  .mode-style { max-width: none; }
}

/* Extract Actions */
.extract-actions { margin-top: 20px; }
#extractBtn { width: 100%; padding: 14px 24px; }
.extracted-label { display: block; margin: 20px 0 10px; font-size: 12px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }
#extractedText { width: 100%; min-height: 180px; padding: 14px; font-size: 13px; line-height: 1.7; color: var(--text-primary); background: var(--white); border: 1px solid var(--border-medium); border-radius: var(--radius-md); resize: vertical; transition: border-color var(--transition-fast), box-shadow var(--transition-fast); }
#extractedText:focus { border-color: var(--accent-primary); box-shadow: var(--shadow-glow); outline: none; }

/* Upload Actions */
.upload-actions { margin-top: 20px; display: flex; flex-direction: column; gap: 12px; }
#generateBtn { width: 100%; padding: 16px 24px; font-size: 15px; }
#uploadStatus { font-size: 12px; color: var(--text-muted); min-height: 20px; }

/* Activity Panel */
.activity-list { display: flex; flex-direction: column; gap: 12px; }
.activity-item {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 16px;
  background: var(--white);
  border: 1px solid var(--border-light);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-xs);
  transition: box-shadow var(--transition-fast), transform var(--transition-fast);
}
.activity-item:hover { box-shadow: var(--shadow-sm); transform: translateX(2px); }
.activity-icon {
  width: 44px;
  height: 44px;
  border-radius: var(--radius-lg);
  display: grid;
  place-items: center;
  font-size: 20px;
  background: var(--accent-light);
  color: var(--accent-primary);
  flex-shrink: 0;
}
.activity-content { flex: 1; min-width: 0; }
.activity-title { font-size: 13px; font-weight: 600; color: var(--text-primary); margin-bottom: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.activity-detail { font-size: 11px; color: var(--text-muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.activity-status {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 4px 10px;
  font-size: 10px;
  font-weight: 600;
  border-radius: var(--radius-full);
  flex-shrink: 0;
}
.activity-status.success { background: var(--success-light); color: var(--success); }
.activity-status.processing { background: var(--warning-light); color: var(--warning); }
.activity-status.pending { background: var(--navy-100); color: var(--text-muted); }
.activity-time { font-size: 10px; color: var(--text-muted); flex-shrink: 0; }

/* Empty State */
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 48px 24px;
  text-align: center;
  color: var(--text-muted);
}
.empty-state-icon { width: 64px; height: 64px; border-radius: var(--radius-xl); background: var(--navy-100); color: var(--text-muted); display: grid; place-items: center; font-size: 28px; margin-bottom: 16px; }
.empty-state h4 { font-size: 16px; font-weight: 600; color: var(--text-secondary); margin-bottom: 6px; }
.empty-state p { font-size: 13px; line-height: 1.6; max-width: 280px; }

/* Footer */
.footer { margin-top: 40px; padding: 24px 0; text-align: center; font-size: 11px; color: var(--text-muted); letter-spacing: 0.05em; border-top: 1px solid var(--border-light); }

/* ============================================================
   MOBILE BOTTOM NAVIGATION
   ============================================================ */
  content: '';
  position: absolute;
/* === Premium Mobile Bottom Navigation === */
.mobile-nav {
  display: block;
  position: fixed;
  bottom: 0; left: 0; right: 0;
  height: calc(var(--mobile-nav-height) + env(safe-area-inset-bottom, 0px));
  background: var(--white);
  border-top: 1px solid var(--border-light);
  box-shadow: 0 -4px 32px rgba(15,23,42,0.1);
  z-index: var(--z-fixed);
  padding: 0 env(safe-area-inset-right, 0px) env(safe-area-inset-bottom, 0px) env(safe-area-inset-left, 0px);
}
.mobile-nav-inner {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  height: 100%;
  max-width: 640px;
  margin: 0 auto;
}
.mobile-nav-item {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 10px 2px;
  color: var(--text-muted);
  font-size: 11px;
  font-weight: 500;
  transition: color var(--transition-base), background var(--transition-base);
  position: relative;
}
.mobile-nav-item:hover { color: var(--text-secondary); background: var(--navy-50); }
.mobile-nav-item.active {
  color: var(--accent-primary);
  background: var(--accent-light);
}
.mobile-nav-item.active::before {
  content: "";
  position: absolute;
  top: 8px; left: 50%;
  transform: translateX(-50%);
  width: 28px; height: 3px;
  background: var(--grad-primary);
  border-radius: 0 0 var(--radius-sm) var(--radius-sm);
}
.mobile-nav-icon {
  width: 32px;
  height: 28px;
  padding: 4px 6px;
  border-radius: 8px;
  background: transparent;
  color: var(--text-muted);
  font-size: 18px;
  transition: background var(--transition-base), color var(--transition-base), transform var(--transition-base);
}
.mobile-nav-item.active .mobile-nav-icon {
  background: var(--accent-light);
  color: var(--accent-primary);
  transform: translateY(-2px);
}
.mobile-nav-text {
  letter-spacing: 0.02em;
  font-size: 10px;
}
@media (max-width: 640px) {
  .mobile-nav { display: block; }
}
/* Floating Mobile Menu Button */
.mobile-menu-btn {
  display: grid;
  place-items: center;
  position: fixed;
  top: 16px; left: 16px;
  z-index: calc(var(--z-fixed) + 1);
  width: 48px; height: 48px;
  border-radius: var(--radius-full);
  background: var(--grad-primary);
  color: var(--white);
  box-shadow: var(--shadow-3d);
  transition: transform var(--transition-base), box-shadow var(--transition-base);
}
.mobile-menu-btn:hover { transform: translateY(-4px); box-shadow: var(--shadow-3d-hover); }
.mobile-menu-btn:active { transform: scale(0.96); box-shadow: var(--shadow-3d-press); }
  top: 0; left: 50%;
}

/* Mobile Menu Button */
.mobile-menu-btn {
  display: none;
  position: fixed;
  top: 16px; left: 16px;
  z-index: calc(var(--z-fixed) + 1);
  width: 44px; height: 44px;
  border-radius: var(--radius-lg);
  background: var(--white);
  border: 1px solid var(--border-light);
  box-shadow: var(--shadow-md);
  color: var(--text-primary);
}
@media (max-width: 640px) { .mobile-menu-btn { display: grid; place-items: center; } }

/* ============================================================
   LOADING STATES
   ============================================================ */
.skeleton { background: linear-gradient(90deg, var(--navy-100) 25%, var(--navy-200) 50%, var(--navy-100) 75%); background-size: 200% 100%; animation: shimmer 1.5s infinite; border-radius: var(--radius-md); }
.skeleton-grid { grid-column: 1 / -1; width: 100%; display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 16px; }
.skeleton-card { height: 128px; border-radius: var(--radius-lg); }
.skeleton-row { height: 68px; }
@keyframes shimmer { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }
.spinner { width: 20px; height: 20px; border: 2px solid var(--border-light); border-top-color: var(--accent-primary); border-radius: 50%; animation: spin 0.8s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
.btn-loading { position: relative; color: transparent !important; pointer-events: none; }
.btn-loading::after { content: ''; position: absolute; width: 20px; height: 20px; border: 2px solid currentColor; border-top-color: var(--white); border-radius: 50%; animation: spin 0.8s linear infinite; }

/* ============================================================
   TOAST NOTIFICATIONS
   ============================================================ */
.toast-container { position: fixed; bottom: 24px; right: 24px; z-index: var(--z-toast); display: flex; flex-direction: column; gap: 12px; pointer-events: none; }
@media (max-width: 640px) {
  .toast-container {
    bottom: calc(24px + var(--mobile-nav-height) + env(safe-area-inset-bottom, 0px));
    left: 16px; right: 16px;
  }
}
.toast {
  display: flex; align-items: center; gap: 12px;
  padding: 14px 18px;
  background: var(--white);
  border: 1px solid var(--border-light);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-xl);
  font-size: 13px;
  color: var(--text-primary);
  pointer-events: auto;
  animation: slideIn 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}
@keyframes slideIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
.toast.success { border-left: 4px solid var(--success); }
.toast.error { border-left: 4px solid var(--error); }
.toast.warning { border-left: 4px solid var(--warning); }
.toast.info { border-left: 4px solid var(--accent-primary); }
.toast-icon { flex-shrink: 0; font-size: 18px; }
.toast.success .toast-icon { color: var(--success); }
.toast.error .toast-icon { color: var(--error); }
.toast.warning .toast-icon { color: var(--warning); }
.toast.info .toast-icon { color: var(--accent-primary); }
.toast-close { margin-left: auto; padding: 4px; color: var(--text-muted); border-radius: var(--radius-sm); }
.toast-close:hover { background: var(--navy-100); color: var(--text-primary); }

/* ============================================================
   PAGE-SPECIFIC STYLES (for navigation pages)
   ============================================================ */
.page-header {
  display: flex; align-items: center; justify-content: space-between;
  gap: 16px; margin-bottom: 32px; flex-wrap: wrap;
}
.page-title { font-size: clamp(24px, 3vw, 32px); font-weight: 700; letter-spacing: -0.03em; }
.page-desc { font-size: 14px; color: var(--text-secondary); margin-top: 4px; }

/* My Notes - Document Grid */
.document-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(270px, 1fr));
  gap: 14px;
  margin-top: 10px;
}
.document-card {
  padding: 16px;
  background: var(--grad-surface);
  border: 1px solid var(--border-light);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-sm);
}
.document-card:hover { box-shadow: var(--shadow-3d-hover); transform: translateY(-2px); }
.document-thumb { width: 100%; height: 130px; border-radius: var(--radius-lg); background: var(--navy-100); object-fit: cover; margin-bottom: 10px; }
.document-info { display: flex; flex-direction: column; gap: 6px; }
.document-name { font-size: 14px; font-weight: 600; color: var(--text-primary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.document-meta { display: flex; gap: 12px; font-size: 11px; color: var(--text-muted); }
.document-actions { display: flex; gap: 8px; margin-top: 10px; padding-top: 10px; border-top: 1px solid var(--border-light); }
.document-actions .btn-3d { flex: 1; padding: 8px 12px; font-size: 11.5px; }

/* History - Order List */
.order-list { display: flex; flex-direction: column; gap: 12px; }
.order-item {
  display: flex; align-items: center; gap: 14px;
  padding: 16px;
  background: var(--grad-surface);
  border: 1px solid var(--border-light);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-sm);
  transition: box-shadow var(--transition-base);
}
.order-item:hover { box-shadow: var(--shadow-3d-hover); }
.order-icon { width: 44px; height: 44px; border-radius: var(--radius-lg); display: grid; place-items: center; font-size: 18px; flex-shrink: 0; }
.order-icon.pdf { background: var(--error-light); color: var(--error); }
.order-icon.text { background: var(--success-light); color: var(--success); }
.order-icon.image { background: var(--accent-light); color: var(--accent-primary); }
.order-details { flex: 1; min-width: 0; }
.order-name { font-size: 14px; font-weight: 600; color: var(--text-primary); margin-bottom: 4px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.order-meta { display: flex; gap: 16px; font-size: 11px; color: var(--text-muted); }
.order-status { display: inline-flex; align-items: center; gap: 6px; padding: 6px 12px; font-size: 11px; font-weight: 600; border-radius: var(--radius-full); }
.order-status.completed { background: var(--success-light); color: var(--success); }
.order-status.processing { background: var(--warning-light); color: var(--warning); }
.order-status.pending { background: var(--navy-100); color: var(--text-muted); }
.order-actions { display: flex; gap: 8px; flex-shrink: 0; }

/* Settings */
.settings-section { margin-bottom: 24px; }
.settings-title { font-size: 14px; font-weight: 700; color: var(--text-primary); margin-bottom: 14px; padding-bottom: 8px; border-bottom: 1px solid var(--border-light); }
.settings-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }
.setting-card { padding: 20px; background: var(--grad-surface); border: 1px solid var(--border-light); border-radius: var(--radius-lg); box-shadow: var(--shadow-sm); }
.setting-label { font-size: 12.5px; font-weight: 600; color: var(--text-primary); margin-bottom: 4px; }
.setting-desc { font-size: 12px; color: var(--text-muted); margin-bottom: 12px; }
.setting-input { width: 100%; }

/* ============================================================
   RESPONSIVE UTILITIES
   ============================================================ */
@media (max-width: 640px) {
  .settings-section { margin-bottom: 24px; }
  .settings-grid { grid-template-columns: minmax(0, 1fr); }
  .setting-card { min-width: 0; padding: 20px; }
  .setting-desc, .setting-label, #geminiModelInfo, #openrouterModelInfo, .setting-card code {
    overflow-wrap: anywhere;
    word-break: break-word;
  }
  .welcome { padding: 20px; border-radius: var(--radius-xl); }
  .welcome-action .btn-3d { width: 100%; }
  .panel { padding: 20px; }
  .section-head { flex-direction: column; align-items: flex-start; gap: 8px; }
  .upload-actions .btn-3d { width: 100%; }
  .order-item { flex-direction: column; align-items: flex-start; }
  .order-actions { width: 100%; }
  .order-actions .btn-3d { flex: 1; }
  .document-actions { flex-direction: column; }
  .document-actions .btn-3d { width: 100%; }
}

/* Print */
/* ============================================================
   PREMIUM UX ADDITIONS
   ============================================================ */

/* Mobile drawer: keep labels visible (the tablet icon-only rule must not
   collapse the 300px mobile drawer). */
.sidebar-close {
  display: none;
  position: absolute;
  top: 14px;
  right: 12px;
  width: 36px;
  height: 36px;
  place-items: center;
  border-radius: var(--radius-full);
  background: var(--navy-100);
  color: var(--text-secondary);
  font-size: 22px;
  line-height: 1;
  z-index: 2;
}
.sidebar-close:hover { background: var(--navy-200); color: var(--text-primary); }

@media (max-width: 640px) {
  .sidebar {
    width: 300px;
    padding: 20px 16px;
    overflow-y: auto;
  }
  .sidebar .brand-copy, .sidebar .nav-label, .sidebar .nav-text, .sidebar .side-bottom { display: block; }
  .sidebar .brand { justify-content: flex-start; padding: 8px 4px 28px; }
  .sidebar .nav a { justify-content: flex-start; padding: 12px 14px; gap: 12px; }
  .sidebar .nav-icon { font-size: 18px; width: 22px; text-align: center; }
  .sidebar-close { display: grid; }
}

/* File manager cards */
.file-item { position: relative; display: flex; flex-direction: column; }
.file-item img, .file-item .pdf-preview-frame { height: 112px; }
.file-item .file-remove {
  position: absolute;
  top: 6px;
  right: 6px;
  width: 26px;
  height: 26px;
  display: grid;
  place-items: center;
  border-radius: var(--radius-full);
  background: rgba(15, 23, 42, 0.72);
  color: var(--white);
  font-size: 16px;
  line-height: 1;
  box-shadow: var(--shadow-sm);
  z-index: 2;
}
.file-item .file-remove:hover { background: var(--error); }
.file-item .file-badge {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  align-self: flex-start;
  margin-bottom: 6px;
  padding: 2px 7px;
  border-radius: var(--radius-full);
  background: var(--accent-light);
  color: var(--accent-primary);
  font-size: 9px;
  font-weight: 700;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
.file-item .file-meta { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.file-item .file-meta small { white-space: nowrap; }
.file-item .file-name { display: block; font-size: 11px; font-weight: 600; color: var(--text-primary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; margin-bottom: 4px; }
.file-item.is-invalid { border-color: var(--error); background: var(--error-light); }
.file-hint { grid-column: 1 / -1; font-size: 11px; color: var(--text-muted); line-height: 1.5; }

/* AI / PDF processing panel */
.processing-card {
  margin-top: 18px;
  padding: 18px;
  border: 1px solid var(--border-light);
  border-radius: var(--radius-xl);
  background: linear-gradient(135deg, rgba(239,246,255,0.95), rgba(255,255,255,0.98));
  box-shadow: var(--shadow-sm);
}
.processing-card[hidden] { display: none; }
.processing-head { display: flex; align-items: center; gap: 14px; }
.processing-orb {
  width: 46px;
  height: 46px;
  flex: 0 0 46px;
  display: grid;
  place-items: center;
  border-radius: var(--radius-full);
  background: var(--grad-primary);
  color: var(--white);
  font-size: 22px;
  box-shadow: 0 0 0 0 rgba(30,58,138,0.28), 0 8px 20px rgba(30,58,138,0.22);
  animation: orbPulse 1.8s ease-in-out infinite;
}
.processing-card.success .processing-orb { animation: checkPop 0.4s var(--transition-bounce); background: var(--success); }
.processing-card.error .processing-orb { animation: none; background: var(--error); }
.processing-card.cancelled { border-color: var(--warning); }
.processing-card.error { animation: processingShake 0.32s ease-in-out; }
@keyframes processingShake {
  0%, 100% { transform: translateX(0); }
  25% { transform: translateX(-3px); }
  75% { transform: translateX(3px); }
}
.processing-card.cancelled .processing-orb { animation: none; background: var(--warning); }
.processing-copy { flex: 1; min-width: 0; }
.processing-meta { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-top: 10px; font-size: 11px; font-weight: 500; color: var(--text-muted); }
.processing-meta span:last-child { font-variant-numeric: tabular-nums; white-space: nowrap; }
.processing-cancel { padding: 7px 14px; font-size: 11px; }
.processing-card.cancelled .processing-progress > span { width: 100%; background: var(--warning); animation: none; }
.processing-title { font-size: 14px; font-weight: 700; color: var(--text-primary); }
.processing-subtitle { margin-top: 3px; font-size: 12px; color: var(--text-muted); }
.processing-steps { list-style: none; display: grid; gap: 8px; margin: 16px 0 0; padding: 0; }
.processing-step { display: flex; align-items: center; gap: 10px; font-size: 12px; color: var(--text-muted); transition: color var(--transition-fast); }
.processing-step .step-dot {
  width: 20px;
  height: 20px;
  flex: 0 0 20px;
  display: grid;
  place-items: center;
  border-radius: var(--radius-full);
  background: var(--navy-100);
  color: var(--text-muted);
  font-size: 10px;
  font-weight: 700;
}
.processing-step.active { color: var(--accent-primary); font-weight: 600; }
.processing-step.active .step-dot { background: var(--accent-light); color: var(--accent-primary); animation: stepPulse 1.2s ease-in-out infinite; }
.processing-step.done { color: var(--success); }
.processing-step.done .step-dot { background: var(--success); color: var(--white); }
.processing-progress { height: 3px; margin-top: 14px; overflow: hidden; border-radius: var(--radius-full); background: var(--navy-200); }
.processing-progress > span { display: block; width: 36%; height: 100%; border-radius: inherit; background: linear-gradient(90deg, var(--accent-primary), var(--accent-primary-light, #60a5fa), var(--accent-primary)); animation: indeterminate 1.35s ease-in-out infinite; }
.processing-progress.real > span { width: 0; animation: none; transition: width 0.18s ease-out; }
.processing-card.success .processing-progress > span { width: 100%; background: var(--success); animation: none; }
.processing-card.error .processing-progress > span { width: 100%; background: var(--error); animation: none; }
.processing-success-check { display: inline-grid; place-items: center; width: 20px; height: 20px; border-radius: var(--radius-full); background: var(--success); color: var(--white); font-size: 12px; animation: checkPop 0.4s var(--transition-bounce); }
.processing-actions { display: flex; gap: 8px; margin-top: 14px; }

/* Editor toolbar + preview actions */
.editor-toolbar { display: flex; flex-wrap: wrap; gap: 6px; margin: 10px 0 8px; }
.editor-toolbar button {
  min-width: 34px;
  padding: 6px 9px;
  border: 1px solid var(--border-light);
  border-radius: var(--radius-md);
  background: var(--white);
  color: var(--text-secondary);
  font-size: 12px;
  font-weight: 600;
}
.editor-toolbar button:hover { border-color: var(--accent-primary); color: var(--accent-primary); background: var(--accent-light); }
.preview-actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
.preview-actions .btn-3d { padding: 10px 16px; font-size: 12px; }
.editor-empty-hint { margin-top: 6px; font-size: 11px; color: var(--text-muted); }

/* PDF preview modal */
.modal-backdrop {
  display: none;
  position: fixed;
  inset: 0;
  z-index: calc(var(--z-toast) + 2);
  align-items: center;
  justify-content: center;
  padding: 18px;
  background: rgba(15,23,42,0.55);
  backdrop-filter: blur(5px);
}
.modal-backdrop.open { display: flex; }
.pdf-modal {
  display: flex;
  flex-direction: column;
  width: min(1040px, 96vw);
  height: min(90vh, 900px);
  overflow: hidden;
  border-radius: var(--radius-2xl);
  background: var(--white);
  box-shadow: var(--shadow-2xl);
}
.pdf-modal-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 14px 18px; border-bottom: 1px solid var(--border-light); }
.pdf-modal-head h3 { font-size: 15px; font-weight: 700; color: var(--text-primary); }
.pdf-modal-head p { font-size: 11px; color: var(--text-muted); margin-top: 2px; }
.pdf-modal-actions { display: flex; align-items: center; gap: 8px; flex: 0 0 auto; }
.pdf-modal-actions .btn-3d { padding: 8px 12px; font-size: 12px; }
.pdf-preview-body {
  flex: 1;
  min-height: 0;
  overflow: auto;
  padding: 18px;
  background: var(--navy-100);
  overscroll-behavior: contain;
}
.pdf-preview-pages { display: flex; flex-direction: column; align-items: center; gap: 18px; }
.pdf-preview-page {
  width: min(100%, 860px);
  overflow: hidden;
  border-radius: var(--radius-md);
  background: var(--white);
  box-shadow: var(--shadow-md);
}
.pdf-preview-page img { display: block; width: 100%; height: auto; }
.pdf-preview-note { max-width: 860px; margin: 0 auto 12px; padding: 9px 12px; border-radius: var(--radius-md); background: var(--white); color: var(--text-muted); font-size: 11px; text-align: center; }
.pdf-preview-state {
  display: flex;
  min-height: 100%;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 12px;
  padding: 30px 18px;
  text-align: center;
  color: var(--text-secondary);
}
.pdf-preview-state strong { font-size: 15px; color: var(--text-primary); }
.pdf-preview-state p { max-width: 460px; font-size: 12px; line-height: 1.6; color: var(--text-muted); }
.pdf-preview-spinner {
  width: 38px;
  height: 38px;
  border: 3px solid var(--navy-200);
  border-top-color: var(--accent-primary);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}
.pdf-preview-state.error .pdf-preview-spinner { display: none; }
.pdf-preview-state.error strong { color: var(--error); }
.pdf-preview-state .btn-3d { margin-top: 2px; }
@media (max-width: 700px) {
  .modal-backdrop { padding: 0; }
  .pdf-modal { width: 100vw; height: 100dvh; max-height: 100dvh; border-radius: 0; }
  .pdf-modal-head { padding: 12px 14px; align-items: flex-start; }
  .pdf-modal-head p { max-width: 220px; }
  .pdf-modal-actions .btn-3d { padding: 7px 10px; }
  .pdf-preview-body { padding: 8px; }
  .pdf-preview-pages { gap: 10px; }
  .pdf-preview-page { border-radius: 6px; }
}

/* Search / filter toolbars */
.document-meta, .order-meta { flex-wrap: wrap; align-items: center; }
.document-actions { flex-wrap: wrap; }
.order-item { flex-wrap: wrap; }
.list-toolbar { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 14px; }
.list-toolbar .form-input, .list-toolbar .form-select { min-width: 150px; flex: 1 1 170px; padding: 8px 10px; font-size: 12px; }
.list-toolbar .toolbar-count { font-size: 11px; color: var(--text-muted); white-space: nowrap; }

/* Toast actions */
.toast.processing { border-left-color: var(--accent-primary); }
.toast.processing .toast-icon { color: var(--accent-primary); animation: spin 0.9s linear infinite; }
.toast-action { margin-left: 6px; padding: 4px 8px; border-radius: var(--radius-sm); background: var(--accent-light); color: var(--accent-primary); font-size: 11px; font-weight: 700; white-space: nowrap; }
.toast-action:hover { background: var(--accent-primary); color: var(--white); }
.toast { pointer-events: auto; }

/* Accessible tooltips */
[data-tooltip] { position: relative; }
[data-tooltip]:hover::after, [data-tooltip]:focus-visible::after {
  content: attr(data-tooltip);
  position: absolute;
  left: 50%;
  bottom: calc(100% + 7px);
  transform: translateX(-50%);
  z-index: var(--z-toast);
  max-width: 220px;
  padding: 6px 8px;
  border-radius: var(--radius-sm);
  background: var(--navy-900);
  color: var(--white);
  font-size: 10px;
  line-height: 1.4;
  white-space: normal;
  box-shadow: var(--shadow-md);
  pointer-events: none;
}

/* Focus visibility */
:focus-visible { outline: 2px solid var(--accent-primary); outline-offset: 2px; }
.sidebar a:focus-visible, .mobile-nav-item:focus-visible { outline-offset: -2px; }

@keyframes orbPulse {
  0%, 100% { box-shadow: 0 0 0 0 rgba(30,58,138,0.26), 0 8px 20px rgba(30,58,138,0.20); transform: scale(1); }
  50% { box-shadow: 0 0 0 9px rgba(30,58,138,0.06), 0 8px 24px rgba(30,58,138,0.28); transform: scale(1.04); }
}
@keyframes stepPulse { 0%, 100% { transform: scale(1); } 50% { transform: scale(1.16); } }
@keyframes indeterminate { 0% { transform: translateX(-110%); } 100% { transform: translateX(310%); } }
@keyframes checkPop { 0% { transform: scale(0.4); opacity: 0; } 100% { transform: scale(1); opacity: 1; } }

@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: 0.001ms !important; animation-iteration-count: 1 !important; transition-duration: 0.001ms !important; scroll-behavior: auto !important; }
}

.premium-panel {
  margin-top: 18px;
  padding: 16px;
  border: 1px solid #fde68a;
  border-radius: 14px;
  background: linear-gradient(135deg, #fffbeb, #fefce8);
}
.premium-head { display: flex; align-items: center; gap: 9px; color: #92400e; margin-bottom: 6px; }
.premium-badge {
  display: inline-flex; align-items: center; padding: 3px 8px; border-radius: 999px;
  background: #f59e0b; color: #fff; font-size: 10px; font-weight: 800; letter-spacing: .08em;
}
.premium-panel p { margin: 5px 0; color: #78350f; font-size: 12.5px; line-height: 1.55; }
.premium-row { display: flex; gap: 8px; align-items: center; }
.premium-row .form-input { flex: 1; min-width: 0; }
#premiumStatus { font-weight: 600; }
#premiumStatus.ok { color: #166534; }
#premiumStatus.locked { color: #9a3412; }

.smart-block-list { display: grid; gap: 8px; margin-bottom: 18px; }
.smart-block {
  border: 1px solid var(--border-light); border-radius: 10px; padding: 10px 12px;
  background: var(--surface-2); font-size: 13px; line-height: 1.55;
}
.smart-block .smart-block-label {
  display: inline-block; margin-right: 8px; padding: 1px 6px; border-radius: 5px;
  background: var(--accent-light); color: var(--accent-primary);
  font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: .05em;
}
.smart-table { width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 12px; }
.smart-table th, .smart-table td { border: 1px solid var(--border-light); padding: 6px 8px; text-align: left; vertical-align: top; }
.smart-table th { background: var(--accent-light); color: var(--accent-primary); font-weight: 700; }
.diagram-review-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 14px; }
.diagram-card {
  border: 1px solid var(--border-light); border-radius: 14px; padding: 12px;
  background: var(--surface); box-shadow: var(--shadow-sm); display: flex; flex-direction: column; gap: 8px;
}
.diagram-card.excluded { opacity: .55; }
.diagram-card-head { display: flex; justify-content: space-between; gap: 8px; align-items: flex-start; }
.diagram-card-title { font-size: 14px; font-weight: 700; color: var(--text-primary); }
.diagram-card-meta { font-size: 11px; color: var(--text-muted); }
.diagram-preview {
  min-height: 120px; border-radius: 10px; background: var(--surface); border: 1px solid var(--border-light);
  display: flex; align-items: center; justify-content: center; flex-direction: column; overflow: hidden; padding: 6px;
}
.diagram-preview img { max-width: 100%; max-height: 260px; display: block; }
.diagram-preview .diagram-source-image { border-radius: 6px; box-shadow: var(--shadow-sm); }
.diagram-preview-note { font-size: 10px; color: var(--text-muted); margin-top: 6px; text-align: center; }
.diagram-preview .diagram-error { color: #b45309; font-size: 12px; padding: 12px; text-align: center; }
.smart-review-toolbar {
  display: flex; align-items: center; flex-wrap: wrap; gap: 8px 12px; margin-top: 12px;
  padding: 10px 12px; border: 1px solid var(--border-light); border-radius: 10px;
  background: var(--surface-2);
}
.smart-review-toolbar label { font-size: 12px; font-weight: 700; color: var(--text-secondary); }
.smart-review-toolbar select { max-width: 260px; padding: 7px 10px; font-size: 12px; }
.smart-review-toolbar-note { font-size: 11px; color: var(--text-muted); }
.diagram-actions { display: flex; flex-wrap: wrap; gap: 6px; }
.diagram-actions button { font-size: 11px; padding: 6px 9px; }
.diagram-labels { font-size: 11px; color: var(--text-muted); line-height: 1.45; }
.diagram-warning { font-size: 11px; color: #b45309; background: #fffbeb; border: 1px solid #fde68a; border-radius: 7px; padding: 6px 8px; }
.smart-review-note { font-size: 12px; color: var(--text-muted); margin-bottom: 10px; }
.smart-review-actions { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 12px; }

@media (max-width: 640px) {
  .premium-row { flex-direction: column; align-items: stretch; }
  .diagram-review-grid { grid-template-columns: 1fr; }
  .smart-review-toolbar { align-items: stretch; flex-direction: column; }
  .smart-review-toolbar select { max-width: 100%; width: 100%; }
  .processing-card { padding: 14px; }
  .processing-orb { width: 40px; height: 40px; flex-basis: 40px; font-size: 19px; }
  .processing-actions { flex-wrap: wrap; }
  .processing-actions .btn-3d { flex: 1 1 auto; }
}

@media print { .sidebar, .mobile-nav, .mobile-menu-btn, .topbar, .footer, .btn-3d, .dropzone, .upload-settings, .extract-actions, .upload-actions, .processing-card, .editor-toolbar, .preview-actions, .list-toolbar, .modal-backdrop, .premium-panel, .smart-review-actions { display: none !important; } .main { margin: 0; padding: 0; max-width: 100%; } .app { grid-template-columns: 1fr; } }

/* ============================================================
   GLASS & DEPTH UTILITIES (luxury layer)
   Extends existing components without duplicating them.
   ============================================================ */

/* Glass surfaces — readable contrast on every theme */
.surface-glass {
  background: var(--glass-bg);
  backdrop-filter: var(--glass-blur);
  -webkit-backdrop-filter: var(--glass-blur);
  border: 1px solid var(--glass-border);
  box-shadow: var(--elev-1), var(--depth-line);
}
.surface-glass-strong {
  background: var(--glass-bg-strong);
  backdrop-filter: var(--glass-blur-strong);
  -webkit-backdrop-filter: var(--glass-blur-strong);
  border: 1px solid var(--glass-border-strong);
  box-shadow: var(--elev-2), var(--depth-line);
}

/* Sheen highlight — top-light reflection for 3D depth */
.sheen {
  position: relative;
  overflow: hidden;
}
.sheen::before {
  content: '';
  position: absolute;
  inset: 0;
  border-radius: inherit;
  pointer-events: none;
  z-index: 2;
  background: linear-gradient(
    135deg,
    transparent 40%,
    var(--glass-sheen) 50%,
    transparent 60%
  );
  opacity: 0;
  transition: transform var(--transition-base), opacity var(--transition-base);
}
.sheen:hover::before {
  opacity: 1;
  transform: translateX(-100%) translateY(-50%);
}

/* Elevation tiers (applied on top of existing cards/panels) */
.depth-1 { box-shadow: var(--elev-1), var(--depth-line); }
.depth-2 { box-shadow: var(--elev-2), var(--depth-line); }
.depth-3 { box-shadow: var(--elev-3), var(--depth-line); }
.depth-4 { box-shadow: var(--elev-4), var(--depth-line); }
.depth-1:hover { box-shadow: var(--elev-2), var(--depth-line); }
.depth-2:hover { box-shadow: var(--elev-3), var(--depth-line); }
.depth-3:hover { box-shadow: var(--elev-4), var(--depth-line); }
.depth-4:hover { box-shadow: var(--shadow-2xl), var(--depth-line); }

/* Pressed state */
.pressed:active {
  transform: translateY(0) scale(0.995);
  box-shadow: var(--shadow-3d-press);
}

/* Glass ring focus for interactive surfaces */
.focus-ring:focus-within {
  border-color: var(--glass-ring);
  box-shadow: var(--elev-2), 0 0 0 4px var(--accent-light);
}

/* Keep text contrast guaranteed on glass — never let surfaces wash out copy */
.surface-glass, .surface-glass-strong, .panel, .stat-card, .card-3d, .card-glass, .card-elevated {
  color: var(--text-primary);
}

/* Fallback when backdrop-filter isn't available (low-end Android) */
@supports not (backdrop-filter) and not (-webkit-backdrop-filter) {
  .surface-glass { background: var(--white); }
  .surface-glass-strong { background: var(--white); }
  .surface-glass, .surface-glass-strong { border-color: var(--border-medium); }
}

/* ============================================================
   STUDY WORKSPACE, ADMIN, DOCUMENT MANAGEMENT
   ============================================================ */
.dashboard-grid { display: grid; grid-template-columns: minmax(0, 1.15fr) minmax(0, .85fr); gap: 18px; margin-bottom: 20px; perspective: 1400px; }
.dashboard-card { padding: 20px; perspective: 1200px; transform-style: preserve-3d; transition: transform var(--transition-base), box-shadow var(--transition-base); }
.dashboard-card:hover { transform: translateY(-3px) rotateX(1.5deg) translateZ(6px); box-shadow: var(--elev-3); }
.dashboard-card h3 { font-size: 15px; margin-bottom: 4px; }
.dashboard-card p { font-size: 12px; color: var(--text-muted); margin-bottom: 14px; }
.quick-actions { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 9px; }
.quick-action { display: flex; align-items: center; gap: 9px; padding: 11px 12px; border: 1px solid var(--border-light); border-radius: var(--radius-md); background: var(--white); font-size: 12px; font-weight: 600; color: var(--text-secondary); transition: all var(--transition-fast); }
.quick-action:hover { border-color: var(--accent-primary); color: var(--accent-primary); background: var(--accent-light); transform: translateY(-1px); }
.quick-action span { font-size: 16px; }
.recent-mini-list { display: flex; flex-direction: column; gap: 8px; }
.recent-mini { display: flex; gap: 10px; align-items: center; padding: 9px 10px; border-radius: var(--radius-md); background: var(--surface-2); }
.recent-mini-icon { width: 34px; height: 34px; border-radius: 9px; display: grid; place-items: center; background: var(--accent-light); color: var(--accent-primary); flex: 0 0 34px; }
.recent-mini strong { display: block; font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.recent-mini small { display: block; font-size: 10px; color: var(--text-muted); }
.study-layout { display: grid; grid-template-columns: minmax(0, 1.15fr) minmax(0, .85fr); gap: 18px; }
.study-panel { padding: 20px; }
.study-actions { display: flex; flex-wrap: wrap; gap: 7px; margin: 10px 0 4px; }
.study-chip { padding: 6px 10px; border: 1px solid var(--border-medium); border-radius: var(--radius-full); background: var(--white); font-size: 10.5px; font-weight: 600; color: var(--text-secondary); }
.study-chip:hover, .study-chip.active { border-color: var(--accent-primary); background: var(--accent-light); color: var(--accent-primary); }
.study-fields { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; margin-top: 10px; }
.study-fields label { display: block; font-size: 11px; font-weight: 700; color: var(--text-muted); margin-bottom: 5px; }
.study-source, .study-notes { width: 100%; padding: 10px 12px; border: 1px solid var(--border-medium); border-radius: var(--radius-md); background: var(--white); font-size: 12px; }
.study-notes { min-height: 150px; resize: vertical; line-height: 1.65; }
.study-result { margin-top: 16px; padding: 16px; border: 1px solid var(--border-light); border-radius: var(--radius-lg); background: var(--surface-2); }
.study-result-head { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 8px; margin-bottom: 10px; }
.study-result-text { white-space: pre-wrap; overflow-wrap: anywhere; font-family: inherit; font-size: 12.5px; line-height: 1.7; color: var(--text-primary); margin: 0; }
.study-saved { display: flex; flex-direction: column; gap: 8px; margin-top: 12px; }
.study-set { padding: 11px; border: 1px solid var(--border-light); border-radius: var(--radius-md); background: var(--white); }
.study-set strong { display: block; font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.study-set small { display: block; color: var(--text-muted); font-size: 10px; margin: 2px 0 7px; }
.study-set-actions { display: flex; gap: 6px; flex-wrap: wrap; }
.study-set-actions button { font-size: 10px; padding: 5px 8px; }
.admin-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin: 14px 0 20px; }
.admin-stat { padding: 15px; border: 1px solid var(--border-light); border-radius: var(--radius-lg); background: var(--white); }
.admin-stat span { display: block; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: .06em; color: var(--text-muted); }
.admin-stat strong { display: block; font-size: 24px; line-height: 1.2; margin-top: 5px; color: var(--text-primary); }
.admin-stat small { display: block; font-size: 10px; color: var(--text-muted); margin-top: 3px; }
.admin-columns { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }
.admin-block { padding: 16px; border: 1px solid var(--border-light); border-radius: var(--radius-lg); background: var(--white); margin-bottom: 14px; }
.admin-block h4 { font-size: 13px; margin-bottom: 10px; }
.admin-list { display: flex; flex-direction: column; gap: 7px; }
.admin-row { display: flex; justify-content: space-between; gap: 10px; padding: 7px 0; border-bottom: 1px solid var(--border-light); font-size: 11px; }
.admin-row:last-child { border-bottom: 0; }
.admin-row span:last-child { color: var(--text-muted); text-align: right; }
.admin-form { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
.admin-form .form-input, .admin-form .form-select { padding: 8px 10px; font-size: 12px; }
.admin-form button { grid-column: 1 / -1; }
.document-badges { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 6px; }
.doc-badge { padding: 2px 7px; border-radius: var(--radius-full); background: var(--navy-100); color: var(--text-muted); font-size: 9px; font-weight: 600; }
.doc-badge.favorite { background: #fef3c7; color: #b45309; }
/* === Premium Plan Cards === */
.plan-card {
  position: relative;
  padding: 32px 24px;
  background: var(--glass-bg-strong);
  backdrop-filter: var(--glass-blur-strong);
  -webkit-backdrop-filter: var(--glass-blur-strong);
  border: 1px solid var(--glass-border);
  border-radius: var(--radius-xl);
  box-shadow: var(--shadow-lg), var(--depth-line);
  text-align: center;
  transition: box-shadow var(--transition-base), transform var(--transition-base);
}
.plan-card:hover { box-shadow: var(--shadow-xl), var(--depth-line); transform: translateY(-4px); }
.plan-card:active { box-shadow: var(--shadow-3d-press); transform: translateY(0); }
.plan-card::before {
  content: "";
  position: absolute;
  top: 0; left: 0; right: 0; height: 3px;
  background: var(--grad-primary);
  opacity: 0; transition: opacity var(--transition-base);
}
.plan-card:hover::before { opacity: 1; }
.plan-card.selected {
  border-color: var(--accent-primary);
  box-shadow: var(--shadow-premium);
}
.plan-card .plan-name {
  font-size: 18px;
  font-weight: 700;
  letter-spacing: -0.02em;
  color: var(--text-primary);
  margin-bottom: 4px;
}
.plan-card .plan-price {
  font-size: 32px;
  font-weight: 800;
  color: var(--accent-primary);
  margin: 16px 0;
}
.plan-card .plan-period {
  font-size: 12px;
  color: var(--text-muted);
  margin-bottom: 24px;
}
.plan-card .plan-features {
  text-align: left;
  max-width: 360px;
  margin: 0 auto 24px;
}
.plan-card .plan-feature {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 0;
  border-bottom: 1px solid var(--border-light);
  font-size: 13px;
  color: var(--text-secondary);
  transition: color var(--transition-fast);
}
.plan-card .plan-feature:hover { color: var(--accent-primary); }
.plan-card .plan-feature-icon {
  width: 20px;
  height: 20px;
  border-radius: var(--radius-full);
  background: var(--success-light);
  color: var(--success);
  display: grid;
  place-items: center;
  flex-shrink: 0;
}
.plan-action {
  width: 100%;
  padding: 14px 24px;
  font-size: 14px;
  font-weight: 600;
  background: var(--grad-primary);
  color: var(--white);
  border: none;
  border-radius: var(--radius-lg);
  margin-top: 8px;
  transition: background var(--transition-fast), transform var(--transition-fast);
}
.plan-action:hover { background: var(--grad-primary-hover); transform: translateY(-2px); }
.plan-action:active { transform: scale(0.98); }
@media (max-width: 900px) {
  .plan-card { padding: 24px 16px; }
  .plan-price { font-size: 24px; }
}
@media (max-width: 600px) {
  .plan-card { padding: 16px; }
  .plan-price { font-size: 20px; }
}
.doc-badge.folder { background: var(--accent-light); color: var(--accent-primary); }
.document-actions .btn-3d { padding: 8px 10px; font-size: 11px; }
.pagination { display: flex; align-items: center; justify-content: center; gap: 8px; margin-top: 16px; flex-wrap: wrap; }
.pagination button { padding: 7px 10px; border: 1px solid var(--border-medium); border-radius: var(--radius-sm); background: var(--white); font-size: 11px; }
.pagination button:disabled { opacity: .45; cursor: not-allowed; }
.pagination span { font-size: 11px; color: var(--text-muted); }
.document-modal { width: min(620px, 94vw); max-height: 90vh; overflow: auto; padding: 20px; border-radius: var(--radius-xl); background: var(--white); box-shadow: var(--shadow-2xl); }
.document-modal h3 { font-size: 17px; margin-bottom: 4px; }
.document-modal p { font-size: 11px; color: var(--text-muted); margin-bottom: 14px; }
.document-form { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
.document-form label { display: block; font-size: 10px; font-weight: 700; color: var(--text-muted); margin-bottom: 4px; }
.document-form .form-input, .document-form .form-select { width: 100%; padding: 8px 10px; font-size: 12px; }
.document-form .wide { grid-column: 1 / -1; }
.document-modal-actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 14px; }
.document-modal-actions .danger { color: var(--error); }
.pdf-studio { margin-top: 16px; border: 1px solid var(--border-light); border-radius: var(--radius-lg); padding: 14px; background: var(--surface-2); }
.pdf-studio .studio-summary { cursor: pointer; display: flex; align-items: center; gap: 8px; font-size: 13px; font-weight: 700; color: var(--text-primary); padding: 10px 12px; border-radius: var(--radius-md); background: var(--white); border: 1px solid var(--border-medium); margin-bottom: 12px; }
.pdf-studio .studio-summary[role="button"] { cursor: pointer; }
.pdf-studio[open] > .studio-summary { background: var(--accent-light); color: var(--accent-primary); border-color: var(--accent-primary); margin-bottom: 14px; }
.pdf-studio .studio-intro { font-size: 12px; color: var(--text-muted); margin: 0 0 16px; line-height: 1.6; }

.pdf-studio .studio-section { margin-bottom: 16px; }
.pdf-studio .studio-section-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 10px; padding-bottom: 8px; border-bottom: 1px solid var(--border-light); }
.pdf-studio .studio-section-title { font-size: 13px; font-weight: 700; color: var(--text-primary); letter-spacing: -0.01em; margin: 0; }
.pdf-studio .studio-section-desc { font-size: 11px; color: var(--text-secondary); margin: 0; }

.pdf-studio .studio-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px 14px; margin-top: 4px; }
.pdf-studio .studio-field { display: flex; flex-direction: column; gap: 5px; }
.pdf-studio .studio-field.wide { grid-column: 1 / -1; }
.pdf-studio .studio-field-label { font-size: 11.5px; font-weight: 700; color: var(--text-primary); }
.pdf-studio .studio-field-hint { font-size: 10px; color: var(--text-muted); line-height: 1.45; margin-bottom: 2px; }
.pdf-studio .studio-field .form-input, .pdf-studio .studio-field .form-select { width: 100%; padding: 8px 10px; font-size: 12px; }
.pdf-studio .studio-accent-row { display: flex; align-items: center; gap: 8px; margin-top: 2px; }
.pdf-studio .studio-accent-hint { font-size: 9.5px; color: var(--text-muted); }

.admin-lock { padding: 18px; border: 1px dashed var(--border-medium); border-radius: var(--radius-lg); background: var(--surface-2); }
@media (max-width: 950px) {
  .dashboard-grid, .study-layout, .admin-columns { grid-template-columns: 1fr; }
  .admin-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .pdf-studio .studio-grid { grid-template-columns: 1fr; }
}
@media (max-width: 600px) {
  .quick-actions, .study-fields, .admin-form, .document-form { grid-template-columns: 1fr; }
  .admin-grid { grid-template-columns: 1fr 1fr; gap: 8px; }
  .admin-stat { padding: 11px; }
  .admin-stat strong { font-size: 19px; }
  .pdf-studio .studio-grid { grid-template-columns: 1fr; }
  .study-panel { padding: 15px; }
}
}
/* --- Animated Download Button (ab-13) --- */
.ab-13 { display: inline-flex; flex-direction: column; align-items: center; gap: 6px; }
.ab-13__label { font-size: 11px; color: var(--text-muted); margin: 0; }
.ab-13__btn {
  display: inline-flex; align-items: center; gap: 8px;
  padding: 10px 20px; border: none; border-radius: var(--radius-md);
  background: var(--grad-primary); color: var(--white);
  font-size: 13px; font-weight: 600; cursor: pointer;
  transition: transform 0.2s, box-shadow 0.2s, background 0.3s;
  box-shadow: var(--shadow-3d);
  position: relative; overflow: hidden;
}
.ab-13__btn:hover { transform: translateY(-2px); box-shadow: var(--shadow-3d-hover); }
.ab-13__btn:active { transform: scale(0.96); }
.ab-13__btn:disabled { opacity: 0.7; cursor: not-allowed; transform: none; }
.ab-13__btn--loading { background: var(--navy-600); }
.ab-13__btn--success { background: #059669; }
.ab-13__btn--error { background: #dc2626; }
.ab-13__icon {
  width: 18px; height: 18px;
  transition: transform 0.3s ease;
}
.ab-13__btn--loading .ab-13__icon {
  animation: ab-13-spin 1s linear infinite;
}
.ab-13__btn--success .ab-13__icon {
  animation: ab-13-bounce 0.4s ease;
}
@keyframes ab-13-spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}
@keyframes ab-13-bounce {
  0%, 100% { transform: scale(1); }
  50% { transform: scale(1.3); }
}
.ab-13__text { white-space: nowrap; }
.ab-13__size { font-size: 10px; color: var(--text-muted); margin: 0; }
@media (max-width: 640px) {
  .ab-13__btn { padding: 8px 16px; font-size: 12px; }
  .ab-13__icon { width: 16px; height: 16px; }
}
</style>
</head>
<body>
<!-- Shared navigation icon sprite: defined once, reused by desktop + mobile nav -->
<svg class="icon-sprite" aria-hidden="true" focusable="false" xmlns="http://www.w3.org/2000/svg">
  <symbol id="icon-home" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 10.5 12 3l9 7.5"/><path d="M5 9.5V21h14V9.5"/><path d="M9.5 21v-6h5v6"/></symbol>
  <symbol id="icon-notes" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 8h8M8 12h8M8 16h5"/></symbol>
  <symbol id="icon-upload" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 16V4"/><path d="m7 9 5-5 5 5"/><path d="M4 16v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3"/></symbol>
  <symbol id="icon-history" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></symbol>
  <symbol id="icon-study" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 5.5A2.5 2.5 0 0 1 6.5 3H20v16H6.5A2.5 2.5 0 0 0 4 21.5z"/><path d="M8 7h8M8 11h6M8 15h4"/></symbol>
  <symbol id="icon-admin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 4.5 6v5.5c0 4.6 3.2 8 7.5 9.5 4.3-1.5 7.5-4.9 7.5-9.5V6z"/><path d="m9 12 2 2 4-4"/></symbol>
  <symbol id="icon-settings" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1"/></symbol>
  <symbol id="icon-menu" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 6h16M4 12h16M4 18h16"/></symbol>
</svg>

<!-- Skip link for keyboard and screen-reader users -->
<a class="skip-link" href="#mainContent">Skip to content</a>

<!-- Mobile Menu Button -->
<button class="mobile-menu-btn" id="mobileMenuBtn" aria-label="Open menu" aria-expanded="false">
  <svg width="24" height="24" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><use href="#icon-menu"></use></svg>
</button>

<!-- Sidebar Overlay -->
<div class="sidebar-overlay" id="sidebarOverlay" aria-hidden="true"></div>

<!-- Sidebar -->
<aside class="sidebar" id="sidebar" role="navigation" aria-label="Main navigation">
  <button type="button" class="sidebar-close" id="sidebarClose" aria-label="Close navigation menu">&times;</button>
  <div class="brand">
    <div class="logo" aria-hidden="true">N</div>
    <div class="brand-copy">
      <strong>NotesAI</strong>
      <small>Premium Workspace</small>
    </div>
  </div>

  <div class="nav-label">Workspace</div>
  <nav class="nav">
    <a class="{% if page == 'dashboard' %}active{% endif %}" href="/" data-page="dashboard" aria-label="Dashboard" title="Dashboard"{% if page == 'dashboard' %} aria-current="page"{% endif %}><svg class="nav-icon" aria-hidden="true" focusable="false"><use href="#icon-home"></use></svg><span class="nav-text">Dashboard</span></a>
    <a class="{% if page == 'study' %}active{% endif %}" href="/study" data-page="study" aria-label="AI Study" title="AI Study"{% if page == 'study' %} aria-current="page"{% endif %}><svg class="nav-icon" aria-hidden="true" focusable="false"><use href="#icon-study"></use></svg><span class="nav-text">AI Study</span></a>
    <a class="{% if page == 'my-notes' %}active{% endif %}" href="/my-notes" data-page="my-notes" aria-label="My Notes" title="My Notes"{% if page == 'my-notes' %} aria-current="page"{% endif %}><svg class="nav-icon" aria-hidden="true" focusable="false"><use href="#icon-notes"></use></svg><span class="nav-text">My Notes</span></a>
    <a class="{% if page == 'new-order' %}active{% endif %}" href="/new-order" data-page="new-order" aria-label="PDF Studio" title="PDF Studio"{% if page == 'new-order' %} aria-current="page"{% endif %}><svg class="nav-icon" aria-hidden="true" focusable="false"><use href="#icon-upload"></use></svg><span class="nav-text">PDF Studio</span></a>
    <a class="{% if page == 'history' %}active{% endif %}" href="/history" data-page="history" aria-label="History" title="History"{% if page == 'history' %} aria-current="page"{% endif %}><svg class="nav-icon" aria-hidden="true" focusable="false"><use href="#icon-history"></use></svg><span class="nav-text">History</span></a>
  </nav>

  <div class="nav-label">Workspace</div>
  <nav class="nav">
    <a class="{% if page == 'admin' %}active{% endif %}" href="/admin" data-page="admin" aria-label="Admin" title="Admin"{% if page == 'admin' %} aria-current="page"{% endif %}><svg class="nav-icon" aria-hidden="true" focusable="false"><use href="#icon-admin"></use></svg><span class="nav-text">Admin</span></a>
    <a class="{% if page == 'settings' %}active{% endif %}" href="/settings" data-page="settings" aria-label="Settings" title="Settings"{% if page == 'settings' %} aria-current="page"{% endif %}><svg class="nav-icon" aria-hidden="true" focusable="false"><use href="#icon-settings"></use></svg><span class="nav-text">Settings</span></a>
  </nav>

  <div class="side-bottom">
    <span class="premium-badge"><span aria-hidden="true">✦</span> Premium Workspace</span>
    <p>Transform handwritten notes into polished digital documents with AI precision.</p>
  </div>
</aside>

<!-- Main Content -->
<main class="main" id="mainContent" role="main">
  {% if page == 'dashboard' %}
  <!-- Dashboard Header -->
  <header class="topbar" role="banner">
    <div class="topbar-left">
      <div class="eyebrow">PREMIUM WORKSPACE</div>
      <h1>Dashboard</h1>
    </div>
    <div class="avatar" aria-hidden="true">N</div>
  </header>

  <!-- Welcome Hero -->
  <section class="welcome hero" aria-labelledby="welcome-title">
    <div class="hero-glow" aria-hidden="true"></div>
    <div class="welcome-content">
      <h2 id="welcome-title">Ideas, refined. <span>Effortlessly.</span></h2>
      <p>Transform handwritten notes into polished digital documents with AI-powered precision.</p>
    </div>
    <a class="btn-3d btn-primary welcome-action" href="/new-order"><span aria-hidden="true">＋</span> Create New Order</a>
  </section>

  <!-- Statistics -->
  <section class="stats" aria-label="Workspace statistics">
    <article class="stat-card">
      <div class="stat-header">
        <span class="stat-label">Stored Documents</span>
        <span class="stat-icon" aria-hidden="true">▤</span>
      </div>
      <div class="stat-value" id="statTotal">—</div>
      <p class="stat-desc">Active files in this workspace</p>
    </article>
    <article class="stat-card">
      <div class="stat-header">
        <span class="stat-label">In Progress</span>
        <span class="stat-icon" aria-hidden="true">◷</span>
      </div>
      <div class="stat-value" id="statProgress">—</div>
      <p class="stat-desc">Orders being processed</p>
    </article>
    <article class="stat-card">
      <div class="stat-header">
        <span class="stat-label">Completed</span>
        <span class="stat-icon" aria-hidden="true">✓</span>
      </div>
      <div class="stat-value" id="statCompleted">—</div>
      <p class="stat-desc">All-time completed jobs</p>
    </article>
    <article class="stat-card">
      <div class="stat-header">
        <span class="stat-label">Failed Jobs</span>
        <span class="stat-icon" aria-hidden="true">!</span>
      </div>
      <div class="stat-value" id="statFailed">—</div>
      <p class="stat-desc">All-time failed jobs</p>
    </article>
    <article class="stat-card">
      <div class="stat-header">
        <span class="stat-label">Storage Used</span>
        <span class="stat-icon" aria-hidden="true">◫</span>
      </div>
      <div class="stat-value" id="statStorage">—</div>
      <p class="stat-desc">Local PDF workspace</p>
    </article>
    <article class="stat-card">
      <div class="stat-header">
        <span class="stat-label">Workspace Plan</span>
        <span class="stat-icon" aria-hidden="true">✦</span>
      </div>
      <div class="stat-value" id="statPlan" style="font-size:22px;">—</div>
      <p class="stat-desc" id="statPlanDesc">Loading plan…</p>
    </article>
  </section>

  <!-- Workspace Plan -->
  <article class="panel plan-card depth-3 sheen">
    <div class="plan-head">
      <div class="panel-eyebrow">WORKSPACE PLAN</div>
      <div class="plan-title-wrap">
        <h3 id="planTitle">Loading plan…</h3>
        <span class="plan-badge" id="planBadge">—</span>
      </div>
    </div>
    <p id="planDesc">Your NotesAI workspace plan and limits.</p>
    <div class="plan-stats" id="planStats" style="display:grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-top: 14px;">
      <div class="plan-stat">
        <div class="plan-stat-value" id="planMaxDocs">—</div>
        <div class="plan-stat-label">Max documents</div>
      </div>
      <div class="plan-stat">
        <div class="plan-stat-value" id="planStorage">—</div>
        <div class="plan-stat-label">Storage</div>
      </div>
      <div class="plan-stat">
        <div class="plan-stat-value" id="planStatus">—</div>
        <div class="plan-stat-label">Status</div>
      </div>
    </div>
    <div class="plan-actions" style="display:flex; gap:8px; margin-top: 14px; flex-wrap:wrap;">
      <a class="btn-3d btn-secondary" href="/settings"><span aria-hidden="true">⚙</span> Manage Workspace</a>
    </div>
  </article>

  <div class="dashboard-grid">
    <article class="panel dashboard-card depth-2 sheen">
      <div class="dash-card-head">
        <h3>Quick actions</h3>
        <span class="dash-card-chip">01 / CREATE</span>
      </div>
      <p>Jump straight into the workspace.</p>
      <div class="quick-actions">
        <a class="quick-action" href="/new-order"><span aria-hidden="true">✦</span> Create a PDF</a>
        <a class="quick-action" href="/study"><span aria-hidden="true">✧</span> Study with AI</a>
        <a class="quick-action" href="/my-notes"><span aria-hidden="true">▤</span> My documents</a>
        <a class="quick-action" href="/admin"><span aria-hidden="true">◈</span> Admin overview</a>
      </div>
    </article>
    <article class="panel dashboard-card depth-2 sheen">
      <div class="dash-card-head">
        <h3>Recent documents</h3>
        <span class="dash-card-chip">02 / LIBRARY</span>
      </div>
      <p>Your newest generated files.</p>
      <div class="recent-mini-list" id="dashboardRecent">
        <div class="empty-state" style="padding:16px;"><p>No documents yet.</p></div>
      </div>
    </article>
    <article class="panel dashboard-card depth-2 sheen">
      <div class="dash-card-head">
        <h3>Recent activity</h3>
        <span class="dash-card-chip">03 / TIMELINE</span>
      </div>
      <p>Your latest document actions.</p>
      <div class="activity-timeline" id="dashboardActivity">
        <div class="empty-state" style="padding:12px 16px;"><p>No recent activity.</p></div>
      </div>
    </article>
  </div>
  {% elif page == 'new-order' %}
  <!-- New Order Page - Focused Upload Workspace -->
  <div class="section-head">
    <h2>Document Studio</h2>
    <span class="section-badge">CREATE NEW ORDER</span>
  </div>
  {% else %}
  <!-- Navigation Page Header for my-notes, history, settings -->
  <div class="page-header">
    <div>
      <h1 class="page-title">{{ page_title }}</h1>
      <p class="page-desc">{{ page_desc }}</p>
    </div>
  </div>
  {% endif %}

  <section class="workspace" aria-label="Workspace panels">
    {% if page == 'dashboard' or page == 'new-order' %}
    <!-- Document Studio Panel -->
    <article class="panel" id="upload">
      <div class="panel-header">
        <div class="panel-eyebrow">AI CONVERSION</div>
        <h3>Bring your notes to life</h3>
        <p>Select handwritten-note images or an existing PDF. Preview files, choose page settings, and generate a premium PDF.</p>
      </div>

      <form id="uploadForm" enctype="multipart/form-data" novalidate>
        <input type="hidden" id="jobId" name="jobId" value="">
        <!-- Dropzone -->
        <div class="dropzone" id="dropzone" role="button" tabindex="0" aria-label="Upload files: drag and drop, or press Enter to choose files">
          <div class="dropzone-icon" aria-hidden="true">✧</div>
          <strong>Your document starts here</strong>
          <p>JPG, PNG, WEBP, BMP or PDF · Maximum 20 MB</p>
          <button type="button" class="btn-outline" onclick="document.getElementById('noteFile').click()">Choose Files</button>
          <input id="noteFile" name="noteFiles" type="file" accept="image/*,.pdf" multiple hidden aria-label="File input">
          <div id="filePreview" class="file-preview" aria-live="polite"><p>No file selected</p></div>
        </div>

        <!-- Upload Settings -->
        <div class="upload-settings">
          <label>
            <span class="form-label">Page Size</span>
            <select name="pageSize" class="form-select">
              <option value="A4">A4</option>
              <option value="Letter">Letter</option>
            </select>
          </label>
          <label>
            <span class="form-label">Orientation</span>
            <select name="orientation" class="form-select">
              <option value="P">Portrait</option>
              <option value="L">Landscape</option>
            </select>
          </label>
          <label>
            <span class="form-label">Page Margin</span>
            <select name="margin" class="form-select">
              <option value="8">Compact (8mm)</option>
              <option value="12" selected>Standard (12mm)</option>
              <option value="16">Wide (16mm)</option>
            </select>
          </label>
        </div>

        <!-- PDF Output Mode -->
        <div class="upload-settings mode-settings" style="margin-top: 20px;">
          <div class="mode-field">
            <span class="form-label" id="pdfModeLabel">PDF Output Mode</span>
            <!-- Native select stays as the submitted form value; the visible
                 cards give every mode the same size, type and spacing. -->
            <select name="mode" id="pdfMode" class="visually-hidden" tabindex="-1" aria-hidden="true">
              <option value="professional">Professional Text PDF</option>
              <option value="image">Original Image PDF</option>
              <option value="smart">Smart Recreated PDF</option>
            </select>
            <div class="mode-grid" id="pdfModeCards" role="radiogroup" aria-labelledby="pdfModeLabel">
              <label class="mode-card selected" data-mode="professional">
                <input type="radio" name="modeChoice" value="professional" checked>
                <span class="mode-card-title">Professional Text PDF</span>
                <span class="mode-card-desc">AI-structured text, real tables, formulas and clean typography.</span>
              </label>
              <label class="mode-card" data-mode="image">
                <input type="radio" name="modeChoice" value="image">
                <span class="mode-card-title">Original Image PDF</span>
                <span class="mode-card-desc">Keep your uploaded pages exactly as they are, safely embedded.</span>
              </label>
              <label class="mode-card" data-mode="smart">
                <input type="radio" name="modeChoice" value="smart">
                <span class="mode-card-title">Smart Recreated PDF <span class="free-badge">FREE</span></span>
                <span class="mode-card-desc">Content-aware layout, universal diagrams, tables and charts.</span>
              </label>
            </div>
          </div>
        </div>

        <!-- PDF Studio — organized, beginner-friendly settings -->
        <details class="pdf-studio" open>
          <summary class="studio-summary" role="button" aria-expanded="true">
            <span aria-hidden="true">✎</span> PDF Studio — design your PDF
          </summary>
          <p class="studio-intro">These controls change how your PDF looks. Your original extracted content is never removed or rewritten.</p>

          <div class="studio-section">
            <div class="studio-section-head">
              <h4 class="studio-section-title">A. Document Design</h4>
              <p class="studio-section-desc">Pick the look and feel of your PDF.</p>
            </div>
            <div class="studio-grid">
              <label class="studio-field wide">
                <span class="studio-field-label">Document title</span>
                <span class="studio-field-hint">Title shown on the cover and first page. Leave empty to use the extracted title.</span>
                <input class="form-input" name="title" maxlength="200" placeholder="Leave empty to use the extracted title">
              </label>
              <label class="studio-field wide">
                <span class="studio-field-label">Subtitle</span>
                <span class="studio-field-hint">Optional short line shown under the title.</span>
                <input class="form-input" name="subtitle" maxlength="300" placeholder="Optional subtitle">
              </label>
              <label class="studio-field">
                <span class="studio-field-label">Document style</span>
                <span class="studio-field-hint">Controls headings, colors and overall mood.</span>
                <select class="form-select" name="style">
                  <option value="professional">Professional</option>
                  <option value="academic">Academic</option>
                  <option value="minimal">Minimal</option>
                  <option value="modern">Modern</option>
                </select>
              </label>
              <label class="studio-field">
                <span class="studio-field-label">Text size</span>
                <span class="studio-field-hint">Choose how large the text will appear in your PDF.</span>
                <select class="form-select" name="fontSize">
                  <option value="9">9 pt — compact</option>
                  <option value="10">10 pt</option>
                  <option value="11" selected>11 pt — standard</option>
                  <option value="12">12 pt</option>
                  <option value="13">13 pt</option>
                  <option value="14">14 pt — large</option>
                </select>
              </label>
              <label class="studio-field">
                <span class="studio-field-label">Accent color</span>
                <span class="studio-field-hint">Choose the main color used in your PDF design.</span>
                <span class="studio-accent-row">
                  <input class="form-input" name="accentColor" type="color" value="#1e3a8a" aria-label="PDF accent color">
                  <input type="checkbox" name="useAccentColor" value="1" aria-label="Use custom accent color">
                  <span class="studio-accent-hint">Override the style’s default colors</span>
                </span>
              </label>
            </div>
          </div>

          <div class="studio-section">
            <div class="studio-section-head">
              <h4 class="studio-section-title">B. Page Settings</h4>
              <p class="studio-section-desc">Set paper size, edges and page numbers.</p>
            </div>
            <div class="studio-grid">
              <label class="studio-field">
                <span class="studio-field-label">Page size</span>
                <span class="studio-field-hint">Choose the paper size for your PDF.</span>
                <select class="form-select" name="pageSize">
                  <option value="A4">A4</option>
                  <option value="Letter">Letter</option>
                </select>
              </label>
              <label class="studio-field">
                <span class="studio-field-label">Orientation</span>
                <span class="studio-field-hint">Portrait is taller; Landscape is wider.</span>
                <select class="form-select" name="orientation">
                  <option value="P">Portrait</option>
                  <option value="L">Landscape</option>
                </select>
              </label>
              <label class="studio-field">
                <span class="studio-field-label">Page margin</span>
                <span class="studio-field-hint">Space between the content and the page edge.</span>
                <select class="form-select" name="margin">
                  <option value="8">Compact (8 mm)</option>
                  <option value="12" selected>Standard (12 mm)</option>
                  <option value="16">Wide (16 mm)</option>
                </select>
              </label>
              <label class="studio-field wide">
                <span class="studio-field-label">Page numbers</span>
                <span class="studio-field-hint">Show page numbers on each printed page.</span>
                <select class="form-select" name="showPageNumbers">
                  <option value="1" selected>Show</option>
                  <option value="0">Hide</option>
                </select>
              </label>
              <label class="studio-field wide">
                <span class="studio-field-label">Cover page</span>
                <span class="studio-field-hint">Add a title page before your document.</span>
                <input type="checkbox" name="coverPage" value="1">
              </label>
              <label class="studio-field wide">
                <span class="studio-field-label">Table of contents</span>
                <span class="studio-field-hint">Adds a contents list. Works best when your document has two or more headings.</span>
                <input type="checkbox" name="includeToc" value="1">
              </label>
            </div>
          </div>

          <div class="studio-section">
            <div class="studio-section-head">
              <h4 class="studio-section-title">C. Header and Footer</h4>
              <p class="studio-section-desc">Add text at the top and bottom of each page.</p>
            </div>
            <div class="studio-grid">
              <label class="studio-field wide">
                <span class="studio-field-label">Header text</span>
                <span class="studio-field-hint">Text shown at the top of each page. Defaults to the document title.</span>
                <input class="form-input" name="headerText" maxlength="120" placeholder="Defaults to document title">
              </label>
              <label class="studio-field wide">
                <span class="studio-field-label">Footer text</span>
                <span class="studio-field-hint">Text shown at the bottom of each page. Defaults to “NotesAI”.</span>
                <input class="form-input" name="footerText" maxlength="160" placeholder="Defaults to NotesAI">
              </label>
            </div>
          </div>

          <div class="studio-section">
            <div class="studio-section-head">
              <h4 class="studio-section-title">D. Document Organization</h4>
              <p class="studio-section-desc">File your document so it is easy to find later.</p>
            </div>
            <div class="studio-grid">
              <label class="studio-field">
                <span class="studio-field-label">Folder</span>
                <span class="studio-field-hint">Example: Semester 2, Biology, Revision.</span>
                <input class="form-input" name="folder" maxlength="80" placeholder="e.g. Semester 2">
              </label>
              <label class="studio-field wide">
                <span class="studio-field-label">Tags</span>
                <span class="studio-field-hint">Comma-separated keywords. Example: biology, revision.</span>
                <input class="form-input" name="tags" maxlength="200" placeholder="biology, revision">
              </label>
              <label class="studio-field">
                <span class="studio-field-label">PDF retention (temporary)</span>
                <span class="studio-field-hint">Auto-delete the generated PDF after this period.</span>
                <select class="form-input" name="retentionDays">
                  <option value="">Keep forever</option>
                  <option value="3">3 days</option>
                  <option value="7">7 days</option>
                  <option value="30">30 days</option>
                </select>
              </label>
              <label class="studio-field">
                <span class="studio-field-label">Service option</span>
                <span class="studio-field-hint">Processing priority for this PDF.</span>
                <select class="form-input" name="serviceOption">
                  <option value="standard">Standard</option>
                  <option value="priority">Priority</option>
                  <option value="express">Express</option>
                </select>
              </label>
            </div>
          </div>
        </details>

        <!-- Extract Actions -->
        <div class="extract-actions">
          <button type="button" class="btn-3d btn-secondary" id="extractBtn" style="width: 100%;" data-tooltip="Read the selected files with the active AI provider">
            <span aria-hidden="true">✧</span> Extract Text with AI
          </button>
          <p id="providerHint" style="margin-top:8px;font-size:12px;color:var(--text-muted);"></p>
        </div>

        <!-- AI Processing Steps -->
        <div class="processing-card" id="aiProcessing" hidden aria-busy="true">
          <div class="processing-head">
            <div class="processing-orb" aria-hidden="true" data-icon="✦">✦</div>
            <div class="processing-copy">
              <div class="processing-title" id="aiProcessingTitle">AI is working</div>
              <div class="processing-subtitle" id="aiProcessingSubtitle" role="status" aria-live="polite" aria-atomic="true">Please keep this page open.</div>
            </div>
          </div>
          <div class="processing-meta">
            <span id="aiProcessingPercent" aria-hidden="true">Preparing…</span>
            <span id="aiProcessingElapsed" aria-label="Elapsed time" aria-hidden="true">0:00</span>
          </div>
          <ol class="processing-steps" id="aiProcessingSteps">
            <li class="processing-step" data-step="0"><span class="step-dot">1</span><span>Uploading your files</span></li>
            <li class="processing-step" data-step="1"><span class="step-dot">2</span><span>Checking the free vision model</span></li>
            <li class="processing-step" data-step="2"><span class="step-dot">3</span><span>Reading the page, tables and diagrams</span></li>
            <li class="processing-step" data-step="3"><span class="step-dot">4</span><span>Validating and formatting the result</span></li>
          </ol>
          <div class="processing-progress" id="aiProcessingProgress" aria-label="Upload progress"><span></span></div>
          <div class="processing-actions" id="aiProcessingActions" hidden></div>
        </div>

        <!-- Extracted Text -->
        <label class="extracted-label" for="extractedText">Extracted text — review and edit</label>
        <div class="editor-toolbar" role="toolbar" aria-label="Text formatting">
          <button type="button" data-format="h1" data-tooltip="Insert document heading">H1</button>
          <button type="button" data-format="h2" data-tooltip="Insert section heading">H2</button>
          <button type="button" data-format="bold" data-tooltip="Bold selected text"><strong>B</strong></button>
          <button type="button" data-format="bullet" data-tooltip="Insert bullet point">• List</button>
          <button type="button" data-format="paragraph" data-tooltip="Insert paragraph break">¶</button>
        </div>
        <textarea id="extractedText" name="extractedText" class="form-textarea" placeholder="Extracted text will appear here. You can edit it, add headings and generate a PDF preview."></textarea>
        <p class="editor-empty-hint" id="editorEmptyHint">Tip: use H1/H2 to create headings; blank lines separate paragraphs.</p>

        <!-- Structured Preview -->
        <div id="structuredPreview" class="panel" style="display: none; margin-top: 20px;">
          <div class="panel-header">
            <div class="panel-eyebrow">DOCUMENT PREVIEW</div>
            <h3>Professional PDF Preview</h3>
            <p>Review the AI-structured document before generating the final PDF.</p>
          </div>
          <div id="previewContent" style="max-height: 400px; overflow-y: auto;"></div>
          <div class="preview-actions">
            <button type="button" class="btn-3d btn-secondary" id="previewPdfBtn" data-tooltip="Generate a temporary PDF preview without adding it to history">
              <span aria-hidden="true">◉</span> Preview PDF
            </button>
          </div>
        </div>

        <!-- Smart diagram review -->
        <div id="smartReview" class="panel" style="display: none; margin-top: 20px;">
          <div class="panel-header">
            <div class="panel-eyebrow">SMART RECONSTRUCTION REVIEW</div>
            <h3>Page understanding &amp; diagrams</h3>
            <p>Check extracted structure, tables, diagram labels and placement before generating the premium PDF. Unclear diagrams can be kept as the original crop.</p>
            <div class="smart-review-toolbar">
              <label for="diagramStyle">Diagram appearance</label>
              <select class="form-select" id="diagramStyle">
                <option value="color">Color Digital Diagram</option>
                <option value="pencil">Pencil Sketch Diagram</option>
              </select>
              <span class="smart-review-toolbar-note">Applies to recreated diagrams only. Original crops stay unchanged.</span>
            </div>
          </div>
          <div id="smartReviewContent"></div>
        </div>

        <!-- Generate Actions -->
        <div class="upload-actions">
          <button type="submit" class="btn-3d btn-primary" id="generateBtn" style="width: 100%;" data-tooltip="Generate the final PDF and save it to My Notes">
            <span aria-hidden="true">⟳</span> Generate & Download PDF
          </button>
          <p id="uploadStatus" role="status" aria-live="polite"></p>
        </div>

        <!-- PDF Processing Steps -->
        <div class="processing-card" id="pdfProcessing" hidden aria-busy="true">
          <div class="processing-head">
            <div class="processing-orb" aria-hidden="true" data-icon="◈">◈</div>
            <div class="processing-copy">
              <div class="processing-title" id="pdfProcessingTitle">Preparing your document</div>
              <div class="processing-subtitle" id="pdfProcessingSubtitle" role="status" aria-live="polite" aria-atomic="true">Building a print-ready PDF.</div>
            </div>
          </div>
          <div class="processing-meta">
            <span id="pdfProcessingPercent" aria-hidden="true">Preparing…</span>
            <span id="pdfProcessingElapsed" aria-label="Elapsed time" aria-hidden="true">0:00</span>
          </div>
          <ol class="processing-steps" id="pdfProcessingSteps">
            <li class="processing-step" data-step="0"><span class="step-dot">1</span><span>Preparing document</span></li>
            <li class="processing-step" data-step="1"><span class="step-dot">2</span><span>Formatting pages</span></li>
            <li class="processing-step" data-step="2"><span class="step-dot">3</span><span>Generating PDF</span></li>
            <li class="processing-step" data-step="3"><span class="step-dot">4</span><span>Finalizing download</span></li>
          </ol>
          <div class="processing-progress" id="pdfProcessingProgress" aria-label="Upload and download progress"><span></span></div>
          <div class="processing-actions" id="pdfProcessingActions" hidden></div>
        </div>
      </form>
    </article>
    {% endif %}

    {% if page == 'study' %}
    <article class="panel study-panel" id="studyPanel">
      <div class="panel-header">
        <div class="panel-eyebrow">AI STUDY WORKSPACE</div>
        <h3>Turn notes into study material</h3>
        <p>Use a saved document or paste notes. Generate summaries, questions, flashcards, quizzes and revision sheets with the active provider.</p>
      </div>
      <div class="study-actions" id="studyActions" role="group" aria-label="Study actions">
        <button type="button" class="study-chip active" data-action="summarize">Summarize</button>
        <button type="button" class="study-chip" data-action="key_points">Key points</button>
        <button type="button" class="study-chip" data-action="rewrite">Rewrite</button>
        <button type="button" class="study-chip" data-action="translate">Translate</button>
        <button type="button" class="study-chip" data-action="headings">Structure</button>
        <button type="button" class="study-chip" data-action="qa">Q&amp;A</button>
        <button type="button" class="study-chip" data-action="mcq">MCQs</button>
        <button type="button" class="study-chip" data-action="short_questions">Short questions</button>
        <button type="button" class="study-chip" data-action="long_questions">Long questions</button>
        <button type="button" class="study-chip" data-action="flashcards">Flashcards</button>
        <button type="button" class="study-chip" data-action="quiz">Quiz</button>
        <button type="button" class="study-chip" data-action="exam_topics">Exam topics</button>
        <button type="button" class="study-chip" data-action="chapter_summary">Chapter summary</button>
        <button type="button" class="study-chip" data-action="explain">Explain simply</button>
        <button type="button" class="study-chip" data-action="revision">Revision sheet</button>
      </div>
      <div class="study-fields">
        <label>Source document
          <select class="form-select study-source" id="studyDocumentSelect">
            <option value="">Paste notes below</option>
          </select>
        </label>
        <label>Language
          <select class="form-select study-source" id="studyLanguage">
            <option>English</option>
            <option>Urdu</option>
            <option>Arabic</option>
            <option>Hindi</option>
            <option>Roman Urdu</option>
          </select>
        </label>
        <label>Item count
          <input class="form-input study-source" id="studyCount" type="number" min="1" max="30" value="8" inputmode="numeric">
        </label>
        <label>Extra instruction
          <input class="form-input study-source" id="studyPrompt" type="text" maxlength="500" placeholder="Optional focus or exam style">
        </label>
      </div>
      <label class="extracted-label" for="studyText">Notes to study</label>
      <textarea class="study-notes" id="studyText" dir="auto" placeholder="Select a saved document above, or paste notes here. The AI will not invent facts outside this text."></textarea>
      <div class="upload-actions" style="margin-top:14px;">
        <button type="button" class="btn-3d btn-primary" id="studyGenerateBtn"><span aria-hidden="true">✧</span> Generate study material</button>
        <p id="studyStatus" role="status" aria-live="polite" style="font-size:12px;color:var(--text-muted);"></p>
      </div>
      <div class="study-result" id="studyResult" hidden>
        <div class="study-result-head">
          <strong id="studyResultTitle">Study result</strong>
          <div class="study-set-actions">
            <button type="button" class="btn-3d btn-secondary" id="studyCopyBtn">Copy</button>
            <button type="button" class="btn-3d btn-secondary" id="studySaveBtn">Save</button>
            <button type="button" class="btn-3d btn-primary" id="studyUseBtn">Use in PDF Studio</button>
          </div>
        </div>
        <pre class="study-result-text" id="studyResultText" dir="auto"></pre>
      </div>
      <div class="settings-section" style="margin-top:18px;">
        <h4 class="settings-title">Saved study sets</h4>
        <div class="study-saved" id="studySaved"></div>
      </div>
    </article>

    {% elif page == 'admin' %}
    <article class="panel study-panel" id="adminPanel">
      <div class="panel-header">
        <div class="panel-eyebrow">LOCAL ADMIN</div>
        <h3>Workspace overview</h3>
        <p>Real data from this NotesAI workspace. Remote access requires the server admin token. No online payment gateway or cloud provider is claimed.</p>
      </div>
      <div class="admin-lock" id="adminLock" hidden>
        <label class="form-label" for="adminPageToken">Admin token for remote access</label>
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:6px;">
          <input type="password" class="form-input" id="adminPageToken" placeholder="Optional on this device" autocomplete="off" style="flex:1 1 220px;">
          <button type="button" class="btn-3d btn-secondary" id="adminReloadBtn">Reload</button>
        </div>
        <p style="font-size:11px;color:var(--text-muted);margin-top:6px;">The token is stored in this browser session only.</p>
      </div>
      <div class="admin-grid" id="adminStats">
        <div class="admin-stat"><span>Documents</span><strong id="adminDocs">—</strong><small>Stored PDFs</small></div>
        <div class="admin-stat"><span>Storage</span><strong id="adminStorage">—</strong><small>Local workspace</small></div>
        <div class="admin-stat"><span>Failed jobs</span><strong id="adminFailed">—</strong><small>Recent activity</small></div>
        <div class="admin-stat"><span>Study sets</span><strong id="adminStudySets">—</strong><small>Saved results</small></div>
      </div>
      <div class="admin-columns">
        <div>
          <div class="admin-block">
            <h4>System &amp; provider</h4>
            <div class="admin-list" id="adminSystem"></div>
          </div>
          <div class="admin-block">
            <h4>Failed jobs</h4>
            <div class="admin-list" id="adminFailedList"><div class="empty-state" style="padding:14px;"><p>No failed jobs.</p></div></div>
          </div>
          <div class="admin-block">
            <h4>Recent activity</h4>
            <div class="admin-list" id="adminActivity"></div>
          </div>
        </div>
        <div>
          <div class="admin-block">
            <h4>Workspace plan</h4>
            <div class="admin-list" id="adminPlan"></div>
            <form class="admin-form" id="adminPlanForm" style="margin-top:10px;">
              <select class="form-select" id="adminPlanSelect" aria-label="Workspace plan">
                <option value="free">Free workspace</option>
                <option value="pro">Professional workspace</option>
              </select>
              <input class="form-input" id="adminRenewal" type="date" aria-label="Renewal date">
              <button type="submit" class="btn-3d btn-primary">Activate local plan</button>
            </form>
          </div>
          <div class="admin-block">
            <h4>Manual payment record</h4>
            <p style="font-size:11px;color:var(--text-muted);margin-bottom:8px;">For offline/manual verification only. No card data is stored.</p>
            <form class="admin-form" id="adminPaymentForm">
              <input class="form-input" id="paymentAmount" type="number" min="0" step="0.01" placeholder="Amount" aria-label="Payment amount">
              <input class="form-input" id="paymentMethod" type="text" maxlength="40" placeholder="Method" aria-label="Payment method">
              <input class="form-input" id="paymentReference" type="text" maxlength="120" placeholder="Reference" aria-label="Payment reference">
              <input class="form-input" id="paymentCurrency" type="text" maxlength="8" value="PKR" aria-label="Currency">
              <input class="form-input" id="paymentNote" type="text" maxlength="300" placeholder="Note" aria-label="Payment note" style="grid-column:1/-1;">
              <button type="submit" class="btn-3d btn-secondary">Record payment</button>
            </form>
            <div class="admin-list" id="adminPayments" style="margin-top:10px;"></div>
          </div>
          <div class="admin-block">
            <h4>Backup</h4>
            <p style="font-size:11px;color:var(--text-muted);margin-bottom:8px;">Download a local ZIP of documents and metadata. API keys and <code>.env</code> are never included.</p>
            <button type="button" class="btn-3d btn-secondary" id="adminBackupBtn">Download workspace backup</button>
          </div>
        </div>
      </div>
    </article>
    {% endif %}

    {% if page not in ['study', 'admin'] %}
    <!-- Activity / My Notes / History / Settings Panel -->
    <article class="panel" id="activity">
      <div class="panel-header">
        <div class="panel-eyebrow">{% if page == 'my-notes' %}YOUR LIBRARY{% elif page == 'history' %}ORDER HISTORY{% elif page == 'settings' %}WORKSPACE SETTINGS{% else %}RECENT ACTIVITY{% endif %}</div>
        <h3>{% if page == 'my-notes' %}My Documents{% elif page == 'history' %}Previous Orders{% elif page == 'settings' %}Preferences{% else %}Recent Activity{% endif %}</h3>
        <p>{% if page == 'my-notes' %}Your digital document library.{% elif page == 'history' %}Your previous and completed orders.{% elif page == 'settings' %}Manage your NotesAI workspace preferences.{% else %}Your latest documents and orders appear here.{% endif %}</p>
      </div>

      {% if page == 'my-notes' %}
      <!-- My Notes Search & Filter -->
      <div class="list-toolbar" id="documentToolbar">
        <input type="search" class="form-input" id="documentSearch" placeholder="Search by name, folder or tags…" aria-label="Search documents">
        <select class="form-select" id="documentStatusFilter" aria-label="Filter documents by status">
          <option value="all">All statuses</option>
          <option value="completed">Completed</option>
          <option value="processing">Processing</option>
          <option value="pending">Pending</option>
        </select>
        <select class="form-select" id="documentKindFilter" aria-label="Filter documents by type">
          <option value="all">All types</option>
          <option value="professional">Professional</option>
          <option value="smart">Smart</option>
          <option value="image">Image PDF</option>
          <option value="text">Text</option>
          <option value="existing">Existing PDF</option>
        </select>
        <input class="form-input" id="documentFolderFilter" placeholder="Filter by folder (e.g. Semester 2)…" aria-label="Filter by folder">
        <input class="form-input" id="documentTagFilter" placeholder="Filter by tag (e.g. biology)…" aria-label="Filter by tag">
        <label class="toggle-row" style="margin:0;align-items:center;"><input type="checkbox" id="documentFavoriteFilter"> Favorites</label>
        <label class="toggle-row" style="margin:0;align-items:center;"><input type="checkbox" id="documentTrashFilter"> Trash</label>
        <span class="toolbar-count" id="documentCount" aria-live="polite"></span>
      </div>
      <!-- My Notes Grid -->
      <div class="document-grid" id="documentGrid">
        <div class="empty-state">
          <div class="empty-state-icon" aria-hidden="true">▤</div>
          <h4>No documents yet</h4>
          <p>Create your first document from the PDF Studio or New Order page.</p>
        </div>
      </div>
      <div class="pagination" id="documentPager"></div>

      {% elif page == 'history' %}
      <!-- History Search & Filter -->
      <div class="list-toolbar" id="orderToolbar">
        <input type="search" class="form-input" id="orderSearch" placeholder="Search history…" aria-label="Search history">
        <select class="form-select" id="orderStatusFilter" aria-label="Filter history by status">
          <option value="all">All statuses</option>
          <option value="completed">Completed</option>
          <option value="processing">Processing</option>
          <option value="pending">Pending</option>
        </select>
        <span class="toolbar-count" id="orderCount" aria-live="polite"></span>
      </div>
      <!-- History List -->
      <div class="order-list" id="orderList">
        <div class="empty-state">
          <div class="empty-state-icon" aria-hidden="true">◷</div>
          <h4>No orders yet</h4>
          <p>Your completed and processing orders will appear here.</p>
        </div>
      </div>

      {% elif page == 'settings' %}
      <!-- Settings -->
      <div class="settings-section">
        <h4 class="settings-title">AI Provider</h4>
        <div class="settings-grid">
          <div class="setting-card">
            <div class="setting-label">Active AI Provider</div>
            <p class="setting-desc">Gemini is the default. OpenRouter uses verified FREE vision models only. API keys are configured on the server in <code>.env</code> and are never shown in the browser.</p>
            <select class="form-select setting-input" id="providerSelect" aria-label="Active AI provider">
              <option value="gemini">Google Gemini (Default)</option>
              <option value="openrouter">OpenRouter – Free Models Only</option>
            </select>
            <small id="providerSaveStatus" role="status" aria-live="polite" style="display:block;margin-top:8px;color:var(--text-muted);">Loading active provider…</small>
          </div>
          <div class="setting-card">
            <div class="setting-label">Gemini Connection</div>
            <p class="setting-desc">Default provider. Model: <span id="geminiModelInfo">—</span></p>
            <p id="geminiStatus" aria-live="polite" style="font-size:13px;color:var(--text-muted);">Checking connection…</p>
          </div>
          <div class="setting-card">
            <div class="setting-label">OpenRouter Connection</div>
            <p class="setting-desc">Alternate provider. Selected free model: <span id="openrouterModelInfo">—</span></p>
            <p id="openrouterStatus" aria-live="polite" style="font-size:13px;color:var(--text-muted);">Checking connection…</p>
            <p id="openrouterFreeCount" style="font-size:12px;color:var(--text-muted);">Loading free model list…</p>
          </div>
          <div class="setting-card">
            <div class="setting-label">Connection Test</div>
            <p class="setting-desc">Test the currently selected provider with a small live API call.</p>
            <button type="button" class="btn-3d btn-primary" id="testProviderBtn">Test Connection</button>
            <p id="providerTestStatus" style="margin-top:10px;font-size:13px;color:var(--text-muted);"></p>
          </div>
        </div>
      </div>
      <div class="settings-section">
        <h4 class="settings-title">Server Access</h4>
        <div class="settings-grid">
          <div class="setting-card">
            <div class="setting-label">Admin Token (remote access only)</div>
            <p class="setting-desc">Only required when this page is opened from another device. Must match <code>NOTESAI_ADMIN_TOKEN</code> on the server. Stored in this browser session only, never on the server.</p>
            <input type="password" class="form-input setting-input" id="adminToken" placeholder="Optional admin token" autocomplete="off">
            <small style="display:block;margin-top:8px;color:var(--text-muted);">Local access on this device does not require a token.</small>
          </div>
        </div>
      </div>

      <div class="settings-section">
        <h4 class="settings-title">Appearance</h4>
        <div class="settings-grid">
          <div class="setting-card">
            <div class="setting-label">Theme</div>
            <p class="setting-desc">Choose your preferred color theme.</p>
            <select class="form-select setting-input" id="themeSelect">
              <option value="premium">Premium (Royal Blue)</option>
              <option value="light">Light</option>
              <option value="ocean">Ocean (Teal)</option>
              <option value="graphite">Graphite (Dark)</option>
              <option value="dark">Midnight (Dark)</option>
            </select>
          </div>
        </div>
      </div>
      <div class="settings-section">
        <h4 class="settings-title">Data Management</h4>
        <div class="settings-grid">
          <div class="setting-card">
            <div class="setting-label">Clear Activity History</div>
            <p class="setting-desc">Permanently delete all activity records.</p>
            <button type="button" class="btn-3d btn-destructive" id="clearActivity">Clear History</button>
          </div>
          <div class="setting-card">
            <div class="setting-label">Reset Statistics</div>
            <p class="setting-desc">Reset all dashboard counters to zero.</p>
            <button type="button" class="btn-3d btn-destructive" id="resetStats">Reset Stats</button>
          </div>
        </div>
      </div>

      {% else %}
      <!-- Default Dashboard Activity -->
      <div class="activity-list" id="activityList">
        <div class="empty-state">
          <div class="empty-state-icon" aria-hidden="true">◷</div>
          <h4>No recent activity</h4>
          <p>Your document conversions and orders will appear here.</p>
        </div>
      </div>
      {% endif %}
    </article>
    {% endif %}
  </section>

  {% if page == 'dashboard' %}
  <footer class="footer">NOTESAI · PREMIUM WORKSPACE FOR REFINED THINKING</footer>
  {% endif %}
</main>

<!-- Mobile Bottom Navigation -->
<nav class="mobile-nav" id="mobileNav" role="navigation" aria-label="Mobile navigation">
  <div class="mobile-nav-inner">
    <a class="mobile-nav-item {% if page == 'dashboard' %}active{% endif %}" href="/" data-page="dashboard"{% if page == 'dashboard' %} aria-current="page"{% endif %}>
      <svg class="mobile-nav-icon" aria-hidden="true" focusable="false"><use href="#icon-home"></use></svg>
      <span class="mobile-nav-text">Dashboard</span>
    </a>
    <a class="mobile-nav-item {% if page == 'study' %}active{% endif %}" href="/study" data-page="study"{% if page == 'study' %} aria-current="page"{% endif %}>
      <svg class="mobile-nav-icon" aria-hidden="true" focusable="false"><use href="#icon-study"></use></svg>
      <span class="mobile-nav-text">AI Study</span>
    </a>
    <a class="mobile-nav-item {% if page == 'new-order' %}active{% endif %}" href="/new-order" data-page="new-order"{% if page == 'new-order' %} aria-current="page"{% endif %}>
      <svg class="mobile-nav-icon" aria-hidden="true" focusable="false"><use href="#icon-upload"></use></svg>
      <span class="mobile-nav-text">PDF Studio</span>
    </a>
    <a class="mobile-nav-item {% if page == 'my-notes' %}active{% endif %}" href="/my-notes" data-page="my-notes"{% if page == 'my-notes' %} aria-current="page"{% endif %}>
      <svg class="mobile-nav-icon" aria-hidden="true" focusable="false"><use href="#icon-notes"></use></svg>
      <span class="mobile-nav-text">My Notes</span>
    </a>
    <a class="mobile-nav-item {% if page == 'settings' %}active{% endif %}" href="/settings" data-page="settings"{% if page == 'settings' %} aria-current="page"{% endif %}>
      <svg class="mobile-nav-icon" aria-hidden="true" focusable="false"><use href="#icon-settings"></use></svg>
      <span class="mobile-nav-text">Settings</span>
    </a>
  </div>
</nav>

<!-- PDF Preview Modal -->
<div class="modal-backdrop" id="pdfPreviewModal" role="dialog" aria-modal="true" aria-labelledby="pdfPreviewTitle" aria-hidden="true">
  <div class="pdf-modal">
    <div class="pdf-modal-head">
      <div>
        <h3 id="pdfPreviewTitle">PDF Preview</h3>
        <p id="pdfPreviewSubtitle">Preview only — this does not add a document to history.</p>
      </div>
      <div class="pdf-modal-actions">
        <button type="button" class="btn-3d btn-secondary" id="pdfPreviewRetry" hidden>
          <span aria-hidden="true">↻</span> Retry
        </button>
        <button type="button" class="btn-3d btn-secondary" id="closePdfPreview" aria-label="Close PDF preview">Close</button>
      </div>
    </div>
    <div id="pdfPreviewBody" class="pdf-preview-body" aria-live="polite" aria-busy="false"></div>
  </div>
</div>

<!-- Document details / management modal -->
<div class="modal-backdrop" id="documentModal" role="dialog" aria-modal="true" aria-labelledby="documentModalTitle" aria-hidden="true">
  <div class="document-modal">
    <h3 id="documentModalTitle">Document details</h3>
    <p id="documentModalMeta">Manage this document without touching the original PDF.</p>
    <form id="documentForm" class="document-form">
      <input type="hidden" id="documentModalId">
      <label class="wide">Name
        <input class="form-input" id="documentModalName" maxlength="120" required>
      </label>
      <label>Folder
        <input class="form-input" id="documentModalFolder" maxlength="80" placeholder="e.g. Semester 2">
      </label>
      <label>Tags
        <input class="form-input" id="documentModalTags" maxlength="200" placeholder="biology, revision">
      </label>
      <label class="wide">Category
        <input class="form-input" id="documentModalCategory" maxlength="80" placeholder="Optional category">
      </label>
      <label class="wide toggle-row" style="margin:0;">
        <input type="checkbox" id="documentModalFavorite"> Favorite this document
      </label>
    </form>
    <div class="document-modal-actions">
      <button type="button" class="btn-3d btn-primary" id="documentModalSave">Save details</button>
      <button type="button" class="btn-3d btn-secondary" id="documentModalDownload">Download</button>
      <button type="button" class="btn-3d btn-destructive" id="documentModalDelete">Move to trash</button>
      <button type="button" class="btn-3d btn-secondary" id="documentModalRestore" hidden>Restore</button>
      <button type="button" class="btn-3d btn-secondary" id="documentModalClose">Close</button>
    </div>
  </div>
</div>

<!-- Toast Container -->
<div class="toast-container" id="toastContainer" aria-live="polite" aria-atomic="true"></div>

<script>
// ============================================================
// NOTESAI PREMIUM — CLIENT-SIDE LOGIC
// ============================================================
(function() {
  'use strict';

  // ----- DOM Elements -----
  const form = document.getElementById('uploadForm');
  const input = document.getElementById('noteFile');
  const dropzone = document.getElementById('dropzone');
  const preview = document.getElementById('filePreview');
  const status = document.getElementById('uploadStatus');
  const extractBtn = document.getElementById('extractBtn');
  const extractedText = document.getElementById('extractedText');
  const generateBtn = document.getElementById('generateBtn');
  const mobileMenuBtn = document.getElementById('mobileMenuBtn');
  const sidebar = document.getElementById('sidebar');
  const sidebarOverlay = document.getElementById('sidebarOverlay');
  const sidebarClose = document.getElementById('sidebarClose');
  const toastContainer = document.getElementById('toastContainer');
  const aiProcessing = document.getElementById('aiProcessing');
  const aiProcessingTitle = document.getElementById('aiProcessingTitle');
  const aiProcessingSubtitle = document.getElementById('aiProcessingSubtitle');
  const aiProcessingSteps = document.getElementById('aiProcessingSteps');
  const aiProcessingProgress = document.getElementById('aiProcessingProgress');
  const aiProcessingActions = document.getElementById('aiProcessingActions');
  const aiProcessingPercent = document.getElementById('aiProcessingPercent');
  const aiProcessingElapsed = document.getElementById('aiProcessingElapsed');
  const pdfProcessing = document.getElementById('pdfProcessing');
  const pdfProcessingTitle = document.getElementById('pdfProcessingTitle');
  const pdfProcessingSubtitle = document.getElementById('pdfProcessingSubtitle');
  const pdfProcessingSteps = document.getElementById('pdfProcessingSteps');
  const pdfProcessingProgress = document.getElementById('pdfProcessingProgress');
  const pdfProcessingActions = document.getElementById('pdfProcessingActions');
  const pdfProcessingPercent = document.getElementById('pdfProcessingPercent');
  const pdfProcessingElapsed = document.getElementById('pdfProcessingElapsed');
  const previewPdfBtn = document.getElementById('previewPdfBtn');
  const pdfPreviewModal = document.getElementById('pdfPreviewModal');
  const pdfPreviewBody = document.getElementById('pdfPreviewBody');
  const pdfPreviewSubtitle = document.getElementById('pdfPreviewSubtitle');
  const pdfPreviewRetry = document.getElementById('pdfPreviewRetry');
  const closePdfPreview = document.getElementById('closePdfPreview');
  const pdfModeCards = document.getElementById('pdfModeCards');
  const editorEmptyHint = document.getElementById('editorEmptyHint');
  const documentSearch = document.getElementById('documentSearch');
  const documentStatusFilter = document.getElementById('documentStatusFilter');
  const documentKindFilter = document.getElementById('documentKindFilter');
  const documentFolderFilter = document.getElementById('documentFolderFilter');
  const documentTagFilter = document.getElementById('documentTagFilter');
  const documentFavoriteFilter = document.getElementById('documentFavoriteFilter');
  const documentTrashFilter = document.getElementById('documentTrashFilter');
  const documentPager = document.getElementById('documentPager');
  const documentCount = document.getElementById('documentCount');
  const statFailed = document.getElementById('statFailed');
  const statStorage = document.getElementById('statStorage');
  const statPlan = document.getElementById('statPlan');
  const statPlanDesc = document.getElementById('statPlanDesc');
  const dashboardRecent = document.getElementById('dashboardRecent');
  const documentModal = document.getElementById('documentModal');
  const documentModalId = document.getElementById('documentModalId');
  const documentModalName = document.getElementById('documentModalName');
  const documentModalFolder = document.getElementById('documentModalFolder');
  const documentModalTags = document.getElementById('documentModalTags');
  const documentModalCategory = document.getElementById('documentModalCategory');
  const documentModalFavorite = document.getElementById('documentModalFavorite');
  const documentModalMeta = document.getElementById('documentModalMeta');
  const documentModalSave = document.getElementById('documentModalSave');
  const documentModalDownload = document.getElementById('documentModalDownload');
  const documentModalDelete = document.getElementById('documentModalDelete');
  const documentModalRestore = document.getElementById('documentModalRestore');
  const documentModalClose = document.getElementById('documentModalClose');
  const orderSearch = document.getElementById('orderSearch');
  const orderStatusFilter = document.getElementById('orderStatusFilter');
  const orderCount = document.getElementById('orderCount');
  let selectedFiles = [];
  let allDocuments = [];
  let allOrders = [];
  let documentPage = 1;
  let documentPageSize = 8;
  let documentShowTrash = false;
  let activeDocument = null;
  let lastPdfFocus = null;
  const statTotal = document.getElementById('statTotal');
  const statProgress = document.getElementById('statProgress');
  const statCompleted = document.getElementById('statCompleted');
  const activityList = document.getElementById('activityList');
  const documentGrid = document.getElementById('documentGrid');
  const orderList = document.getElementById('orderList');
  const clearActivityBtn = document.getElementById('clearActivity');
  const resetStatsBtn = document.getElementById('resetStats');
  const themeSelect = document.getElementById('themeSelect');
  const providerSelect = document.getElementById('providerSelect');
  const providerSaveStatus = document.getElementById('providerSaveStatus');
  let savedProvider = '';
  let providerSaveInFlight = false;
  let providerSaveFailed = false;
  if (providerSelect) providerSelect.disabled = true;
  const geminiStatus = document.getElementById('geminiStatus');
  const geminiModelInfo = document.getElementById('geminiModelInfo');
  const openrouterStatus = document.getElementById('openrouterStatus');
  const openrouterModelInfo = document.getElementById('openrouterModelInfo');
  const openrouterFreeCount = document.getElementById('openrouterFreeCount');
  const testProviderBtn = document.getElementById('testProviderBtn');
  const providerTestStatus = document.getElementById('providerTestStatus');
  const providerHint = document.getElementById('providerHint');
  const adminTokenInput = document.getElementById('adminToken');
  const pdfModeSelect = document.getElementById('pdfMode');
  const structuredPreview = document.getElementById('structuredPreview');
  const previewContent = document.getElementById('previewContent');
  const smartReview = document.getElementById('smartReview');
  const smartReviewContent = document.getElementById('smartReviewContent');
  const diagramStyleSelect = document.getElementById('diagramStyle');
  let currentAnalysis = null;
  let currentDiagramPreviews = {};
  let diagramPreviewModes = {};

  // ----- Single-flight request guard + cancellation -----
  // Only one AI/PDF request may run at a time. Retry actions and double
  // clicks reuse this guard, so a document is never submitted twice.
  let requestState = { active: false, kind: '', controller: null, cancelled: false, id: 0 };
  let requestSequence = 0;
  const processingClocks = {
    ai: { start: 0, timer: null },
    pdf: { start: 0, timer: null },
  };
  let offlineNoticeShown = false;

  function browserIsOffline() {
    return typeof navigator !== 'undefined' && navigator.onLine === false;
  }

  function beginRequest(kind) {
    if (browserIsOffline() && kind === 'ai') {
      showToast('You are offline. Reconnect to the internet before using AI extraction.', 'warning', 6000);
      return 0;
    }
    if (browserIsOffline()) {
      showToast('You are offline. Local PDF generation may still work; AI features need a connection.', 'warning', 6000);
    }
    if (requestState.active) {
      showToast('A request is already running. Please wait or cancel it.', 'warning', 3500);
      return 0;
    }
    requestSequence += 1;
    requestState = {
      active: true,
      kind: kind,
      controller: typeof AbortController === 'function' ? new AbortController() : null,
      cancelled: false,
      id: requestSequence,
    };
    return requestState.id;
  }

  function requestIsActive(id) {
    return requestState.active && requestState.id === id;
  }

  function endRequest(id) {
    if (!requestState.active || requestState.id !== id) return;
    requestState = { active: false, kind: '', controller: null, cancelled: false, id: requestState.id };
  }

  function cancelActiveRequest(kind) {
    if (!requestState.active) return false;
    if (kind && requestState.kind !== kind) return false;
    requestState.cancelled = true;
    const parts = processingElements(kind || requestState.kind);
    if (parts && parts.subtitle) parts.subtitle.textContent = 'Cancelling the request…';
    if (parts && parts.cancel) {
      parts.cancel.disabled = true;
      parts.cancel.textContent = 'Cancelling…';
    }
    if (requestState.controller) {
      try { requestState.controller.abort(); } catch (_) {}
    }
    return true;
  }

  function formatElapsed(milliseconds) {
    const total = Math.max(0, Math.floor(milliseconds / 1000));
    const minutes = Math.floor(total / 60);
    const seconds = total % 60;
    return minutes + ':' + String(seconds).padStart(2, '0');
  }

  function startProcessingClock(kind) {
    const parts = processingElements(kind);
    const clock = processingClocks[kind];
    if (!parts || !parts.elapsed || !clock) return;
    if (clock.timer) clearInterval(clock.timer);
    clock.start = Date.now();
    parts.elapsed.textContent = '0:00';
    clock.timer = setInterval(() => {
      if (!parts.elapsed) return;
      parts.elapsed.textContent = formatElapsed(Date.now() - clock.start);
    }, 1000);
  }

  function stopProcessingClock(kind) {
    const clock = processingClocks[kind];
    if (clock && clock.timer) {
      clearInterval(clock.timer);
      clock.timer = null;
    }
  }

  function currentDiagramStyle() {
    return diagramStyleSelect && diagramStyleSelect.value === 'pencil' ? 'pencil' : 'color';
  }

  // ----- Safe browser storage (private mode / blocked storage must not stop init) -----
  function storageGet(kind, key) {
    try {
      const store = window[kind];
      return store ? store.getItem(key) : null;
    } catch (_) {
      return null;
    }
  }
  function storageSet(kind, key, value) {
    try {
      const store = window[kind];
      if (store) store.setItem(key, value);
    } catch (_) {}
  }
  function storageRemove(kind, key) {
    try {
      const store = window[kind];
      if (store) store.removeItem(key);
    } catch (_) {}
  }

  // ----- Admin token (only needed for remote access) -----
  function adminHeaders() {
    const headers = { 'Content-Type': 'application/json' };
    const token = adminTokenInput ? adminTokenInput.value.trim() : '';
    if (token) headers['X-Admin-Token'] = token;
    return headers;
  }
  if (adminTokenInput) {
    const savedToken = storageGet('sessionStorage', 'notesaiAdminToken');
    if (savedToken) adminTokenInput.value = savedToken;
    adminTokenInput.addEventListener('change', () => {
      const value = adminTokenInput.value.trim();
      if (value) storageSet('sessionStorage', 'notesaiAdminToken', value);
      else storageRemove('sessionStorage', 'notesaiAdminToken');
    });
  }

  // ----- PDF Mode Selector -----
  function syncModeCards() {
    if (!pdfModeSelect || !pdfModeCards) return;
    const selected = pdfModeSelect.value;
    pdfModeCards.querySelectorAll('.mode-card').forEach(card => {
      const active = card.dataset.mode === selected;
      card.classList.toggle('selected', active);
      const radio = card.querySelector('input[type="radio"]');
      if (radio) radio.checked = active;
    });
  }

  function applyPdfMode() {
    if (!pdfModeSelect) return;
    const isSmart = pdfModeSelect.value === 'smart';
    syncModeCards();
    if (isSmart && currentAnalysis) {
      renderSmartReview(currentAnalysis, currentDiagramPreviews);
    }
    if (!isSmart && smartReview) smartReview.style.display = 'none';
  }

  if (pdfModeCards) {
    pdfModeCards.addEventListener('change', event => {
      const radio = event.target.closest('input[type="radio"]');
      if (!radio) return;
      if (pdfModeSelect) pdfModeSelect.value = radio.value;
      applyPdfMode();
    });
  }
  if (pdfModeSelect) {
    pdfModeSelect.addEventListener('change', applyPdfMode);
    applyPdfMode();
  }

  // ----- Render Structured Preview -----
  function formatInlineHtml(text) {
    return escapeHtml(text)
      .replace(/\*\*(.+?)\*\*/gs, '<strong>$1</strong>')
      .replace(/\n/g, '<br>');
  }

  function legacyTableHtml(lines) {
    const rows = lines.map(line => line.replace(/^\s*\|/, '').replace(/\|\s*$/, '')
      .split('|').map(cell => cell.trim().replace(/^(?:[•\-*·]|\d+[.)])\s+/, '')));
    if (!rows.length) return '';
    const width = Math.max(...rows.map(row => row.length));
    const padded = rows.map(row => row.concat(Array(Math.max(0, width - row.length)).fill('')));
    const header = padded.shift() || [];
    let table = '<table class="smart-table" style="margin:10px 0;width:100%;border-collapse:collapse;">';
    table += '<thead><tr>' + header.map(cell => `<th>${formatInlineHtml(cell)}</th>`).join('') + '</tr></thead><tbody>';
    padded.forEach(row => {
      table += '<tr>' + row.map(cell => `<td>${formatInlineHtml(cell)}</td>`).join('') + '</tr>';
    });
    return table + '</tbody></table>';
  }

  function legacyFlowHtml(lines) {
    return lines.map(line => {
      const parts = line.split(/\s*(?:->|→|=>|➜|➡)\s*/).filter(Boolean);
      if (parts.length < 2) return `<p style="margin:8px 0;">${formatInlineHtml(line)}</p>`;
      const cards = parts.map((part, index) => {
        const chip = `<span style="display:inline-block;padding:7px 10px;border:1px solid var(--border);border-radius:6px;background:#f8fafc;font-size:13px;">${formatInlineHtml(part)}</span>`;
        return (index ? '<span style="color:var(--accent-primary);font-weight:700;">→</span>' : '') + chip;
      }).join('');
      return `<div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:8px 0;">${cards}</div>`;
    }).join('');
  }

  function renderLegacyContent(content, heading = '') {
    const lines = String(content || '').split('\n');
    const isTable = line => line.includes('|');
    const isList = line => /^(?:[•\-*·]|\d+[.)])\s+/.test(line);
    const isCallout = line => /^(trick|remember|note|shortcut|golden rule|important|tip|warning|total|practice daily)\b/i.test(line);
    const isFlow = line => /(?:->|→|=>|➜|➡)/.test(line);
    if (lines.length > 1 && /memory|trick/i.test(heading) && !content.includes('|') && !lines.every(isFlow)) {
      const label = /memory/i.test(heading) ? 'Memory Trick' : 'Trick';
      return `<div class="smart-block" style="background:#eff6ff;border-color:#bfdbfe;"><span class="smart-block-label">${formatInlineHtml(label)}</span>${formatInlineHtml(content)}</div>`;
    }
    let html = '';
    let index = 0;
    while (index < lines.length) {
      const line = lines[index].trim();
      if (!line) { index += 1; continue; }
      if (isTable(line)) {
        const tableLines = [];
        while (index < lines.length && lines[index].trim() && isTable(lines[index])) {
          tableLines.push(lines[index].trim());
          index += 1;
        }
        html += legacyTableHtml(tableLines);
        continue;
      }
      if (isCallout(line)) {
        const match = line.match(/^(trick|remember|note|shortcut|golden rule|important|tip|warning|total|practice daily)\b\s*[:\-–—]?\s*(.*)$/i);
        const label = match ? match[1] : 'Note';
        const body = [match && match[2] ? match[2] : ''];
        index += 1;
        while (index < lines.length && lines[index].trim() && !isTable(lines[index]) && !isList(lines[index]) && !isCallout(lines[index])) {
          body.push(lines[index].trim());
          index += 1;
        }
        html += `<div class="smart-block" style="background:#eff6ff;border-color:#bfdbfe;"><span class="smart-block-label">${formatInlineHtml(label)}</span>${formatInlineHtml(body.filter(Boolean).join('\n'))}</div>`;
        continue;
      }
      if (isList(line)) {
        const items = [];
        while (index < lines.length && isList(lines[index])) {
          items.push(lines[index].trim().replace(/^(?:[•\-*·]|\d+[.)])\s+/, ''));
          index += 1;
        }
        html += '<ul style="margin:8px 0 8px 20px;line-height:1.8;">' + items.map(item => `<li>${formatInlineHtml(item)}</li>`).join('') + '</ul>';
        continue;
      }
      if (isFlow(line)) {
        const flowLines = [];
        while (index < lines.length && lines[index].trim() && isFlow(lines[index])) {
          flowLines.push(lines[index].trim());
          index += 1;
        }
        html += legacyFlowHtml(flowLines);
        continue;
      }
      const paragraph = [];
      while (index < lines.length && lines[index].trim() && !isTable(lines[index]) && !isList(lines[index]) && !isCallout(lines[index]) && !isFlow(lines[index])) {
        paragraph.push(lines[index].trim());
        index += 1;
      }
      html += `<p style="margin:10px 0; font-size:14px; line-height:1.8; color:var(--text-primary);">${formatInlineHtml(paragraph.join(' '))}</p>`;
    }
    return html;
  }

  function renderStructuredPreview(structured) {
    if (!structured || !previewContent) return;
    const normaliseKey = value => String(value || '').toLowerCase()
      .replace(/[^\w\u0600-\u06FF]+/g, ' ').replace(/\s+/g, ' ').trim();
    const titleKey = normaliseKey(structured.title);
    let lastHeadingKey = '';

    let html = '';
    if (structured.title) {
      html += `<div style="text-align:center; margin-bottom:24px; padding-bottom:16px; border-bottom:2px solid var(--accent-light);">
        <h2 style="font-size:24px; font-weight:700; color:var(--text-primary); margin-bottom:8px;">${formatInlineHtml(structured.title)}</h2>
      </div>`;
    }

    if (structured.sections && structured.sections.length) {
      structured.sections.forEach(section => {
        const level = section.level || 1;
        let heading = section.heading || '';
        const content = section.content || '';
        const headingKey = normaliseKey(heading);
        if (heading && titleKey && headingKey === titleKey) heading = '';
        if (heading && headingKey && headingKey === lastHeadingKey) heading = '';
        if (headingKey) lastHeadingKey = headingKey;

        const headingStyles = {
          1: 'font-size:20px; font-weight:700; color:var(--accent-primary); margin:20px 0 12px; padding-bottom:8px; border-bottom:1px solid var(--border-light);',
          2: 'font-size:17px; font-weight:600; color:var(--text-primary); margin:16px 0 8px;',
          3: 'font-size:15px; font-weight:600; color:var(--text-secondary); margin:12px 0 6px;'
        };

        if (heading) {
          html += `<h${level} style="${headingStyles[level] || headingStyles[1]}">${formatInlineHtml(heading)}</h${level}>`;
        }

        if (content) {
          html += renderLegacyContent(content, heading);
        }
      });
    }

    if (!html) {
      html = '<p style="color:var(--text-muted); text-align:center; padding:32px;">No structured content available</p>';
    }

    previewContent.innerHTML = html;
    if (structuredPreview) structuredPreview.style.display = 'block';
  }

  // ----- Smart reconstruction review -----
  function svgDataUrl(svg) {
    return 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg || '');
  }

  function diagramById(diagramId) {
    if (!currentAnalysis) return null;
    for (const page of currentAnalysis.pages || []) {
      const diagram = (page.diagrams || []).find(item => item.id === diagramId);
      if (diagram) return diagram;
    }
    return null;
  }

  function blockLabel(block) {
    if (!block) return '';
    if (block.type === 'heading') return block.text || '';
    if (block.type === 'paragraph') return (block.text || '').slice(0, 80);
    if (block.type === 'table') return block.title || 'Table';
    if (block.type === 'question') return (block.question || '').slice(0, 80);
    if (block.type === 'callout') return block.label || 'Callout';
    if (block.type === 'flow') return block.title || 'Flow';
    if (block.type === 'diagram') return 'Diagram';
    return block.type || '';
  }

  function renderSmartBlock(block) {
    if (!block) return '';
    if (block.type === 'heading') {
      const level = Math.max(1, Math.min(3, Number(block.level) || 1));
      return `<div class="smart-block"><span class="smart-block-label">H${level}</span><strong>${formatInlineHtml(block.text || '')}</strong></div>`;
    }
    if (block.type === 'paragraph') {
      return `<div class="smart-block"><span class="smart-block-label">Text</span>${formatInlineHtml(block.text || '')}</div>`;
    }
    if (block.type === 'list') {
      const items = (block.items || []).map(item => `<li>${formatInlineHtml(item)}</li>`).join('');
      return `<div class="smart-block"><span class="smart-block-label">List</span><ul style="margin:4px 0 0 18px;">${items}</ul></div>`;
    }
    if (block.type === 'table') {
      const columns = block.columns || [];
      const rows = block.rows || [];
      let table = '<table class="smart-table">';
      if (columns.length) {
        table += '<thead><tr>' + columns.map(cell => `<th>${formatInlineHtml(cell)}</th>`).join('') + '</tr></thead>';
      }
      table += '<tbody>' + rows.map(row => '<tr>' + row.map(cell => `<td>${formatInlineHtml(cell)}</td>`).join('') + '</tr>').join('') + '</tbody></table>';
      return `<div class="smart-block"><span class="smart-block-label">Table</span>${block.title ? `<strong>${formatInlineHtml(block.title)}</strong>` : ''}${table}</div>`;
    }
    if (block.type === 'callout') {
      return `<div class="smart-block" style="background:#eff6ff;border-color:#bfdbfe;"><span class="smart-block-label">${formatInlineHtml(block.label || 'Note')}</span>${formatInlineHtml(block.text || '')}</div>`;
    }
    if (block.type === 'question') {
      return `<div class="smart-block"><span class="smart-block-label">Q&amp;A</span><strong>Q: ${formatInlineHtml(block.question || '')}</strong><br>A: ${formatInlineHtml(block.answer || '')}</div>`;
    }
    if (block.type === 'formula') {
      return `<div class="smart-block" style="text-align:center;font-family:monospace;"><span class="smart-block-label">Formula</span>${formatInlineHtml(block.text || '')}</div>`;
    }
    if (block.type === 'flow') {
      const steps = (block.steps || []).map(step => typeof step === 'string' ? step : (step.text || step.label || ''));
      const cards = steps.map((step, index) => {
        const chip = `<span style="display:inline-block;padding:6px 9px;border:1px solid var(--border);border-radius:6px;background:#f8fafc;">${formatInlineHtml(step)}</span>`;
        return (index ? '<span style="color:var(--accent-primary);font-weight:700;">→</span>' : '') + chip;
      }).join('');
      return `<div class="smart-block"><span class="smart-block-label">Flow</span>${block.title ? `<strong>${formatInlineHtml(block.title)}</strong><br>` : ''}<div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-top:6px;">${cards}</div></div>`;
    }
    if (block.type === 'uncertain') {
      return `<div class="smart-block" style="background:#fffbeb;border-color:#fde68a;color:#92400e;"><span class="smart-block-label">Review</span>${formatInlineHtml(block.text || '')}</div>`;
    }
    if (block.type === 'page_break') return '<hr style="border:0;border-top:1px solid var(--border-light);margin:14px 0;">';
    return '';
  }

  function renderDiagramCard(diagram, page, previews) {
    const preview = previews[diagram.id] || {};
    const sourceImage = preview.original_data_url
      ? `<img class="diagram-source-image" alt="Original source crop for ${escapeHtml(diagram.title || 'diagram')}" src="${preview.original_data_url}">`
      : '';
    const showRecreation = Boolean(diagramPreviewModes[diagram.id]);
    const useSource = (!showRecreation && diagram.use_original) || (!preview.svg && sourceImage);
    const sourceNote = preview.source_note || 'Source diagram preserved for accuracy.';
    const previewHtml = useSource && sourceImage
      ? `${sourceImage}<div class="diagram-preview-note">${escapeHtml(sourceNote)}</div>`
      : (preview.svg
        ? `<img alt="Preview of ${escapeHtml(diagram.title || 'diagram')}" src="${svgDataUrl(preview.svg)}">${diagram.use_original ? '<div class="diagram-preview-note">AI recreation preview — not used in the PDF until you click Use recreation.</div>' : ''}`
        : `<div class="diagram-error">${escapeHtml(preview.error || 'Source crop will be used because a vector preview is not available.')}</div>`);
    const labels = (diagram.labels || []).map(label => label.text).filter(Boolean);
    const warnings = [...(diagram.warnings || []), ...(diagram.uncertain || [])];
    const confidence = Number(diagram.confidence || 0);
    const canRecreate = Boolean(preview.svg);
    const previewToggle = preview.svg && sourceImage
      ? `<button type="button" class="btn-outline" data-diagram-action="toggle-preview" data-diagram-id="${escapeHtml(diagram.id)}">${useSource ? 'View AI recreation' : 'View source crop'}</button>`
      : '';
    const blockOptions = (page.blocks || [])
      .filter(block => block.type !== 'diagram')
      .map(block => `<option value="${escapeHtml(block.id)}" ${diagram.placement && diagram.placement.anchor_block_id === block.id ? 'selected' : ''}>${escapeHtml(blockLabel(block))}</option>`)
      .join('');
    return `<div class="diagram-card ${diagram.excluded ? 'excluded' : ''}" data-diagram-card="${escapeHtml(diagram.id)}">
      <div class="diagram-card-head">
        <div>
          <div class="diagram-card-title">${escapeHtml(diagram.title || diagram.type || 'Diagram')}</div>
          <div class="diagram-card-meta">${escapeHtml(diagram.category || 'other')} · ${escapeHtml(diagram.type || 'unknown')} · ${Math.round(confidence * 100)}% confidence</div>
        </div>
        <span class="premium-badge" style="background:${diagram.review_required ? '#b45309' : '#166534'};">${diagram.review_required ? 'REVIEW' : 'OK'}</span>
      </div>
      <div class="diagram-preview">${previewHtml}</div>
      ${preview.error && !useSource && !sourceImage ? `<div class="diagram-warning">${escapeHtml(preview.error)}</div>` : ''}
      ${labels.length ? `<div class="diagram-labels"><strong>Labels:</strong> ${labels.map(escapeHtml).join(' · ')}</div>` : ''}
      ${warnings.length ? `<div class="diagram-warning">${warnings.map(escapeHtml).join('<br>')}</div>` : ''}
      <label class="diagram-labels">Place after
        <select class="form-select" data-diagram-placement="${escapeHtml(diagram.id)}" style="margin-top:4px;font-size:11px;padding:5px;">
          ${blockOptions || '<option value="">End of page</option>'}
        </select>
      </label>
      <div class="diagram-actions">
        <button type="button" class="btn-outline" data-diagram-action="approve" data-diagram-id="${escapeHtml(diagram.id)}">${diagram.excluded ? 'Include' : 'Approve'}</button>
        ${previewToggle}
        <button type="button" class="btn-outline" data-diagram-action="original" data-diagram-id="${escapeHtml(diagram.id)}" ${canRecreate ? '' : 'disabled title="No AI recreation is available. The source crop is the accurate option."'}>${diagram.use_original ? 'Use recreation' : 'Keep original'}</button>
        <button type="button" class="btn-outline" data-diagram-action="edit" data-diagram-id="${escapeHtml(diagram.id)}">Edit labels</button>
        <button type="button" class="btn-outline" data-diagram-action="preview" data-diagram-id="${escapeHtml(diagram.id)}">Refresh preview</button>
        ${(diagram.labels || []).length ? `<button type="button" class="btn-outline" data-diagram-action="reconstruct" data-diagram-id="${escapeHtml(diagram.id)}">Retry recreation</button>` : ''}
        <button type="button" class="btn-outline" data-diagram-action="remove" data-diagram-id="${escapeHtml(diagram.id)}">${diagram.excluded ? 'Restore' : 'Remove'}</button>
      </div>
    </div>`;
  }

  function renderSmartReview(analysis, previews) {
    currentAnalysis = analysis || null;
    currentDiagramPreviews = previews || {};
    if (!smartReview || !smartReviewContent) return;
    if (!currentAnalysis) {
      smartReview.style.display = 'none';
      return;
    }
    const pages = currentAnalysis.pages || [];
    let html = '';
    if ((currentAnalysis.warnings || []).length) {
      html += `<div class="diagram-warning" style="margin-bottom:12px;"><strong>Review notes:</strong><br>${currentAnalysis.warnings.map(escapeHtml).join('<br>')}</div>`;
    }
    html += `<div class="smart-review-note">${pages.length} page(s) analysed. Diagrams are placed with their related blocks; edit labels or keep the original crop when a recreation is not safe.</div>`;
    pages.forEach(page => {
      if (pages.length > 1) {
        html += `<h4 style="margin:16px 0 8px;color:var(--accent-primary);">Page ${(page.page_index || 0) + 1}</h4>`;
      }
      html += '<div class="smart-block-list">';
      (page.blocks || []).forEach(block => {
        if (block.type === 'diagram') {
          const diagram = (page.diagrams || []).find(item => item.id === block.diagram_id);
          if (diagram) html += `<div class="smart-block" style="background:var(--surface-2);"><span class="smart-block-label">Diagram</span><strong>${escapeHtml(diagram.title || diagram.type || 'Diagram')}</strong> — placed here after the related block.</div>`;
        } else {
          html += renderSmartBlock(block);
        }
      });
      html += '</div>';
      if ((page.diagrams || []).length) {
        html += '<div class="diagram-review-grid">' + page.diagrams.map(diagram => renderDiagramCard(diagram, page, currentDiagramPreviews)).join('') + '</div>';
      }
    });
    smartReviewContent.innerHTML = html;
    smartReview.style.display = 'block';
  }

  async function refreshDiagramPreview(diagramId) {
    const diagram = diagramById(diagramId);
    if (!diagram) return;
    try {
      const response = await fetchWithTimeout('/api/diagrams/preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ diagram, style: currentDiagramStyle() }),
      }, 30000);
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'Preview failed.');
      currentDiagramPreviews[diagramId] = {
        ...(currentDiagramPreviews[diagramId] || {}),
        svg: data.svg,
        error: '',
      };
    } catch (error) {
      currentDiagramPreviews[diagramId] = {
        ...(currentDiagramPreviews[diagramId] || {}),
        error: error.message || 'Preview failed.',
      };
    }
    renderSmartReview(currentAnalysis, currentDiagramPreviews);
  }

  function replaceDiagram(diagramId, nextDiagram) {
    if (!currentAnalysis || !nextDiagram) return false;
    for (const page of currentAnalysis.pages || []) {
      const diagrams = page.diagrams || [];
      const index = diagrams.findIndex(item => item.id === diagramId);
      if (index >= 0) {
        diagrams[index] = nextDiagram;
        return true;
      }
    }
    return false;
  }

  async function reconstructDiagram(diagramId, button) {
    const diagram = diagramById(diagramId);
    if (!diagram) return;
    const hasFiles = selectedFiles.length > 0 || (input && input.files && input.files.length > 0);
    if (!hasFiles) {
      showToast('Re-select the source page to retry recreation.', 'error', 4000);
      return;
    }
    setButtonLoading(button, true);
    try {
      const data = formDataWithSelectedFiles();
      data.append('diagram', JSON.stringify(diagram));
      data.append('pageIndex', String(diagram.page_index || 0));
      data.append('diagramStyle', currentDiagramStyle());
      const response = await fetchWithTimeout('/api/diagrams/reconstruct', {
        method: 'POST',
        body: data,
      }, 180000);
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(payload.error || payload.detail || 'Recreation retry failed.');
      }
      if (!replaceDiagram(diagramId, payload.diagram)) {
        throw new Error('Could not update this diagram.');
      }
      currentDiagramPreviews[diagramId] = {
        ...(currentDiagramPreviews[diagramId] || {}),
        ...(payload.preview || {}),
      };
      diagramPreviewModes[diagramId] = false;
      renderSmartReview(currentAnalysis, currentDiagramPreviews);
      showToast(
        payload.diagram && payload.diagram.use_original
          ? 'Recreation retry finished. The source crop is still the default; compare it with the AI preview.'
          : 'Recreation retry finished. Review the diagram before generating the PDF.',
        'success',
        4500,
      );
    } catch (error) {
      showToast(error.message || 'Recreation retry failed. The source crop is still available.', 'error', 5000);
    } finally {
      setButtonLoading(button, false);
    }
  }

  async function refreshAllDiagramPreviews() {
    if (!currentAnalysis) return;
    const diagrams = [];
    (currentAnalysis.pages || []).forEach(page => {
      (page.diagrams || []).forEach(diagram => diagrams.push(diagram));
    });
    if (!diagrams.length) return;
    try {
      const response = await fetchWithTimeout('/api/diagrams/preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ diagrams, style: currentDiagramStyle() }),
      }, 60000);
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'Could not refresh diagram previews.');
      Object.entries(data.previews || {}).forEach(([diagramId, preview]) => {
        currentDiagramPreviews[diagramId] = {
          ...(currentDiagramPreviews[diagramId] || {}),
          ...preview,
        };
      });
      renderSmartReview(currentAnalysis, currentDiagramPreviews);
      showToast('Diagram appearance updated.', 'success', 2500);
    } catch (error) {
      showToast(error.message || 'Could not refresh diagram previews.', 'error');
    }
  }

  function moveDiagramBlock(diagramId, anchorBlockId) {
    if (!currentAnalysis) return;
    const page = (currentAnalysis.pages || []).find(item => (item.diagrams || []).some(diagram => diagram.id === diagramId));
    if (!page) return;
    const blockIndex = (page.blocks || []).findIndex(block => block.type === 'diagram' && block.diagram_id === diagramId);
    if (blockIndex < 0) return;
    const [diagramBlock] = page.blocks.splice(blockIndex, 1);
    const targetIndex = (page.blocks || []).findIndex(block => block.id === anchorBlockId);
    page.blocks.splice(targetIndex >= 0 ? targetIndex + 1 : page.blocks.length, 0, diagramBlock);
    const diagram = (page.diagrams || []).find(item => item.id === diagramId);
    if (diagram) diagram.placement = { ...(diagram.placement || {}), anchor_block_id: anchorBlockId, position: 'after' };
    renderSmartReview(currentAnalysis, currentDiagramPreviews);
  }

  if (smartReviewContent && !smartReviewContent.dataset.bound) {
    smartReviewContent.dataset.bound = '1';
    smartReviewContent.addEventListener('click', async event => {
      const button = event.target.closest('[data-diagram-action]');
      if (!button) return;
      const diagramId = button.getAttribute('data-diagram-id');
      const diagram = diagramById(diagramId);
      if (!diagram) return;
      const action = button.getAttribute('data-diagram-action');
      if (action === 'approve') {
        diagram.excluded = false;
        diagram.review_required = false;
        renderSmartReview(currentAnalysis, currentDiagramPreviews);
      } else if (action === 'remove') {
        diagram.excluded = !diagram.excluded;
        renderSmartReview(currentAnalysis, currentDiagramPreviews);
      } else if (action === 'original') {
        diagram.use_original = !diagram.use_original;
        diagramPreviewModes[diagramId] = false;
        renderSmartReview(currentAnalysis, currentDiagramPreviews);
      } else if (action === 'toggle-preview') {
        diagramPreviewModes[diagramId] = !diagramPreviewModes[diagramId];
        renderSmartReview(currentAnalysis, currentDiagramPreviews);
      } else if (action === 'edit') {
        const currentLabels = (diagram.labels || []).map(label => label.text).filter(Boolean).join(', ');
        const nextLabels = window.prompt('Edit diagram labels (comma-separated). Only correct what you can read in the source:', currentLabels);
        if (nextLabels === null) return;
        const labels = nextLabels.split(',').map(item => item.trim()).filter(Boolean);
        diagram.labels = labels.map(text => ({ text, source_text: text, confidence: 1 }));
        if (diagram.type === 'solar_system' && labels.length === 8) {
          diagram.template_data = { ...(diagram.template_data || {}), planets: labels.map((name, index) => ({ name, order: index + 1 })) };
        }
        await refreshDiagramPreview(diagramId);
      } else if (action === 'preview') {
        await refreshDiagramPreview(diagramId);
      } else if (action === 'reconstruct') {
        await reconstructDiagram(diagramId, button);
      }
    });
    smartReviewContent.addEventListener('change', event => {
      const select = event.target.closest('[data-diagram-placement]');
      if (!select) return;
      moveDiagramBlock(select.getAttribute('data-diagram-placement'), select.value);
    });
  }

  if (diagramStyleSelect && !diagramStyleSelect.dataset.bound) {
    diagramStyleSelect.dataset.bound = '1';
    diagramStyleSelect.addEventListener('change', () => {
      refreshAllDiagramPreviews();
    });
  }

  // ----- Utility Functions -----
  function showToast(message, type = 'info', duration = 4000, action = null) {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    const icons = {
      success: '✓',
      error: '✕',
      warning: '⚠',
      info: 'ℹ',
      processing: '◌'
    };
    const icon = document.createElement('span');
    icon.className = 'toast-icon';
    icon.setAttribute('aria-hidden', 'true');
    icon.textContent = icons[type] || icons.info;
    const text = document.createElement('span');
    text.textContent = message;
    const close = document.createElement('button');
    close.className = 'toast-close';
    close.setAttribute('aria-label', 'Dismiss');
    close.innerHTML = '&times;';
    close.addEventListener('click', () => toast.remove());
    toast.append(icon, text);
    if (action && typeof action.onClick === 'function') {
      const button = document.createElement('button');
      button.className = 'toast-action';
      button.textContent = action.label || 'Retry';
      button.addEventListener('click', () => {
        toast.remove();
        action.onClick();
      });
      toast.appendChild(button);
    }
    toast.appendChild(close);
    toastContainer.appendChild(toast);
    if (duration > 0) setTimeout(() => toast.remove(), duration);
    return toast;
  }

  function escapeHtml(text) {
    return String(text == null ? '' : text).replace(/[&<>"']/g, character => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    }[character]));
  }

  function formatBytes(bytes) {
    const value = Number(bytes) || 0;
    if (value < 1024) return value + ' B';
    if (value < 1048576) return (value / 1024).toFixed(1) + ' KB';
    return (value / 1048576).toFixed(2) + ' MB';
  }

  function formatDate(iso) {
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return '—';
    return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  }

  function setButtonLoading(btn, loading) {
    if (!btn) return;
    if (loading) {
      btn.classList.add('btn-loading');
      btn.disabled = true;
      btn.setAttribute('aria-busy', 'true');
    } else {
      btn.classList.remove('btn-loading');
      btn.disabled = false;
      btn.removeAttribute('aria-busy');
    }
  }

  function setActionBusy(busy) {
    [extractBtn, previewPdfBtn, generateBtn].forEach(button => {
      if (button) button.disabled = !!busy;
    });
  }

  function humanError(status, data, fallback) {
    const message = data && data.error ? String(data.error) : '';
    const code = data && data.code ? String(data.code) : '';
    if (status === 413) return 'File is too large. Each upload must be 20 MB or smaller.';
    if (status === 401 || status === 403) return message || 'You are not allowed to do that. Check the admin token in Settings.';
    if (status === 429) return message || 'Too many requests. Please wait a moment and retry.';
    if (status === 409 || code === 'REQUEST_IN_PROGRESS') return message || 'This request is already running. Wait for it to finish, then retry.';
    if (code === 'PROVIDER_NOT_CONFIGURED') return message || 'Add an AI provider API key in Settings or the server .env, then retry.';
    if (code === 'PROVIDER_MISMATCH') return message || 'Switch to the requested provider in Settings first.';
    if (code === 'PROVIDER_AUTH_FAILED') return message || 'The AI provider rejected the API key. Update it in Settings.';
    if (code === 'PDF_FONT_MISSING' || code === 'PDF_SHAPING_UNAVAILABLE') return message || 'The PDF fonts or Urdu shaping support are unavailable on this server.';
    if (code === 'EMPTY_AI_RESPONSE') return message || 'The AI returned no text. Try a clearer image.';
    if (code === 'INVALID_IMAGE' || code === 'UNSUPPORTED_FILE' || code === 'INVALID_PDF') return message || 'This file could not be read. Choose a JPG, PNG, WEBP, BMP or PDF.';
    if (code === 'DOCUMENT_NOT_FOUND' || code === 'DOCUMENT_NOT_EDITABLE') return message || 'This document is not available for that action.';
    if (status === 502 || status === 503 || status === 504) return message || 'The AI service is temporarily unavailable. Please retry in a moment.';
    if (status >= 500) return message || 'The server could not complete this request. Please retry.';
    return message || fallback;
  }

  function errorMeta(status, data, fallbackCode) {
    const code = data && data.code ? String(data.code) : (fallbackCode || '');
    let retryable = data && typeof data.retryable === 'boolean' ? data.retryable : undefined;
    if (retryable === undefined) {
      retryable = !code || status === 0 || status === 408 || status === 429 || status >= 500;
    }
    return { code: code, retryable: Boolean(retryable) };
  }

  function recoveryHint(code) {
    if (!code) return '';
    if (code === 'PROVIDER_NOT_CONFIGURED' || code === 'PROVIDER_AUTH_FAILED' || code === 'PROVIDER_MISMATCH') {
      return 'Open Settings to check the active provider and API key.';
    }
    if (code === 'PDF_FONT_MISSING' || code === 'PDF_SHAPING_UNAVAILABLE') {
      return 'Restore the bundled fonts or use Original Image PDF mode.';
    }
    if (code === 'REQUEST_IN_PROGRESS') {
      return 'The previous request is still finishing on the server. Wait a few seconds, then retry.';
    }
    if (code === 'INVALID_IMAGE' || code === 'UNSUPPORTED_FILE' || code === 'INVALID_PDF' || code === 'NO_FILES') {
      return 'Choose a supported file and try again.';
    }
    if (code === 'RATE_LIMITED') return 'The free provider is busy. Wait a moment, then retry.';
    if (code === 'AI_UNAVAILABLE' || code === 'AI_TIMEOUT' || code === 'NETWORK_ERROR') {
      return 'Check your connection and retry in a moment.';
    }
    return '';
  }

  function codeNeedsSettings(code) {
    return ['PROVIDER_NOT_CONFIGURED', 'PROVIDER_AUTH_FAILED', 'PROVIDER_MISMATCH'].indexOf(code) !== -1;
  }

  function xhrRequest(url, formData, options = {}) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', url, true);
      xhr.responseType = options.responseType || 'json';
      xhr.timeout = options.timeout || 180000;
      if (options.signal) {
        if (options.signal.aborted) {
          reject(new Error('aborted'));
          return;
        }
        options.signal.addEventListener('abort', () => {
          try { xhr.abort(); } catch (_) {}
        }, { once: true });
      }
      Object.entries(options.headers || {}).forEach(([key, value]) => {
        try { xhr.setRequestHeader(key, value); } catch (_) {}
      });
      if (xhr.upload) {
        if (options.onUploadProgress) {
          xhr.upload.onprogress = event => {
            if (event.lengthComputable) options.onUploadProgress(event.loaded, event.total);
          };
        }
        if (options.onUploadComplete) {
          xhr.upload.onload = () => options.onUploadComplete();
        }
      }
      if (options.onDownloadProgress) {
        xhr.onprogress = event => {
          if (event.lengthComputable) options.onDownloadProgress(event.loaded, event.total);
        };
      }
      xhr.onload = () => {
        const headers = {};
        (xhr.getAllResponseHeaders() || '').trim().split(/[\r\n]+/).forEach(line => {
          const index = line.indexOf(':');
          if (index > 0) headers[line.slice(0, index).trim().toLowerCase()] = line.slice(index + 1).trim();
        });
        let data = xhr.response;
        if ((options.responseType || 'json') === 'json' && typeof data === 'string') {
          try { data = JSON.parse(data); } catch (_) { data = null; }
        }
        resolve({ ok: xhr.status >= 200 && xhr.status < 300, status: xhr.status, data, headers });
      };
      xhr.onerror = () => reject(new Error('network'));
      xhr.ontimeout = () => reject(new Error('timeout'));
      xhr.onabort = () => reject(new Error('aborted'));
      xhr.send(formData);
    });
  }

  async function fetchWithTimeout(url, options = {}, timeoutMs = 60000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      return await fetch(url, { ...options, signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
  }

  async function blobError(response, fallback) {
    if (response && response.data && typeof response.data === 'object' && !response.data.text) {
      return {
        message: response.data.error || fallback,
        code: response.data.code || '',
        retryable: response.data.retryable,
      };
    }
    if (response && response.data && typeof response.data.text === 'function') {
      try {
        const text = await response.data.text();
        if (text) {
          try {
            const parsed = JSON.parse(text);
            if (parsed && (parsed.error || parsed.code)) {
              return {
                message: parsed.error || fallback,
                code: parsed.code || '',
                retryable: parsed.retryable,
              };
            }
          } catch (_) {}
        }
      } catch (_) {}
    }
    return { message: fallback, code: '', retryable: undefined };
  }

  function processingElements(kind) {
    return kind === 'ai'
      ? { panel: aiProcessing, title: aiProcessingTitle, subtitle: aiProcessingSubtitle,
          steps: aiProcessingSteps, progress: aiProcessingProgress, actions: aiProcessingActions,
          percent: aiProcessingPercent, elapsed: aiProcessingElapsed, cancel: null }
      : { panel: pdfProcessing, title: pdfProcessingTitle, subtitle: pdfProcessingSubtitle,
          steps: pdfProcessingSteps, progress: pdfProcessingProgress, actions: pdfProcessingActions,
          percent: pdfProcessingPercent, elapsed: pdfProcessingElapsed, cancel: null };
  }

  function clearProcessingActions(actions) {
    if (!actions) return;
    actions.replaceChildren();
    actions.hidden = true;
  }

  function hideProcessing(kind) {
    const parts = processingElements(kind);
    if (parts.panel) parts.panel.hidden = true;
  }

  function startProcessing(kind, title, subtitle) {
    const parts = processingElements(kind);
    if (!parts.panel) return;
    parts.panel.hidden = false;
    parts.panel.classList.remove('success', 'error', 'cancelled');
    parts.panel.setAttribute('aria-busy', 'true');
    const orb = parts.panel.querySelector('.processing-orb');
    if (orb) orb.textContent = orb.dataset.icon || (kind === 'ai' ? '✦' : '◈');
    if (parts.title) parts.title.textContent = title || 'Processing';
    if (parts.subtitle) parts.subtitle.textContent = subtitle || 'Please keep this page open.';
    if (parts.percent) parts.percent.textContent = 'Preparing…';
    if (parts.progress) {
      parts.progress.classList.remove('real');
      parts.progress.removeAttribute('role');
      parts.progress.removeAttribute('aria-valuenow');
      parts.progress.removeAttribute('aria-valuemin');
      parts.progress.removeAttribute('aria-valuemax');
      const bar = parts.progress.querySelector('span');
      if (bar) bar.style.width = '';
    }
    clearProcessingActions(parts.actions);
    startProcessingClock(kind);
    if (parts.actions) {
      const cancel = document.createElement('button');
      cancel.type = 'button';
      cancel.className = 'btn-3d btn-secondary processing-cancel';
      cancel.dataset.cancel = kind;
      cancel.textContent = 'Cancel';
      cancel.addEventListener('click', () => cancelActiveRequest(kind));
      parts.actions.replaceChildren(cancel);
      parts.actions.hidden = false;
      parts.cancel = cancel;
    }
    if (parts.steps) {
      Array.from(parts.steps.children).forEach((step, index) => {
        step.classList.toggle('active', index === 0);
        step.classList.toggle('done', false);
        const dot = step.querySelector('.step-dot');
        if (dot) dot.textContent = String(index + 1);
      });
    }
  }

  function setProcessingStep(kind, activeIndex, subtitle) {
    const parts = processingElements(kind);
    if (!parts.panel || !parts.steps) return;
    const total = parts.steps.children.length;
    Array.from(parts.steps.children).forEach((step, index) => {
      step.classList.toggle('done', index < activeIndex);
      step.classList.toggle('active', index === activeIndex);
      const dot = step.querySelector('.step-dot');
      if (dot) dot.textContent = index < activeIndex ? '✓' : String(index + 1);
    });
    if (subtitle && parts.subtitle) parts.subtitle.textContent = subtitle;
    if (parts.percent && !(parts.progress && parts.progress.classList.contains('real'))) {
      parts.percent.textContent = 'Step ' + Math.min(activeIndex + 1, total) + ' of ' + total;
    }
  }

  function setUploadProgress(kind, loaded, total) {
    const parts = processingElements(kind);
    if (!parts.progress) return;
    const bar = parts.progress.querySelector('span');
    if (!bar || !total) return;
    const percent = Math.max(0, Math.min(100, Math.round((loaded / total) * 100)));
    parts.progress.classList.add('real');
    parts.progress.setAttribute('role', 'progressbar');
    parts.progress.setAttribute('aria-valuemin', '0');
    parts.progress.setAttribute('aria-valuemax', '100');
    parts.progress.setAttribute('aria-valuenow', String(percent));
    bar.style.width = percent + '%';
    if (parts.percent) {
      parts.percent.textContent = percent >= 100 ? 'Upload complete — processing…' : percent + '% uploaded';
    }
    if (percent >= 100) {
      setTimeout(() => {
        parts.progress.classList.remove('real');
        parts.progress.removeAttribute('aria-valuenow');
        bar.style.width = '';
      }, 350);
    }
  }

  function setDownloadProgress(kind, loaded, total) {
    const parts = processingElements(kind);
    if (!parts.progress) return;
    const bar = parts.progress.querySelector('span');
    if (!bar || !total) return;
    const percent = Math.max(0, Math.min(100, Math.round((loaded / total) * 100)));
    if (parts.steps && parts.steps.children.length) {
      setProcessingStep(kind, parts.steps.children.length - 1, 'Receiving the finished PDF…');
    }
    parts.progress.classList.add('real');
    parts.progress.setAttribute('role', 'progressbar');
    parts.progress.setAttribute('aria-valuemin', '0');
    parts.progress.setAttribute('aria-valuemax', '100');
    parts.progress.setAttribute('aria-valuenow', String(percent));
    bar.style.width = percent + '%';
    if (parts.percent) {
      parts.percent.textContent = percent >= 100 ? 'Download ready' : percent + '% received';
    }
  }

  function finishProcessing(kind, outcome, message, retry, options = {}) {
    const parts = processingElements(kind);
    if (!parts.panel) return;
    const cancelled = outcome === 'cancelled';
    const ok = outcome === true;
    const code = options.code || '';
    const hint = recoveryHint(code);
    const retryable = options.retryable !== false;
    parts.panel.hidden = false;
    parts.panel.classList.remove('success', 'error', 'cancelled');
    parts.panel.classList.add(cancelled ? 'cancelled' : (ok ? 'success' : 'error'));
    parts.panel.setAttribute('aria-busy', 'false');
    const orb = parts.panel.querySelector('.processing-orb');
    if (orb) orb.textContent = ok ? '✓' : (cancelled ? '‖' : '!');
    stopProcessingClock(kind);
    if (parts.steps) {
      Array.from(parts.steps.children).forEach((step, index) => {
        const wasDone = step.classList.contains('done');
        step.classList.toggle('done', ok || (wasDone && !cancelled));
        step.classList.remove('active');
        const dot = step.querySelector('.step-dot');
        if (dot) dot.textContent = (ok || (wasDone && !cancelled)) ? '✓' : String(index + 1);
      });
    }
    if (parts.title) {
      parts.title.textContent = ok ? 'Completed successfully' : (cancelled ? 'Request cancelled' : 'Could not complete');
      parts.title.setAttribute('tabindex', '-1');
    }
    if (parts.subtitle) {
      const base = message || (ok ? 'Your document is ready.' : (cancelled ? 'You can retry when you are ready.' : 'Please retry.'));
      parts.subtitle.textContent = hint ? base + ' ' + hint : base;
    }
    if (parts.percent) {
      parts.percent.textContent = ok ? 'Complete' : (cancelled ? 'Cancelled' : 'Stopped');
    }
    clearProcessingActions(parts.actions);
    parts.cancel = null;
    if (!ok && parts.actions) {
      if (retry && retryable) {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'btn-3d btn-secondary';
        button.textContent = 'Retry';
        button.addEventListener('click', () => {
          if (requestState.active) {
            showToast('A request is already running. Please wait or cancel it.', 'warning', 3500);
            return;
          }
          retry();
        });
        parts.actions.appendChild(button);
      }
      if (codeNeedsSettings(code)) {
        const settingsLink = document.createElement('a');
        settingsLink.className = 'btn-3d btn-secondary';
        settingsLink.href = '/settings';
        settingsLink.textContent = 'Open Settings';
        parts.actions.appendChild(settingsLink);
      }
      const dismiss = document.createElement('button');
      dismiss.type = 'button';
      dismiss.className = 'btn-3d btn-ghost';
      dismiss.textContent = 'Dismiss';
      dismiss.addEventListener('click', () => hideProcessing(kind));
      parts.actions.appendChild(dismiss);
      parts.actions.hidden = false;
      if (!cancelled && parts.title) {
        try { parts.title.focus({ preventScroll: true }); } catch (_) {}
      }
    }
    if (ok) {
      setTimeout(() => { parts.panel.hidden = true; }, 2400);
    }
  }

  // ----- API Calls -----
  async function fetchStats() {
    try {
      const res = await fetch('/api/stats');
      if (res.ok) {
        const data = await res.json();
        if (statProgress) statProgress.textContent = data.in_progress || 0;
        if (statCompleted) statCompleted.textContent = data.completed || 0;
        if (statFailed) statFailed.textContent = data.failed || 0;
      }
    } catch (_) {}
    fetchPlan();
  }

  async function fetchPlan() {
    if (!statPlan) return;
    try {
      const res = await fetch('/api/plan', { cache: 'no-store' });
      if (!res.ok) return;
      const data = await res.json();
      statPlan.textContent = data.label || 'Free workspace';
      if (statPlanDesc) {
        const limits = data.limits || {};
        statPlanDesc.textContent = `${limits.max_documents || 100} documents · ${limits.max_storage_mb || 250} MB target`;
      }
    } catch (_) {}
  }

  async function fetchActivity() {
    if (!activityList) return;
    try {
      const res = await fetch('/api/activity');
      if (res.ok) {
        const data = await res.json();
        renderActivity(data);
      }
    } catch (_) {}
  }

  function renderListLoading(container, label) {
    if (!container) return;
    container.setAttribute('aria-busy', 'true');
    const isOrders = container.id === 'orderList';
    const cards = Array.from({ length: isOrders ? 3 : 4 }, () =>
      `<div class="skeleton skeleton-card${isOrders ? ' skeleton-row' : ''}"></div>`
    ).join('');
    container.innerHTML = `
      <div class="skeleton-grid" aria-hidden="true">${cards}</div>
      <span class="visually-hidden">${label}. Please wait a moment.</span>
    `;
  }

  function renderListError(container, label, retry) {
    if (!container) return;
    container.setAttribute('aria-busy', 'false');
    container.innerHTML = `
      <div class="empty-state" style="grid-column: 1 / -1; width: 100%;">
        <div class="empty-state-icon" aria-hidden="true">⚠</div>
        <h4>${label}</h4>
        <p>Check that NotesAI is running, then try again.</p>
        <button type="button" class="btn-3d btn-secondary" data-retry>Retry</button>
      </div>
    `;
    const button = container.querySelector('[data-retry]');
    if (button) button.addEventListener('click', retry);
  }

  async function fetchDocuments() {
    if (!documentGrid && !dashboardRecent && !statTotal && !statStorage) return;
    if (documentGrid) renderListLoading(documentGrid, 'Loading documents');
    try {
      const url = documentShowTrash ? '/api/documents?trash=1' : '/api/documents';
      const res = await fetchWithTimeout(url, { cache: 'no-store' }, 30000);
      if (res.ok) {
        const data = await res.json();
        allDocuments = Array.isArray(data) ? data : [];
        if (documentGrid) applyDocumentFilters();
        else updateDocumentDashboard();
      } else {
        throw new Error('Could not load documents.');
      }
    } catch (_) {
      if (documentGrid) renderListError(documentGrid, 'Could not load documents', fetchDocuments);
      if (documentCount) documentCount.textContent = '—';
      showToast('Could not load document history. Please retry.', 'error', 6000, {
        label: 'Retry',
        onClick: fetchDocuments
      });
    } finally {
      if (documentGrid) documentGrid.setAttribute('aria-busy', 'false');
    }
  }

  async function fetchOrders() {
    if (!orderList) return;
    renderListLoading(orderList, 'Loading order history');
    try {
      const res = await fetchWithTimeout('/api/orders', { cache: 'no-store' }, 30000);
      if (res.ok) {
        const data = await res.json();
        allOrders = Array.isArray(data) ? data : [];
        applyOrderFilters();
      } else {
        throw new Error('Could not load orders.');
      }
    } catch (_) {
      renderListError(orderList, 'Could not load order history', fetchOrders);
      if (orderCount) orderCount.textContent = '—';
      showToast('Could not load order history. Please retry.', 'error', 6000, {
        label: 'Retry',
        onClick: fetchOrders
      });
    } finally {
      orderList.setAttribute('aria-busy', 'false');
    }
  }

  function applyDocumentFilters() {
    if (!documentGrid) return;
    const query = (documentSearch ? documentSearch.value : '').trim().toLowerCase();
    const status = documentStatusFilter ? documentStatusFilter.value : 'all';
    const kind = documentKindFilter ? documentKindFilter.value : 'all';
    const folder = (documentFolderFilter ? documentFolderFilter.value : '').trim().toLowerCase();
    const tag = (documentTagFilter ? documentTagFilter.value : '').trim().toLowerCase();
    const onlyFavorites = !!(documentFavoriteFilter && documentFavoriteFilter.checked);
    const filtered = allDocuments.filter(doc => {
      const name = String(doc.name || '');
      const folderValue = String(doc.folder || '');
      const tags = Array.isArray(doc.tags) ? doc.tags : [];
      const haystack = [name, folderValue, doc.category || '', ...tags].join(' ').toLowerCase();
      const matchesQuery = !query || haystack.includes(query);
      const matchesStatus = status === 'all' || String(doc.status || 'completed') === status;
      const matchesKind = kind === 'all' || String(doc.kind || '') === kind;
      const matchesFolder = !folder || folderValue.toLowerCase().includes(folder);
      const matchesTag = !tag || tags.some(value => String(value).toLowerCase().includes(tag));
      const matchesFavorite = !onlyFavorites || !!doc.favorite;
      return matchesQuery && matchesStatus && matchesKind && matchesFolder && matchesTag && matchesFavorite;
    });
    const totalPages = Math.max(1, Math.ceil(filtered.length / documentPageSize));
    if (documentPage > totalPages) documentPage = totalPages;
    const start = (documentPage - 1) * documentPageSize;
    const pageDocs = filtered.slice(start, start + documentPageSize);
    if (documentCount) documentCount.textContent = `${filtered.length} of ${allDocuments.length} document(s)`;
    renderDocuments(pageDocs, allDocuments.length > 0);
    renderDocumentPager(filtered.length);
    updateDocumentDashboard();
  }

  function renderDocumentPager(total) {
    if (!documentPager) return;
    const pages = Math.max(1, Math.ceil(total / documentPageSize));
    if (pages <= 1) {
      documentPager.innerHTML = '';
      return;
    }
    documentPager.innerHTML = `
      <button type="button" data-doc-page="${Math.max(1, documentPage - 1)}" ${documentPage <= 1 ? 'disabled' : ''}>Previous</button>
      <span>Page ${documentPage} of ${pages}</span>
      <button type="button" data-doc-page="${Math.min(pages, documentPage + 1)}" ${documentPage >= pages ? 'disabled' : ''}>Next</button>
    `;
  }

  function updateDocumentDashboard() {
    const activeDocs = allDocuments.filter(doc => !doc.deleted_at);
    if (statTotal) statTotal.textContent = activeDocs.length;
    if (statStorage) {
      const total = activeDocs.reduce((sum, doc) => sum + Number(doc.size || 0), 0);
      statStorage.textContent = formatBytes(total);
    }
    if (!dashboardRecent) return;
    if (!activeDocs.length) {
      dashboardRecent.innerHTML = '<div class="empty-state" style="padding:16px;"><p>No documents yet.</p></div>';
      return;
    }
    dashboardRecent.innerHTML = activeDocs.slice(0, 4).map(doc => `
      <a class="recent-mini" href="/my-notes">
        <span class="recent-mini-icon" aria-hidden="true">▤</span>
        <span style="min-width:0;">
          <strong>${escapeHtml(doc.name || 'Untitled document')}</strong>
          <small>${formatBytes(doc.size)} · ${escapeHtml(formatDate(doc.created))}</small>
        </span>
      </a>
    `).join('');
  }

  function applyOrderFilters() {
    if (!orderList) return;
    const query = (orderSearch ? orderSearch.value : '').trim().toLowerCase();
    const status = orderStatusFilter ? orderStatusFilter.value : 'all';
    const filtered = allOrders.filter(order => {
      const matchesQuery = !query || String(order.name || '').toLowerCase().includes(query);
      const matchesStatus = status === 'all' || String(order.status || 'completed') === status;
      return matchesQuery && matchesStatus;
    });
    if (orderCount) orderCount.textContent = filtered.length + ' of ' + allOrders.length + ' order(s)';
    renderOrders(filtered, allOrders.length > 0);
  }

  // ----- Render Functions -----
  function renderActivity(activities) {
    if (!activities.length) {
      activityList.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon" aria-hidden="true">◷</div>
          <h4>No recent activity</h4>
          <p>Your document conversions and orders will appear here.</p>
        </div>
      `;
      return;
    }
    activityList.innerHTML = activities.map(a => `
      <div class="activity-item">
        <div class="activity-icon" aria-hidden="true">${getActivityIcon(a.action)}</div>
        <div class="activity-content">
          <div class="activity-title">${escapeHtml(a.action)}</div>
          <div class="activity-detail">${escapeHtml(a.detail)}</div>
        </div>
        <span class="activity-status ${escapeHtml(a.status)}">${escapeHtml(a.status)}</span>
        <time class="activity-time" datetime="${escapeHtml(a.timestamp)}">${formatDate(a.timestamp)}</time>
      </div>
    `).join('');
  }

  function getActivityIcon(action) {
    const icons = {
      'Upload': '⇧',
      'Extract': '✧',
      'Generate PDF': '⟳',
      'Download': '⤓',
      'Create Order': '＋',
      'Settings': '⚙'
    };
    return icons[action] || '▤';
  }

  function renderDocuments(docs, hasAny) {
    if (!docs.length) {
      const inTrash = documentShowTrash;
      documentGrid.innerHTML = `
        <div class="empty-state" style="grid-column: 1 / -1;">
          <div class="empty-state-icon" aria-hidden="true">${hasAny ? '⌕' : '▤'}</div>
          <h4>${inTrash ? 'Trash is empty' : hasAny ? 'No matching documents' : 'No documents yet'}</h4>
          <p>${inTrash ? 'Deleted documents appear here until you restore them.' : hasAny ? 'Try a different search term or filter.' : 'Create your first document from PDF Studio.'}</p>
        </div>
      `;
      return;
    }
    documentGrid.innerHTML = docs.map(d => {
      const status = String(d.status || 'completed');
      const isDeleted = !!d.deleted_at;
      const canRegenerate = !isDeleted && ['professional', 'text', 'regenerated', 'smart', 'smart-regenerated'].includes(String(d.kind || ''));
      const tags = Array.isArray(d.tags) ? d.tags : [];
      const badges = [
        d.folder ? `<span class="doc-badge folder">▸ ${escapeHtml(d.folder)}</span>` : '',
        d.favorite ? '<span class="doc-badge favorite">★ Favorite</span>' : '',
        ...tags.slice(0, 3).map(tag => `<span class="doc-badge">${escapeHtml(tag)}</span>`),
      ].filter(Boolean).join('');
      return `
      <article class="document-card">
        ${d.thumbnail ? `<img src="${escapeHtml(d.thumbnail)}" alt="" class="document-thumb" loading="lazy">` : '<div class="document-thumb" style="display:grid;place-items:center;color:var(--text-muted);font-size:32px;">▤</div>'}
        <div class="document-info">
          <span class="document-name" title="${escapeHtml(d.name)}">${escapeHtml(d.name)}</span>
          <div class="document-meta">
            <span>${escapeHtml(d.kind || d.type || 'pdf')}</span>
            <span>${formatBytes(d.size)}</span>
            <span>${formatDate(d.created)}</span>
            <span class="order-status ${escapeHtml(status)}">${escapeHtml(status)}</span>
          </div>
          ${badges ? `<div class="document-badges">${badges}</div>` : ''}
        </div>
        <div class="document-actions">
          <button class="btn-3d btn-secondary" type="button" data-doc-action="details" data-doc-id="${escapeHtml(d.id)}">Details</button>
          ${isDeleted ? '' : `<button class="btn-3d btn-secondary" type="button" data-doc-action="download" data-doc-id="${escapeHtml(d.id)}">Download</button>`}
          ${isDeleted ? `<button class="btn-3d btn-primary" type="button" data-doc-action="restore" data-doc-id="${escapeHtml(d.id)}">Restore</button>` : canRegenerate ? `<button class="btn-3d btn-primary" type="button" data-doc-action="regenerate" data-doc-id="${escapeHtml(d.id)}">Regenerate</button>` : ''}
        </div>
      </article>
    `;
    }).join('');
  }

  function openDocumentModal(id) {
    if (!documentModal) return;
    const doc = allDocuments.find(item => item.id === id);
    if (!doc) {
      showToast('That document is no longer available. Refresh and retry.', 'warning');
      return;
    }
    activeDocument = doc;
    lastFocusedElement = document.activeElement;
    if (documentModalId) documentModalId.value = doc.id;
    if (documentModalName) documentModalName.value = doc.name || '';
    if (documentModalFolder) documentModalFolder.value = doc.folder || '';
    if (documentModalTags) documentModalTags.value = Array.isArray(doc.tags) ? doc.tags.join(', ') : '';
    if (documentModalCategory) documentModalCategory.value = doc.category || '';
    if (documentModalFavorite) documentModalFavorite.checked = !!doc.favorite;
    if (documentModalMeta) {
      documentModalMeta.textContent = `${doc.kind || doc.type || 'pdf'} · ${formatBytes(doc.size)} · ${formatDate(doc.created)}${doc.deleted_at ? ' · In trash' : ''}`;
    }
    if (documentModalDelete) documentModalDelete.hidden = !!doc.deleted_at;
    if (documentModalRestore) documentModalRestore.hidden = !doc.deleted_at;
    if (documentModalDownload) documentModalDownload.hidden = !!doc.deleted_at;
    documentModal.classList.add('open');
    documentModal.setAttribute('aria-hidden', 'false');
    updateBodyScrollLock();
    if (documentModalName) documentModalName.focus();
  }

  function closeDocumentModal() {
    if (!documentModal) return;
    documentModal.classList.remove('open');
    documentModal.setAttribute('aria-hidden', 'true');
    activeDocument = null;
    updateBodyScrollLock();
    if (lastFocusedElement && typeof lastFocusedElement.focus === 'function') lastFocusedElement.focus();
  }

  async function saveDocumentDetails() {
    if (!activeDocument || !documentModalId) return;
    const payload = {
      name: documentModalName ? documentModalName.value.trim() : '',
      folder: documentModalFolder ? documentModalFolder.value.trim() : '',
      category: documentModalCategory ? documentModalCategory.value.trim() : '',
      tags: documentModalTags ? documentModalTags.value.split(',').map(value => value.trim()).filter(Boolean) : [],
      favorite: !!(documentModalFavorite && documentModalFavorite.checked),
    };
    if (!payload.name) {
      showToast('Enter a document name.', 'warning');
      return;
    }
    setButtonLoading(documentModalSave, true);
    try {
      const res = await fetch('/api/documents/' + encodeURIComponent(documentModalId.value), {
        method: 'PATCH', headers: adminHeaders(), body: JSON.stringify(payload)
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || 'Could not save document details.');
      closeDocumentModal();
      showToast('Document details saved.', 'success');
      fetchDocuments();
    } catch (error) {
      showToast(error.message || 'Could not save document details.', 'error', 6000);
    } finally {
      setButtonLoading(documentModalSave, false);
    }
  }

  async function trashActiveDocument() {
    if (!activeDocument) return;
    if (!window.confirm('Move this document to trash? You can restore it later.')) return;
    setButtonLoading(documentModalDelete, true);
    try {
      const res = await fetch('/api/documents/' + encodeURIComponent(activeDocument.id), {
        method: 'DELETE', headers: adminHeaders()
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || 'Could not move the document to trash.');
      closeDocumentModal();
      showToast('Document moved to trash.', 'success');
      fetchDocuments();
    } catch (error) {
      showToast(error.message || 'Could not move the document to trash.', 'error', 6000);
    } finally {
      setButtonLoading(documentModalDelete, false);
    }
  }

  async function restoreActiveDocument() {
    if (!activeDocument) return;
    setButtonLoading(documentModalRestore, true);
    try {
      const res = await fetch('/api/documents/' + encodeURIComponent(activeDocument.id) + '/restore', {
        method: 'POST', headers: adminHeaders()
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || 'Could not restore the document.');
      closeDocumentModal();
      showToast('Document restored.', 'success');
      fetchDocuments();
    } catch (error) {
      showToast(error.message || 'Could not restore the document.', 'error', 6000);
    } finally {
      setButtonLoading(documentModalRestore, false);
    }
  }

  function renderOrders(orders, hasAny) {
    if (!orders.length) {
      orderList.innerHTML = `
        <div class="empty-state" style="width:100%;">
          <div class="empty-state-icon" aria-hidden="true">${hasAny ? '⌕' : '◷'}</div>
          <h4>${hasAny ? 'No matching orders' : 'No orders yet'}</h4>
          <p>${hasAny ? 'Try a different search term or status filter.' : 'Your completed and processing orders will appear here.'}</p>
        </div>
      `;
      return;
    }
    orderList.innerHTML = orders.map(o => {
      const status = String(o.status || 'completed');
      return `
      <div class="order-item">
        <div class="order-icon ${escapeHtml(o.type || 'pdf')}">${getOrderIcon(o.type)}</div>
        <div class="order-details">
          <div class="order-name" title="${escapeHtml(o.name)}">${escapeHtml(o.name)}</div>
          <div class="order-meta">
            <span>${escapeHtml(o.type || 'pdf')}</span>
            <span>${formatBytes(o.size)}</span>
            <span>${formatDate(o.created)}</span>
          </div>
        </div>
        <span class="order-status ${escapeHtml(status)}">${escapeHtml(status)}</span>
        <div class="order-actions">
          <button class="btn-3d btn-secondary" onclick="downloadOrder('${escapeHtml(o.id)}')" data-tooltip="Download this PDF again">Download</button>
          ${status !== 'completed' ? `<button class="btn-3d btn-primary" onclick="retryOrder('${escapeHtml(o.id)}')">Retry</button>` : ''}
        </div>
      </div>
    `;
    }).join('');
  }

  function getOrderIcon(type) {
    const icons = { pdf: '▤', text: '✎', image: '▥' };
    return icons[type] || '▤';
  }

  // ----- Job identity (prevents duplicate statistic counting) -----
  const jobIdInput = document.getElementById('jobId');
  function newJobId() {
    if (window.crypto && typeof window.crypto.randomUUID === 'function') {
      return window.crypto.randomUUID();
    }
    return 'job-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 10);
  }
  function refreshJobId() {
    if (jobIdInput) jobIdInput.value = newJobId();
  }
  refreshJobId();

  // ----- Dropzone / File Manager -----
  const MAX_FILE_BYTES = 20 * 1024 * 1024;
  const ALLOWED_EXTENSIONS = ['jpg', 'jpeg', 'png', 'webp', 'bmp', 'pdf'];

  function fileExtension(file) {
    const name = String(file && file.name ? file.name : '');
    return name.includes('.') ? name.split('.').pop().toLowerCase() : '';
  }

  function fileKey(file) {
    return [file.name, file.size, file.lastModified].join('|');
  }

  function fileTypeLabel(file) {
    const ext = fileExtension(file);
    if (ext === 'pdf') return 'PDF';
    return (ext || 'image').toUpperCase();
  }

  function syncInputFiles() {
    try {
      const transfer = new DataTransfer();
      selectedFiles.forEach(file => transfer.items.add(file));
      input.files = transfer.files;
    } catch (_) {
      // Older browsers may not allow assigning input.files. Selected files are
      // still appended explicitly to every request; clear the stale native
      // selection so it can never be submitted by accident.
      try { input.value = ''; } catch (_) {}
    }
  }

  function renderFilePreview() {
    if (!preview) return;
    preview.querySelectorAll('img[src^="blob:"], iframe[src^="blob:"]').forEach(element => {
      URL.revokeObjectURL(element.src);
    });
    preview.replaceChildren();
    if (!selectedFiles.length) {
      const empty = document.createElement('p');
      empty.textContent = 'No file selected';
      preview.appendChild(empty);
      status.textContent = '';
      return;
    }
    selectedFiles.forEach((file, index) => {
      const card = document.createElement('div');
      card.className = 'file-item';
      const ext = fileExtension(file);
      if (ext !== 'pdf' && (file.type.startsWith('image/') || ['jpg','jpeg','png','webp','bmp'].includes(ext))) {
        const img = document.createElement('img');
        img.alt = 'Selected image preview';
        img.src = URL.createObjectURL(file);
        card.appendChild(img);
      } else {
        const frame = document.createElement('iframe');
        frame.className = 'pdf-preview-frame';
        frame.title = 'PDF preview';
        frame.src = URL.createObjectURL(file);
        card.appendChild(frame);
      }
      const remove = document.createElement('button');
      remove.type = 'button';
      remove.className = 'file-remove';
      remove.setAttribute('aria-label', 'Remove ' + file.name);
      remove.innerHTML = '&times;';
      remove.addEventListener('click', event => {
        event.preventDefault();
        event.stopPropagation();
        selectedFiles.splice(index, 1);
        syncInputFiles();
        renderFilePreview();
        refreshJobId();
      });
      const badge = document.createElement('span');
      badge.className = 'file-badge';
      badge.textContent = fileTypeLabel(file);
      const name = document.createElement('strong');
      name.className = 'file-name';
      name.textContent = file.name;
      name.title = file.name;
      const meta = document.createElement('div');
      meta.className = 'file-meta';
      const size = document.createElement('small');
      size.textContent = formatBytes(file.size);
      meta.appendChild(size);
      card.append(remove, badge, name, meta);
      preview.appendChild(card);
    });
    const total = selectedFiles.reduce((sum, file) => sum + file.size, 0);
    status.textContent = selectedFiles.length + ' file(s) selected · ' + formatBytes(total) + ' total.';
  }

  function addFiles(files) {
    const incoming = Array.from(files || []);
    if (!incoming.length) return;
    const hasPdf = selectedFiles.some(file => fileExtension(file) === 'pdf')
      || incoming.some(file => fileExtension(file) === 'pdf');
    if (hasPdf && selectedFiles.length + incoming.length > 1) {
      showToast('Upload one PDF at a time, without mixing it with images.', 'warning');
      return;
    }
    const existing = new Set(selectedFiles.map(fileKey));
    let added = 0;
    incoming.forEach(file => {
      const ext = fileExtension(file);
      if (!ALLOWED_EXTENSIONS.includes(ext)) {
        showToast('Unsupported file: ' + file.name + '. Use JPG, PNG, WEBP, BMP or PDF.', 'warning');
        return;
      }
      if (file.size > MAX_FILE_BYTES) {
        showToast(file.name + ' is larger than 20 MB and was not added.', 'error');
        return;
      }
      if (existing.has(fileKey(file))) {
        showToast(file.name + ' is already selected.', 'info');
        return;
      }
      existing.add(fileKey(file));
      selectedFiles.push(file);
      added += 1;
    });
    if (added) {
      syncInputFiles();
      renderFilePreview();
      refreshJobId();
      dropzone.classList.remove('drag-active');
    }
  }

  if (dropzone && input) {
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(evt => {
      dropzone.addEventListener(evt, e => { e.preventDefault(); e.stopPropagation(); }, false);
    });
    ['dragenter', 'dragover'].forEach(evt => dropzone.addEventListener(evt, () => dropzone.classList.add('drag-active'), false));
    ['dragleave', 'drop'].forEach(evt => dropzone.addEventListener(evt, () => dropzone.classList.remove('drag-active'), false));
    dropzone.addEventListener('drop', e => addFiles(e.dataTransfer.files), false);
    dropzone.addEventListener('click', event => {
      if (event.target.closest('button')) return;
      input.click();
    });
    dropzone.addEventListener('keydown', e => {
      if (e.target !== dropzone) return;
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); }
    });
    input.addEventListener('change', () => {
      const files = Array.from(input.files || []);
      input.value = '';
      addFiles(files);
    });
  }

  // ----- Download helpers -----
  function filenameFromHeaders(headers, fallback) {
    const disposition = headers && headers['content-disposition'] ? headers['content-disposition'] : '';
    const utf8 = /filename\*=UTF-8''([^;]+)/i.exec(disposition);
    if (utf8) {
      try { return decodeURIComponent(utf8[1]); } catch (_) {}
    }
    const plain = /filename="?([^";]+)"?/i.exec(disposition);
    return plain ? plain[1] : fallback;
  }

  function triggerBlobDownload(blob, filename) {
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename || 'NotesAI-Document.pdf';
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 3000);
  }

  function hasFiles() {
    return selectedFiles.length > 0 || (input && input.files && input.files.length > 0);
  }

  function formDataWithSelectedFiles() {
    const data = new FormData(form);
    data.delete('noteFiles');
    const files = selectedFiles.length ? selectedFiles : Array.from((input && input.files) || []);
    files.forEach(file => data.append('noteFiles', file, file.name));
    return data;
  }

  // ----- Extract Text -----
  async function runExtraction(options = {}) {
    if (!hasFiles()) {
      showToast('Please choose note images or a PDF first.', 'warning');
      return false;
    }
    const smartMode = pdfModeSelect && pdfModeSelect.value === 'smart';
    const retryExtraction = () => {
      if (requestState.active) return false;
      return runExtraction(options);
    };
    const requestId = beginRequest('ai');
    if (!requestId) return false;
    startProcessing('ai', 'AI is reading your notes', 'Uploading your selected files…');
    setProcessingStep('ai', 0, 'Uploading your selected files…');
    setActionBusy(true);
    setButtonLoading(extractBtn, true);
    status.textContent = 'AI is reading your notes…';
    const stageTimers = [];
    const scheduleStage = (delay, step, message) => {
      stageTimers.push(setTimeout(() => {
        setProcessingStep('ai', step, message);
      }, delay));
    };
    scheduleStage(1400, 1, 'Checking the verified free vision model…');
    scheduleStage(5000, 2, 'Model is reading the page, tables and diagrams…');
    scheduleStage(18000, 2, 'Still reading — free vision models can take 10–30 seconds for a detailed page…');
    scheduleStage(45000, 2, 'Still working on a complex page. Your uploaded files and text are safe; you can retry if it takes too long.');
    try {
      const extractionForm = formDataWithSelectedFiles();
      extractionForm.set('diagramStyle', currentDiagramStyle());
      if (options.preview) extractionForm.set('preview', '1');
      if (smartMode) extractionForm.set('analysis', 'smart');
      const response = await xhrRequest('/extract-text', extractionForm, {
        timeout: smartMode ? 180000 : 150000,
        signal: requestState.controller ? requestState.controller.signal : undefined,
        onUploadProgress: (loaded, total) => setUploadProgress('ai', loaded, total),
        onUploadComplete: () => setProcessingStep('ai', 1, smartMode ? 'Checking the verified free model, then reading the page and its diagrams…' : 'Checking the provider, then reading the document…')
      });
      if (requestState.cancelled) throw new Error('aborted');
      if (!response.ok) {
        const message = humanError(response.status, response.data, 'Text extraction failed. Please retry.');
        const meta = errorMeta(response.status, response.data);
        status.textContent = message;
        finishProcessing('ai', false, message, retryExtraction, meta);
        showToast(message, 'error', 7000, meta.retryable ? { label: 'Retry', onClick: retryExtraction } : null);
        return false;
      }
      setProcessingStep('ai', 2, smartMode ? 'Extracting text, tables and labels…' : 'Extracting text from the document…');
      const data = response.data || {};
      setProcessingStep('ai', 3, smartMode ? 'Preparing the diagram review…' : 'Formatting the extracted text…');
      extractedText.value = data.text || '';
      if (data.smart && data.analysis) {
        currentAnalysis = data.analysis;
        currentDiagramPreviews = data.diagram_previews || {};
        diagramPreviewModes = {};
        renderSmartReview(data.analysis, currentDiagramPreviews);
        if (structuredPreview) structuredPreview.style.display = 'none';
        if (editorEmptyHint) editorEmptyHint.textContent = 'Smart review uses the structured blocks and diagrams above. Text edits do not change diagram placement; use the review controls for that.';
      } else {
        currentAnalysis = null;
        currentDiagramPreviews = {};
        diagramPreviewModes = {};
        if (smartReview) smartReview.style.display = 'none';
        if (data.structured) renderStructuredPreview(data.structured);
        else updateStructuredPreviewFromText();
      }
      const prov = data.provider ? ` (${data.provider}${data.model ? ': ' + data.model : ''})` : '';
      status.textContent = (data.smart ? 'Page understanding ready' : 'Text extracted') + prov + '. Review and edit before continuing.';
      finishProcessing('ai', true, data.smart ? 'Page understanding ready.' : 'Text extracted successfully.');
      showToast((data.smart ? 'Page understanding ready' : 'Text extracted successfully') + (data.provider ? ' via ' + data.provider : '') + '!', 'success');
      extractedText.focus();
      return true;
    } catch (error) {
      if (error && error.message === 'aborted') {
        const message = 'Request cancelled. You can retry when you are ready.';
        status.textContent = message;
        finishProcessing('ai', 'cancelled', message, retryExtraction);
        showToast(message, 'info', 4000);
        return false;
      }
      const message = error && error.message === 'timeout'
        ? 'The AI request timed out. Check your connection and retry.'
        : 'Connection error. Check that NotesAI is running and retry.';
      status.textContent = message;
      const meta = { code: error && error.message === 'timeout' ? 'AI_TIMEOUT' : 'NETWORK_ERROR', retryable: true };
      finishProcessing('ai', false, message, retryExtraction, meta);
      showToast(message, 'error', 7000, { label: 'Retry', onClick: retryExtraction });
      return false;
    } finally {
      stageTimers.forEach(clearTimeout);
      endRequest(requestId);
      setActionBusy(false);
      setButtonLoading(extractBtn, false);
    }
  }

  if (extractBtn) extractBtn.addEventListener('click', () => runExtraction());

  // ----- Generate PDF -----
  async function runPdfGeneration() {
    const mode = pdfModeSelect ? pdfModeSelect.value : 'professional';
    const smartMode = mode === 'smart';
    let hasText = extractedText.value.trim().length > 0;
    if (mode === 'image' && !hasFiles()) {
      showToast('Choose at least one image for the Original Image PDF mode.', 'warning');
      return;
    }
    if (smartMode && !currentAnalysis && !hasFiles()) {
      showToast('Choose page images first so Smart mode can understand the diagrams.', 'warning');
      return;
    }
    if (!hasFiles() && !(mode === 'professional' && hasText) && !(smartMode && currentAnalysis)) {
      showToast('Choose a file or extract/edit some text first.', 'warning');
      return;
    }

    if (mode === 'professional' && !hasText) {
      const extracted = await runExtraction();
      if (!extracted) return;
      hasText = extractedText.value.trim().length > 0;
    }
    if (mode === 'professional' && !hasText) {
      const message = 'Extraction returned no text. Add some text or try a clearer image.';
      status.textContent = message;
      showToast(message, 'warning');
      return;
    }
    if (smartMode && !currentAnalysis) {
      const extracted = await runExtraction();
      if (!extracted || !currentAnalysis) {
        const message = 'Smart page understanding did not return a diagram analysis. Try again or switch provider.';
        status.textContent = message;
        showToast(message, 'error');
        return;
      }
    }

    const retryGeneration = () => {
      if (requestState.active) return false;
      return runPdfGeneration();
    };
    const requestId = beginRequest('pdf');
    if (!requestId) return;
    startProcessing('pdf', 'Preparing your document', 'Uploading the source file…');
    setProcessingStep('pdf', 0, 'Uploading the source file…');
    setActionBusy(true);
    setButtonLoading(generateBtn, true);
    status.textContent = smartMode ? 'Recreating diagrams and generating PDF…' : mode === 'professional' ? 'Generating professional PDF…' : 'Preparing your PDF…';
    const stageTimers = [];
    const scheduleStage = (delay, step, message) => {
      stageTimers.push(setTimeout(() => setProcessingStep('pdf', step, message), delay));
    };
    scheduleStage(1600, 1, smartMode ? 'Rendering diagrams and placing them with related notes…' : 'Formatting pages and typography…');
    scheduleStage(8000, 2, 'Generating the PDF file…');
    scheduleStage(30000, 2, 'Still working on a detailed document. Your files are safe; you can cancel and retry if needed.');
    try {
      const formData = formDataWithSelectedFiles();
      formData.set('diagramStyle', currentDiagramStyle());
      formData.set('preview', '0');
      if (smartMode) {
        formData.set('mode', 'smart');
        formData.set('analysis', JSON.stringify(currentAnalysis));
      }
      const response = await xhrRequest('/generate-pdf', formData, {
        responseType: 'blob',
        timeout: smartMode ? 240000 : 180000,
        signal: requestState.controller ? requestState.controller.signal : undefined,
        onUploadProgress: (loaded, total) => setUploadProgress('pdf', loaded, total),
        onUploadComplete: () => setProcessingStep('pdf', 1, smartMode ? 'Rendering diagrams and placing them with related notes…' : 'Formatting pages and typography…'),
        onDownloadProgress: (loaded, total) => setDownloadProgress('pdf', loaded, total)
      });
      if (requestState.cancelled) throw new Error('aborted');
      if (!response.ok) {
        const info = await blobError(response, humanError(response.status, null, 'PDF generation failed. Please retry.'));
        const message = humanError(response.status, { error: info.message, code: info.code, retryable: info.retryable }, info.message);
        status.textContent = message;
        finishProcessing('pdf', false, message, retryGeneration, { code: info.code, retryable: info.retryable });
        showToast(message, 'error', 7000, info.retryable === false ? null : { label: 'Retry', onClick: retryGeneration });
        return;
      }
      setProcessingStep('pdf', 2, 'Generating the PDF file…');
      const statusHeader = response.headers['x-notesai-status'] || '';
      const filename = filenameFromHeaders(response.headers, statusHeader === 'professional-pdf'
        ? 'NotesAI-Professional.pdf'
        : statusHeader === 'text-pdf' ? 'NotesAI-Text.pdf'
          : statusHeader === 'smart-pdf' ? 'NotesAI-Smart.pdf' : 'NotesAI-Document.pdf');
      setProcessingStep('pdf', 3, 'Finalizing your download…');
      triggerBlobDownload(response.data, filename);
      const diagramWarnings = Number(response.headers['x-notesai-diagram-warnings'] || 0);
      const message = statusHeader === 'already-pdf'
        ? 'Your existing PDF has been downloaded.'
        : statusHeader === 'professional-pdf'
          ? 'Professional PDF generated and downloaded successfully.'
          : statusHeader === 'text-pdf'
            ? 'Text-based PDF generated and downloaded successfully.'
            : statusHeader === 'smart-pdf'
              ? (diagramWarnings
                ? `Smart PDF generated with ${diagramWarnings} diagram review note(s). Check the PDF and keep originals where needed.`
                : 'Smart PDF generated with recreated diagrams and downloaded successfully.')
            : statusHeader === 'image-pdf'
              ? 'Image-based PDF generated and downloaded successfully.'
              : 'PDF generated and downloaded successfully.';
      status.textContent = message;
      finishProcessing('pdf', true, message);
      showToast(message, diagramWarnings ? 'warning' : 'success');
      refreshJobId();
      fetchStats();
      fetchActivity();
      fetchDocuments();
      fetchOrders();
    } catch (error) {
      if (error && error.message === 'aborted') {
        const message = 'PDF generation cancelled. You can retry when you are ready.';
        status.textContent = message;
        finishProcessing('pdf', 'cancelled', message, retryGeneration);
        showToast(message, 'info', 4000);
        return;
      }
      const message = error && error.message === 'timeout'
        ? 'PDF generation timed out. Please retry.'
        : 'Connection error while generating the PDF. Please retry.';
      status.textContent = message;
      const meta = { code: error && error.message === 'timeout' ? 'AI_TIMEOUT' : 'NETWORK_ERROR', retryable: true };
      finishProcessing('pdf', false, message, retryGeneration, meta);
      showToast(message, 'error', 7000, { label: 'Retry', onClick: retryGeneration });
    } finally {
      stageTimers.forEach(clearTimeout);
      endRequest(requestId);
      setActionBusy(false);
      setButtonLoading(generateBtn, false);
    }
  }

  if (form) {
    form.addEventListener('submit', event => {
      event.preventDefault();
      runPdfGeneration();
    });
  }

  // ----- PDF Preview -----
  function updateBodyScrollLock() {
    const locked = Boolean(
      (pdfPreviewModal && pdfPreviewModal.classList.contains('open')) ||
      (sidebar && sidebar.classList.contains('open'))
    );
    document.body.style.overflow = locked ? 'hidden' : '';
  }

  function closePdfPreviewModal() {
    if (!pdfPreviewModal) return;
    pdfPreviewModal.classList.remove('open');
    pdfPreviewModal.setAttribute('aria-hidden', 'true');
    if (pdfPreviewBody) {
      pdfPreviewBody.replaceChildren();
      pdfPreviewBody.setAttribute('aria-busy', 'false');
    }
    if (pdfPreviewRetry) pdfPreviewRetry.hidden = true;
    if (pdfPreviewSubtitle) pdfPreviewSubtitle.textContent = 'Preview only — this does not add a document to history.';
    updateBodyScrollLock();
    if (lastPdfFocus && typeof lastPdfFocus.focus === 'function') {
      lastPdfFocus.focus();
    }
    lastPdfFocus = null;
  }

  function openPdfPreviewModal() {
    if (!pdfPreviewModal) return;
    lastPdfFocus = document.activeElement;
    pdfPreviewModal.classList.add('open');
    pdfPreviewModal.setAttribute('aria-hidden', 'false');
    updateBodyScrollLock();
    if (closePdfPreview) closePdfPreview.focus();
  }

  function setPdfPreviewLoading(message) {
    if (!pdfPreviewBody) return;
    if (pdfPreviewRetry) pdfPreviewRetry.hidden = true;
    if (pdfPreviewSubtitle) pdfPreviewSubtitle.textContent = 'Rendering your PDF preview — not saved to history.';
    pdfPreviewBody.setAttribute('aria-busy', 'true');
    pdfPreviewBody.innerHTML = `<div class="pdf-preview-state"><div class="pdf-preview-spinner" aria-hidden="true"></div><strong>Rendering PDF preview</strong><p>${escapeHtml(message || 'Please wait while the PDF pages are prepared.')}</p></div>`;
  }

  function showPdfPreviewError(message) {
    if (!pdfPreviewBody) return;
    if (pdfPreviewRetry) pdfPreviewRetry.hidden = false;
    if (pdfPreviewSubtitle) pdfPreviewSubtitle.textContent = 'Preview could not be rendered.';
    pdfPreviewBody.setAttribute('aria-busy', 'false');
    pdfPreviewBody.innerHTML = `<div class="pdf-preview-state error"><strong>Preview unavailable</strong><p>${escapeHtml(message || 'Could not create the PDF preview. Please retry.')}</p></div>`;
  }

  function renderPdfPreview(data) {
    if (!pdfPreviewBody) return;
    const pages = (data && data.pages) || [];
    if (!pages.length) {
      showPdfPreviewError('The generated PDF had no previewable pages.');
      return;
    }
    const pageCount = Number(data.page_count || pages.length);
    const note = data.truncated
      ? `<div class="pdf-preview-note">Showing the first ${pages.length} of ${pageCount} pages. Download the PDF to view every page.</div>`
      : '';
    const pageHtml = pages.map(page => {
      const number = Number(page.page || 1);
      return `<div class="pdf-preview-page"><img src="${page.data_url}" alt="PDF page ${number}" loading="${number === 1 ? 'eager' : 'lazy'}"></div>`;
    }).join('');
    pdfPreviewBody.setAttribute('aria-busy', 'false');
    pdfPreviewBody.innerHTML = `${note}<div class="pdf-preview-pages">${pageHtml}</div>`;
    if (pdfPreviewRetry) pdfPreviewRetry.hidden = true;
    if (pdfPreviewSubtitle) {
      pdfPreviewSubtitle.textContent = `${pageCount} page${pageCount === 1 ? '' : 's'} rendered locally — not saved to history.`;
    }
  }

  async function previewPdf() {
    const mode = pdfModeSelect ? pdfModeSelect.value : 'professional';
    const smartMode = mode === 'smart';
    if (!hasFiles() && !extractedText.value.trim() && !(smartMode && currentAnalysis)) {
      showToast('Choose a file or extract/edit some text first.', 'warning');
      return;
    }
    if (mode === 'image' && !hasFiles()) {
      showToast('Choose at least one image for the Original Image PDF mode.', 'warning');
      return;
    }
    if (mode === 'professional' && !extractedText.value.trim()) {
      const extracted = await runExtraction({ preview: true });
      if (!extracted) return;
    }
    if (smartMode && !currentAnalysis) {
      const extracted = await runExtraction({ preview: true });
      if (!extracted || !currentAnalysis) {
        showToast('Smart page understanding did not return a diagram analysis.', 'error');
        return;
      }
    }
    const retryPreview = () => {
      if (requestState.active) return false;
      return previewPdf();
    };
    const requestId = beginRequest('pdf');
    if (!requestId) return;
    openPdfPreviewModal();
    setPdfPreviewLoading('Preparing your document. This can take a few seconds.');
    startProcessing('pdf', 'Preparing PDF preview', 'This preview will not be saved to history.');
    setProcessingStep('pdf', 0, 'Preparing document…');
    setActionBusy(true);
    setButtonLoading(previewPdfBtn, true);
    try {
      const formData = formDataWithSelectedFiles();
      formData.set('diagramStyle', currentDiagramStyle());
      formData.set('preview', '1');
      formData.set('previewImages', '1');
      if (smartMode) {
        formData.set('mode', 'smart');
        formData.set('analysis', JSON.stringify(currentAnalysis));
      }
      const response = await xhrRequest('/generate-pdf', formData, {
        responseType: 'json',
        timeout: 180000,
        signal: requestState.controller ? requestState.controller.signal : undefined,
        onUploadProgress: (loaded, total) => setUploadProgress('pdf', loaded, total),
        onUploadComplete: () => {
          setProcessingStep('pdf', 1, smartMode ? 'Rendering diagrams and formatting pages…' : 'Formatting pages and typography…');
          setPdfPreviewLoading(smartMode ? 'Rendering diagrams and formatting pages…' : 'Formatting pages and typography…');
        }
      });
      if (requestState.cancelled) throw new Error('aborted');
      if (!response.ok) {
        const message = humanError(response.status, response.data, 'Could not create the PDF preview.');
        const meta = errorMeta(response.status, response.data);
        showPdfPreviewError(message);
        finishProcessing('pdf', false, message, retryPreview, meta);
        showToast(message, 'error', 7000, meta.retryable ? { label: 'Retry', onClick: retryPreview } : null);
        return;
      }
      setProcessingStep('pdf', 2, 'Rendering page previews…');
      setPdfPreviewLoading('Rendering page previews…');
      renderPdfPreview((response.data && response.data.preview) || response.data);
      setProcessingStep('pdf', 3, 'Preview ready.');
      finishProcessing('pdf', true, 'PDF preview ready.');
      showToast('PDF preview ready.', 'success');
    } catch (error) {
      if (error && error.message === 'aborted') {
        const message = 'PDF preview cancelled. You can retry when you are ready.';
        showPdfPreviewError(message);
        finishProcessing('pdf', 'cancelled', message, retryPreview);
        showToast(message, 'info', 4000);
        return;
      }
      const message = error && error.message === 'timeout'
        ? 'PDF preview timed out. Please retry.'
        : 'Could not create the PDF preview. Please retry.';
      showPdfPreviewError(message);
      finishProcessing('pdf', false, message, retryPreview, {
        code: error && error.message === 'timeout' ? 'AI_TIMEOUT' : 'NETWORK_ERROR',
        retryable: true
      });
      showToast(message, 'error', 7000, { label: 'Retry', onClick: retryPreview });
    } finally {
      endRequest(requestId);
      setActionBusy(false);
      setButtonLoading(previewPdfBtn, false);
    }
  }

  if (previewPdfBtn) previewPdfBtn.addEventListener('click', previewPdf);
  if (pdfPreviewRetry) pdfPreviewRetry.addEventListener('click', previewPdf);
  if (closePdfPreview) closePdfPreview.addEventListener('click', closePdfPreviewModal);
  if (pdfPreviewModal) {
    pdfPreviewModal.addEventListener('click', event => {
      if (event.target === pdfPreviewModal) closePdfPreviewModal();
    });
    pdfPreviewModal.addEventListener('keydown', event => {
      if (event.key !== 'Tab') return;
      const focusable = Array.from(pdfPreviewModal.querySelectorAll('button, iframe, a[href], [tabindex]:not([tabindex="-1"])'))
        .filter(element => element.offsetParent !== null);
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    });
  }

  // ----- Editor toolbar + live structured preview -----
  function insertEditorText(before, after, placeholder) {
    if (!extractedText) return;
    const start = extractedText.selectionStart || 0;
    const end = extractedText.selectionEnd || 0;
    const value = extractedText.value;
    const selected = value.slice(start, end) || placeholder || '';
    extractedText.value = value.slice(0, start) + before + selected + after + value.slice(end);
    const cursor = start + before.length + selected.length + after.length;
    extractedText.focus();
    extractedText.setSelectionRange(cursor, cursor);
    extractedText.dispatchEvent(new Event('input', { bubbles: true }));
  }

  function insertEditorLinePrefix(prefix) {
    if (!extractedText) return;
    const start = extractedText.selectionStart || 0;
    const value = extractedText.value;
    const lineStart = value.lastIndexOf('\n', Math.max(0, start - 1)) + 1;
    extractedText.value = value.slice(0, lineStart) + prefix + value.slice(lineStart);
    const cursor = start + prefix.length;
    extractedText.focus();
    extractedText.setSelectionRange(cursor, cursor);
    extractedText.dispatchEvent(new Event('input', { bubbles: true }));
  }

  function applyEditorFormat(format) {
    if (!extractedText) return;
    if (format === 'h1') insertEditorLinePrefix('# ');
    else if (format === 'h2') insertEditorLinePrefix('## ');
    else if (format === 'bold') insertEditorText('**', '**', 'bold text');
    else if (format === 'bullet') insertEditorLinePrefix('- ');
    else insertEditorText('\n\n', '', '');
  }

  document.querySelectorAll('.editor-toolbar [data-format]').forEach(button => {
    button.addEventListener('click', () => applyEditorFormat(button.dataset.format));
  });

  function parseEditorPreview(text) {
    const cleaned = String(text || '').trim();
    if (!cleaned) return null;
    try {
      const parsed = JSON.parse(cleaned);
      if (parsed && typeof parsed === 'object' && Array.isArray(parsed.sections)) return parsed;
    } catch (_) {}
    const structured = { title: '', sections: [] };
    let current = null;
    let content = [];
    const flush = () => {
      const body = content.join('\n').replace(/\n{3,}/g, '\n\n').trim();
      if (current) {
        current.content = body;
        structured.sections.push(current);
      } else if (body) {
        // Text between the title and the first heading is still body content.
        structured.sections.push({ heading: '', level: 1, content: body });
      }
      current = null;
      content = [];
    };
    cleaned.split('\n').forEach(line => {
      const trimmed = line.trim();
      if (trimmed.startsWith('# ')) {
        flush();
        if (!structured.title) structured.title = trimmed.slice(2).trim();
        else current = { heading: trimmed.slice(2).trim(), level: 1, content: '' };
      } else if (trimmed.startsWith('## ')) {
        flush();
        current = { heading: trimmed.slice(3).trim(), level: 1, content: '' };
      } else if (trimmed.startsWith('### ')) {
        flush();
        current = { heading: trimmed.slice(4).trim(), level: 2, content: '' };
      } else if (trimmed.startsWith('#### ')) {
        flush();
        current = { heading: trimmed.slice(5).trim(), level: 3, content: '' };
      } else {
        content.push(line);
      }
    });
    flush();
    if (!structured.title && structured.sections.length && structured.sections[0].heading) {
      const first = structured.sections.shift();
      structured.title = first.heading;
      if (String(first.content || '').trim()) {
        structured.sections.unshift({ heading: '', level: first.level || 1, content: first.content || '' });
      }
    }
    if (!structured.title) structured.title = 'Converted Document';
    if (!structured.sections.length) {
      structured.sections.push({ heading: '', level: 1, content: cleaned });
    }
    return structured;
  }

  let previewTimer = null;
  function updateStructuredPreviewFromText() {
    if (!extractedText || !previewContent) return;
    const text = extractedText.value.trim();
    if (!text) {
      if (structuredPreview) structuredPreview.style.display = 'none';
      return;
    }
    const structured = parseEditorPreview(text);
    if (structured) renderStructuredPreview(structured);
  }

  if (extractedText) {
    extractedText.addEventListener('input', () => {
      if (editorEmptyHint) {
        editorEmptyHint.textContent = extractedText.value.trim()
          ? 'Live preview updates as you edit. Blank lines separate paragraphs.'
          : 'Tip: use H1/H2 to create headings; blank lines separate paragraphs.';
      }
      clearTimeout(previewTimer);
      previewTimer = setTimeout(updateStructuredPreviewFromText, 300);
    });
  }

  // ----- Search / filter -----
  if (documentSearch) documentSearch.addEventListener('input', () => { documentPage = 1; applyDocumentFilters(); });
  if (documentStatusFilter) documentStatusFilter.addEventListener('change', () => { documentPage = 1; applyDocumentFilters(); });
  if (documentKindFilter) documentKindFilter.addEventListener('change', () => { documentPage = 1; applyDocumentFilters(); });
  if (documentFolderFilter) documentFolderFilter.addEventListener('input', () => { documentPage = 1; applyDocumentFilters(); });
  if (documentTagFilter) documentTagFilter.addEventListener('input', () => { documentPage = 1; applyDocumentFilters(); });
  if (documentFavoriteFilter) documentFavoriteFilter.addEventListener('change', () => { documentPage = 1; applyDocumentFilters(); });
  if (documentTrashFilter) {
    documentTrashFilter.addEventListener('change', () => {
      documentShowTrash = documentTrashFilter.checked;
      documentPage = 1;
      fetchDocuments();
    });
  }
  if (documentPager) {
    documentPager.addEventListener('click', event => {
      const button = event.target.closest('[data-doc-page]');
      if (!button || button.disabled) return;
      documentPage = Math.max(1, Number(button.dataset.docPage) || 1);
      applyDocumentFilters();
      documentGrid.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  }
  if (documentGrid) {
    documentGrid.addEventListener('click', event => {
      const button = event.target.closest('[data-doc-action]');
      if (!button) return;
      const id = button.dataset.docId;
      const action = button.dataset.docAction;
      if (action === 'details') openDocumentModal(id);
      else if (action === 'download') window.downloadDocument(id);
      else if (action === 'regenerate') window.regeneratePdf(id);
      else if (action === 'restore') {
        const doc = allDocuments.find(item => item.id === id);
        if (doc) {
          activeDocument = doc;
          restoreActiveDocument();
        }
      }
    });
  }
  if (documentModal) {
    documentModal.addEventListener('click', event => {
      if (event.target === documentModal) closeDocumentModal();
    });
  }
  if (documentModalClose) documentModalClose.addEventListener('click', closeDocumentModal);
  if (documentModalSave) documentModalSave.addEventListener('click', saveDocumentDetails);
  if (documentModalDelete) documentModalDelete.addEventListener('click', trashActiveDocument);
  if (documentModalRestore) documentModalRestore.addEventListener('click', restoreActiveDocument);
  if (documentModalDownload) {
    documentModalDownload.addEventListener('click', () => {
      if (activeDocument) window.downloadDocument(activeDocument.id);
    });
  }
  if (orderSearch) orderSearch.addEventListener('input', applyOrderFilters);
  if (orderStatusFilter) orderStatusFilter.addEventListener('change', applyOrderFilters);

  // ----- Mobile Menu -----
  let lastFocusedElement = null;
  function openSidebar() {
    if (!sidebar) return;
    lastFocusedElement = document.activeElement;
    sidebar.classList.add('open');
    if (sidebarOverlay) { sidebarOverlay.classList.add('visible'); sidebarOverlay.setAttribute('aria-hidden', 'false'); }
    if (mobileMenuBtn) { mobileMenuBtn.setAttribute('aria-expanded', 'true'); mobileMenuBtn.setAttribute('aria-label', 'Close menu'); }
    syncSidebarAccessibility();
    updateBodyScrollLock();
    if (sidebarClose) sidebarClose.focus();
  }
  function syncSidebarAccessibility() {
    if (!sidebar) return;
    const mobile = window.matchMedia('(max-width: 640px)').matches;
    const open = sidebar.classList.contains('open');
    if (mobile && !open) {
      sidebar.setAttribute('aria-hidden', 'true');
      sidebar.setAttribute('inert', '');
    } else {
      sidebar.removeAttribute('aria-hidden');
      sidebar.removeAttribute('inert');
    }
  }

  function closeSidebar() {
    if (!sidebar) return;
    sidebar.classList.remove('open');
    if (sidebarOverlay) { sidebarOverlay.classList.remove('visible'); sidebarOverlay.setAttribute('aria-hidden', 'true'); }
    if (mobileMenuBtn) { mobileMenuBtn.setAttribute('aria-expanded', 'false'); mobileMenuBtn.setAttribute('aria-label', 'Open menu'); }
    syncSidebarAccessibility();
    updateBodyScrollLock();
    if (lastFocusedElement && typeof lastFocusedElement.focus === 'function') {
      lastFocusedElement.focus();
    }
  }
  if (mobileMenuBtn && sidebar && sidebarOverlay) {
    mobileMenuBtn.addEventListener('click', () => {
      if (sidebar.classList.contains('open')) closeSidebar();
      else openSidebar();
    });
    sidebarOverlay.addEventListener('click', closeSidebar);
    if (sidebarClose) sidebarClose.addEventListener('click', closeSidebar);
    sidebar.querySelectorAll('a[href]').forEach(link => link.addEventListener('click', () => {
      if (window.matchMedia('(max-width: 640px)').matches) closeSidebar();
    }));
    sidebar.addEventListener('keydown', event => {
      if (!sidebar.classList.contains('open') || event.key !== 'Tab') return;
      const focusable = Array.from(sidebar.querySelectorAll('a[href], button:not([disabled])'))
        .filter(element => element.offsetParent !== null);
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    });
  }
  document.addEventListener('keydown', event => {
    if (event.key !== 'Escape') return;
    if (documentModal && documentModal.classList.contains('open')) {
      closeDocumentModal();
    } else if (pdfPreviewModal && pdfPreviewModal.classList.contains('open')) {
      closePdfPreviewModal();
    } else if (sidebar && sidebar.classList.contains('open')) {
      closeSidebar();
    }
  });
  window.addEventListener('resize', () => {
    if (window.innerWidth > 640 && sidebar && sidebar.classList.contains('open')) {
      closeSidebar();
    }
    syncSidebarAccessibility();
  });

  // ----- Settings -----
  // Connection status is authoritative. A stale/absent `configured` flag must
  // never turn a backend "connected" result into "Not Configured" in the UI.
  function providerStatusLabel(entry) {
    if (!entry) return 'Status unavailable';
    if (entry.status === 'connected') return 'Connected';
    if (entry.status === 'failed') return 'Failed';
    if (entry.status === 'not_configured') return 'Not Configured';
    if (entry.configured === false) return 'Not Configured';
    return 'Not tested';
  }

  function providerStatusColor(entry) {
    if (!entry) return 'var(--text-muted)';
    if (entry.status === 'connected') return 'var(--success)';
    if (entry.status === 'failed') return '#dc2626';
    if (entry.status === 'not_configured' || entry.configured === false) return 'var(--text-muted)';
    return 'var(--text-muted)';
  }

  async function loadProviderStatus() {
    try {
      const res = await fetch('/api/provider-status?_=' + Date.now(), {
        cache: 'no-store',
        headers: { 'Accept': 'application/json' }
      });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const data = await res.json();
      const active = data.active || data.preferred;
      if (active && !providerSaveInFlight) {
        savedProvider = active;
        if (providerSelect) {
          providerSelect.value = active;
          providerSelect.disabled = false;
        }
        if (providerSaveStatus) {
          providerSaveStatus.textContent = 'Active provider (server): ' + active;
        }
      } else if (providerSelect) {
        providerSelect.disabled = false;
      }

      const gemini = data.gemini || {};
      const openrouter = data.openrouter || {};

      if (geminiModelInfo) geminiModelInfo.textContent = gemini.model || '—';
      if (geminiStatus) {
        const message = gemini.message ? (' — ' + gemini.message) : '';
        geminiStatus.textContent = providerStatusLabel(gemini) + message;
        geminiStatus.style.color = providerStatusColor(gemini);
      }

      if (openrouterModelInfo) openrouterModelInfo.textContent = openrouter.selected_model || '—';
      if (openrouterFreeCount) {
        const freeCount = Number(openrouter.free_vision_models || 0);
        const showCount = openrouter.configured || openrouter.status === 'connected' || freeCount > 0;
        openrouterFreeCount.textContent = showCount
          ? (freeCount + ' free vision model(s) available')
          : '';
      }
      if (openrouterStatus) {
        const message = openrouter.message ? (' — ' + openrouter.message) : '';
        openrouterStatus.textContent = providerStatusLabel(openrouter) + message;
        openrouterStatus.style.color = providerStatusColor(openrouter);
      }

      if (providerHint) {
        providerHint.textContent = active
          ? ('AI provider: ' + active + (active === 'gemini' ? ' (default)' : ' (free models only)'))
          : 'No AI provider configured.';
      }
    } catch (_) {
      if (providerSelect) providerSelect.disabled = false;
      if (providerSaveStatus && providerSaveStatus.textContent === 'Loading active provider…') {
        providerSaveStatus.textContent = 'Could not load active provider. Reload the page.';
      }
      // Do not leave a stale placeholder forever.
      const stale = (el) => !el.textContent ||
        el.textContent.indexOf('Checking') === 0 ||
        el.textContent === 'Not configured.';
      if (geminiStatus && stale(geminiStatus)) {
        geminiStatus.textContent = 'Status unavailable. Reload the page.';
      }
      if (openrouterStatus && stale(openrouterStatus)) {
        openrouterStatus.textContent = 'Status unavailable. Reload the page.';
      }
    }
  }

  if (providerSelect) {
    providerSelect.addEventListener('change', async () => {
      const provider = providerSelect.value;
      const previous = savedProvider || provider;
      providerSaveInFlight = true;
      providerSaveFailed = false;
      providerSelect.disabled = true;
      if (providerSaveStatus) providerSaveStatus.textContent = 'Saving…';
      try {
        const res = await fetch('/api/settings/provider', {
          method: 'POST',
          headers: adminHeaders(),
          body: JSON.stringify({ provider }),
          // Keep the save alive if the user immediately navigates to New Order.
          keepalive: true
        });
        const data = await res.json();
        if (!res.ok) {
          providerSaveFailed = true;
          providerSelect.value = previous;
          showToast(data.error || 'Failed to switch provider.', 'error');
        } else {
          savedProvider = provider;
          showToast('AI provider switched to ' + provider + '.', 'success');
          if (providerSaveStatus) {
            providerSaveStatus.textContent = 'Active provider (server): ' + provider;
          }
        }
      } catch (_) {
        providerSaveFailed = true;
        providerSelect.value = previous;
        showToast('Failed to switch provider.', 'error');
      } finally {
        providerSaveInFlight = false;
        providerSelect.disabled = false;
      }
      // Re-read the authoritative server value after every save attempt.
      await loadProviderStatus();
      if (providerSaveFailed && providerSaveStatus) {
        providerSaveStatus.textContent = 'Save failed. Active provider (server): ' + (savedProvider || previous);
      }
    });
  }

  if (testProviderBtn) {
    testProviderBtn.addEventListener('click', async () => {
      const provider = (providerSelect && providerSelect.value) || 'gemini';
      setButtonLoading(testProviderBtn, true);
      if (providerTestStatus) providerTestStatus.textContent = 'Testing ' + provider + '…';
      try {
        const res = await fetch('/api/provider/test', { method: 'POST', headers: adminHeaders(), body: JSON.stringify({ provider }) });
        const data = await res.json();
        if (data.ok) {
          if (providerTestStatus) providerTestStatus.textContent = 'Connected. Model: ' + (data.model || 'default');
          showToast(data.message || 'Connection successful.', 'success');
        } else {
          if (providerTestStatus) providerTestStatus.textContent = data.error || 'Connection failed.';
          showToast(data.error || 'Connection failed.', 'error');
        }
        loadProviderStatus();
      } catch (_) {
        if (providerTestStatus) providerTestStatus.textContent = 'Connection test failed.';
        showToast('Connection test failed.', 'error');
      } finally {
        setButtonLoading(testProviderBtn, false);
      }
    });
  }

  function applyTheme(theme) {
    const allowed = ['premium', 'light', 'ocean', 'graphite', 'dark'];
    const next = allowed.includes(theme) ? theme : 'premium';
    document.documentElement.setAttribute('data-theme', next);
    return next;
  }

  const savedTheme = applyTheme(storageGet('localStorage', 'theme') || 'premium');
  if (themeSelect) {
    themeSelect.value = savedTheme;
    themeSelect.addEventListener('change', () => {
      const next = applyTheme(themeSelect.value);
      storageSet('localStorage', 'theme', next);
      showToast('Theme applied.', 'success', 2200);
    });
  }

  if (clearActivityBtn) {
    clearActivityBtn.addEventListener('click', async () => {
      if (!confirm('Clear all activity history? This cannot be undone.')) return;
      try {
        const res = await fetchWithTimeout('/api/activity/clear', {
          method: 'POST', headers: adminHeaders()
        }, 30000);
        if (!res.ok) {
          let message = 'Failed to clear activity. Please retry.';
          try { const data = await res.json(); message = data.error || message; } catch (_) {}
          throw new Error(message);
        }
        showToast('Activity history cleared.', 'success');
        fetchActivity();
      } catch (error) {
        showToast(error.message || 'Failed to clear activity.', 'error', 7000);
      }
    });
  }

  if (resetStatsBtn) {
    resetStatsBtn.addEventListener('click', async () => {
      if (!confirm('Reset all statistics to zero? This cannot be undone.')) return;
      try {
        const res = await fetchWithTimeout('/api/stats/reset', {
          method: 'POST', headers: adminHeaders()
        }, 30000);
        if (!res.ok) {
          let message = 'Failed to reset stats. Please retry.';
          try { const data = await res.json(); message = data.error || message; } catch (_) {}
          throw new Error(message);
        }
        showToast('Statistics reset.', 'success');
        fetchStats();
      } catch (error) {
        showToast(error.message || 'Failed to reset stats.', 'error', 7000);
      }
    });
  }

  // ----- Global Functions for Inline Handlers -----
  async function downloadStoredDocument(id, fallbackName) {
    const toast = showToast('Preparing your download…', 'processing', 0);
    try {
      const response = await fetchWithTimeout('/api/documents/' + encodeURIComponent(id) + '/download', { cache: 'no-store' }, 60000);
      if (!response.ok) {
        let message = 'Could not download this document. Please retry.';
        let meta = { code: 'DOWNLOAD_FAILED', retryable: true };
        try {
          const data = await response.json();
          message = data.error || message;
          meta = errorMeta(response.status, data, meta.code);
        } catch (_) {}
        const error = new Error(message);
        error.code = meta.code;
        error.retryable = meta.retryable;
        throw error;
      }
      const blob = await response.blob();
      const filename = filenameFromHeaders(
        { 'content-disposition': response.headers.get('Content-Disposition') || '' },
        fallbackName || 'NotesAI-Document.pdf'
      );
      triggerBlobDownload(blob, filename);
      toast.remove();
      showToast('Download started.', 'success');
    } catch (error) {
      toast.remove();
      const message = error && error.name === 'AbortError'
        ? 'Download timed out. Please retry.'
        : (error.message || 'Download failed. Please retry.');
      showToast(message, 'error', 7000, {
        label: 'Retry',
        onClick: () => downloadStoredDocument(id, fallbackName)
      });
    }
  }

  // --- Animated Download Button (ab-13) ---
  function animateDownloadButton(btn, state) {
    const icon = btn.querySelector('.ab-13__icon');
    const text = btn.querySelector('.ab-13__text');
    btn.classList.remove('ab-13__btn--loading', 'ab-13__btn--success', 'ab-13__btn--error');
    if (state === 'loading') {
      btn.classList.add('ab-13__btn--loading');
      btn.disabled = true;
      if (text) text.textContent = 'Downloading…';
    } else if (state === 'success') {
      btn.classList.add('ab-13__btn--success');
      btn.disabled = false;
      if (text) text.textContent = 'Downloaded!';
      if (icon) {
        // Swap to checkmark
        icon.innerHTML = '<polyline points="20 6 9 17 4 12"/>';
      }
      setTimeout(() => {
        btn.classList.remove('ab-13__btn--success');
        if (text) text.textContent = 'Download PDF';
        if (icon) {
          icon.innerHTML = '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>';
        }
      }, 2000);
    } else if (state === 'error') {
      btn.classList.add('ab-13__btn--error');
      btn.disabled = false;
      if (text) text.textContent = 'Failed — Retry';
      setTimeout(() => {
        btn.classList.remove('ab-13__btn--error');
        if (text) text.textContent = 'Download PDF';
      }, 3000);
    } else {
      btn.disabled = false;
      if (text) text.textContent = 'Download PDF';
    }
  }

  async function animatedDownload(id, fallbackName, btn) {
    if (btn && btn.disabled) return; // Prevent duplicate clicks
    if (btn) animateDownloadButton(btn, 'loading');
    try {
      const response = await fetchWithTimeout('/api/documents/' + encodeURIComponent(id) + '/download', { cache: 'no-store' }, 60000);
      if (!response.ok) {
        throw new Error('Download failed');
      }
      const blob = await response.blob();
      const filename = filenameFromHeaders(
        { 'content-disposition': response.headers.get('Content-Disposition') || '' },
        fallbackName || 'NotesAI-Document.pdf'
      );
      triggerBlobDownload(blob, filename);
      if (btn) animateDownloadButton(btn, 'success');
    } catch (error) {
      if (btn) animateDownloadButton(btn, 'error');
    }
  }

  async function regenerateStoredDocument(id, fallbackName) {
    const toast = showToast('Regenerating your PDF…', 'processing', 0);
    try {
      const headers = {};
      const token = adminTokenInput ? adminTokenInput.value.trim() : '';
      if (token) headers['X-Admin-Token'] = token;
      const response = await fetchWithTimeout('/api/documents/' + encodeURIComponent(id) + '/regenerate', {
        method: 'POST',
        headers
      }, 120000);
      if (!response.ok) {
        let message = 'Could not regenerate this PDF. Please retry.';
        try {
          const data = await response.json();
          message = data.error || message;
        } catch (_) {}
        throw new Error(message);
      }
      const blob = await response.blob();
      triggerBlobDownload(blob, fallbackName || 'NotesAI-Regenerated.pdf');
      toast.remove();
      showToast('Regenerated PDF downloaded.', 'success');
      fetchStats();
      fetchActivity();
      fetchDocuments();
      fetchOrders();
    } catch (error) {
      toast.remove();
      const message = error && error.name === 'AbortError'
        ? 'Regeneration timed out. Please retry.'
        : (error.message || 'Regeneration failed. Please retry.');
      showToast(message, 'error', 7000, {
        label: 'Retry',
        onClick: () => regenerateStoredDocument(id, fallbackName)
      });
    }
  }

  window.downloadDocument = function(id) {
    const doc = allDocuments.find(item => item.id === id);
    downloadStoredDocument(id, doc ? (String(doc.name).replace(/\.pdf$/i, '') + '.pdf') : 'NotesAI-Document.pdf');
  };
  window.regeneratePdf = function(id) {
    const doc = allDocuments.find(item => item.id === id);
    regenerateStoredDocument(id, doc ? (String(doc.name).replace(/\.pdf$/i, '') + '.pdf') : 'NotesAI-Regenerated.pdf');
  };
  window.downloadOrder = function(id) {
    const order = allOrders.find(item => item.id === id);
    downloadStoredDocument(id, order ? (String(order.name).replace(/\.pdf$/i, '') + '.pdf') : 'NotesAI-Document.pdf');
  };
  window.retryOrder = function(id) {
    const order = allOrders.find(item => item.id === id);
    regenerateStoredDocument(id, order ? (String(order.name).replace(/\.pdf$/i, '') + '.pdf') : 'NotesAI-Regenerated.pdf');
  };

  // Shared helpers for the Study and Admin workspaces. Keeping these on a
  // small namespace avoids duplicating toast, escaping or auth logic.
  window.notesaiShowToast = showToast;
  window.notesaiAdminHeaders = adminHeaders;
  window.notesaiFormatDate = formatDate;
  window.notesaiFormatBytes = formatBytes;
  window.notesaiEscapeHtml = escapeHtml;
  window.notesaiRefreshDocuments = fetchDocuments;
  window.notesaiRefreshActivity = fetchActivity;

  // ----- Initial Load -----
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  window.addEventListener('offline', () => {
    if (offlineNoticeShown) return;
    offlineNoticeShown = true;
    showToast('You are offline. The current request may time out; reconnect and retry.', 'warning', 8000);
  });
  window.addEventListener('online', () => {
    if (!offlineNoticeShown) return;
    offlineNoticeShown = false;
    showToast('Connection restored.', 'success', 3500);
  });

  function init() {
    syncSidebarAccessibility();
    // Each call is isolated so one failing dashboard API can never prevent the
    // provider dropdown/status cards from loading on the Settings page.
    try { fetchStats(); } catch (_) {}
    try { fetchActivity(); } catch (_) {}
    try { fetchDocuments(); } catch (_) {}
    try { fetchOrders(); } catch (_) {}
    try { loadProviderStatus(); } catch (_) {}
    const currentPage = '{{ page }}' || 'dashboard';
    document.querySelectorAll('[data-page]').forEach(el => {
      const isActive = el.dataset.page === currentPage;
      el.classList.toggle('active', isActive);
      if (isActive) el.setAttribute('aria-current', 'page');
      else el.removeAttribute('aria-current');
    });
  }

  // Re-sync when returning from another tab or the mobile back/forward cache.
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) loadProviderStatus();
  });
  window.addEventListener('pageshow', (event) => {
    if (event.persisted) loadProviderStatus();
  });
})();
</script>
<script>
/* Study and Admin workspaces use a small, self-contained controller. */
(() => {
  const toast = (message, type = 'success', timeout = 4500) => {
    if (typeof window.notesaiShowToast === 'function') {
      window.notesaiShowToast(message, type, timeout);
    } else {
      const status = document.getElementById('studyStatus');
      if (status) status.textContent = message;
    }
  };
  const escapeHtml = value => String(value == null ? '' : value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  const formatDate = value => {
    if (typeof window.notesaiFormatDate === 'function') return window.notesaiFormatDate(value);
    const date = value ? new Date(value) : null;
    return date && !Number.isNaN(date.getTime()) ? date.toLocaleString() : '—';
  };
  const formatBytes = value => {
    if (typeof window.notesaiFormatBytes === 'function') return window.notesaiFormatBytes(value);
    return String(value || 0) + ' B';
  };
  const adminHeaders = () => {
    const headers = { 'Content-Type': 'application/json' };
    const input = document.getElementById('adminPageToken');
    let token = input ? input.value.trim() : '';
    if (!token) {
      try { token = sessionStorage.getItem('notesaiAdminToken') || ''; } catch (_) {}
    }
    if (token) headers['X-Admin-Token'] = token;
    return headers;
  };
  const requestJson = async (url, options = {}) => {
    const response = await fetch(url, options);
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(data.error || ('Request failed with status ' + response.status));
      error.status = response.status;
      error.data = data;
      throw error;
    }
    return data;
  };

  // ------------------------------------------------------------
  // AI Study Workspace
  // ------------------------------------------------------------
  const studyPanel = document.getElementById('studyPanel');
  if (studyPanel) {
    const actionButtons = Array.from(studyPanel.querySelectorAll('[data-action]'));
    const sourceSelect = document.getElementById('studyDocumentSelect');
    const language = document.getElementById('studyLanguage');
    const count = document.getElementById('studyCount');
    const prompt = document.getElementById('studyPrompt');
    const text = document.getElementById('studyText');
    const generateBtn = document.getElementById('studyGenerateBtn');
    const status = document.getElementById('studyStatus');
    const resultBox = document.getElementById('studyResult');
    const resultText = document.getElementById('studyResultText');
    const resultTitle = document.getElementById('studyResultTitle');
    const copyBtn = document.getElementById('studyCopyBtn');
    const saveBtn = document.getElementById('studySaveBtn');
    const useBtn = document.getElementById('studyUseBtn');
    const savedBox = document.getElementById('studySaved');
    let selectedAction = 'summarize';
    let lastStudy = null;
    let savedSets = [];

    const setStatus = (message, isError = false) => {
      if (!status) return;
      status.textContent = message || '';
      status.style.color = isError ? 'var(--error)' : 'var(--text-muted)';
    };

    actionButtons.forEach(button => {
      button.addEventListener('click', () => {
        actionButtons.forEach(item => item.classList.remove('active'));
        button.classList.add('active');
        selectedAction = button.dataset.action || 'summarize';
      });
    });

    const showStudy = (data) => {
      lastStudy = data;
      if (resultText) resultText.textContent = data.result || '';
      if (resultTitle) resultTitle.textContent = (data.action_label || 'Study result') + (data.source_name ? ' — ' + data.source_name : '');
      if (resultBox) resultBox.hidden = false;
      const shortened = data.truncated ? ' Notes longer than 30,000 characters were shortened.' : '';
      setStatus(`Generated with ${data.provider || 'AI'}${data.model ? ' · ' + data.model : ''}.${shortened}`);
    };

    const renderSaved = () => {
      if (!savedBox) return;
      if (!savedSets.length) {
        savedBox.innerHTML = '<div class="empty-state" style="padding:16px;"><p>No saved study sets yet.</p></div>';
        return;
      }
      savedBox.innerHTML = savedSets.map(item => `
        <div class="study-set">
          <strong title="${escapeHtml(item.title)}">${escapeHtml(item.title || 'Study set')}</strong>
          <small>${escapeHtml(item.action || 'study')} · ${escapeHtml(formatDate(item.created))}</small>
          <div class="study-set-actions">
            <button type="button" class="btn-3d btn-secondary" data-study-action="load" data-study-id="${escapeHtml(item.id)}">Open</button>
            <button type="button" class="btn-3d btn-destructive" data-study-action="delete" data-study-id="${escapeHtml(item.id)}">Delete</button>
          </div>
        </div>
      `).join('');
    };

    const loadSaved = async () => {
      try {
        const data = await requestJson('/api/study/sets', { cache: 'no-store' });
        savedSets = Array.isArray(data) ? data : [];
        renderSaved();
      } catch (_) {
        if (savedBox) savedBox.innerHTML = '<div class="empty-state" style="padding:16px;"><p>Could not load saved study sets.</p></div>';
      }
    };

    const loadSources = async () => {
      if (!sourceSelect) return;
      try {
        const data = await requestJson('/api/documents', { cache: 'no-store' });
        const docs = Array.isArray(data) ? data : [];
        sourceSelect.innerHTML = '<option value="">Paste notes below</option>' + docs.map(doc =>
          `<option value="${escapeHtml(doc.id)}">${escapeHtml(doc.name || 'Untitled document')}</option>`
        ).join('');
      } catch (_) {
        sourceSelect.innerHTML = '<option value="">Paste notes below</option>';
      }
    };

    if (sourceSelect) {
      sourceSelect.addEventListener('change', () => {
        if (sourceSelect.value && text) {
          text.placeholder = 'The selected document will be used. You can also type additional notes here.';
          setStatus('Selected document ready.');
        } else if (text) {
          text.placeholder = 'Select a saved document above, or paste notes here. The AI will not invent facts outside this text.';
          setStatus('');
        }
      });
    }

    if (generateBtn) {
      generateBtn.addEventListener('click', async () => {
        const documentId = sourceSelect ? sourceSelect.value : '';
        const notes = text ? text.value.trim() : '';
        if (!documentId && !notes) {
          toast('Choose a document or paste some notes first.', 'warning');
          setStatus('Choose a document or paste some notes first.', true);
          return;
        }
        generateBtn.disabled = true;
        generateBtn.textContent = 'Generating…';
        setStatus('Reading your notes and generating study material…');
        try {
          const data = await requestJson('/api/study/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              action: selectedAction,
              document_id: documentId,
              text: notes,
              language: language ? language.value : 'English',
              count: count ? count.value : 8,
              prompt: prompt ? prompt.value : '',
              save: false,
            }),
          });
          showStudy(data);
          toast('Study material ready.', 'success');
        } catch (error) {
          setStatus(error.message || 'Study generation failed. Please retry.', true);
          toast(error.message || 'Study generation failed. Please retry.', 'error', 7000);
        } finally {
          generateBtn.disabled = false;
          generateBtn.innerHTML = '<span aria-hidden="true">✧</span> Generate study material';
        }
      });
    }

    if (copyBtn) {
      copyBtn.addEventListener('click', async () => {
        const value = resultText ? resultText.textContent : '';
        if (!value) return;
        try {
          await navigator.clipboard.writeText(value);
          toast('Study result copied.', 'success');
        } catch (_) {
          const area = document.createElement('textarea');
          area.value = value;
          document.body.appendChild(area);
          area.select();
          document.execCommand('copy');
          area.remove();
          toast('Study result copied.', 'success');
        }
      });
    }

    if (saveBtn) {
      saveBtn.addEventListener('click', async () => {
        if (!lastStudy) return;
        saveBtn.disabled = true;
        try {
          const source = sourceSelect && sourceSelect.value ? { id: sourceSelect.value, name: sourceSelect.options[sourceSelect.selectedIndex].text } : null;
          const data = await requestJson('/api/study/sets', {
            method: 'POST',
            headers: adminHeaders(),
            body: JSON.stringify({
              action: lastStudy.action || selectedAction,
              result: lastStudy.result || '',
              language: lastStudy.language || (language ? language.value : 'English'),
              provider: lastStudy.provider || '',
              model: lastStudy.model || '',
              source_document_id: lastStudy.source_document_id || (source ? source.id : ''),
              title: '',
            }),
          });
          toast('Study set saved.', 'success');
          if (data.set && savedSets) {
            savedSets.unshift(data.set);
            renderSaved();
          } else {
            loadSaved();
          }
        } catch (error) {
          toast(error.message || 'Could not save the study set.', 'error', 6000);
        } finally {
          saveBtn.disabled = false;
        }
      });
    }

    if (useBtn) {
      useBtn.addEventListener('click', () => {
        if (!lastStudy || !lastStudy.result) return;
        try { sessionStorage.setItem('notesaiStudyDraft', lastStudy.result); } catch (_) {}
        window.location.href = '/new-order';
      });
    }

    if (savedBox) {
      savedBox.addEventListener('click', async event => {
        const button = event.target.closest('[data-study-action]');
        if (!button) return;
        const id = button.dataset.studyId;
        const action = button.dataset.studyAction;
        const item = savedSets.find(entry => entry.id === id);
        if (action === 'load' && item) {
          showStudy({
            result: item.result,
            action_label: item.action || 'Study result',
            provider: item.provider || '',
            model: item.model || '',
            source_name: item.source_name || '',
            source_document_id: item.source_document_id || '',
            action: item.action || 'summarize',
          });
          resultBox.scrollIntoView({ behavior: 'smooth', block: 'start' });
          return;
        }
        if (action === 'delete') {
          if (!window.confirm('Delete this saved study set?')) return;
          button.disabled = true;
          try {
            await requestJson('/api/study/sets/' + encodeURIComponent(id), { method: 'DELETE', headers: adminHeaders() });
            savedSets = savedSets.filter(entry => entry.id !== id);
            renderSaved();
            toast('Study set deleted.', 'success');
          } catch (error) {
            button.disabled = false;
            toast(error.message || 'Could not delete the study set.', 'error', 6000);
          }
        }
      });
    }

    loadSources();
    loadSaved();
  }

  // ------------------------------------------------------------
  // Local Admin workspace
  // ------------------------------------------------------------
  const adminPanel = document.getElementById('adminPanel');
  if (adminPanel) {
    const tokenInput = document.getElementById('adminPageToken');
    const reloadBtn = document.getElementById('adminReloadBtn');
    const lock = document.getElementById('adminLock');
    const planForm = document.getElementById('adminPlanForm');
    const planSelect = document.getElementById('adminPlanSelect');
    const renewal = document.getElementById('adminRenewal');
    const paymentForm = document.getElementById('adminPaymentForm');
    const backupBtn = document.getElementById('adminBackupBtn');
    let overview = null;

    if (lock) lock.hidden = false;
    if (tokenInput) {
      try {
        const saved = sessionStorage.getItem('notesaiAdminToken');
        if (saved) tokenInput.value = saved;
      } catch (_) {}
      tokenInput.addEventListener('change', () => {
        try {
          if (tokenInput.value.trim()) sessionStorage.setItem('notesaiAdminToken', tokenInput.value.trim());
          else sessionStorage.removeItem('notesaiAdminToken');
        } catch (_) {}
      });
    }

    const setText = (id, value) => {
      const element = document.getElementById(id);
      if (element) element.textContent = value;
    };

    const renderAdmin = (data) => {
      overview = data;
      const docs = data.documents || {};
      const failed = data.failed_jobs || [];
      setText('adminDocs', docs.total || 0);
      setText('adminStorage', formatBytes(docs.storage_bytes || 0));
      setText('adminFailed', failed.length);
      setText('adminStudySets', data.study_sets || 0);

      const system = document.getElementById('adminSystem');
      if (system) {
        const disk = data.disk || {};
        const provider = data.provider || {};
        const active = data.active_provider || '—';
        const providerEntry = provider[active] || {};
        const kindText = Object.entries(docs.kinds || {})
          .filter(([, count]) => Number(count) > 0)
          .map(([kind, count]) => `${kind}: ${count}`)
          .join(' · ') || '—';
        system.innerHTML = `
          <div class="admin-row"><span>Health</span><span>${escapeHtml((data.health && data.health.status) || 'unknown')}</span></div>
          <div class="admin-row"><span>Active provider</span><span>${escapeHtml(active)}</span></div>
          <div class="admin-row"><span>Provider status</span><span>${escapeHtml(providerEntry.status || 'not tested')}</span></div>
          <div class="admin-row"><span>Documents / trash</span><span>${escapeHtml(docs.total || 0)} / ${escapeHtml(docs.trash || 0)}</span></div>
          <div class="admin-row"><span>Document kinds</span><span>${escapeHtml(kindText)}</span></div>
          <div class="admin-row"><span>Favorites</span><span>${escapeHtml(docs.favorites || 0)}</span></div>
          <div class="admin-row"><span>Disk free</span><span>${escapeHtml(disk.free ? formatBytes(disk.free) : '—')}</span></div>
          <div class="admin-row"><span>Python</span><span>${escapeHtml((data.health && data.health.python) || '—')}</span></div>
        `;
      }

      const failedBox = document.getElementById('adminFailedList');
      if (failedBox) {
        failedBox.innerHTML = failed.length ? failed.map(item => `
          <div class="admin-row"><span>${escapeHtml(item.action || 'Job')}<br><small>${escapeHtml(item.detail || '')}</small></span><span>${escapeHtml(formatDate(item.timestamp))}</span></div>
        `).join('') : '<div class="empty-state" style="padding:14px;"><p>No failed jobs.</p></div>';
      }

      const activityBox = document.getElementById('adminActivity');
      if (activityBox) {
        activityBox.innerHTML = (data.activity || []).slice(0, 12).map(item => `
          <div class="admin-row"><span>${escapeHtml(item.action || 'Activity')}<br><small>${escapeHtml(item.detail || '')}</small></span><span>${escapeHtml(item.status || '')}<br><small>${escapeHtml(formatDate(item.timestamp))}</small></span></div>
        `).join('') || '<div class="empty-state" style="padding:14px;"><p>No activity yet.</p></div>';
      }

      const billing = data.billing || {};
      const planBox = document.getElementById('adminPlan');
      if (planBox) {
        const limits = billing.limits || {};
        planBox.innerHTML = `
          <div class="admin-row"><span>Current plan</span><span>${escapeHtml(billing.plan || 'free')}</span></div>
          <div class="admin-row"><span>Status</span><span>${escapeHtml(billing.status || 'active')}</span></div>
          <div class="admin-row"><span>Renewal</span><span>${escapeHtml(billing.renewal || 'Not set')}</span></div>
          <div class="admin-row"><span>Document limit</span><span>${escapeHtml(limits.max_documents || 100)}</span></div>
          <div class="admin-row"><span>Storage target</span><span>${escapeHtml(limits.max_storage_mb || 250)} MB</span></div>
          <div class="admin-row"><span>Online payments</span><span>Not connected (manual records only)</span></div>
        `;
        if (planSelect) planSelect.value = billing.plan || 'free';
        if (renewal && billing.renewal) renewal.value = String(billing.renewal).slice(0, 10);
      }

      const payments = document.getElementById('adminPayments');
      if (payments) {
        const rows = billing.payments || [];
        payments.innerHTML = rows.length ? rows.slice(-8).reverse().map(item => `
          <div class="admin-row"><span>${escapeHtml(item.amount)} ${escapeHtml(item.currency || '')} · ${escapeHtml(item.method || 'manual')}<br><small>${escapeHtml(item.reference || item.note || '')}</small></span><span>${escapeHtml(formatDate(item.created))}</span></div>
        `).join('') : '<div class="empty-state" style="padding:14px;"><p>No manual payments recorded.</p></div>';
      }
    };

    const loadAdmin = async () => {
      setText('adminDocs', '…');
      try {
        const data = await requestJson('/api/admin/overview', { cache: 'no-store', headers: adminHeaders() });
        renderAdmin(data);
      } catch (error) {
        if (error.status === 401 || error.status === 403) {
          if (lock) lock.hidden = false;
          toast('Admin token required for this remote session.', 'warning', 6500);
        } else {
          toast(error.message || 'Could not load the admin overview.', 'error', 7000);
        }
        setText('adminDocs', 'Locked');
        setText('adminStorage', '—');
        setText('adminFailed', '—');
        setText('adminStudySets', '—');
      }
    };

    if (reloadBtn) reloadBtn.addEventListener('click', loadAdmin);
    if (planForm) {
      planForm.addEventListener('submit', async event => {
        event.preventDefault();
        const button = planForm.querySelector('button[type="submit"]');
        if (button) button.disabled = true;
        try {
          await requestJson('/api/admin/billing', {
            method: 'POST', headers: adminHeaders(),
            body: JSON.stringify({
              action: 'activate',
              plan: planSelect ? planSelect.value : 'free',
              renewal: renewal ? renewal.value : '',
            }),
          });
          toast('Workspace plan updated.', 'success');
          loadAdmin();
        } catch (error) {
          toast(error.message || 'Could not update the plan.', 'error', 6000);
        } finally {
          if (button) button.disabled = false;
        }
      });
    }
    if (paymentForm) {
      paymentForm.addEventListener('submit', async event => {
        event.preventDefault();
        const amount = document.getElementById('paymentAmount');
        const method = document.getElementById('paymentMethod');
        const reference = document.getElementById('paymentReference');
        const currency = document.getElementById('paymentCurrency');
        const note = document.getElementById('paymentNote');
        try {
          await requestJson('/api/admin/billing', {
            method: 'POST', headers: adminHeaders(),
            body: JSON.stringify({
              action: 'record_payment',
              amount: amount ? amount.value : 0,
              method: method ? method.value : 'manual',
              reference: reference ? reference.value : '',
              currency: currency ? currency.value : 'PKR',
              note: note ? note.value : '',
            }),
          });
          toast('Manual payment recorded.', 'success');
          if (amount) amount.value = '';
          if (reference) reference.value = '';
          if (note) note.value = '';
          loadAdmin();
        } catch (error) {
          toast(error.message || 'Could not record the payment.', 'error', 6000);
        }
      });
    }
    if (backupBtn) {
      backupBtn.addEventListener('click', async () => {
        backupBtn.disabled = true;
        try {
          const response = await fetch('/api/admin/backup', { headers: adminHeaders() });
          if (!response.ok) {
            const data = await response.json().catch(() => ({}));
            throw new Error(data.error || 'Could not create the backup.');
          }
          const blob = await response.blob();
          const url = URL.createObjectURL(blob);
          const link = document.createElement('a');
          link.href = url;
          link.download = 'NotesAI-backup-' + new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-') + '.zip';
          document.body.appendChild(link);
          link.click();
          link.remove();
          setTimeout(() => URL.revokeObjectURL(url), 3000);
          toast('Workspace backup downloaded.', 'success');
        } catch (error) {
          toast(error.message || 'Could not create the backup.', 'error', 6000);
        } finally {
          backupBtn.disabled = false;
        }
      });
    }
    loadAdmin();
  }

  // Move a generated study result into the PDF editor without a server round-trip.
  const editor = document.getElementById('extractedText');
  if (editor) {
    let draft = '';
    try { draft = sessionStorage.getItem('notesaiStudyDraft') || ''; } catch (_) {}
    if (draft) {
      try { sessionStorage.removeItem('notesaiStudyDraft'); } catch (_) {}
      editor.value = draft;
      editor.dispatchEvent(new Event('input', { bubbles: true }));
      const mode = document.getElementById('pdfMode');
      if (mode) {
        mode.value = 'professional';
        mode.dispatchEvent(new Event('change', { bubbles: true }));
      }
      toast('Study result loaded into the PDF editor.', 'success');
    }
  }
})();
</script>
<script>
  // Register Service Worker for PWA
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('/sw.js', { scope: '/' })
        .then((registration) => {
          console.log('Service Worker registered:', registration.scope);
          // Check for updates
          registration.addEventListener('updatefound', () => {
            const newWorker = registration.installing;
            newWorker.addEventListener('statechange', () => {
              if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
                // New version available
                if (confirm('A new version of NotesAI is available. Reload to update?')) {
                  newWorker.postMessage({ type: 'SKIP_WAITING' });
                  window.location.reload();
                }
              }
            });
          });
        })
        .catch((error) => {
          console.warn('Service Worker registration failed:', error);
        });
    });
  }

  // Network status indicator
  window.addEventListener('online', () => {
    document.body.classList.remove('offline');
    showToast('Connection restored', 'success', 3000);
  });
  window.addEventListener('offline', () => {
    document.body.classList.add('offline');
    showToast('You are offline. Some features may be unavailable.', 'warning', 5000);
  });
</script>
</body>
</html>
"""

# ============================================================
# AI PROVIDER STATUS / SETTINGS API
# ============================================================
@app.route("/api/provider-status")
def api_provider_status():
    active = get_active_provider()
    gemini = get_gemini_config()
    openrouter = get_openrouter_config()
    status = load_provider_status()

    selected_model = ""
    free_models = []
    if openrouter["api_key"]:
        selected_model, free_models = select_openrouter_free_model()

    return jsonify({
        "active": active,
        "preferred": active,
        "gemini": {
            "configured": bool(gemini["api_key"]),
            "model": gemini["model"],
            "status": status["gemini"]["status"],
            "message": status["gemini"]["message"],
            "checked_at": status["gemini"]["checked_at"],
        },
        "openrouter": {
            "configured": bool(openrouter["api_key"]),
            "selected_model": selected_model or openrouter["model"],
            "free_vision_models": len(free_models),
            "status": status["openrouter"]["status"],
            "message": status["openrouter"]["message"],
            "checked_at": status["openrouter"]["checked_at"],
        },
    })


@app.route("/api/provider/test", methods=["POST"])
def api_provider_test():
    denied = require_admin()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    provider = (data.get("provider") or get_active_provider()).strip().lower()
    if provider not in {"gemini", "openrouter"}:
        return _provider_error("Invalid provider.", 400, "INVALID_PROVIDER", retryable=False)

    if provider == "gemini":
        gemini = get_gemini_config()
        if not gemini["api_key"]:
            save_provider_status("gemini", "not_configured", "GEMINI_API_KEY is not configured.", model=gemini["model"])
            return _provider_error("GEMINI_API_KEY is not configured in the server .env.", 400, "PROVIDER_NOT_CONFIGURED", retryable=False, provider="gemini")
        model, code, message = select_working_gemini_model(
            gemini["api_key"], configured=gemini["model"], timeout_ms=60000
        )
        if model:
            if model != gemini["model"]:
                _write_env_file({"GEMINI_MODEL": model})
            save_provider_status("gemini", "connected", "Connection successful.", model=model)
            return jsonify(ok=True, provider="gemini", model=model, message="Gemini connection successful.")
        status, error = _gemini_http_error(code, message)
        save_provider_status("gemini", "failed", error, model=gemini["model"])
        return _provider_error(error, status, _ai_error_code(status), provider="gemini")

    openrouter = get_openrouter_config()
    if not openrouter["api_key"]:
        save_provider_status("openrouter", "not_configured", "OPENROUTER_API_KEY is not configured.")
        return _provider_error("OPENROUTER_API_KEY is not configured in the server .env.", 400, "PROVIDER_NOT_CONFIGURED", retryable=False, provider="openrouter")

    base_url = validate_openrouter_base_url(openrouter["base_url"])
    if not base_url:
        save_provider_status("openrouter", "failed", "OpenRouter base URL is not allowed.")
        return _provider_error("OpenRouter base URL is not allowed.", 400, "PROVIDER_BASE_URL_INVALID", retryable=False, provider="openrouter")

    try:
        key_resp = requests.get(
            base_url + "/key",
            headers={"Authorization": f"Bearer {openrouter['api_key']}", "Content-Type": "application/json"},
            timeout=(10, 30),
        )
    except requests.Timeout:
        save_provider_status("openrouter", "failed", "OpenRouter connection timed out.")
        return _provider_error("OpenRouter connection timed out.", 504, "AI_TIMEOUT", provider="openrouter")
    except Exception as exc:
        save_provider_status("openrouter", "failed", f"OpenRouter connection failed: {type(exc).__name__}")
        return _provider_error(f"OpenRouter connection failed: {type(exc).__name__}", 502, "AI_UNAVAILABLE", provider="openrouter")

    if key_resp.status_code == 401:
        save_provider_status("openrouter", "failed", "Invalid OpenRouter API key.")
        return _provider_error("Invalid OpenRouter API key.", 401, "PROVIDER_AUTH_FAILED", retryable=False, provider="openrouter")
    if not key_resp.ok:
        save_provider_status("openrouter", "failed", f"OpenRouter key check failed (HTTP {key_resp.status_code}).")
        return _provider_error(f"OpenRouter key check failed (HTTP {key_resp.status_code}).", 502, "AI_UNAVAILABLE", provider="openrouter")

    models = discover_openrouter_free_models(force=True)
    if not models:
        save_provider_status("openrouter", "failed", "No free vision models available.")
        return _provider_error("No free vision-capable OpenRouter models are available right now.", 503, "AI_UNAVAILABLE", provider="openrouter")

    selected, _ranked = select_openrouter_free_model()
    candidates = [selected] + [m.get("id") for m in models if m.get("id") != selected][:1]
    last_status, last_error, last_model = 502, "OpenRouter connection test failed.", selected
    for model in candidates:
        ok, code, message = test_openrouter_model(openrouter["api_key"], model, base_url)
        if ok:
            save_provider_status("openrouter", "connected", f"Connected ({len(models)} free vision models).", model=model)
            return jsonify(ok=True, provider="openrouter", model=model, free_models=len(models), message="OpenRouter connection successful.")
        last_status, last_error, last_model = code or 502, message, model
        if code == 401:
            break
    save_provider_status("openrouter", "failed", last_error, model=last_model)
    return _provider_error(last_error, last_status, _ai_error_code(last_status), provider="openrouter")


@app.route("/api/settings/provider", methods=["POST"])
def api_settings_provider():
    denied = require_admin()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    try:
        provider = set_active_provider(data.get("provider"))
    except ValueError:
        return _provider_error("Provider must be 'gemini' or 'openrouter'.", 400, "INVALID_PROVIDER", retryable=False)
    app.logger.info("AI provider switched to %s", provider)
    return jsonify(ok=True, active=provider)


# ============================================================
@app.route("/api/stats")
@require_user_or_admin
@security.rate_limit("api_general")
def api_stats():
    return jsonify(load_stats())

@app.route("/api/stats/reset", methods=["POST"])
def api_stats_reset():
    denied = require_admin()
    if denied:
        return denied
    save_stats({"total_documents": 0, "in_progress": 0, "completed": 0, "failed": 0})
    return jsonify({"status": "ok"})

@app.route("/api/activity")
@require_user_or_admin
def api_activity():
    return jsonify(load_activity())

@app.route("/api/activity/clear", methods=["POST"])
def api_activity_clear():
    denied = require_admin()
    if denied:
        return denied
    save_activity([])
    return jsonify({"status": "ok"})

@app.route("/api/premium/status")
@require_user_or_admin
def api_premium_status():
    return jsonify({
        "premium_feature": "Smart Diagram Recreation",
        "configured": premium_configured(),
        "authorized": premium_authorized(),
        "free_mode": SMART_FREE_MODE,
    })


@app.route("/api/plan")
@require_user_or_admin
def api_plan():
    billing = load_billing()
    return jsonify({
        "plan": billing.get("plan", "free"),
        "label": PLAN_LIMITS.get(billing.get("plan"), PLAN_LIMITS["free"])["label"],
        "status": billing.get("status", "active"),
        "renewal": billing.get("renewal"),
        "limits": PLAN_LIMITS[billing.get("plan", "free")],
        "manual_billing": True,
        "online_payment_configured": False,
    })


@app.route("/api/study/generate", methods=["POST"])
@require_user_or_admin
@security.rate_limit("api_ai")
def api_study_generate():
    payload = request.get_json(silent=True) or request.form
    action = str(payload.get("action") or "").strip()
    if action not in STUDY_ACTIONS:
        return _error_response("Choose a valid study action.", 400, "INVALID_STUDY_ACTION", retryable=False)
    document_id = str(payload.get("document_id") or "").strip()
    source_document = None
    text = str(payload.get("text") or "").strip()
    if document_id:
        source_document = get_document(document_id)
        if not source_document:
            return _error_response("The selected document was not found.", 404, "DOCUMENT_NOT_FOUND", retryable=False)
        text = _document_text_for_study(source_document) or text
    if not text:
        return _error_response("Choose a document or paste some notes first.", 400, "STUDY_TEXT_REQUIRED", retryable=False)
    truncated = len(text) > 30000
    if truncated:
        text = text[:30000]
    language = str(payload.get("language") or "English").strip()[:60]
    try:
        count = max(1, min(30, int(payload.get("count") or 8)))
    except (TypeError, ValueError):
        count = 8
    prompt = build_study_prompt(action, text, language=language, count=count, prompt=payload.get("prompt") or "")
    result, provider, model, status, error = generate_text_with_provider(prompt)
    if status != 200:
        return _ai_failure_response(status, error, provider, model, code="STUDY_GENERATION_FAILED")
    saved = None
    if str(payload.get("save") or "").lower() in {"1", "true", "yes", "on"}:
        saved = save_study_set(
            action, result, source_document=source_document, language=language,
            provider=provider, model=model, title=payload.get("title") or "",
        )
    add_activity("Study", f"Generated {STUDY_ACTIONS[action][0].lower()}", "completed", provider=provider)
    return jsonify({
        "ok": True,
        "action": action,
        "action_label": STUDY_ACTIONS[action][0],
        "result": result,
        "provider": provider,
        "model": model,
        "language": language,
        "source_document_id": (source_document or {}).get("id") or "",
        "source_name": (source_document or {}).get("name") or "",
        "saved": saved,
        "truncated": truncated,
    })


@app.route("/api/study/sets", methods=["GET", "POST"])
def api_study_sets():
    if request.method == "GET":
        return jsonify([_public_study_set(item) for item in load_study_sets()])
    denied = require_admin()
    if denied:
        return denied
    payload = request.get_json(silent=True) or request.form
    result = str(payload.get("result") or "").strip()
    action = str(payload.get("action") or "").strip()
    if not result:
        return _error_response("There is no study result to save.", 400, "STUDY_RESULT_REQUIRED", retryable=False)
    if action not in STUDY_ACTIONS:
        action = "summarize"
    source_document = None
    document_id = str(payload.get("source_document_id") or "").strip()
    if document_id:
        source_document = get_document(document_id)
    saved = save_study_set(
        action, result, source_document=source_document,
        language=str(payload.get("language") or "English")[:60],
        provider=str(payload.get("provider") or "")[:80],
        model=str(payload.get("model") or "")[:120],
        title=payload.get("title") or "",
    )
    return jsonify({"ok": True, "set": saved})


@app.route("/api/study/sets/<set_id>", methods=["DELETE"])
def api_study_set_delete(set_id):
    denied = require_admin()
    if denied:
        return denied
    if not re.fullmatch(r"[a-f0-9]{32}", str(set_id or "")):
        return _error_response("Invalid study set id.", 400, "INVALID_STUDY_SET", retryable=False)
    with _STUDY_LOCK:
        items = load_study_sets()
        remaining = [item for item in items if item.get("id") != set_id]
        if len(remaining) == len(items):
            return _error_response("Study set not found.", 404, "STUDY_SET_NOT_FOUND", retryable=False)
        save_study_sets(remaining)
    return jsonify({"ok": True})


@app.route("/api/admin/overview")
def api_admin_overview():
    # Rate limiting
    from security import _check_rate_limit
    allowed, retry_after = _check_rate_limit("api_admin", 30, 60)
    if not allowed:
        response = jsonify({"error": "Rate limit exceeded.", "code": "RATE_LIMITED", "retry_after": retry_after})
        response.status_code = 429
        return response
    denied = require_admin()
    if denied:
        return denied
    documents = [_document_defaults(item) for item in _load_documents()]
    active_documents = [item for item in documents if not item.get("deleted_at")]
    storage_bytes = sum(int(item.get("size") or 0) for item in active_documents)
    try:
        disk = shutil.disk_usage(PROJECT_ROOT)
        disk_payload = {"total": disk.total, "used": disk.used, "free": disk.free}
    except Exception:
        disk_payload = {}
    raw_activity = load_activity()
    activity = [item for item in raw_activity if isinstance(item, dict)] if isinstance(raw_activity, list) else []
    failed = [item for item in activity if item.get("status") == "failed"]
    billing = load_billing()
    return jsonify({
        "stats": load_stats(),
        "documents": {
            "total": len(active_documents),
            "trash": len(documents) - len(active_documents),
            "storage_bytes": storage_bytes,
            "favorites": sum(1 for item in active_documents if item.get("favorite")),
            "kinds": {kind: sum(1 for item in active_documents if item.get("kind") == kind) for kind in ("professional", "smart", "image", "text", "existing", "regenerated", "smart-regenerated")},
        },
        "activity": activity[:40],
        "failed_jobs": failed[:20],
        "provider": load_provider_status(),
        "active_provider": get_active_provider(),
        "billing": {key: billing.get(key) for key in ("plan", "status", "renewal", "payments", "updated_at", "limits")},
        "study_sets": len(load_study_sets()),
        "disk": disk_payload,
        "health": {"status": "ok", "app": "NotesAI Premium", "python": os.sys.version.split()[0]},
    })


@app.route("/api/admin/billing", methods=["POST"])
def api_admin_billing():
    denied = require_admin()
    if denied:
        return denied
    payload = request.get_json(silent=True) or request.form
    billing = load_billing()
    action = str(payload.get("action") or "").strip()
    if action == "activate":
        plan = str(payload.get("plan") or "").strip().lower()
        if plan not in PLAN_LIMITS:
            return _error_response("Choose a valid plan.", 400, "INVALID_PLAN", retryable=False)
        billing["plan"] = plan
        billing["status"] = "active"
        billing["renewal"] = str(payload.get("renewal") or "").strip()[:40] or None
    elif action == "record_payment":
        try:
            amount = float(payload.get("amount") or 0)
        except (TypeError, ValueError):
            return _error_response("Enter a valid payment amount.", 400, "INVALID_AMOUNT", retryable=False)
        if amount != amount or amount < 0 or amount > 1_000_000_000:
            return _error_response("Enter a valid payment amount.", 400, "INVALID_AMOUNT", retryable=False)
        billing["payments"] = list(billing.get("payments") or [])
        billing["payments"].append({
            "amount": round(amount, 2),
            "currency": str(payload.get("currency") or "PKR")[:8].upper(),
            "method": str(payload.get("method") or "manual")[:40],
            "reference": str(payload.get("reference") or "")[:120],
            "note": str(payload.get("note") or "")[:300],
            "created": datetime.now().isoformat(timespec="seconds"),
            "verified_by": "local admin",
        })
        if str(payload.get("activate_plan") or "").lower() in {"1", "true", "yes", "on"}:
            plan = str(payload.get("plan") or billing.get("plan") or "free").lower()
            if plan in PLAN_LIMITS:
                billing["plan"] = plan
                billing["status"] = "active"
    else:
        return _error_response("Choose a valid billing action.", 400, "INVALID_BILLING_ACTION", retryable=False)
    save_billing(billing)
    add_activity("Billing", f"Updated workspace plan ({billing.get('plan')})", "completed")
    return jsonify({"ok": True, "billing": load_billing()})


@app.route("/api/admin/backup")
def api_admin_backup():
    denied = require_admin()
    if denied:
        return denied
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in (DOCUMENTS_FILE, ACTIVITY_FILE, STATS_FILE, STUDY_SETS_FILE, BILLING_FILE):
            if path.is_file():
                archive.write(path, arcname=path.name)
        for path in sorted(DOCUMENTS_DIR.glob("*.pdf")):
            if path.is_file():
                archive.write(path, arcname=f"documents/{path.name}")
        manifest = {
            "created": datetime.now().isoformat(timespec="seconds"),
            "app": "NotesAI",
            "note": "Local workspace backup. .env and API keys are never included.",
        }
        archive.writestr("backup-manifest.json", json.dumps(manifest, indent=2))
    buffer.seek(0)
    return send_file(
        buffer, mimetype="application/zip", as_attachment=True,
        download_name=f"NotesAI-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}.zip",
    )


@app.route("/api/diagrams/preview", methods=["POST"])
@require_user_or_admin
@security.rate_limit("api_ai")
def api_diagram_preview():
    payload = request.get_json(silent=True) or {}
    style = normalise_diagram_style(payload.get("style") or request.form.get("diagramStyle", "color"))

    def preview_one(raw):
        diagram = normalise_diagram(raw)
        if not diagram:
            return None, {"error": "Invalid diagram specification."}
        preview = {
            "diagram_id": diagram.get("id"),
            "use_original": bool(diagram.get("use_original")),
        }
        if (diagram.get("scene") or {}).get("elements") or diagram.get("template_data"):
            try:
                preview["svg"] = render_diagram_svg(diagram, style=style).decode("utf-8")
            except DiagramRenderError as exc:
                preview["error"] = str(exc)
            except Exception:
                app.logger.exception("Diagram preview failed")
                preview["error"] = "Could not render this diagram preview."
        if diagram.get("use_original"):
            preview["source_note"] = (
                "Source diagram preserved for accuracy. An AI recreation is available for review."
            )
        elif diagram.get("recreation_mode") == "trace":
            match = diagram.get("quality", {}).get("structural_match")
            match_text = f"{match:.0%}" if isinstance(match, (int, float)) else ""
            preview["source_note"] = (
                f"Vector-traced from the source; structure and labels preserved{'.' if not match_text else f' — structural match {match_text}.'}"
            )
        elif not preview.get("svg"):
            preview["source_note"] = (
                "Source diagram will be preserved because a reliable vector preview is not available."
            )
        return diagram.get("id"), preview

    batch = payload.get("diagrams")
    if isinstance(batch, list):
        previews = {}
        for item in batch[:SMART_MAX_DIAGRAMS]:
            if not isinstance(item, dict):
                continue
            diagram_id, preview = preview_one(item)
            if diagram_id:
                previews[diagram_id] = preview
        response = jsonify(previews=previews, style=style)
        response.headers["Cache-Control"] = "no-store"
        return response

    raw = payload.get("diagram") if isinstance(payload.get("diagram"), dict) else payload
    diagram_id, preview = preview_one(raw)
    if diagram_id is None:
        return jsonify(error=preview.get("error", "Invalid diagram specification.")), 400
    response = jsonify(**preview)
    response.headers["Cache-Control"] = "no-store"
    return response, 200


@app.route("/api/diagrams/reconstruct", methods=["POST"])
@require_user_or_admin
@security.rate_limit("api_ai")
def api_diagram_reconstruct():
    """Run one controlled geometry retry for a diagram using the uploaded page."""
    raw = request.form.get("diagram") or ""
    try:
        raw_diagram = json.loads(raw)
    except (TypeError, ValueError):
        return jsonify(error="The diagram payload is invalid."), 400
    if not isinstance(raw_diagram, dict):
        return jsonify(error="The diagram payload is invalid."), 400
    files = [f for f in request.files.getlist("noteFiles") if f and f.filename]
    if not files:
        return jsonify(error="Re-select the source page to retry recreation."), 400
    try:
        page_index = int(request.form.get("pageIndex") or raw_diagram.get("page_index") or 0)
    except (TypeError, ValueError):
        page_index = 0
    try:
        pages = prepare_source_pages(files)
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    if page_index < 0 or page_index >= len(pages):
        return jsonify(error="The source page for this diagram is not available."), 400
    provider = resolve_extraction_provider()
    if not provider:
        return jsonify(error="No AI provider is configured for diagram recreation."), 503
    diagram = normalise_diagram(raw_diagram, page_index)
    if not diagram or not diagram.get("labels"):
        return jsonify(error="This diagram has no labels to reconstruct."), 400
    style = normalise_diagram_style(request.form.get("diagramStyle", "color"))

    # Try a source-accurate vector trace first for line-art diagrams.
    # This preserves anatomy and labels exactly instead of asking the model
    # to redraw them from scratch.
    diagram_type = str(diagram.get("type") or "").lower()
    has_scene = bool((diagram.get("scene") or {}).get("elements"))
    has_template = bool(diagram.get("template_data"))
    if (
        diagram_type not in {"chart", "flowchart", "solar_system"}
        and not has_template
        and not has_scene
    ):
        try:
            source_preview = _diagram_source_preview(pages[page_index], diagram)
            if source_preview:
                diagram["source_preview"] = source_preview
                trace_svg, trace_quality = trace_data_url(source_preview, style=style)
                if trace_quality.get("accepted"):
                    diagram["recreation_mode"] = "trace"
                    diagram["quality"] = trace_quality
                    diagram["use_original"] = False
                    diagram["confidence"] = trace_quality.get("structural_match", 0.0)
                    diagram["review_required"] = True
                    # The trace is source-accurate; clear the "source preserved" warnings.
                    diagram["warnings"] = [
                        w for w in (diagram.get("warnings") or [])
                        if "source crop" not in w and "source diagram" not in w
                    ]
                    preview = {
                        "diagram_id": diagram.get("id"),
                        "use_original": False,
                        "source_note": (
                            "Vector-traced from the source; structure and labels preserved."
                        ),
                        "original_data_url": source_preview,
                        "svg": trace_svg.decode("utf-8"),
                    }
                    app.logger.info(
                        "Diagram manual recreation provider=trace model=trace diagram=%s",
                        diagram.get("id") or "",
                    )
                    return jsonify(
                        diagram=diagram,
                        preview=preview,
                        provider="trace",
                        model="trace",
                    ), 200
        except TraceQualityError:
            app.logger.info(
                "Reconstruct trace rejected diagram=%s", diagram.get("id") or ""
            )

    repair, model, error = _repair_diagram_scene(pages[page_index], diagram, provider)
    if not repair:
        return jsonify(
            error="The model could not build a reliable recreation. The source crop is still available.",
            detail=sanitize_provider_message(error),
            provider=provider,
            model=model,
        ), 422
    _apply_repaired_scene(diagram, repair)
    source_preview = _diagram_source_preview(pages[page_index], diagram)
    if source_preview:
        diagram["source_preview"] = source_preview
    preview = {
        "diagram_id": diagram.get("id"),
        "use_original": bool(diagram.get("use_original")),
        "source_note": (
            "Vector-traced from the source; structure and labels preserved."
            if diagram.get("recreation_mode") == "trace"
            else "Source diagram preserved for accuracy. An AI recreation is available for review."
        ),
        "original_data_url": source_preview,
    }
    try:
        preview["svg"] = render_diagram_svg(diagram, style=style).decode("utf-8")
    except Exception as exc:
        preview["error"] = sanitize_provider_message(str(exc))
    app.logger.info(
        "Diagram manual recreation provider=%s model=%s diagram=%s use_original=%s",
        provider, model or "", diagram.get("id") or "", bool(diagram.get("use_original")),
    )
    response = jsonify(diagram=diagram, preview=preview, provider=provider, model=model or "")
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/api/documents/cleanup", methods=["POST"])
@require_user_or_admin
@security.rate_limit("api_general")
def api_documents_cleanup():
    removed = cleanup_expired_documents()
    return jsonify({"removed": removed})


@app.route("/api/documents")
@require_user_or_admin
@security.rate_limit("api_general")
def api_documents():
    # Phase 3: Filter by user when authenticated
    _current_user_id = None
    try:
        _current_user_id = user_isolation.get_optional_user_id()
    except Exception:
        pass

    include_deleted = request.args.get("trash") == "1"
    query = (request.args.get("q") or "").strip().lower()
    status = (request.args.get("status") or "all").strip().lower()
    kind = (request.args.get("kind") or "all").strip().lower()
    folder = (request.args.get("folder") or "").strip().lower()
    tag = (request.args.get("tag") or "").strip().lower()
    favorite = request.args.get("favorite") == "1"
    documents = []
    for item in _load_documents():
        record = _document_defaults(item)
        # Phase 3: Filter by user ownership when authenticated
        if _current_user_id and not user_isolation.verify_document_ownership(record, _current_user_id):
            continue
        if include_deleted:
            if not record.get("deleted_at"):
                continue
        elif record.get("deleted_at"):
            continue
        if query and query not in (str(record.get("name") or "") + " " + " ".join(record.get("tags") or []) + " " + str(record.get("folder") or "") + " " + str(record.get("category") or "")).lower():
            continue
        if status not in {"", "all"} and str(record.get("status") or "completed").lower() != status:
            continue
        if kind not in {"", "all"} and str(record.get("kind") or "").lower() != kind:
            continue
        if folder and folder not in str(record.get("folder") or "").lower():
            continue
        if tag and tag not in [str(value).lower() for value in record.get("tags") or []]:
            continue
        if favorite and not record.get("favorite"):
            continue
        documents.append(_public_document(record))
    total = len(documents)
    try:
        offset = max(0, int(request.args.get("offset", 0)))
    except (TypeError, ValueError):
        offset = 0
    try:
        limit = max(0, min(200, int(request.args.get("limit", 0))))
    except (TypeError, ValueError):
        limit = 0
    if limit:
        documents = documents[offset:offset + limit]
    elif offset:
        documents = documents[offset:]
    response = jsonify(documents)
    response.headers["X-NotesAI-Data-Source"] = "local-documents"
    response.headers["X-Total-Count"] = str(total)
    response.headers["X-Offset"] = str(offset)
    response.headers["X-Limit"] = str(limit)
    return response


@app.route("/api/documents/<document_id>", methods=["GET", "PATCH", "DELETE"])
@require_user_or_admin
def api_document_detail(document_id):
    if request.method == "GET":
        document = get_document(document_id, include_deleted=request.args.get("trash") == "1")
        # Phase 3: Verify ownership when authenticated
        _uid = None
        try:
            _uid = user_isolation.get_optional_user_id()
        except Exception:
            pass
        if _uid and document and not user_isolation.verify_document_ownership(document, _uid):
            return _error_response("Document not found.", 404, "DOCUMENT_NOT_FOUND", retryable=False)
        if not document:
            return _error_response("Document not found.", 404, "DOCUMENT_NOT_FOUND", retryable=False)
        payload = _public_document(document)
        return jsonify(payload)
    denied = require_admin()
    if denied:
        return denied
    if not _valid_document_id(document_id):
        return _error_response("Invalid document id.", 400, "INVALID_DOCUMENT_ID", retryable=False)
    with _DOCUMENTS_LOCK:
        documents = _load_documents()
        target = next((item for item in documents if item.get("id") == document_id), None)
        if not target:
            return _error_response("Document not found.", 404, "DOCUMENT_NOT_FOUND", retryable=False)
        record = _document_defaults(target)
        if request.method == "DELETE":
            record["deleted_at"] = datetime.now().isoformat(timespec="seconds")
            record["updated_at"] = record["deleted_at"]
            target.update(record)
            _save_documents(documents)
            add_activity("Document", "Moved a document to trash", "completed", document_id=document_id)
            return jsonify({"ok": True, "document": _public_document(record)})
        payload = request.get_json(silent=True) or request.form
        if "name" in payload:
            name = _safe_display_name(payload.get("name"), record.get("name") or "NotesAI Document")
            if not name:
                return _error_response("Document name is required.", 400, "INVALID_NAME", retryable=False)
            record["name"] = name[:120]
        if "folder" in payload:
            record["folder"] = str(payload.get("folder") or "").strip()[:80]
        if "category" in payload:
            record["category"] = str(payload.get("category") or "").strip()[:80]
        if "tags" in payload:
            raw_tags = payload.get("tags")
            if isinstance(raw_tags, str):
                raw_tags = raw_tags.split(",")
            if not isinstance(raw_tags, list):
                raw_tags = []
            record["tags"] = [str(value).strip()[:32] for value in raw_tags if str(value).strip()][:12]
        if "favorite" in payload:
            value = payload.get("favorite")
            record["favorite"] = value is True or str(value).lower() in {"1", "true", "yes", "on"}
        record["updated_at"] = datetime.now().isoformat(timespec="seconds")
        target.update(record)
        _save_documents(documents)
        add_activity("Document", "Updated document details", "completed", document_id=document_id)
        return jsonify({"ok": True, "document": _public_document(record)})


@app.route("/api/documents/<document_id>/restore", methods=["POST"])
def restore_document(document_id):
    denied = require_admin()
    if denied:
        return denied
    if not _valid_document_id(document_id):
        return _error_response("Invalid document id.", 400, "INVALID_DOCUMENT_ID", retryable=False)
    with _DOCUMENTS_LOCK:
        documents = _load_documents()
        target = next((item for item in documents if item.get("id") == document_id), None)
        if not target:
            return _error_response("Document not found.", 404, "DOCUMENT_NOT_FOUND", retryable=False)
        record = _document_defaults(target)
        record["deleted_at"] = None
        record["updated_at"] = datetime.now().isoformat(timespec="seconds")
        target.update(record)
        _save_documents(documents)
    add_activity("Document", "Restored a document from trash", "completed", document_id=document_id)
    return jsonify({"ok": True, "document": _public_document(record)})


@app.route("/api/orders")
@require_user_or_admin
def api_orders():
    # The local document registry is the order/history source. No invented
    # records are returned when the user has not generated anything yet.
    orders = []
    for item in _load_documents():
        orders.append({
            "id": item.get("id"),
            "name": item.get("name"),
            "type": "pdf",
            "size": item.get("size", 0),
            "created": item.get("created"),
            "status": item.get("status", "completed"),
        })
    response = jsonify(orders)
    response.headers["X-NotesAI-Data-Source"] = "local-documents"
    return response


@app.route("/api/documents/<document_id>/download")
@require_user_or_admin
def download_document(document_id):
    document = get_document(document_id)
    # Phase 3: Verify ownership when authenticated
    _uid = None
    try:
        _uid = user_isolation.get_optional_user_id()
    except Exception:
        pass
    if _uid and document and not user_isolation.verify_document_ownership(document, _uid):
        return _error_response("Document not found.", 404, "DOCUMENT_NOT_FOUND", retryable=False)
    path = document_file_path(document)
    if not document or not path:
        return _error_response("Document not found.", 404, "DOCUMENT_NOT_FOUND", retryable=False)
    download_name = _safe_display_name(document.get("name"), "NotesAI-Document")
    if not download_name.lower().endswith(".pdf"):
        download_name += ".pdf"
    return send_file(
        path,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=download_name,
    )


@app.route("/api/documents/<document_id>/regenerate", methods=["POST"])
def regenerate_document(document_id):
    denied = require_admin()
    if denied:
        return denied
    document = get_document(document_id)
    if not document:
        return _error_response("Document not found.", 404, "DOCUMENT_NOT_FOUND", retryable=False)
    text = (document.get("text") or "").strip()
    if not text:
        return _error_response(
            "This document has no editable text to regenerate. Original image PDFs cannot be regenerated.",
            400, "DOCUMENT_NOT_EDITABLE", retryable=False,
        )
    options = {
        "pageSize": document.get("page_size", "A4"),
        "orientation": document.get("orientation", "P"),
        "margin": document.get("margin", 12),
        "fontSize": 11,
        "style": document.get("style", "professional"),
        "diagramStyle": document.get("diagram_style", "color"),
    }
    if isinstance(document.get("pdf_options"), dict):
        options.update(document["pdf_options"])
    options["folder"] = document.get("folder", "")
    options["category"] = document.get("category", "")
    options["tags"] = list(document.get("tags") or [])
    options["favorite"] = bool(document.get("favorite"))
    diagram_warnings = []
    try:
        if document.get("kind") in {"smart", "smart-regenerated"}:
            analysis = json.loads(text)
            pdf_bytes, diagram_warnings = generate_smart_pdf(analysis, options)
            kind = "smart-regenerated"
        else:
            structured = parse_gemini_structured_response(text)
            pdf_bytes = generate_professional_pdf(structured, options)
            kind = "regenerated"
    except PdfCapabilityError as exc:
        return pdf_capability_error_response(exc)
    except Exception:
        app.logger.exception("Document regeneration failed")
        return _error_response(
            "Could not regenerate this PDF. Please try again.",
            500, "PDF_GENERATION_FAILED", retryable=True,
        )

    saved = save_generated_document(
        pdf_bytes,
        document.get("name") or "NotesAI-Regenerated",
        kind,
        options,
        text=text,
        provider=document.get("provider", ""),
        model=document.get("model", ""),
    )
    note_document_created(None)
    add_activity("Generate PDF", "Regenerated an existing document", "completed")
    download_name = _safe_display_name(document.get('name'), 'NotesAI-Regenerated')
    if download_name.lower().endswith(".pdf"):
        download_name = download_name[:-4]
    response = send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"{download_name}.pdf",
    )
    if saved:
        response.headers["X-NotesAI-Document-Id"] = saved["id"]
    response.headers["X-NotesAI-Diagram-Warnings"] = str(len(diagram_warnings))
    return response

# ============================================================
# EXTRACT TEXT ENDPOINT
# ============================================================
@app.route("/extract-text", methods=["POST"])
@require_user_or_admin
@security.rate_limit("api_upload")
@_single_flight("extract")
def extract_text():
    files = [f for f in request.files.getlist("noteFiles") if f and f.filename]
    if not files:
        return _error_response(
            "Choose at least one image or PDF first.", 400, "NO_FILES", retryable=False,
        )

    requested = (request.form.get("provider") or "").strip().lower()
    job_id = (request.form.get("jobId") or "").strip()[:80]
    preview = request.form.get("preview") == "1"
    active = get_active_provider()
    if requested and requested != active:
        return _error_response(
            f"Provider '{requested}' is not active. Switch to it in Settings first (active: {active}).",
            400, "PROVIDER_MISMATCH", retryable=False,
        )

    provider = resolve_extraction_provider()
    if not provider:
        if active == "gemini":
            error = "GEMINI_API_KEY is not configured in the server .env."
        else:
            error = "OPENROUTER_API_KEY is not configured in the server .env."
        response = _error_response(error, 503, "PROVIDER_NOT_CONFIGURED", retryable=False)
        response[0].headers["X-NotesAI-Provider"] = active
        return response

    analysis_mode = (request.form.get("analysis") or "").strip().lower() == "smart" or (request.form.get("mode") or "").strip().lower() == "smart"
    if analysis_mode:
        diagram_style = normalise_diagram_style(request.form.get("diagramStyle", "color"))
        analysis, model_used, status, error, previews = analyze_smart_pages(files, provider, diagram_style=diagram_style)
        app.logger.info(
            "Smart extraction provider=%s model=%s files=%d status=%s",
            provider, model_used or "", len(files), "failed" if status else "ok",
        )
        if status:
            if not preview:
                note_extraction_failure(job_id)
                add_activity("Extract", f"Smart analysis failed via {provider}", "failed")
            return _ai_failure_response(
                status, error, provider, model_used,
                extra_headers={"X-NotesAI-Analysis": "smart"},
            )
        text = analysis_to_text(analysis)
        structured = analysis_to_structured(analysis)
        if not preview:
            note_extraction_success(job_id)
            add_activity("Extract", f"Smart page analysis via {provider} ({len(files)} file(s))", "completed")
        response = jsonify(
            text=text,
            structured=structured,
            analysis=analysis,
            diagram_previews=previews,
            warnings=analysis.get("warnings") or [],
            provider=provider,
            model=model_used,
            smart=True,
        )
        response.headers["X-NotesAI-Provider"] = provider
        response.headers["X-NotesAI-Analysis"] = "smart"
        if model_used:
            response.headers["X-NotesAI-Model"] = model_used
        return response

    text, model_used, status, error = extract_text_with_provider(files, provider)
    app.logger.info(
        "AI extraction provider=%s model=%s files=%d status=%s",
        provider, model_used or "", len(files), "failed" if status else "ok",
    )
    if status:
        if not preview:
            note_extraction_failure(job_id)
            add_activity("Extract", f"Extraction failed via {provider}", "failed")
        return _ai_failure_response(status, error, provider, model_used)
    if not text:
        if not preview:
            note_extraction_failure(job_id)
            add_activity("Extract", f"Extraction failed via {provider}", "failed")
        return _ai_failure_response(
            502, "AI returned no text. Try a clearer image.", provider, "",
            code="EMPTY_AI_RESPONSE",
        )

    structured = parse_gemini_structured_response(text)
    if not preview:
        note_extraction_success(job_id)
        add_activity("Extract", f"Extracted text via {provider} ({len(files)} file(s))", "completed")
    response = jsonify(text=text, structured=structured, provider=provider, model=model_used)
    response.headers["X-NotesAI-Provider"] = provider
    if model_used:
        response.headers["X-NotesAI-Model"] = model_used
    return response

def render_pdf_preview_pages(pdf_bytes, max_pages=12, dpi=100):
    """Render generated PDF pages to JPEG data URLs for the in-app preview.

    Android browsers do not reliably render PDF blobs inside an iframe; they
    show a file card with a UUID and an Open button. Rendering the actual pages
    locally with poppler gives the same preview on mobile and desktop and never
    persists anything to document history.
    """
    if not pdf_bytes or not pdf_bytes.startswith(b"%PDF"):
        raise ValueError("Generated file is not a valid PDF.")
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            pdf_path = Path(temp_dir) / "preview.pdf"
            pdf_path.write_bytes(pdf_bytes)
            info = subprocess.run(
                ["pdfinfo", str(pdf_path)],
                check=False, timeout=20, capture_output=True, text=True,
            )
            match = re.search(r"^Pages:\s+(\d+)", info.stdout or "", re.MULTILINE)
            page_count = int(match.group(1)) if match else 0
            limit = min(page_count or max_pages, max_pages)
            if limit < 1:
                raise RuntimeError("PDF has no pages.")
            prefix = Path(temp_dir) / "page"
            result = subprocess.run(
                ["pdftoppm", "-jpeg", "-r", str(dpi), "-f", "1", "-l", str(limit),
                 str(pdf_path), str(prefix)],
                check=False, timeout=60, capture_output=True,
            )
            if result.returncode != 0:
                raise RuntimeError("Could not render PDF pages.")
            files = sorted(
                Path(temp_dir).glob("page-*.jpg"),
                key=lambda item: int(re.search(r"(\d+)$", item.stem).group(1))
                if re.search(r"(\d+)$", item.stem) else 0,
            )
            pages = []
            for index, path in enumerate(files, 1):
                raw = path.read_bytes()
                with Image.open(io.BytesIO(raw)) as image:
                    width, height = image.size
                pages.append({
                    "page": index,
                    "data_url": "data:image/jpeg;base64," + base64.b64encode(raw).decode("ascii"),
                    "width": width,
                    "height": height,
                })
            if not pages:
                raise RuntimeError("Could not render PDF pages.")
            return {
                "pages": pages,
                "page_count": page_count or len(pages),
                "truncated": (page_count or len(pages)) > len(pages),
            }
    except FileNotFoundError:
        raise RuntimeError("PDF preview renderer is unavailable on this server.")
    except subprocess.TimeoutExpired:
        raise RuntimeError("PDF preview rendering timed out.")


# ============================================================
# GENERATE PDF ENDPOINT
# ============================================================
@app.route("/generate-pdf", methods=["POST"])
@require_user_or_admin
@security.rate_limit("api_pdf")
@_single_flight("generate")
def generate_pdf():
    # Get mode: professional (default) or image.
    mode = request.form.get("mode", "professional")
    if mode not in {"professional", "image", "smart"}:
        return _error_response("Choose a valid PDF output mode.", 400, "INVALID_REQUEST", retryable=False)
    job_id = (request.form.get("jobId") or "").strip()[:80]
    preview = request.form.get("preview") == "1"
    preview_images = preview and request.form.get("previewImages") == "1"
    text = request.form.get("extractedText", "").strip()
    active_provider = get_active_provider()

    try:
        page_size = request.form.get("pageSize", "A4")
        orientation = request.form.get("orientation", "P")
        margin = int(request.form.get("margin", "12"))
    except (TypeError, ValueError):
        return _error_response("Choose valid PDF page settings.", 400, "INVALID_REQUEST", retryable=False)
    if page_size not in {"A4", "Letter"} or orientation not in {"P", "L"} or margin not in {8, 12, 16}:
        return _error_response("Invalid PDF page settings.", 400, "INVALID_REQUEST", retryable=False)
    style = request.form.get("style", "professional")
    if style not in {"professional", "academic", "minimal", "modern"}:
        style = "professional"
    try:
        font_size = max(8, min(16, int(request.form.get("fontSize", "11"))))
    except (TypeError, ValueError):
        font_size = 11
    options = {
        "pageSize": page_size,
        "orientation": orientation,
        "margin": margin,
        "fontSize": font_size,
        "style": style,
        "diagramStyle": normalise_diagram_style(request.form.get("diagramStyle", "color")),
    }
    options.update(normalise_pdf_options(request.form))
    options["folder"] = str(request.form.get("folder") or "").strip()[:80]
    options["category"] = str(request.form.get("category") or "").strip()[:80]
    raw_tags = request.form.get("tags") or ""
    options["tags"] = [tag.strip()[:32] for tag in raw_tags.split(",") if tag.strip()][:12]
    options["favorite"] = str(request.form.get("favorite") or "").lower() in {"1", "true", "yes", "on"}
    options["serviceOption"] = (request.form.get("serviceOption") or "standard").strip().lower()
    if options["serviceOption"] not in {"standard", "priority", "express"}:
        options["serviceOption"] = "standard"
    _rd = (request.form.get("retentionDays") or request.form.get("retention_days") or "").strip().lower()
    if _rd in {"3", "7", "30"}:
        options["retentionDays"] = int(_rd)
    elif _rd in {"keep", "forever", "0", ""}:
        options["retentionDays"] = None

    def pdf_response(pdf_bytes, download_name, status, provider="", model="", document_id=None):
        if preview_images:
            try:
                preview_data = render_pdf_preview_pages(pdf_bytes)
            except Exception as exc:
                app.logger.warning("PDF preview rendering failed: %s", type(exc).__name__)
                return _error_response("Could not render the PDF preview. Please retry.", 500, "PREVIEW_FAILED", retryable=True)
            response = jsonify(preview=preview_data, status=status)
            response.headers["X-NotesAI-Status"] = status
            response.headers["X-NotesAI-Preview"] = "1"
            if provider:
                response.headers["X-NotesAI-Provider"] = provider
            if model:
                response.headers["X-NotesAI-Model"] = model
            return response
        response = send_file(
            io.BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=not preview,
            download_name=download_name,
        )
        response.headers["X-NotesAI-Status"] = status
        if preview:
            response.headers["X-NotesAI-Preview"] = "1"
        if provider:
            response.headers["X-NotesAI-Provider"] = provider
        if model:
            response.headers["X-NotesAI-Model"] = model
        if document_id:
            response.headers["X-NotesAI-Document-Id"] = document_id
        return response

    def persist(pdf_bytes, name, kind, stored_text="", provider="", model="", pages=None):
        if preview:
            return None
        try:
            return save_generated_document(
                pdf_bytes, name, kind, options, text=stored_text,
                provider=provider, model=model, pages=pages,
            )
        except Exception:
            # A history write failure must never prevent the user's download.
            app.logger.exception("Could not persist generated document history")
            return None

    if mode == "smart":
        files = [f for f in request.files.getlist("noteFiles") if f and f.filename]
        analysis_raw = (request.form.get("analysis") or "").strip()
        analysis = None
        provider_used = active_provider
        model_used = ""
        if analysis_raw:
            try:
                analysis = json.loads(analysis_raw)
                if not isinstance(analysis, dict):
                    raise ValueError
            except (json.JSONDecodeError, ValueError, TypeError):
                return _error_response("The smart analysis payload is invalid. Run Smart extraction again.", 400, "INVALID_ANALYSIS", retryable=False)
        if not analysis:
            if not files:
                return _error_response("Smart Recreated PDF needs uploaded page images or a saved analysis.", 400, "NO_SOURCE", retryable=False)
            provider = resolve_extraction_provider()
            if not provider:
                missing = "GEMINI_API_KEY" if active_provider == "gemini" else "OPENROUTER_API_KEY"
                return _error_response(f"No AI provider configured for smart PDF. Add {missing} in server .env.", 503, "PROVIDER_NOT_CONFIGURED", retryable=False)
            analysis, model_used, status, error, _previews = analyze_smart_pages(
                files, provider, diagram_style=options.get("diagramStyle", "color")
            )
            provider_used = provider
            if status:
                return _ai_failure_response(
                    status, error, provider, model_used,
                    extra_headers={"X-NotesAI-Analysis": "smart"},
                )
        else:
            model_used = (request.form.get("model") or "").strip()[:120]
        try:
            source_pages = prepare_source_pages(files) if files else []
        except ValueError as exc:
            app.logger.warning("Smart PDF source pages unavailable: %s", exc)
            source_pages = []
        try:
            analysis = normalise_analysis(analysis)
            pdf_bytes, diagram_warnings = generate_smart_pdf(analysis, options, source_pages)
        except PdfCapabilityError as exc:
            return pdf_capability_error_response(exc)
        except Exception:
            app.logger.exception("Smart PDF generation failed")
            return _error_response("Smart PDF generation failed. Please review the diagram specifications and try again.", 500, "PDF_GENERATION_FAILED", retryable=True)
        name = analysis.get("title") or "NotesAI-Smart"
        saved = persist(
            pdf_bytes, name, "smart",
            stored_text=json.dumps(analysis, ensure_ascii=False),
            provider=provider_used, model=model_used,
            pages=len(analysis.get("pages") or []),
        )
        if not preview:
            note_document_created(job_id)
            add_activity("Generate PDF", "Generated smart recreated PDF", "completed")
        response = pdf_response(
            pdf_bytes, "NotesAI-Smart.pdf", "smart-pdf",
            provider_used, model_used, saved["id"] if saved else None,
        )
        response.headers["X-NotesAI-Diagram-Warnings"] = str(len(diagram_warnings))
        return response

    # If text provided directly, use it (professional or simple text PDF).
    # Original Image mode must still prioritise the selected image files.
    if text and mode != "image":
        try:
            if mode == "professional":
                structured = parse_gemini_structured_response(text)
                pdf_bytes = generate_professional_pdf(structured, options)
                name = structured.get("title") or "NotesAI-Professional"
                saved = persist(pdf_bytes, name, "professional", stored_text=text,
                                provider=getattr(g, "notesai_provider", ""),
                                model=getattr(g, "notesai_model", ""))
                if not preview:
                    note_document_created(job_id)
                    add_activity("Generate PDF", "Generated professional PDF", "completed")
                return pdf_response(
                    pdf_bytes, "NotesAI-Professional.pdf", "professional-pdf",
                    getattr(g, "notesai_provider", ""),
                    getattr(g, "notesai_model", ""),
                    saved["id"] if saved else None,
                )

            # Simple text PDF (legacy behaviour, portable fonts + shaping).
            fonts = resolve_pdf_fonts()
            if contains_arabic(text) and not fonts["arabic"]:
                raise PdfCapabilityError("PDF_FONT_MISSING")
            pdf = FPDF(unit="mm", format="A4")
            pdf.set_margins(margin, margin, margin)
            pdf.set_auto_page_break(auto=True, margin=margin + 8)
            register_pdf_fonts(pdf, fonts)
            pdf.add_page()
            pdf.set_font("NotesAI", size=11)
            prepared = shape_text_for_pdf(text)
            text_align = 'R' if contains_arabic(text) else 'J'
            pdf.multi_cell(w=0, h=6, text=prepared, align=text_align)
            output = pdf.output()
            if isinstance(output, str):
                output = output.encode("latin-1")
            pdf_bytes = bytes(output)
            saved = persist(pdf_bytes, "NotesAI-Text", "text", stored_text=text,
                            provider=getattr(g, "notesai_provider", ""))
            if not preview:
                note_document_created(job_id)
                add_activity("Generate PDF", "Generated text-based PDF", "completed")
            return pdf_response(
                pdf_bytes, "NotesAI-Text.pdf", "text-pdf",
                getattr(g, "notesai_provider", ""),
                getattr(g, "notesai_model", ""),
                saved["id"] if saved else None,
            )
        except PdfCapabilityError as exc:
            return pdf_capability_error_response(exc)
        except Exception:
            app.logger.exception("PDF generation failed")
            return _error_response("PDF generation failed. Please try again.", 500, "PDF_GENERATION_FAILED", retryable=True)

    # No text provided - check for files.
    files = [f for f in request.files.getlist("noteFiles") if f and f.filename]
    if not files:
        return _error_response("Choose at least one image or PDF.", 400, "NO_FILES", retryable=False)

    allowed_images = {"jpg", "jpeg", "png", "webp", "bmp"}
    extensions = [
        f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
        for f in files
    ]

    # Handle PDF upload - return as-is (byte-identical pass-through).
    if "pdf" in extensions:
        if len(files) != 1 or extensions[0] != "pdf":
            return _error_response("Upload one PDF at a time, without mixing it with images.", 400, "INVALID_UPLOAD", retryable=False)
        data = files[0].read()
        # PDF readers allow the %PDF- header within the first 1 KB (some
        # generators add a BOM/whitespace), so do not reject those files.
        if b"%PDF-" not in data[:1024]:
            return _error_response("This file is not a valid PDF.", 400, "INVALID_PDF", retryable=False)
        saved = persist(data, files[0].filename or "NotesAI-Document", "existing")
        if not preview:
            add_activity("Download", "Downloaded existing PDF", "completed")
        return pdf_response(
            data, "NotesAI-Document.pdf", "already-pdf",
            document_id=saved["id"] if saved else None,
        )

    # Validate image formats.
    if any(ext not in allowed_images for ext in extensions):
        return _error_response("Supported formats: JPG, PNG, WEBP, BMP or PDF.", 400, "UNSUPPORTED_FILE", retryable=False)

    # The selected provider handles AI extraction. No automatic cross-provider
    # fallback: Gemini failure never switches to OpenRouter (or vice versa).
    provider = resolve_extraction_provider()

    # If no provider key and mode is professional, return error.
    if mode == "professional" and not provider:
        missing = "GEMINI_API_KEY" if active_provider == "gemini" else "OPENROUTER_API_KEY"
        response = _error_response(
            f"No AI provider configured for professional PDF. Add {missing} in server .env or use Original Image PDF mode.",
            503, "PROVIDER_NOT_CONFIGURED", retryable=False,
        )
        response[0].headers["X-NotesAI-Provider"] = active_provider
        return response

    # If mode is image, create image-based PDF.
    if mode == "image":
        pdf = WatermarkedFPDF(orientation=orientation, unit="mm", format=page_size)
        pdf.set_auto_page_break(auto=False)
        fonts = resolve_pdf_fonts()
        register_pdf_fonts(pdf, fonts)
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                for index, uploaded in enumerate(files):
                    try:
                        uploaded.stream.seek(0)
                        with Image.open(uploaded.stream) as source:
                            source.load()
                            image = source.convert("RGB")
                        image_path = Path(temp_dir) / f"page_{index}.jpg"
                        image.save(image_path, format="JPEG", quality=92)
                        pdf.add_page()
                        max_width = pdf.w - 2 * margin
                        max_height = pdf.h - 2 * margin
                        scale = min(max_width / image.width, max_height / image.height)
                        width = image.width * scale
                        height = image.height * scale
                        pdf.image(str(image_path), x=(pdf.w - width) / 2,
                                  y=(pdf.h - height) / 2, w=width, h=height)
                    except Exception:
                        return _error_response(f"Could not read image: {uploaded.filename}", 400, "INVALID_IMAGE", retryable=False)
                output = pdf.output()
                if isinstance(output, str):
                    output = output.encode("latin-1")
                pdf_bytes = bytes(output)
        except Exception:
            return _error_response("PDF generation failed. Please try another image.", 500, "PDF_GENERATION_FAILED", retryable=True)

        name = files[0].filename.rsplit(".", 1)[0] if files else "NotesAI-Document"
        saved = persist(pdf_bytes, name, "image", pages=len(files))
        if not preview:
            note_document_created(job_id)
            add_activity("Generate PDF", f"Generated image-based PDF ({len(files)} pages)", "completed")
        return pdf_response(
            pdf_bytes, "NotesAI-Document.pdf", "image-pdf",
            document_id=saved["id"] if saved else None,
        )

    # Professional mode: auto-extract and generate professional PDF.
    try:
        for f in files:
            f.stream.seek(0)
        structured, extraction_error = extract_structured_for_pdf(files)
        if extraction_error:
            status, message = extraction_error
            return _ai_failure_response(status, message, active_provider)

        pdf_bytes = generate_professional_pdf(structured, options)
        provider_used = getattr(g, "notesai_provider", active_provider)
        model_used = getattr(g, "notesai_model", "")
        saved = persist(
            pdf_bytes,
            structured.get("title") or "NotesAI-Professional",
            "professional",
            stored_text=json.dumps(structured, ensure_ascii=False),
            provider=provider_used,
            model=model_used,
        )
        if not preview:
            note_document_created(job_id)
            add_activity("Generate PDF", f"Generated professional PDF ({len(files)} pages)", "completed")
        return pdf_response(
            pdf_bytes, "NotesAI-Professional.pdf", "professional-pdf",
            provider_used, model_used, saved["id"] if saved else None,
        )
    except PdfCapabilityError as exc:
        return pdf_capability_error_response(exc)
    except Exception as exc:
        app.logger.exception("Professional PDF generation failed")
        return _error_response(f"Professional PDF generation failed: {type(exc).__name__}", 500, "PDF_GENERATION_FAILED", retryable=True)

# ============================================================
# MAIN ROUTES
# ============================================================
# ============================================================================
# AUTHENTICATION API ROUTES (Phase 2)
# ============================================================================

@app.route("/api/auth/register", methods=["POST"])
@security.rate_limit("auth_register")
def api_auth_register():
    """Register a new user."""
    payload = request.get_json(silent=True) or request.form
    email = str(payload.get("email") or "").strip()
    password = str(payload.get("password") or "")
    name = str(payload.get("name") or "").strip()

    if not email or not password or not name:
        return _error_response("Email, password, and name are required.", 400, "MISSING_FIELDS", retryable=False)

    database.init_db()
    db = database.get_db()
    user, error = register_user(db, email, password, name)
    if error:
        security.audit_log("register_failed", {"email": email}, status="failure")
        return _error_response(error, 400, "REGISTRATION_FAILED", retryable=False)

    security.audit_log("register_success", {"email": email, "user_id": user["id"]})
    # Auto-login after registration
    user, access_token, refresh_token, login_error = login_user(db, email, password)
    if login_error:
        return _error_response(login_error, 400, "LOGIN_FAILED", retryable=False)

    return jsonify({
        "ok": True,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "name": user["name"],
            "role": user["role"],
        },
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": 900,  # 15 minutes
    })


@app.route("/api/auth/login", methods=["POST"])
@security.rate_limit("auth_login")
def api_auth_login():
    """Login a user."""
    payload = request.get_json(silent=True) or request.form
    email = str(payload.get("email") or "").strip()
    password = str(payload.get("password") or "")

    if not email or not password:
        return _error_response("Email and password are required.", 400, "MISSING_FIELDS", retryable=False)

    database.init_db()
    db = database.get_db()
    user, access_token, refresh_token, error = login_user(db, email, password)
    if error:
        security.audit_log("login_failed", {"email": email}, status="failure")
        return _error_response(error, 401, "LOGIN_FAILED", retryable=False)

    security.audit_log("login_success", {"email": email, "user_id": user["id"]})
    return jsonify({
        "ok": True,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "name": user["name"],
            "role": user["role"],
        },
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": 900,
    })


@app.route("/api/auth/refresh", methods=["POST"])
def api_auth_refresh():
    """Refresh an access token."""
    payload = request.get_json(silent=True) or request.form
    refresh_token = str(payload.get("refresh_token") or "").strip()

    if not refresh_token:
        return _error_response("Refresh token is required.", 400, "MISSING_TOKEN", retryable=False)

    database.init_db()
    db = database.get_db()
    access_token, new_refresh, error = refresh_access_token(db, refresh_token)
    if error:
        return _error_response(error, 401, "REFRESH_FAILED", retryable=False)

    return jsonify({
        "ok": True,
        "access_token": access_token,
        "refresh_token": new_refresh,
        "token_type": "Bearer",
        "expires_in": 900,
    })


@app.route("/api/auth/me", methods=["GET"])
@require_auth
def api_auth_me():
    """Get current user profile."""
    user = get_current_user()
    return jsonify({
        "ok": True,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "name": user["name"],
            "role": user["role"],
            "status": user["status"],
            "created_at": user["created_at"],
        },
    })


@app.route("/api/auth/logout", methods=["POST"])
def api_auth_logout():
    """Logout a user."""
    payload = request.get_json(silent=True) or request.form
    refresh_token = str(payload.get("refresh_token") or "").strip()

    database.init_db()
    db = database.get_db()
    logout_user(db, refresh_token if refresh_token else None)

    return jsonify({"ok": True, "message": "Logged out successfully."})


@app.route("/api/auth/logout-all", methods=["POST"])
@require_auth
def api_auth_logout_all():
    """Logout from all devices."""
    database.init_db()
    db = database.get_db()
    logout_all_devices(db, get_current_user_id())
    return jsonify({"ok": True, "message": "Logged out from all devices."})


@app.route("/api/auth/forgot-password", methods=["POST"])
@security.rate_limit("auth_reset")
def api_auth_forgot_password():
    """Request a password reset."""
    payload = request.get_json(silent=True) or request.form
    email = str(payload.get("email") or "").strip()

    if not email:
        return _error_response("Email is required.", 400, "MISSING_EMAIL", retryable=False)

    database.init_db()
    db = database.get_db()
    reset_token, error = request_password_reset(db, email)

    # Always return success (don't reveal if email exists)
    return jsonify({
        "ok": True,
        "message": "If an account with that email exists, a password reset link has been sent.",
    })


@app.route("/api/auth/reset-password", methods=["POST"])
def api_auth_reset_password():
    """Reset password using a reset token."""
    payload = request.get_json(silent=True) or request.form
    reset_token = str(payload.get("token") or "").strip()
    new_password = str(payload.get("new_password") or "")

    if not reset_token or not new_password:
        return _error_response("Token and new password are required.", 400, "MISSING_FIELDS", retryable=False)

    database.init_db()
    db = database.get_db()
    success, error = reset_password(db, reset_token, new_password)
    if not success:
        return _error_response(error, 400, "RESET_FAILED", retryable=False)

    return jsonify({"ok": True, "message": "Password reset successfully. Please login with your new password."})


@app.route("/api/auth/legacy-info", methods=["GET"])
@require_admin_auth
def api_auth_legacy_info():
    """Get legacy account info (admin only)."""
    database.init_db()
    db = database.get_db()
    info = get_legacy_account_info(db)
    if not info:
        return _error_response("Legacy account not found.", 404, "NOT_FOUND", retryable=False)
    return jsonify({"ok": True, "legacy": info})


@app.route("/api/auth/legacy-create", methods=["POST"])
@require_admin_auth
def api_auth_legacy_create():
    """Create legacy account (admin only)."""
    database.init_db()
    db = database.get_db()
    legacy_id = create_legacy_account(db)
    return jsonify({"ok": True, "legacy_id": legacy_id, "message": "Legacy account created."})


# ============================================================================
# AUTHENTICATION API ROUTES (Phase 2) - END
# ============================================================================

# ============================================================================
# PWA ROUTES (Progressive Web App)
# ============================================================================

@app.route("/manifest.json")
def pwa_manifest():
    """Serve the PWA manifest."""
    return send_file("static/manifest.json", mimetype="application/manifest+json")


@app.route("/sw.js")
def pwa_service_worker():
    """Serve the service worker (must be at root scope)."""
    response = send_file("static/sw.js", mimetype="application/javascript")
    response.headers["Service-Worker-Allowed"] = "/"
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response


@app.route("/offline")
def pwa_offline():
    """Serve the offline fallback page."""
    return send_file("static/offline.html", mimetype="text/html")


# ============================================================================
# PWA ROUTES - END
# ============================================================================

@app.route("/")
def home():
    stats = load_stats()
    activity = load_activity()[:5]
    return render_template_string(HTML, page='dashboard', page_title='Dashboard', page_desc='', stats=stats, activity=activity, admin_token=os.getenv('NOTESAI_ADMIN_TOKEN','') or get_env_key('NOTESAI_ADMIN_TOKEN'))

@app.route("/health")
def health():
    return {"status": "ok", "app": "NotesAI Premium"}

# Navigation pages
PAGES = {
    "study": ("AI Study Workspace", "Turn your notes into summaries, questions, flashcards and revision material."),
    "my-notes": ("My Notes", "Search, organize and manage your document library."),
    "new-order": ("PDF Studio", "Upload notes, design the layout and generate a polished PDF."),
    "history": ("Order History", "Your previous and completed orders."),
    "settings": ("Workspace Settings", "Manage your NotesAI workspace preferences."),
    "admin": ("Admin Overview", "Local workspace health, storage, billing and failed-job monitoring."),
}

@app.route("/<page>")
def navigation_page(page):
    if page not in PAGES:
        abort(404)
    title, description = PAGES[page]
    return render_template_string(HTML, page=page, page_title=title, page_desc=description, admin_token=os.getenv('NOTESAI_ADMIN_TOKEN','') or get_env_key('NOTESAI_ADMIN_TOKEN'))

if __name__ == "__main__":
    try:
        cleanup_expired_documents()
    except Exception:
        pass
    # Production-safe defaults: loopback only, debugger disabled.
    # Development:  NOTESAI_DEBUG=1 python app.py
    # LAN access:   NOTESAI_HOST=0.0.0.0 NOTESAI_ADMIN_TOKEN=<secret> python app.py
    runtime_host = os.getenv("NOTESAI_HOST", "127.0.0.1").strip() or "127.0.0.1"
    try:
        runtime_port = int(os.getenv("NOTESAI_PORT", "3000"))
    except (TypeError, ValueError):
        runtime_port = 3000
    runtime_debug = _env_bool("NOTESAI_DEBUG", False)
    # load_dotenv=False: the app reads only PROJECT_ROOT/.env, so an unrelated
    # ~/.env from another project can never supply/override NotesAI keys.
    app.run(host=runtime_host, port=runtime_port, debug=runtime_debug,
            use_reloader=runtime_debug, load_dotenv=False)
