# NotesAI — System Architecture

## Overview

NotesAI is a monolithic Flask web application with an embedded HTML/CSS/JS frontend. It uses file-based JSON storage with a SQLite database schema ready for migration.

## Architecture Diagram

```
┌─────────────────────────────────────────────────┐
│                  Browser / PWA                   │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐   │
│  │ Dashboard │ │ AI Study │ │ PDF Studio   │   │
│  └──────────┘ └──────────┘ └──────────────┘   │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐   │
│  │ My Notes │ │ Settings │ │ Admin        │   │
│  └──────────┘ └──────────┘ └──────────────┘   │
└────────────────────┬────────────────────────────┘
                     │ HTTP/HTTPS
┌────────────────────┴────────────────────────────┐
│              Flask Backend (app.py)               │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐   │
│  │ Routes   │ │ Auth     │ │ Security     │   │
│  │ (23)     │ │ (JWT)    │ │ (Rate/CORS)  │   │
│  └──────────┘ └──────────┘ └──────────────┘   │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐   │
│  │ PDF Gen  │ │ AI Study │ │ Documents    │   │
│  │ (3 modes)│ │ (16 tools)│ │ (CRUD)       │   │
│  └──────────┘ └──────────┘ └──────────────┘   │
└────────────────────┬────────────────────────────┘
                     │
┌────────────────────┴────────────────────────────┐
│              Storage Layer                        │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐   │
│  │ JSON     │ │ SQLite   │ │ File System  │   │
│  │ (current)│ │ (Phase 1)│ │ (PDFs)       │   │
│  └──────────┘ └──────────┘ └──────────────┘   │
└────────────────────┬────────────────────────────┘
                     │
┌────────────────────┴────────────────────────────┐
│              AI Providers                        │
│  ┌──────────┐ ┌──────────────────────────┐     │
│  │ Gemini   │ │ OpenRouter (free only)   │     │
│  └──────────┘ └──────────────────────────┘     │
└─────────────────────────────────────────────────┘
```

## Module Structure

| Module | Purpose | Lines |
|--------|---------|-------|
| `app.py` | Main Flask app, routes, HTML template, PDF generation | ~11,800 |
| `auth.py` | User authentication, JWT, password reset, legacy account | ~445 |
| `database.py` | SQLite schema, connection management | ~337 |
| `models.py` | Data access functions (CRUD) | ~534 |
| `security.py` | Rate limiting, CORS, audit logging, file validation | ~381 |
| `user_isolation.py` | Multi-user ownership and filtering | ~159 |
| `watermark_engine.py` | Tiled PDF watermark | ~120 |
| `migrate_json_to_db.py` | JSON-to-SQLite migration script (dry-run) | ~319 |
| `notesai_schema.py` | Schema normalization, AI prompts | ~1,300 |
| `notesai_diagrams.py` | Diagram rendering engine | ~1,200 |
| `notesai_trace.py` | Diagram tracing utilities | ~400 |

## Data Flow

1. **User uploads image** → `/extract-text` → AI provider extracts text → Returns structured text
2. **User generates PDF** → `/generate-pdf` → Parse text → Generate PDF (3 modes) → Save to documents/ → Return PDF
3. **AI Study** → `/api/study/generate` → Build prompt → AI provider → Return study material
4. **Document management** → `/api/documents/*` → Read/write documents.json → Return metadata

## Storage

- **Current:** File-based JSON (documents.json, activity.json, billing.json, stats.json, provider_status.json)
- **Phase 1:** SQLite schema ready (11 tables, not yet activated)
- **Files:** PDFs stored in `documents/` directory (UUID filenames)
- **Fonts:** Custom fonts in `fonts/` directory

## PWA Architecture

- **Manifest:** `/manifest.json` (standalone display, 8 icons, 3 shortcuts)
- **Service Worker:** `/sw.js` (app shell caching, offline fallback, update detection)
- **Offline Page:** `/offline` (branded offline page with retry)
- **Security:** Private data NOT cached, only static assets cached

## Security Architecture

- **Authentication:** JWT (access 15min + refresh 7 days) with bcrypt passwords
- **Authorization:** `@require_auth`, `@require_admin`, `@require_user_or_admin` decorators
- **Rate Limiting:** In-memory, 8 categories, per-IP/per-user
- **CORS:** Approved origins only
- **Security Headers:** HSTS, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy
- **Audit Logging:** JSON file, secret redaction, thread-safe
- **File Upload:** MIME type, size, extension, content validation
- **Admin Access:** Token-based (env var) + localhost bypass
