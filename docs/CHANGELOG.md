# NotesAI — Changelog

## Phase 6 — Complete Testing & Professional Documentation (2026-11-20)

- Comprehensive project audit (read-only)
- 170+ tests across all phases, 0 failures
- 8 documentation files created (README, ARCHITECTURE, API, SECURITY, PWA, TESTING, DEPLOYMENT, CHANGELOG)
- Data integrity verified (74 documents, 122 activity entries, billing, stats, provider status)
- No production deployment performed

## Phase 5 — PWA Web App (2026-11-20)

- Progressive Web App implementation
- Web App Manifest with 8 icons and 3 shortcuts
- Service Worker with offline fallback and static asset caching
- Offline page with connection retry
- Network status indicator
- App update notification
- Animated download button (loading/success/error states)
- PWA meta tags (theme-color, apple-mobile-web-app-capable, etc.)
- Mobile safe-area support
- Security: private data NOT cached in service worker

## Phase 4 — API Security Hardening (2026-11-20)

- Rate limiting (8 categories, in-memory, no external deps)
- Input validation (document ID, email, filename, text length, integer, choice)
- CORS security (approved origins only, no wildcards)
- HTTPS enforcement (HSTS header, security headers)
- Audit logging (JSON file, secret redaction, thread-safe)
- File upload security (MIME type, size, extension, content validation)
- Animated download button (CSS + JS, loading/success/error states)

## Phase 3 — Multi-User Data Isolation & Legacy Migration (2026-11-20)

- `user_isolation.py` module (ownership verification, document filtering)
- `migrate_json_to_db.py` script (dry-run only)
- User ownership on document endpoints
- Legacy Account creation (admin-only)
- Cross-user access blocked (404 on ownership mismatch)
- 49 tests passed, 0 failures
- Security gap fix: 13 unprotected endpoints protected

## Phase 2 — User Authentication (2026-11-20)

- `auth.py` module (JWT, bcrypt, password reset, legacy account)
- 10 auth endpoints (register, login, refresh, me, logout, logout-all, forgot-password, reset-password, legacy-info, legacy-create)
- JWT access (15min) + refresh (7 days) tokens
- Werkzeug password hashing (pbkdf2:sha256)
- Password reset flow (single-use, expiring tokens)
- Legacy Account (admin-only, cannot login)
- `@require_auth` and `@require_admin` decorators
- 18 auth tests passed, 0 failures

## Phase 1 — Database Schema & Corrections (2026-11-20)

- `database.py` (SQLite schema, 11 tables, connection management)
- `models.py` (CRUD functions for all tables)
- WAL mode, busy_timeout, connection timeout
- Foreign keys with ON DELETE CASCADE ON UPDATE CASCADE
- Missing indexes (documents.status, documents.folder)
- reset_db() guard (confirm=True required)
- SQL injection protection (allowlist validation)
- UTC timestamps
- Email validation
- Admin helper functions (list_users, get_user_stats)
- 23 tests passed, 0 failures

## Phase 0 — Luxury UI Transformation (2026-11-20)

- Complete visual redesign across 8 pages
- Royal blue/navy/white color palette
- Glassmorphism with blur(25px)
- 3D layered shadows
- Mobile bottom navigation
- AI Study prominent on Dashboard
- "Lucky's 59" tiled watermark on all PDFs
- 7 bug fixes (dashboard plan, hamburger button, PDF studio layout, failed jobs, admin protection, AI extraction)

## Pre-Phase — Initial Development

- Flask backend with 20+ APIs
- AI text extraction (Gemini + OpenRouter)
- PDF generation (3 modes: Professional Text, Original Image, Smart Recreated)
- AI Study (16 tools)
- Document management (CRUD, search, filter, tag, favorite)
- Admin dashboard (stats, plan management, billing)
- Urdu/RTL support
- Diagram reconstruction pipeline
- Plans and billing (free/pro)
- Provider status monitoring
