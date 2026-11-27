# NotesAI — Premium Workspace

Transform handwritten notes into polished digital documents with AI-powered precision.

## Overview

NotesAI is a full-stack web application that converts handwritten notes (images) into professional PDF documents using AI-powered text extraction and document reconstruction. It includes an AI Study workspace with 16 study tools, a PDF Studio for document design, and a complete admin dashboard.

## Features

- **AI Text Extraction** — Upload handwritten note images, AI extracts and structures text
- **PDF Generation** — 3 modes: Professional Text, Original Image, Smart Recreated
- **AI Study Tools** — 16 tools: summarize, rewrite, translate, key points, headings, Q&A, MCQs, flashcards, quiz, exam topics, chapter summary, explain, revision sheet, and more
- **PDF Studio** — Luxury document design with templates, styles, margins, headers/footers, TOC, cover pages
- **Document Management** — Search, filter, tag, favorite, folder, category, trash/restore
- **Admin Dashboard** — Statistics, plan management, billing overview, activity log
- **PWA** — Installable Progressive Web App with offline support
- **Watermark** — "Lucky's 59" tiled diagonal watermark on all PDFs
- **Urdu/RTL Support** — Full right-to-left text support with Arabic shaping
- **Responsive Design** — Mobile, tablet, and desktop layouts

## Tech Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| Backend | Flask | 3.1.3 |
| PDF Engine | fpdf2 | 2.9.0 |
| Image Processing | Pillow | 13.0.0 |
| AI (Gemini) | google-genai | 1.55.0 |
| AI (OpenRouter) | requests | 2.34.2 |
| Arabic Shaping | arabic-reshaper, python-bidi | 3.1.0, 0.4.2 |
| Database | SQLite (Phase 1) | Built-in |
| Auth | JWT (manual HS256) + bcrypt (Werkzeug) | — |

## Quick Start

### Prerequisites
- Python 3.10+
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/notesai-github.git
cd notesai-github

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and add your API keys

# Run the server
python app.py
```

### Environment Variables

See `.env.example` for all configuration options. Required:
- `GEMINI_API_KEY` — Google Gemini API key (default provider)
- `AI_PROVIDER` — `gemini` or `openrouter`

Optional:
- `OPENROUTER_API_KEY` — OpenRouter API key
- `NOTESAI_ADMIN_TOKEN` — Legacy admin token (unused by browser; opt-in header fallback only)
- `NOTESAI_ALLOW_ADMIN_TOKEN_HEADER` — Set `1` only for temporary server-to-server migration
- `NOTESAI_ALLOW_LOCALHOST_ADMIN` — Set `1` only for local development; disabled by default
- `NOTESAI_ALLOW_LOCALHOST_USER` — Set `1` only for local development; allows anonymous loopback user APIs; disabled by default
- Guest mode is the default: pages are browsable, but data/action APIs return `401` until sign in. Leave both localhost bypass flags unset to test the walled garden.
- `NOTESAI_TRUST_PROXY_COUNT` — Number of trusted reverse proxies (enables ProxyFix)
- `NOTESAI_COOKIE_SECURE` — Set `1` to force Secure cookies when TLS terminates upstream
- `NOTESAI_CORS_ORIGINS` — Comma-separated extra allowed browser origins
- `NOTESAI_JWT_SECRET` — JWT signing secret (recommended for production)
- `NOTESAI_HOST` — Server host (default: 127.0.0.1)
- `NOTESAI_PORT` — Server port (default: 3000)

### Email validation and verification

Signups reject disposable/temporary email domains and, when `dnspython` is installed, check that the domain has an MX record. Set `NOTESAI_EMAIL_MX_CHECK=0` to skip DNS checks.

OTP verification activates automatically once SMTP is configured with `NOTESAI_SMTP_HOST` and `NOTESAI_SMTP_FROM`. Until then, registration keeps its existing auto-login behavior so deployments without SMTP are not locked out.

- `NOTESAI_SMTP_HOST` — SMTP server host
- `NOTESAI_SMTP_PORT` — SMTP port (default: `587`)
- `NOTESAI_SMTP_USER` / `NOTESAI_SMTP_PASSWORD` — SMTP credentials (optional for local relays)
- `NOTESAI_SMTP_FROM` — Sender address shown to users
- `NOTESAI_SMTP_STARTTLS` — `1` by default; set `0` for providers without STARTTLS
- `NOTESAI_SMTP_SSL` — Set `1` for implicit TLS (usually port `465`)
- `NOTESAI_SMTP_TIMEOUT` — SMTP timeout in seconds (default: `10`)

Endpoints: `POST /api/auth/verify-email` and `POST /api/auth/resend-verification`.

### Access

Open `http://127.0.0.1:3000` in your browser.

## Project Structure

```
notesai-github/
├── app.py              # Main Flask application (11,800+ lines)
├── auth.py             # User authentication (JWT, bcrypt, password reset)
├── database.py         # SQLite schema and connection management
├── models.py           # Data access functions (CRUD for all tables)
├── security.py         # Rate limiting, CORS, audit logging, file validation
├── user_isolation.py   # Multi-user data ownership and filtering
├── watermark_engine.py # Tiled PDF watermark ("Lucky's 59")
├── migrate_json_to_db.py  # JSON-to-SQLite migration script (dry-run)
├── notesai_schema.py   # Schema normalization and AI prompts
├── notesai_diagrams.py # Diagram rendering engine
├── notesai_trace.py    # Diagram tracing utilities
├── requirements.txt    # Python dependencies
├── .env.example        # Environment template
├── static/             # PWA assets (manifest, service worker, icons, offline page)
├── docs/               # Documentation
├── fonts/              # Custom fonts for PDF
└── backup/             # Timestamped backups
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [API Reference](docs/API.md)
- [Security](docs/SECURITY.md)
- [PWA Guide](docs/PWA.md)
- [Testing](docs/TESTING.md)
- [Deployment](docs/DEPLOYMENT.md)
- [Changelog](docs/CHANGELOG.md)

## License

Private project. All rights reserved.
