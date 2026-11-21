# NotesAI — Production Environment Variables Checklist

## Required (MUST set before deployment)

| Variable | Description | How to Generate |
|----------|-------------|-----------------|
| `GEMINI_API_KEY` | Google Gemini API key | https://aistudio.google.com/apikey |
| `AI_PROVIDER` | Active AI provider | `gemini` or `openrouter` |
| `NOTESAI_ADMIN_TOKEN` | Admin access token | `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `NOTESAI_JWT_SECRET` | JWT signing secret | `python3 -c "import secrets; print(secrets.token_hex(32))"` |

## Optional (recommended for production)

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENROUTER_API_KEY` | OpenRouter API key | (empty) |
| `GEMINI_MODEL` | Gemini model override | `gemini-3.1-flash-lite` |
| `OPENROUTER_FREE_MODEL` | OpenRouter free model override | (auto-discover) |
| `NOTESAI_HOST` | Server host | `0.0.0.0` (production) |
| `NOTESAI_PORT` | Server port | Set by hosting provider |
| `NOTESAI_DEBUG` | Debug mode | `0` (production) |
| `NOTESAI_PREMIUM_OPEN` | Premium gate override | `0` |
| `USE_DATABASE` | Enable SQLite database | `0` (Phase 1) |
| `DATABASE_PATH` | SQLite database path | `notesai.db` (project root) |

## PythonAnywhere Setup

1. Go to PythonAnywhere dashboard → "Web" tab
2. Click "Add a new web app"
3. Choose "Manual configuration" → Python 3.13
4. Set source code directory: `/home/yourusername/notesai-github`
5. Set WSGI configuration file: `/var/www/yourusername_pythonanywhere_com_wsgi.py`
6. Copy contents of `pythonanywhere_wsgi.py` to the WSGI file
7. Update `PROJECT_HOME` path with your actual username
8. Set environment variables in the "Environment variables" section
9. Install dependencies: open Bash console → `pip install -r requirements.txt`
10. Reload web app

## Security Notes

- Never commit `.env` to git
- Set `.env` file permissions to 600: `chmod 600 .env`
- JWT secret must be at least 32 bytes (64 hex chars)
- Admin token must be at least 32 bytes (64 hex chars)
- Different secrets for dev/staging/production
