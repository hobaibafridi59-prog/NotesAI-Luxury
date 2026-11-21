# NotesAI — Deployment Guide (Future)

> **This is a planning document. No deployment has been performed.**

## Prerequisites

- Python 3.10+
- pip
- A server with HTTPS support (Railway, Render, VPS, etc.)

## Environment Setup

1. Copy `.env.example` to `.env`
2. Fill in all required values:
   - `GEMINI_API_KEY` — Google Gemini API key
   - `OPENROUTER_API_KEY` — OpenRouter API key (optional)
   - `AI_PROVIDER` — `gemini` or `openrouter`
   - `NOTESAI_ADMIN_TOKEN` — Generate: `python3 -c "import secrets; print(secrets.token_hex(32))"`
   - `NOTESAI_JWT_SECRET` — Generate: `python3 -c "import secrets; print(secrets.token_hex(32))"`
   - `NOTESAI_HOST` — `0.0.0.0` for production
   - `NOTESAI_PORT` — Set by hosting provider
   - `NOTESAI_DEBUG` — `0` for production

3. Set file permissions:
```bash
chmod 600 .env
```

## Deployment Steps (Railway)

1. Create a Railway account at https://railway.app
2. Create a new project → "Deploy from GitHub repo"
3. Connect your GitHub repository
4. Set environment variables in Railway dashboard
5. Railway will auto-detect Python and install dependencies
6. Set start command: `python app.py`
7. Railway provides HTTPS automatically

## Deployment Steps (VPS/Docker)

### Dockerfile (optional)
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 3000
CMD ["python", "app.py"]
```

### Manual VPS Setup
```bash
# Install Python
sudo apt update && sudo apt install python3 python3-pip

# Clone repo
git clone https://github.com/your-username/notesai-github.git
cd notesai-github

# Install dependencies
pip3 install -r requirements.txt

# Configure .env
cp .env.example .env
# Edit .env with production values

# Run with gunicorn (production WSGI server)
pip3 install gunicorn
gunicorn -w 4 -b 0.0.0.0:3000 app:app
```

## Post-Deployment Checklist

- [ ] Verify `/health` returns `{"status": "ok"}`
- [ ] Verify PWA manifest loads (`/manifest.json`)
- [ ] Verify service worker registers (`/sw.js`)
- [ ] Test login/register flow
- [ ] Test PDF generation (all 3 modes)
- [ ] Test AI Study tools
- [ ] Verify HTTPS is working
- [ ] Verify security headers present
- [ ] Test rate limiting
- [ ] Verify audit log is being written
- [ ] Set up automated backups for `notesai.db` and JSON files
- [ ] Configure monitoring (uptime, errors)

## Backup Strategy

```bash
# Daily backup script (cron)
0 2 * * * cd /path/to/notesai-github && cp notesai.db backups/notesai-$(date +\%Y\%m\%d).db && cp documents.json backups/documents-$(date +\%Y\%m\%d).json
```

## Rollback Procedure

1. Stop the server
2. Restore from backup: `cp backups/notesai-<date>.db notesai.db`
3. Restore JSON files from backup
4. Restart the server
5. Verify `/health` returns OK
