# NotesAI — Security Guide

## Authentication

### JWT Tokens
- **Access token:** 15-minute expiry, contains `user_id`, `email`, `role`
- **Refresh token:** 7-day expiry, stored in DB for revocation, rotated on refresh
- **Signing:** HS256 with `NOTESAI_JWT_SECRET` env var
- **Storage (client):** EncryptedSharedPreferences (Android), sessionStorage (web)

### Password Hashing
- Algorithm: Werkzeug `pbkdf2:sha256` (NIST-approved)
- Salt length: 16 bytes
- Minimum password: 8 chars, 1 uppercase, 1 lowercase, 1 digit

### Admin Access
- Method: `X-Admin-Token` header or `admin_token` form field
- Configured via: `NOTESAI_ADMIN_TOKEN` env var
- Localhost bypass: Active when admin token not configured (development only)
- Admin token comparison uses `hmac.compare_digest` (timing-safe)

## Rate Limiting

| Category | Limit | Window | Endpoints |
|----------|-------|--------|-----------|
| Auth login | 5 req | 15 min | `/api/auth/login` |
| Auth register | 3 req | 1 hour | `/api/auth/register` |
| Auth reset | 3 req | 1 hour | `/api/auth/forgot-password` |
| General API | 60 req | 1 min | `/api/stats`, `/api/documents`, `/api/plan`, etc. |
| File upload | 20 req | 1 min | `/extract-text`, `/api/diagrams/*` |
| PDF generation | 5 req | 1 min | `/generate-pdf` |
| AI generation | 10 req | 1 min | `/api/study/generate` |
| Admin | 30 req | 1 min | `/api/admin/*` |

Rate limited responses return HTTP 429 with `Retry-After` header.

## CORS Configuration

Allowed origins:
- `http://localhost:3000`
- `http://127.0.0.1:3000`
- `https://notesai.app`
- `https://www.notesai.app`

No wildcard origins. Preflight cache: 1 hour.

## HTTPS Enforcement

- HSTS header: `max-age=31536000; includeSubDomains` (production only)
- Security headers: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, `Referrer-Policy: strict-origin-when-cross-origin`
- Railway provides HTTPS at proxy level

## Audit Logging

- Location: `audit_log.json`
- Max entries: 1000 (oldest removed when exceeded)
- Secret redaction: Passwords, tokens, keys never logged
- Thread-safe: Lock-protected writes
- Events logged: login success/failure, registration, admin actions

## File Upload Security

- Max file size: 20MB
- Allowed extensions: jpg, jpeg, png, webp, bmp, pdf
- MIME type verification
- Image dimensions check (max 10000x10000)
- PDF header validation (`%PDF-` in first 1KB)
- Path traversal prevention (filename validated with regex)
- Corrupt file detection (PIL validation)

## Secret Management

- All secrets in `.env` file (never committed to git)
- `.env` permissions: `chmod 600`
- Required secrets: `GEMINI_API_KEY`, `OPENROUTER_API_KEY`, `NOTESAI_ADMIN_TOKEN`, `NOTESAI_JWT_SECRET`
- No secrets in code, logs, or error messages
- Environment-specific `.env` files (dev, staging, prod)

## Production Checklist

- [ ] Set `NOTESAI_JWT_SECRET` (generate: `python3 -c "import secrets; print(secrets.token_hex(32))"`)
- [ ] Set `NOTESAI_ADMIN_TOKEN` (generate: `python3 -c "import secrets; print(secrets.token_hex(32))"`)
- [ ] Set `NOTESAI_HOST=0.0.0.0`
- [ ] Set `NOTESAI_DEBUG=0`
- [ ] Update CORS origins with production domain
- [ ] Set `.env` permissions to 600
- [ ] Enable HTTPS (Railway provides automatically)
- [ ] Set up automated database backups
- [ ] Configure audit log retention
