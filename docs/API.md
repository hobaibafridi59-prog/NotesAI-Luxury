# NotesAI — API Reference

## Base URL

```
http://127.0.0.1:3000  (development)
https://your-domain.com  (production)
```

## Authentication

### Register
```
POST /api/auth/register
Content-Type: application/json

{ "email": "user@example.com", "password": "SecurePass123", "name": "John Doe" }

Response: { "ok": true, "user": {...}, "access_token": "...", "refresh_token": "...", "expires_in": 900 }
```

### Login
```
POST /api/auth/login
Content-Type: application/json

{ "email": "user@example.com", "password": "SecurePass123" }

Response: { "ok": true, "user": {...}, "access_token": "...", "refresh_token": "...", "expires_in": 900 }
```

### Refresh Token
```
POST /api/auth/refresh
Content-Type: application/json

{ "refresh_token": "..." }

Response: { "ok": true, "access_token": "...", "refresh_token": "...", "expires_in": 900 }
```

### Get Current User
```
GET /api/auth/me
Authorization: Bearer <access_token>

Response: { "ok": true, "user": { "id", "email", "name", "role", "status", "created_at" } }
```

### Logout
```
POST /api/auth/logout
Content-Type: application/json

{ "refresh_token": "..." }

Response: { "ok": true, "message": "Logged out successfully." }
```

### Logout All Devices
```
POST /api/auth/logout-all
Authorization: Bearer <access_token>

Response: { "ok": true, "message": "Logged out from all devices." }
```

### Forgot Password
```
POST /api/auth/forgot-password
Content-Type: application/json

{ "email": "user@example.com" }

Response: { "ok": true, "message": "If an account with that email exists, a password reset link has been sent." }
```

### Reset Password
```
POST /api/auth/reset-password
Content-Type: application/json

{ "token": "...", "new_password": "NewPass456" }

Response: { "ok": true, "message": "Password reset successfully." }
```

## AI Study

### Generate Study Material
```
POST /api/study/generate
Content-Type: application/json

{
  "action": "summarize",
  "text": "Your notes here...",
  "document_id": "optional_doc_id",
  "language": "English",
  "count": 8,
  "prompt": "Optional focus",
  "save": true
}

Response: { "ok": true, "action": "summarize", "action_label": "Summarize", "result": "...", "provider": "gemini", "model": "...", "language": "English", "saved": {...} }
```

**Actions:** summarize, rewrite, translate, key_points, headings, organize, qa, mcq, short_questions, long_questions, flashcards, quiz, exam_topics, chapter_summary, explain, revision

### Study Sets
```
GET /api/study/sets          # List saved study sets
POST /api/study/sets         # Create study set
DELETE /api/study/sets/<id>  # Delete study set
```

## Documents

### List Documents
```
GET /api/documents?q=search&status=all&kind=all&folder=name&tag=tag&favorite=1&sort=created&order=desc&offset=0&limit=20&trash=0

Response: [{ id, name, type, kind, size, created, updated_at, status, provider, model, style, ... }]
Headers: X-Total-Count, X-Offset, X-Limit
```

### Get/Update/Delete Document
```
GET    /api/documents/<id>           # Get document metadata
PATCH  /api/documents/<id>           # Update (name, folder, category, tags, favorite)
DELETE /api/documents/<id>           # Soft delete (move to trash)
```

### Restore Document
```
POST /api/documents/<document_id>/restore
```

### Download Document
```
GET /api/documents/<document_id>/download
Response: PDF file (application/pdf)
```

### Regenerate Document
```
POST /api/documents/<document_id>/regenerate
```

### Orders (History)
```
GET /api/orders
Response: [{ id, name, type, size, created, status }]
```

## PDF Generation

### Generate PDF
```
POST /generate-pdf
Content-Type: multipart/form-data

Fields:
  mode: professional | image | smart
  style: professional | academic | minimal | modern
  fontSize: 9-14
  pageSize: A4 | Letter
  orientation: P | L
  margin: 8 | 12 | 16
  extractedText: (text content for professional mode)
  title, subtitle, headerText, footerText
  accentColor, diagramStyle
  showPageNumbers: 0 | 1
  coverPage: 0 | 1
  includeToc: 0 | 1
  folder, category, tags, favorite
  noteFiles: (file upload for image/smart modes)
  analysis: (JSON for smart mode)

Response: PDF file (application/pdf)
Headers: X-NotesAI-Status, X-NotesAI-Provider, X-NotesAI-Model
```

## Text Extraction

### Extract Text from Images
```
POST /extract-text
Content-Type: multipart/form-data

Fields:
  noteFiles: (image files)
  provider: gemini | openrouter (optional)

Response: { text, provider, model, status }
```

## Diagrams

### Preview Diagram
```
POST /api/diagrams/preview
Content-Type: application/json

{ "diagram": {...}, "style": "color" }

Response: { preview: "..." }
```

### Reconstruct Diagram
```
POST /api/diagrams/reconstruct
Content-Type: application/json

{ "diagram": {...}, "page_image": "..." }

Response: { diagram: {...}, warnings: [...] }
```

## Admin

### Admin Overview
```
GET /api/admin/overview
Headers: X-Admin-Token: <token> (or localhost)

Response: { stats, documents, activity, failed_jobs, provider, billing, study_sets, disk, health }
```

### Admin Billing
```
POST /api/admin/billing
Headers: X-Admin-Token: <token>

{ "plan": "pro", "status": "active", "renewal": "2026-12-31" }

Response: { ok: true, billing: {...} }
```

### Admin Backup
```
GET /api/admin/backup
Headers: X-Admin-Token: <token>

Response: ZIP file with workspace backup
```

## Provider Settings

### Provider Status
```
GET /api/provider-status
Response: { gemini: {...}, openrouter: {...}, active_provider: "gemini" }
```

### Test Provider
```
POST /api/provider/test
{ "provider": "gemini" }
Response: { status, message, model }
```

### Change Provider
```
POST /api/settings/provider
{ "provider": "openrouter" }
Response: { ok: true, provider: "openrouter" }
```

## Stats & Activity

### Get Stats
```
GET /api/stats
Response: { total_documents, in_progress, completed, failed }
```

### Reset Stats
```
POST /api/stats/reset
Response: { ok: true }
```

### Get Activity
```
GET /api/activity
Response: [{ action, detail, status, timestamp }]
```

### Clear Activity
```
POST /api/activity/clear
Response: { ok: true }
```

## Plan & Premium

### Get Plan
```
GET /api/plan
Response: { plan, label, status, renewal, limits, manual_billing, online_payment_configured }
```

### Premium Status
```
GET /api/premium/status
Response: { premium_feature, configured, authorized, free_mode }
```

## Error Responses

All errors follow this format:
```json
{
  "error": "Human-readable message",
  "code": "ERROR_CODE",
  "retryable": true/false
}
```

Common error codes:
- `AUTH_REQUIRED` — Authentication required
- `INVALID_TOKEN` — Token expired or invalid
- `RATE_LIMITED` — Too many requests
- `DOCUMENT_NOT_FOUND` — Document not found
- `PROVIDER_NOT_CONFIGURED` — AI provider not configured
- `PDF_GENERATION_FAILED` — PDF generation failed
- `INVALID_REQUEST` — Invalid request parameters

## Rate Limits

| Endpoint Category | Limit | Window |
|-------------------|-------|--------|
| Auth (login/register) | 5 req | 15 min |
| Auth (register) | 3 req | 1 hour |
| Auth (reset) | 3 req | 1 hour |
| General API | 60 req | 1 min |
| File upload | 20 req | 1 min |
| PDF generation | 5 req | 1 min |
| AI generation | 10 req | 1 min |
| Admin | 30 req | 1 min |

## CORS

Allowed origins:
- `http://localhost:3000`
- `http://127.0.0.1:3000`
- `https://notesai.app`
- `https://www.notesai.app`
