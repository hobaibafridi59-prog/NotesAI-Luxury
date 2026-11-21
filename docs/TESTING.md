# NotesAI — Testing Guide

## Test Commands

### Syntax Check
```bash
python3 -m py_compile app.py auth.py database.py models.py security.py user_isolation.py watermark_engine.py migrate_json_to_db.py
```

### Route Verification
```python
from app import app
client = app.test_client()
for route in ['/', '/study', '/my-notes', '/new-order', '/settings', '/admin', '/health']:
    r = client.get(route)
    print(f'{route}: {r.status_code}')
```

### PDF Generation Test
```python
from app import app
client = app.test_client()

# Professional mode
r = client.post('/generate-pdf', data={
    'mode': 'professional', 'style': 'professional', 'fontSize': '11',
    'pageSize': 'A4', 'orientation': 'P', 'margin': '12',
    'extractedText': 'Test document.',
}, content_type='multipart/form-data')
print(f'Professional: {r.status_code}')

# Smart mode
r = client.post('/generate-pdf', data={
    'mode': 'smart', 'style': 'professional', 'fontSize': '11',
    'pageSize': 'A4', 'orientation': 'P', 'margin': '12',
    'analysis': '{"title":"Test","pages":[{"blocks":[{"type":"paragraph","text":"Test"}]}]}',
}, content_type='multipart/form-data')
print(f'Smart: {r.status_code}')

# Image mode
from werkzeug.datastructures import FileStorage
import io
fs = FileStorage(stream=io.BytesIO(open('test.png','rb').read()), filename='test.png', content_type='image/png')
r = client.post('/generate-pdf', data={
    'mode': 'image', 'style': 'professional', 'fontSize': '11',
    'pageSize': 'A4', 'orientation': 'P', 'margin': '12',
    'noteFiles': fs,
}, content_type='multipart/form-data')
print(f'Image: {r.status_code}')
```

### Auth Test
```python
from app import app
client = app.test_client()

# Register
r = client.post('/api/auth/register', json={'email': 'test@test.com', 'password': 'TestPass123', 'name': 'Test'})
print(f'Register: {r.status_code}')

# Login
r = client.post('/api/auth/login', json={'email': 'test@test.com', 'password': 'TestPass123'})
print(f'Login: {r.status_code}')
token = r.get_json()['access_token']

# Get user
r = client.get('/api/auth/me', headers={'Authorization': f'Bearer {token}'})
print(f'Get Me: {r.status_code}')

# Invalid token
r = client.get('/api/auth/me', headers={'Authorization': 'Bearer invalid'})
print(f'Invalid token: {r.status_code} (expected 401)')
```

### Database Test (Temporary DB Only)
```bash
# Run comprehensive tests
python3 -c "
import os
os.environ['DATABASE_PATH'] = '/tmp/test_notesai.db'
import database, models
db = database.init_db()
# ... run tests ...
os.remove('/tmp/test_notesai.db')
"
```

### Migration Dry-Run
```bash
python migrate_json_to_db.py --dry-run
python migrate_json_to_db.py --verify
```

### PWA Verification
```bash
# Check manifest
curl http://127.0.0.1:3000/manifest.json | python3 -m json.tool

# Check service worker
curl -I http://127.0.0.1:3000/sw.js

# Check offline page
curl http://127.0.0.1:3000/offline | head -5
```

## Test Results Summary

### Phase 1 (Database Schema)
- 13 tests: 13 passed, 0 failed
- Schema creation, CRUD, foreign keys, cascade delete, rollback

### Phase 2 (Authentication)
- 18 tests: 18 passed, 0 failed
- Register, login, token refresh, logout, password reset, legacy account, SQL injection

### Phase 3 (Multi-User Isolation)
- 49 tests: 49 passed, 0 failed
- Route verification, PDF generation, API verification, auth endpoints, security

### Phase 4 (Security Hardening)
- 43 tests: 43 passed, 0 failed
- Rate limiting, security headers, input validation, audit logging

### Phase 5 (PWA)
- 27 tests: 27 passed, 0 failed
- PWA routes, manifest, service worker, offline page, icons

### Phase 6 (Comprehensive)
- Backend: 7 routes (200 OK), 3 PDF modes (200 OK), 2 APIs (200 OK)
- Security: 3 headers verified, invalid JWT → 401
- Data integrity: 74 documents, 121 activity entries, billing pro/active
- py_compile: 8 files OK

### Total Tests Across All Phases
- **Phase 1:** 13 tests
- **Phase 2:** 18 tests
- **Phase 3:** 49 tests
- **Phase 4:** 43 tests
- **Phase 5:** 27 tests
- **Phase 6:** 20+ tests
- **Grand Total:** 170+ tests, 0 failures

### Known Issues
1. Activity count: 121 (expected 122) — 1 entry lost during test cleanup
2. Dark theme not implemented (only light theme)
3. No real Android device testing (no ADB, no emulator)
4. JWT secret not set in .env (tokens invalidated on restart)
5. No payment gateway configured
