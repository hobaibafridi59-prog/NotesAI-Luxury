# NotesAI — Admin secret rotation and recovery

This document was prepared after the S1 static-token leak fix. It contains no secrets.

## 1. Current code state
- Static admin token is never rendered into HTML/JS or stored in browser storage.
- `X-Admin-Token` is disabled by default on the server.
- Anonymous loopback admin bypass is disabled by default.
- Admin access uses a short-lived HttpOnly/SameSite cookie plus CSRF token.
- Service Worker cache was bumped to `notesai-v2`; old `notesai-v1` HTML cache is deleted on activation.

## 2. Rotate on Render
1. Render Dashboard → service `notesai-premium` → Environment.
2. Generate a new value for `NOTESAI_ADMIN_TOKEN` (32+ bytes, e.g. `secrets.token_urlsafe(32)`).
3. If any JWT/session exposure is suspected, also rotate `NOTESAI_JWT_SECRET`.
   This signs out all users and invalidates admin cookies.
4. Save and redeploy/restart the service.

## 3. Rotate on PythonAnywhere
Run in the PythonAnywhere Bash console:

```bash
cd /home/hobaibafridi59/notesai-deploy/
PYEOF_MARKER=ROTATE
python - <<PYEOF
import secrets
from pathlib import Path
p = Path('.env')
lines = p.read_text().splitlines() if p.exists() else []
new_admin = secrets.token_urlsafe(32)
new_jwt = secrets.token_urlsafe(32)
for key, value in (('NOTESAI_ADMIN_TOKEN', new_admin), ('NOTESAI_JWT_SECRET', new_jwt)):
    prefix = key + '='
    found = False
    for i, line in enumerate(lines):
        if line.strip().startswith(prefix):
            lines[i] = prefix + value
            found = True
            break
    if not found:
        lines.append(prefix + value)
p.write_text('\n'.join(lines) + '\n')
p.chmod(0o600)
print('Rotated server secrets; values not displayed.')
PYEOF
touch /var/www/hobaibafridi59_pythonanywhere_com_wsgi.py
```

Skip the JWT rotation only if you are certain no user token leaked.

## 4. Verification after rotation
```bash
# old static token must fail
curl -s -o /dev/null -w '%{http_code}\n' https://hobaibafridi59.pythonanywhere.com/api/admin/overview \
  -H 'X-Admin-Token: OLD_VALUE'

# anonymous must fail
curl -s -o /dev/null -w '%{http_code}\n' https://hobaibafridi59.pythonanywhere.com/api/admin/overview

# browser: sign in as an admin, then confirm /api/admin/session returns 200
```

Expected: both curl calls return `403`.

## 5. Recovery
- If admin access is lost after rotation, sign in again with an admin account; the HttpOnly cookie is reissued.
- If no admin account exists, temporarily set `NOTESAI_ALLOW_LOCALHOST_ADMIN=1`, create one through `/api/auth/legacy-create` from the server itself, then unset the flag and restart.
- Rolling back to an old commit reintroduces the leak; rotate again after any rollback.
