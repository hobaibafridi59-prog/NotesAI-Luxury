# NotesAI — Live Deploy Checkpoint (Google option removed)

## Current state

- Local `app.py` and `.env.example` are clean vs `a06c081`.
- Google social login UI, OAuth routes, helper modules, and env entries were fully removed locally.
- No new third-party package is required. `requirements.txt` is unchanged.
- `.env` secrets were never copied, committed, or printed.
- The live PythonAnywhere project is **not reachable from this Termux environment**. The steps below must be run in a PythonAnywhere Bash console by the account owner.

Known live facts before this update:

- Live project: `/home/hobaibafridi59/notesai-deploy`
- Live site: `https://hobaibafridi59.pythonanywhere.com`
- Live HEAD was `50bcbe2` (stale).
- Live untracked files `notesai.db` and `audit_log.json` must be preserved. Do **not** run `git clean -fd` and do **not** overwrite `notesai.db`.

---

## 1. Backup on PythonAnywhere

```bash
cd /home/hobaibafridi59/notesai-deploy
TS=$(date +%Y%m%d%H%M%S)
cp -p notesai.db "notesai.db.bak.$TS"
sha256sum .env > ".s1-env-hash-$TS.txt"
git status --porcelain=v1
git rev-parse HEAD
```

`.s1-env-hash-*.txt` contains only a hash. Never `cat` or copy `.env`.

---

## 2. Fetch and fast-forward

```bash
git fetch origin
git log --oneline --decorate -5
git merge --ff-only origin/main
git rev-parse HEAD
```

If the merge reports that untracked files would be overwritten, **stop**. Do not force with `git reset --hard` or `git clean -fd`.

---

## 3. Dependencies

```bash
source venv/bin/activate
python -m pip install -r requirements.txt
```

No Authlib / Flask-Dance install is needed. Google OAuth code was removed.

---

## 4. Reload web app

PythonAnywhere dashboard → **Web** → **Reload**.

Alternative from Bash console:

```bash
touch /var/www/hobaibafridi59_pythonanywhere_com_wsgi.py
```

---

## 5. Verification

```bash
curl -sS -o /dev/null -w '/health -> %{http_code}\n' \
  https://hobaibafridi59.pythonanywhere.com/health

curl -sS -o /dev/null -w '/login/google -> %{http_code}\n' \
  https://hobaibafridi59.pythonanywhere.com/login/google

curl -sS -o /dev/null -w '/api/auth/oauth/google/start -> %{http_code}\n' \
  https://hobaibafridi59.pythonanywhere.com/api/auth/oauth/google/start
```

Expected:

```text
/health -> 200
/login/google -> 404
/api/auth/oauth/google/start -> 404
```

Browser checks:

- Auth Modal shows only email/password Sign In and Sign Up.
- No “Continue with Google” button.
- No “OR” divider.
- No social setup pending/dummy text.
- Existing email/password login still works.
- Refresh on Auth Modal still works.
- Admin Panel at `/admin` still works with the signed HttpOnly admin session.
- `/api/admin/session` returns `200` with `{ "ok": true, "csrf": "...", "expires_in": 1800 }`.
- Normal users still get `403 ADMIN_REQUIRED` / `403 ADMIN_AUTH_REQUIRED` on admin APIs.
- Provider Save/Test still works from the Admin Panel with admin CSRF.

---

## 6. Rollback if something goes wrong

```bash
cd /home/hobaibafridi59/notesai-deploy
git reset --hard <OLD_HEAD_FROM_STEP_1>
cp "notesai.db.bak.$TS" notesai.db
touch /var/www/hobaibafridi59_pythonanywhere_com_wsgi.py
```

Do not delete or overwrite `audit_log.json`.

---

## 7. Separate pending item

Owner promotion (`python promote_owner.py`) is **not** part of this checkpoint. Do not run it unless explicitly approved again.
