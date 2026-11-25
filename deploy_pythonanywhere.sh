#!/bin/bash
# NotesAI — PythonAnywhere Master Deployment Script
# Run this in PythonAnywhere Bash Console:
#   cd /home/hobaibafridi59/notesai-deploy && bash deploy_pythonanywhere.sh
#
# This script:
# 1. Activates the virtual environment
# 2. Installs dependencies
# 3. Verifies persistent storage paths
# 4. Checks environment variables (without printing values)
# 5. Tests Python imports and WSGI
# 6. Verifies existing user data
# 7. Reports readiness

set -e

PROJECT_DIR="/home/hobaibafridi59/notesai-deploy"
VENV_DIR="$PROJECT_DIR/venv"

echo "=== NotesAI PythonAnywhere Deployment ==="
echo ""

# 1. Verify and update project directory
echo "1. Verifying and updating project directory..."
if [ ! -d "$PROJECT_DIR" ]; then
    echo "   ERROR: Project directory not found: $PROJECT_DIR"
    echo "   Please clone the repository first:"
    echo "   git clone https://github.com/hobaibafridi59-prog/NotesAI-Luxury.git $PROJECT_DIR"
    exit 1
fi
cd "$PROJECT_DIR"

# Make sure this directory is a git checkout, then move it to latest main.
if [ ! -d .git ]; then
    git init -q
    echo "   Initialized git in existing project directory"
fi
if ! git remote get-url origin >/dev/null 2>&1; then
    git remote add origin https://github.com/hobaibafridi59-prog/NotesAI-Luxury.git
fi
echo "   Updating code from origin/main..."
git fetch origin
git reset --hard origin/main
echo "   HEAD: $(git log -1 --oneline)"
echo "   OK: $PROJECT_DIR"
echo ""

# 2. Verify Python version
echo "2. Python version..."
python3 --version
echo ""

# 3. Activate virtual environment
echo "3. Activating virtual environment..."
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
    echo "   Created venv"
fi
source "$VENV_DIR/bin/activate"
echo "   Python: $(which python)"
echo ""

# 4. Install dependencies
echo "4. Installing dependencies..."
pip install --upgrade pip -q 2>/dev/null
pip install -r requirements.txt -q
echo "   Installed:"
pip list 2>/dev/null | grep -iE "flask|fpdf|pillow|gunicorn" | sed 's/^/     /'
echo ""

# 5. Verify persistent storage paths
echo "5. Verifying persistent storage..."
for f in documents.json activity.json billing.json stats.json provider_status.json; do
    if [ -f "$f" ]; then
        echo "   OK: $f ($(wc -c < $f) bytes)"
    else
        echo "   WARN: $f not found (will be created on first use)"
    fi
done
[ -d "documents" ] && echo "   OK: documents/ ($(ls documents/ | wc -l) files)" || { echo "   WARN: documents/ not found"; mkdir -p documents; }
[ -d "fonts" ] && echo "   OK: fonts/ ($(ls fonts/ | wc -l) files)" || echo "   WARN: fonts/ not found"
[ -d "static" ] && echo "   OK: static/ exists" || echo "   WARN: static/ not found"
echo ""

# 6. Auto-generate secrets if missing
echo "6. Checking and generating secrets..."
python -c "
import os, secrets
env_path = '.env'
# Read existing .env
env = {}
if os.path.exists(env_path):
    with open(env_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                env[key.strip()] = value.strip()

# Auto-generate JWT secret if missing
if not env.get('NOTESAI_JWT_SECRET'):
    new_secret = secrets.token_hex(32)
    env['NOTESAI_JWT_SECRET'] = new_secret
    print('   Generated NOTESAI_JWT_SECRET (not displayed)')

# Auto-generate admin token if missing
if not env.get('NOTESAI_ADMIN_TOKEN'):
    new_token = secrets.token_hex(32)
    env['NOTESAI_ADMIN_TOKEN'] = new_token
    print('   Generated NOTESAI_ADMIN_TOKEN (not displayed)')

# Write back to .env
with open(env_path, 'w') as f:
    for key, value in env.items():
        f.write(f'{key}={value}\n')
    try:
        os.chmod(env_path, 0o600)
    except Exception:
        pass
print('   Secrets configured (values not displayed)')
" 2>&1 | sed 's/^/   /'

echo ""
echo "7. Checking environment variables..."
check_env() {
    val=$(python -c "import os; print(os.environ.get('$1', ''))" 2>/dev/null)
    if [ -z "$val" ] && [ -f .env ]; then
        val=$(grep -E "^$1=" .env | head -1 | cut -d= -f2-)
    fi
    if [ -z "$val" ]; then
        echo "   WARN: $1: NOT SET (dashboard or .env)"
    else
        echo "   OK: $1: SET (length: ${#val})"
    fi
}
check_env "AI_PROVIDER"
check_env "OPENROUTER_API_KEY"
check_env "GEMINI_API_KEY"
check_env "NOTESAI_ADMIN_TOKEN"
check_env "NOTESAI_JWT_SECRET"
check_env "NOTESAI_HOST"
check_env "NOTESAI_DEBUG"
echo ""

# 8. Verify .env file
echo "8. Checking .env file..."
if [ -f ".env" ]; then
    echo "   OK: .env exists"
    keys=$(grep -c '=' .env 2>/dev/null || echo 0)
    echo "   Keys defined: $keys"
else
    echo "   WARN: .env NOT FOUND"
    echo "   Create .env with: AI_PROVIDER, GEMINI_API_KEY, NOTESAI_ADMIN_TOKEN, NOTESAI_JWT_SECRET"
fi
echo ""

# 9. Test Python imports
echo "9. Testing Python imports..."
python -c "
import flask, fpdf, PIL, requests, json, os, sys
from auth import *
from database import *
from models import *
from security import *
from user_isolation import *
from watermark_engine import *
print('   OK: All modules import successfully')
" 2>&1 | sed 's/^/   /'
echo ""

# 10. Test WSGI import
echo "10. Testing WSGI import..."
python -c "
import sys, os
sys.path.insert(0, '$PROJECT_DIR')
os.chdir('$PROJECT_DIR')
from app import app as application
print('   OK: WSGI import successful')
print(f'   App name: {application.name}')
" 2>&1 | sed 's/^/   /'
echo ""

# 11. Test Flask startup
echo "11. Testing Flask startup..."
python -c "
import sys, os
sys.path.insert(0, '$PROJECT_DIR')
os.chdir('$PROJECT_DIR')
from app import app
client = app.test_client()
r = client.get('/health')
print(f'   Health check: {r.status_code} {r.data.decode()}')
r = client.get('/')
print(f'   Dashboard: {r.status_code} ({len(r.data)} bytes)')
" 2>&1 | sed 's/^/   /'
echo ""

# 12. Verify existing data
echo "12. Verifying existing data..."
python - <<'PYDATA' | sed 's/^/   /'
import json, os

def load(name, default):
    try:
        with open(name, encoding='utf-8') as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return default

docs = load('documents.json', [])
acts = load('activity.json', [])
stats = load('stats.json', {})
billing = load('billing.json', {'plan': 'free', 'status': 'free'})
pdf_count = len(os.listdir('documents')) if os.path.isdir('documents') else 0
print(f'   Documents: {len(docs) if isinstance(docs, list) else 0}')
print(f'   Activity: {len(acts) if isinstance(acts, list) else 0}')
print(f'   Stats: {stats}')
print(f'   Billing: plan={billing.get("plan", "free")}, status={billing.get("status", "free")}')
print(f'   PDF files: {pdf_count}')
PYDATA
echo ""

# 13. Final readiness
echo "=== DEPLOYMENT READY ==="
echo ""
echo "Next steps (on PythonAnywhere dashboard):"
echo "  1. Set environment variables in Web tab"
echo "  2. Update WSGI file with correct path"
echo "  3. Reload web app"
echo "  4. Test: https://hobaibafridi59.pythonanywhere.com/health"
echo ""
