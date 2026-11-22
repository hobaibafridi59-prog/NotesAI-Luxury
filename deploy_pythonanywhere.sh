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

# 1. Verify project directory
echo "1. Verifying project directory..."
if [ ! -d "$PROJECT_DIR" ]; then
    echo "   ERROR: Project directory not found: $PROJECT_DIR"
    echo "   Please clone the repository first:"
    echo "   git clone https://github.com/hobaibafridi59-prog/NotesAI-Luxury.git $PROJECT_DIR"
    exit 1
fi
cd "$PROJECT_DIR"
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
pip install -r requirements.txt -q 2>/dev/null
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

# 6. Check environment variables (without printing values)
echo "6. Checking environment variables..."
check_env() {
    val=$(python -c "import os; print(os.environ.get('$1', ''))" 2>/dev/null)
    if [ -z "$val" ]; then
        echo "   WARN: $1: NOT SET"
    else
        echo "   OK: $1: SET (length: ${#val})"
    fi
}
check_env "GEMINI_API_KEY"
check_env "AI_PROVIDER"
check_env "NOTESAI_ADMIN_TOKEN"
check_env "NOTESAI_JWT_SECRET"
check_env "NOTESAI_HOST"
check_env "NOTESAI_DEBUG"
echo ""

# 7. Verify .env file
echo "7. Checking .env file..."
if [ -f ".env" ]; then
    echo "   OK: .env exists"
    keys=$(grep -c '=' .env 2>/dev/null || echo 0)
    echo "   Keys defined: $keys"
else
    echo "   WARN: .env NOT FOUND"
    echo "   Create .env with: AI_PROVIDER, GEMINI_API_KEY, NOTESAI_ADMIN_TOKEN, NOTESAI_JWT_SECRET"
fi
echo ""

# 8. Test Python imports
echo "8. Testing Python imports..."
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

# 9. Test WSGI import
echo "9. Testing WSGI import..."
python -c "
import sys, os
sys.path.insert(0, '$PROJECT_DIR')
os.chdir('$PROJECT_DIR')
from app import app as application
print('   OK: WSGI import successful')
print(f'   App name: {application.name}')
" 2>&1 | sed 's/^/   /'
echo ""

# 10. Test Flask startup
echo "10. Testing Flask startup..."
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

# 11. Verify existing data
echo "11. Verifying existing data..."
python -c "
import json, os
docs = json.load(open('documents.json'))
acts = json.load(open('activity.json'))
stats = json.load(open('stats.json'))
billing = json.load(open('billing.json'))
print(f'   Documents: {len(docs)}')
print(f'   Activity: {len(acts)}')
print(f'   Stats: {stats}')
print(f'   Billing: plan={billing[\"plan\"]}, status={billing[\"status\"]}')
print(f'   PDF files: {len(os.listdir(\"documents\"))}')
" 2>&1 | sed 's/^/   /'
echo ""

# 12. Final readiness
echo "=== DEPLOYMENT READY ==="
echo ""
echo "Next steps (on PythonAnywhere dashboard):"
echo "  1. Set environment variables in Web tab"
echo "  2. Update WSGI file with correct path"
echo "  3. Reload web app"
echo "  4. Test: https://hobaibafridi59.pythonanywhere.com/health"
echo ""
