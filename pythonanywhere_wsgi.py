"""
PythonAnywhere WSGI Configuration File.

Copy this file to /var/www/hobaibafridi59_pythonanywhere_com_wsgi.py
on PythonAnywhere and update the paths.

DO NOT commit this file with real secrets.
"""
import sys
import os

# Project directory (update with your actual username)
PROJECT_HOME = '/home/hobaibafridi59/notesai-deploy'

if PROJECT_HOME not in sys.path:
    sys.path.insert(0, PROJECT_HOME)

# Environment variables (set these in PythonAnywhere dashboard instead)
# os.environ['NOTESAI_HOST'] = '0.0.0.0'
# os.environ['NOTESAI_DEBUG'] = '0'

# Load .env file from project directory
env_path = os.path.join(PROJECT_HOME, '.env')
if os.path.exists(env_path):
    with open(env_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                os.environ[key.strip()] = value.strip()

# Import Flask app
from app import app as application

# Ensure database and data files use project directory
os.chdir(PROJECT_HOME)
