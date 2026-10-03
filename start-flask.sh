#!/bin/bash
# Startup script for vulnerable Flask app

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$APP_DIR"

# Create virtual environment if it doesn't exist
if [ ! -d "$APP_DIR/venv" ]; then
    echo "Creating Python virtual environment..."
    /usr/bin/python3 -m venv venv
fi

# Install/update dependencies
echo "Installing dependencies..."
source venv/bin/activate
pip install -q --upgrade pip
pip install -q -r requirements.txt

# Run the Flask app
echo "Starting vulnerable Flask application on port 5000..."
exec python3 app.py
