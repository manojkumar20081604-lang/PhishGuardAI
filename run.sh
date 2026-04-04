#!/bin/bash

echo "================================================"
echo " PHISHGUARD - AI Phishing Detection System"
echo " For College Science Expo 2024"
echo "================================================"
echo ""

echo "[1/3] Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python not found. Please install Python 3.8+"
    exit 1
fi
echo "[OK] Python found"
python3 --version

echo ""
echo "[2/3] Installing dependencies..."
pip3 install -r requirements.txt --quiet
if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to install dependencies"
    exit 1
fi
echo "[OK] Dependencies installed"

echo ""
echo "[3/3] Starting Flask server..."
echo ""
echo "IMPORTANT:"
echo "- The app will open at: http://localhost:5000"
echo "- Press Ctrl+C to stop the server"
echo ""
echo "[START] Starting server..."
echo ""

cd backend
python3 app.py
