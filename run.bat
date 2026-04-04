@echo off
title PhishGuard - AI Phishing Detection System
color 0A

echo.
echo  ================================================
echo   PHISHGUARD - AI Phishing Detection System
echo   For College Science Expo 2024
echo  ================================================
echo.

echo [1/3] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.8+
    echo Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)
echo [OK] Python found

echo.
echo [2/3] Installing dependencies...
pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo [ERROR] Failed to install dependencies
    pause
    exit /b 1
)
echo [OK] Dependencies installed

echo.
echo [3/3] Starting Flask server...
echo.
echo IMPORTANT: 
echo - The app will open at: http://localhost:5000
echo - Press Ctrl+C to stop the server
echo.
echo [START] Starting server...
echo.

cd /d "%~dp0backend"
python app.py

pause
