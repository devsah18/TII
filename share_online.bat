@echo off
title TRACE - Launch Online
echo ===================================================
echo   Starting TRACE Full-Stack Application + Ngrok
echo ===================================================

echo [1/3] Starting Backend (FastAPI on http://127.0.0.1:8000)...
start "TRACE - Backend (Port 8000)" cmd /k "cd /d %~dp0backend && call .venv\Scripts\activate.bat && python -m uvicorn app.main:app --reload --port 8000"

timeout /t 3 /nobreak > nul

echo [2/3] Starting Frontend (Vite on http://localhost:5173)...
start "TRACE - Frontend (Port 5173)" cmd /k "cd /d %~dp0frontend && npm run dev"

timeout /t 3 /nobreak > nul

echo [3/3] Starting Public Tunnel (ngrok on Port 5173)...
start "TRACE - Ngrok Tunnel" cmd /k "ngrok http 5173 --url=immobile-kindle-hydrant.ngrok-free.dev"

echo.
echo ===================================================
echo   All services launched in separate windows!
echo.
echo   Share this link with your friend:
echo   https://immobile-kindle-hydrant.ngrok-free.dev
echo ===================================================
pause
