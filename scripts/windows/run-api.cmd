@echo off
rem LatentView CloudNexus - API and dashboard on http://localhost:8000 (no terminal or npm needed).
rem Build the dashboard once first:  cd frontend  &&  npm run build
setlocal
set "ROOT=%~dp0..\.."
set "FRONTEND_DIST=%ROOT%\frontend\dist"
cd /d "%ROOT%\backend"
if not exist "%ROOT%\logs" mkdir "%ROOT%\logs"
:loop
echo %date% %time% starting API >> "%ROOT%\logs\api.log"
".venv\Scripts\python.exe" -m uvicorn app.main:app --host 127.0.0.1 --port 8000 >> "%ROOT%\logs\api.log" 2>&1
echo %date% %time% API stopped with code %errorlevel%; restarting in 15 seconds >> "%ROOT%\logs\api.log"
timeout /t 15 /nobreak > nul
goto loop
