@echo off
rem LatentView CloudNexus - runs every job on its schedule (Asia/Kolkata). Restarts itself if it ever stops.
setlocal
set "ROOT=%~dp0..\.."
cd /d "%ROOT%\backend"
if not exist "%ROOT%\logs" mkdir "%ROOT%\logs"
:loop
echo %date% %time% starting scheduler >> "%ROOT%\logs\scheduler.log"
".venv\Scripts\python.exe" -m app.workers.local_scheduler >> "%ROOT%\logs\scheduler.log" 2>&1
echo %date% %time% scheduler stopped with code %errorlevel%; restarting in 15 seconds >> "%ROOT%\logs\scheduler.log"
timeout /t 15 /nobreak > nul
goto loop
