@echo off
rem Quick health view: tasks, port, API health, last log lines.
schtasks /Query /TN "CloudNexus API" /FO LIST | findstr /i "Status Last"
schtasks /Query /TN "CloudNexus Scheduler" /FO LIST | findstr /i "Status Last"
netstat -ano | findstr ":8000" | findstr LISTENING
curl.exe -s http://127.0.0.1:8000/health/ready
echo.
powershell -NoProfile -Command "Get-Content '%~dp0..\..\logs\scheduler.log' -Tail 8"
