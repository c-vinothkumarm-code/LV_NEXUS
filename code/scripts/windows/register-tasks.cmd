@echo off
rem Registers the API and the scheduler as Windows scheduled tasks that start when you sign in to Windows,
rem run hidden, and need no open terminal or browser. Run from a normal (non-admin) Command Prompt.
rem Remove later with:  schtasks /Delete /TN "CloudNexus API" /F   and   schtasks /Delete /TN "CloudNexus Scheduler" /F
setlocal
set "HERE=%~dp0"
schtasks /Create /F /TN "CloudNexus API" /SC ONLOGON /RL LIMITED /TR "cmd /c \"%HERE%run-api.cmd\""
schtasks /Create /F /TN "CloudNexus Scheduler" /SC ONLOGON /RL LIMITED /TR "cmd /c \"%HERE%run-scheduler.cmd\""
echo.
echo Start them now without signing out:
echo   schtasks /Run /TN "CloudNexus API"
echo   schtasks /Run /TN "CloudNexus Scheduler"
echo Check:  schtasks /Query /TN "CloudNexus API" /V /FO LIST
