@echo off
rem Strata one-stop entry: starts router if needed, opens the live panel IN THIS WINDOW,
rem then drops to the ops menu. Closing this window does NOT stop the router (detached child).
rem Keep this file pure ASCII + CRLF: Chinese rem / LF-only breaks cmd parsing under cp950 (review R1-A/F4).
rem '>nul' below is the Windows bit bucket -- never '>dev/null' (bashism that ate this file once, R1-A).
chcp 65001 >nul
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 launch.py go
) else (
  python launch.py go
)
echo.
pause
