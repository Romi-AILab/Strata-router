@echo off
rem Strata monorepo ROOT entry (v0.2.0): unified start from the project root --
rem delegates to monitor\launch.py go: starts router if needed, opens the live
rem panel IN THIS WINDOW, then drops to the ops menu. Closing this window does
rem NOT stop the router (detached child). monitor\!-start.bat stays equivalent.
rem Keep this file pure ASCII + CRLF: Chinese rem / LF-only breaks cmd parsing under cp950 (review R1-A/F4).
rem '>nul' below is the Windows bit bucket -- never '>dev/null' (bashism, R1-A).
chcp 65001 >nul
cd /d "%~dp0monitor"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 launch.py go
) else (
  python launch.py go
)
echo.
pause
