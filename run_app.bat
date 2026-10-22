@echo off
rem ThreatVision Pro - one-click launcher (Windows)
rem Opens the dashboard in its own app window (Edge or Chrome), like a desktop program.
cd /d "%~dp0"

rem pick "python" or the "py" launcher, whichever exists
where python >nul 2>nul
if %errorlevel%==0 (set PY=python) else (set PY=py)

rem skip Streamlit's first-run email question (it can look like the app is stuck)
if not exist "%USERPROFILE%\.streamlit\credentials.toml" (
    mkdir "%USERPROFILE%\.streamlit" 2>nul
    (echo [general]& echo email = "") > "%USERPROFILE%\.streamlit\credentials.toml"
)

echo Checking packages...
%PY% -m pip install -q -r requirements.txt

echo Starting ThreatVision Pro...
%PY% threat_analyzer.py
pause
