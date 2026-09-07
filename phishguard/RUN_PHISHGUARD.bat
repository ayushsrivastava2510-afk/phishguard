@echo off
title PhishGuard Cyber SOC & Extension Bridge
echo ========================================================
echo   Starting PhishGuard Cyber Forensics Platform...
echo ========================================================
echo.
cd /d "%~dp0"

echo [1/2] Launching Chrome Extension SOC Bridge (Port 8765)...
if exist "..\venv\Scripts\python.exe" (
    start "PhishGuard Extension Bridge (Port 8765)" /min "..\venv\Scripts\python.exe" bridge_server.py
) else if exist "venv\Scripts\python.exe" (
    start "PhishGuard Extension Bridge (Port 8765)" /min "venv\Scripts\python.exe" bridge_server.py
) else (
    start "PhishGuard Extension Bridge (Port 8765)" /min python bridge_server.py
)

echo [2/2] Launching Streamlit SOC Dashboard (Port 8501)...
if exist "..\venv\Scripts\python.exe" (
    echo [INFO] Found Virtual Environment! Launching Streamlit Dashboard...
    ..\venv\Scripts\python.exe -m streamlit run app.py
) else if exist "venv\Scripts\python.exe" (
    echo [INFO] Found Local Virtual Environment! Launching Streamlit Dashboard...
    venv\Scripts\python.exe -m streamlit run app.py
) else (
    echo [INFO] Launching with system python...
    streamlit run app.py
)
pause
