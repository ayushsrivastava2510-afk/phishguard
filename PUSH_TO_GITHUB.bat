@echo off
title PhishGuard - Push to GitHub
cd /d "%~dp0"
echo =======================================================
echo     PHISHGUARD SOC - PUSH CODE TO GITHUB
echo =======================================================
echo.
echo Remote URL: https://github.com/ayushsrivastava2510-afk/phishguard.git
echo Branch: main
echo.
echo Pushing commits to GitHub...
echo (If a browser window appears, click 'Sign in with your browser' to authorize)
echo.

"C:\Users\Ayush\AppData\Local\Programs\MinGit\cmd\git.exe" push -u origin main

if %ERRORLEVEL% equ 0 (
    echo.
    echo =======================================================
    echo [SUCCESS] Code pushed successfully to GitHub!
    echo View repository at: https://github.com/ayushsrivastava2510-afk/phishguard
    echo =======================================================
) else (
    echo.
    echo [NOTE] If you were prompted for credentials in the terminal:
    echo Username: ayushsrivastava2510-afk
    echo Password: use a GitHub Personal Access Token (PAT)
    echo (Generate token at: https://github.com/settings/tokens)
)

echo.
pause
