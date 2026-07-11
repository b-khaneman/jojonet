@echo off
REM Upload JojoNet-Fixed to GitHub (run after: gh auth login)
set PATH=D:\tools\MinGit\cmd;D:\tools\gh\bin;%PATH%
cd /d "%~dp0"

echo === GitHub auth check ===
gh auth status || (
  echo.
  echo First login:
  echo   gh auth login -h github.com -p https -w
  echo Then run this script again.
  exit /b 1
)

for /f "delims=" %%u in ('gh api user -q .login') do set GHUSER=%%u
echo Logged in as: %GHUSER%

set REPO=jojonet-fixed
echo.
echo Creating/updating repo %GHUSER%/%REPO% ...
gh repo view %GHUSER%/%REPO% >nul 2>&1
if errorlevel 1 (
  gh repo create %REPO% --public --source=. --remote=origin --description "JojoNet Fixed v1.1.0 - hardened Iran/Foreign tunnel manager" --push
) else (
  git remote remove origin 2>nul
  git remote add origin https://github.com/%GHUSER%/%REPO%.git
  git push -u origin main
)

echo.
echo Also updating jojobang with fixed release? Skipping by default.
echo Done. Open: https://github.com/%GHUSER%/%REPO%
pause
