@echo off
setlocal
cd /d "%~dp0"
echo Starting ReconSpace 1.0.0...
where py >nul 2>nul
if not errorlevel 1 (
  py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>nul
  if not errorlevel 1 (
    py -3 -m reconspace serve %*
    exit /b %errorlevel%
  )
)
where python >nul 2>nul
if not errorlevel 1 (
  python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>nul
  if not errorlevel 1 (
    python -m reconspace serve %*
    exit /b %errorlevel%
  )
)
echo Python 3.11 or newer was not found.
echo Install Python 3.11+ or build/use ReconSpace.exe, then try again.
pause
exit /b 1
