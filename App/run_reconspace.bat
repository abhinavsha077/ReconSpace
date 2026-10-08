@echo off
setlocal
cd /d "%~dp0"
echo Starting ReconSpace 1.3.0...
where py >nul 2>nul
if errorlevel 1 goto python_fallback
py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>nul
if errorlevel 1 goto python_fallback
py -3 -m reconspace serve %*
exit /b %errorlevel%
:python_fallback
where python >nul 2>nul
if errorlevel 1 goto missing_python
python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>nul
if errorlevel 1 goto missing_python
python -m reconspace serve %*
exit /b %errorlevel%
:missing_python
echo Python 3.11 or newer was not found.
echo Install Python 3.11+ or build/use ReconSpace.exe, then try again.
pause
exit /b 1
