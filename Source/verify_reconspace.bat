@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (
  echo Python launcher "py" was not found. Install Python 3.11+ to run source verification.
  pause
  exit /b 1
)

echo [1/4] Compiling Python sources...
py -3 -m compileall -q reconspace tests
if errorlevel 1 goto :failed

echo [2/4] Running safety and correctness tests...
py -3 -m unittest discover -s tests -v
if errorlevel 1 goto :failed

echo [3/4] Validating the built-in metadata-only rule pack...
py -3 -m reconspace validate-rules --builtin >nul
if errorlevel 1 goto :failed

echo [4/4] Running read-only readiness diagnostic...
py -3 -m reconspace doctor --root %SystemDrive%\ --pretty
if errorlevel 1 goto :failed

echo.
echo ReconSpace verification passed.
pause
exit /b 0

:failed
echo.
echo ReconSpace verification FAILED.
pause
exit /b 1
