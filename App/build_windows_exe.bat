@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (
  echo Python launcher "py" was not found. Install Python 3.11+ first.
  pause
  exit /b 1
)

echo ReconSpace Windows EXE builder
echo.
echo This is an explicit developer action. It creates a local .build-venv and dist/build artifacts.
echo It does NOT scan, clean, uninstall, or change Windows system settings.
echo.

if not exist ".build-venv\Scripts\python.exe" (
  echo [1/3] Creating isolated build environment...
  py -3 -m venv .build-venv
  if errorlevel 1 goto :failed
) else (
  echo [1/3] Reusing local .build-venv...
)

echo [2/3] Installing PyInstaller 6.x inside the isolated build environment...
".build-venv\Scripts\python.exe" -m pip install "pyinstaller>=6,<7"
if errorlevel 1 goto :failed

echo [3/3] Building one-file ReconSpace.exe...
".build-venv\Scripts\python.exe" -m PyInstaller --noconfirm --clean --onefile --name ReconSpace launcher.py
if errorlevel 1 goto :failed

echo.
echo Built: %CD%\dist\ReconSpace.exe
echo Build environment: %CD%\.build-venv
echo.
echo Run verify_reconspace.bat and follow WINDOWS_VALIDATION.md before relying on the EXE on a production machine.
exit /b 0

:failed
echo.
echo EXE build FAILED.
exit /b 1
