@echo off
setlocal
call "%~dp0App\run_reconspace.bat" %*
exit /b %errorlevel%
