@echo off
chcp 65001 >nul
pushd "%~dp0"
ClassLock.exe --selftest
echo.
echo exit code: %ERRORLEVEL%
pause
popd
