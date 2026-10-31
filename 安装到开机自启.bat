@echo off
chcp 65001 >nul
pushd "%~dp0"
if not exist "ClassLock.exe" (echo [x] ClassLock.exe not found & pause & exit /b 1)
if not exist "classlock.cfg" (
  echo [x] No password set. Run set-password first.
  pause
  exit /b 1
)
ClassLock.exe --install
popd
