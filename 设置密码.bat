@echo off
chcp 65001 >nul
pushd "%~dp0"
ClassLock.exe --set-password
popd
