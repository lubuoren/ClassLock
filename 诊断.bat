@echo off
chcp 65001 >nul
cd /d "%~dp0"
set LOG=%~dp0诊断结果.txt
echo 正在收集诊断信息，请稍候...
echo.
(
echo ===== 0. 当前目录与文件 =====
cd
if exist "ClassLock.exe" (dir "ClassLock.exe") else (echo !! 当前目录没有 ClassLock.exe  [这就是 cmd 中直接回到提示符的原因])
echo.
echo ===== 1. 文件"来自网络"标记 + 解除锁定 =====
powershell -NoProfile -ExecutionPolicy Bypass -Command "try{$s=Get-Item '.\ClassLock.exe' -Stream * -ErrorAction Stop | Select-Object Stream,Length | Format-Table -AutoSize | Out-String; Write-Output $s}catch{Write-Output 'no alternate stream'}; try{Unblock-File -Path '.\ClassLock.exe' -ErrorAction Stop; Write-Output 'Unblock-File: OK'}catch{Write-Output ('Unblock-File: ' + $_.Exception.Message)}"
echo.
echo ===== 2. ClassLock.exe --diag =====
ClassLock.exe --diag
echo 退出码: %ERRORLEVEL%
echo.
echo ===== 3. 启动痕迹（有 = 进程被启动了；没有 = 被系统/杀软拦在门外）=====
if exist "%TEMP%\classlock-start.log" (type "%TEMP%\classlock-start.log") else (echo 没有启动痕迹文件)
echo.
echo ===== 4. 现有配置 =====
if exist "classlock.cfg" (type "classlock.cfg") else (echo 还没有 classlock.cfg)
echo.
echo ===== 5. 文件哈希（对照: v1.2 应为 253952 字节左右）=====
certutil -hashfile "ClassLock.exe" SHA256 2^>nul
) > "%LOG%" 2>&1
type "%LOG%"
echo.
echo 以上内容已保存到: %LOG%
echo 把它整段复制发回来即可。
pause
