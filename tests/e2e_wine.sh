#!/usr/bin/env bash
# Linux + wine + Xvfb 端到端验证：设密码 -> 锁定 -> 错误密码不通过 -> 正确密码解锁
# 注意：GUI 子系统 PE 必须有 DISPLAY 才能启动，所以 Xvfb 最先起。
set -u
export WINEPREFIX=${WINEPREFIX:-$HOME/.cache/cl-wine}
export WINEDEBUG=-all
export WINEDLLOVERRIDES="mscoree,mshtml="
DIR=/tmp/classlock-test
PASS='Class2026!'
DISP=:77
cd "$DIR" || exit 1

say() { echo "[$(date +%H:%M:%S)] $*"; }
alive() { pgrep -u "$(id -u)" -x ClassLock.exe >/dev/null && echo 1 || echo 0; }
cleanup() {
  wineserver -k 2>/dev/null
  [ -n "${XPID:-}" ] && kill "$XPID" 2>/dev/null
  sleep 1
}
trap cleanup EXIT

say "0) 准备显示环境"
pkill -f "Xvfb $DISP" 2>/dev/null
wineserver -k 2>/dev/null
sleep 1
Xvfb $DISP -screen 0 1920x1080x24 >/dev/null 2>&1 &
XPID=$!
sleep 2
export DISPLAY=$DISP
say "   DISPLAY=$DISPLAY xvfb pid=$XPID"
rm -f classlock.cfg classlock.log
find "$WINEPREFIX/drive_c/users" -name classlock.cfg -delete 2>/dev/null

say "1) 非交互设密码 (--set-password --passfile)"
printf '%s\r\n' "$PASS" > "$WINEPREFIX/drive_c/cl-pw.txt"
wine ClassLock.exe --set-password --passfile 'C:\cl-pw.txt'
say "   exit=$?"
rm -f "$WINEPREFIX/drive_c/cl-pw.txt"

say "2) 配置文件"
if [ -f classlock.cfg ]; then
  cat classlock.cfg
  if grep -q 'Class2026' classlock.cfg; then say "   !! 明文泄漏"; else say "   OK: 无明文密码"; fi
else
  say "   !! classlock.cfg 不存在；诊断日志："
  cat classlock.log 2>/dev/null
fi

say "3) 启动锁屏"
wine ClassLock.exe --lock &
sleep 8
say "   锁定进程存活: $(alive)  (期望 1)"
command -v ffmpeg >/dev/null && ffmpeg -loglevel error -y -f x11grab -video_size 1920x1080 \
  -i $DISP -frames:v 1 "$DIR/lock.png" && say "   截图 lock.png"

WID=$(xdotool search --class ClassLock 2>/dev/null | head -1)
say "   窗口 id: ${WID:-none}"
[ -n "${WID:-}" ] && xdotool windowfocus "$WID" 2>/dev/null

say "4) 错误密码 + Enter（应保持锁定）"
xdotool type --delay 100 'totally-wrong'
xdotool key Return
sleep 4
say "   仍锁定: $(alive)  (期望 1)"
command -v ffmpeg >/dev/null && ffmpeg -loglevel error -y -f x11grab -video_size 1920x1080 \
  -i $DISP -frames:v 1 "$DIR/lock-wrong.png" 2>/dev/null

say "5) 正确密码 + Enter（应解锁退出）"
for i in $(seq 1 14); do xdotool key BackSpace; done
xdotool type --delay 100 "$PASS"
xdotool key Return
sleep 5
say "   解锁后进程存活: $(alive)  (期望 0)"

say "6) 结论"
if [ "$(alive)" = "0" ]; then echo "RESULT: UNLOCK OK"; else echo "RESULT: STILL LOCKED (FAIL)"; fi
