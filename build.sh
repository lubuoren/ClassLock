#!/usr/bin/env bash
# 交叉编译 ClassLock.exe（Linux -> Windows x64）
set -euo pipefail
cd "$(dirname "$0")"

CXX=${TARGET_CXX:-x86_64-w64-mingw32-g++}
FLAGS=(-std=c++17 -O2 -Wall -DUNICODE -D_UNICODE -mconsole
       -static -static-libgcc -static-libstdc++ -s
       -Wl,--no-insert-timestamp)
LIBS=(-lbcrypt -limm32 -lshell32 -luser32 -lgdi32 -ladvapi32)

"$CXX" "${FLAGS[@]}" src/classlock.cpp -o ClassLock.exe "${LIBS[@]}"
echo "built: $(pwd)/ClassLock.exe ($(stat -c %s ClassLock.exe) bytes)"
