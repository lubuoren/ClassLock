# AGENTS.md — ClassLock 工程约定

Windows 10/11 x64 锁屏工具。单文件 C++ 源码，在 Linux 上交叉编译成 PE64。以下命令都在仓库根目录执行。

## 构建

```bash
sudo apt-get install -y --no-install-recommends g++-mingw-w64-x86-64   # 一次性
./build.sh
```

- 工具链 `x86_64-w64-mingw32-g++`，参数 `-std=c++17 -O2 -mconsole -static -static-libgcc -static-libstdc++ -s -Wl,--no-insert-timestamp`，链接 `bcrypt imm32 shell32 user32 gdi32 advapi32`。
- `-mconsole` 不能改回 `-mwindows`：GUI 子系统下 cmd 不会等待子进程，用户一敲回车就回到 `C:\>`，看起来像"进程被杀"。双击锁屏时的黑窗由 `RunLock()` 开头的 `FreeConsole()` 消掉。
- `-Wl,--no-insert-timestamp` 是可复现构建的支点：同一份源码编译两次得到逐字节相同的 exe。已验证 SHA-256 = `eb0aa41b700f4d8625efd0930c7cbb538c75af443b71266f52cebe093e9bc8bc`（254976 字节，`ClassLock.exe` 与 `ClassLock-v1.2-CUI.exe` 相同）。改了编译参数或源码，这个值必然变——发布前重新核对。

## 测试

- 自检：`wine ClassLock.exe --selftest`。Linux 上无法直接执行 PE，必须走 wine（本容器默认未安装，用时 `sudo apt-get install -y --no-install-recommends wine64`）。
  共 8 项：base64 往返(32B)、PBKDF2 RFC 向量 iter=1、iter=2、真实 `kIterations` 耗时、cfg 写读字节一致、盐复解析、密码复算一致、错误密码必拒。结果同时写 `%LOCALAPPDATA%\ClassLock\selftest.log`。
- 端到端：`tests/e2e_wine.sh`（wine + Xvfb `:77` 1920×1080，xdotool 打字、ffmpeg 抓图）。前置条件是脚本里的 `DIR=/tmp/classlock-test` 存在且 exe 已放进去：
  ```bash
  mkdir -p /tmp/classlock-test && cp ClassLock.exe /tmp/classlock-test/
  tests/e2e_wine.sh
  ```
  流程：`--set-password --passfile` → 查 cfg 无明文 → `--lock` 起锁屏 → 进程存活 → 错密码后仍锁定 → 正确密码 + Enter 后退出 → 末行 `RESULT: UNLOCK OK`。
- 截图在 `tests/shots/`。wine 缺中文字体，图里汉字是方框，属正常；中文渲染只能在 Windows 上确认。
- 2026-10-22 的完整实测记录（含控制台等待行为、热键通道）见 `README.md` 第六之二节。真机上尚未验证的部分：`Ctrl+Alt+Del` → 任务管理器路径、真实多显示器焦点抢占、组策略/极域环境。

## 源码地图

`src/classlock.cpp`，1255 行，单文件，除 Win32/BCrypt 外无依赖。按文件内注释分区：

编码与加密（`B64Enc`/`B64Dec`/`DeriveKey`/`ConstantTimeEq`/`RandomBytes`）→ 配置（`LoadConfig`/`BuildCfgText`/`FindCfgPath`）→ 控制台辅助（`EnsureConsole`/`ReadLineMasked`）→ 锁屏绘制（`PaintLock`，纯 GDI，不依赖 msimg32）→ 输入钩子（`KbProc`/`MsProc`/`ClipPointer`/`RegrabForeground`）→ 窗口过程（`WndProc`）→ `RunLock` → 子命令（`CmdSetPassword`/`CmdInstall`/`CmdUninstall`/`CmdDiag`/`RunSelfTest`）→ `TraceStart` → `main`。

## 不变量（改动前先确认这些不被破坏）

- 密码存储：PBKDF2-HMAC-SHA256，`kIterations=200000`、盐 16 字节随机、派生值 32 字节，Base64 写入 `classlock.cfg`。密码只存在于栈上的局部变量，校验后 `SecureZeroMemory`；不进 argv、不进注册表、不进日志。
- 配置查找顺序：exe 同目录 `classlock.cfg` → `%LOCALAPPDATA%\ClassLock\classlock.cfg`（`FindCfgPath`）。可解析门槛 `salt>=8B && hash>=16B && iter>=1000`。
- 无密码时拒绝锁定（`RunLock` 返回 2）。这是防自锁的刻意设计，不要改成"允许锁定"。
- 低层钩子必须装在消息循环所在线程（`RunLock` 里装完即跑 `GetMessageW`）。`WH_KEYBOARD_LL`/`WH_MOUSE_LL` 返回 1 吞消息；修饰键与 `Ctrl+Alt+Shift+Q` 必须放行，否则 `RegisterHotKey` 收不到完整序列。热键注册失败不算致命——密码通道仍在。
- 逃生通道不可移除：`WM_QUERYENDSESSION` 恒返回 TRUE（允许关机/重启）、不拦 `Ctrl+Alt+Del`（SAS 由 winlogon 在独立桌面处理）、`--uninstall` 能全撤。
- 单实例：`Local\ClassLockSingleton` 互斥体，已存在则静默退出 0。
- 窗口：`WS_POPUP | WS_EX_TOPMOST | WS_EX_TOOLWINDOW`，按 `SM_*VIRTUALSCREEN` 覆盖整个虚拟桌面；200 ms 定时器抢前台（`AttachThreadInput` + `SetForegroundWindow`）并 `ClipCursor` 把指针夹在屏幕中心 1×1；`ImmAssociateContext(hwnd, NULL)` 关掉 IME 候选窗。
- 退出码：0 正常、2 未设密码、3 `RegisterClassExW` 失败、4 建窗失败、5 钩子安装失败、11 `--passfile` 读失败。
- 输入限制：锁屏界面只接受 ASCII 可见字符（`32 <= ch < 127`）、长度上限 64；这是 `WM_CHAR` 处理与配置格式的共同约束。

## 排错

- 启动痕迹：`main` 的第一条指令就写 `classlock-start.log`（先试 `%TEMP%`，失败退 exe 同目录），记录版本、pid、本地时间、完整命令行。文件不存在说明进程根本没被系统启动（SmartScreen / 杀软 / AppLocker 拦掉），而不是程序自己崩了。
- 失败原因追加写到 exe 同目录 `classlock.log`（`LogDiag`）。GUI 子系统看不到控制台输出，排错只能靠这个文件。
- `ClassLock.exe --diag`（对应 `诊断.bat`）打印 exe 路径、PE 子系统号、是否管理员、目录可写性、配置解析结果、BCrypt PBKDF2 可用性、两种钩子能否安装。
- 用户说"运行了没反应"时，先让他跑 `诊断.bat` 并把整段输出发回来，再问细节。

## 别做

- 不引第三方库、不拆新源文件：单文件 + 静态链接 + 无运行库依赖是交付契约。
- 不写内核驱动、不拦 SAS、不做持久化对抗、不写引导区、不碰用户数据。
- 不改 `classlock.cfg` 的 `format=classlock-v1` 语义而不升版本号。
- 不把 `classlock.cfg` 和 exe 一起发出去。
