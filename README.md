# ClassLock — Windows 全屏锁屏 / HID 输入劫持

面向 Windows 10 / 11 x64 的锁屏工具。锁定后劫持键盘与鼠标的全部输入通道，
只放行密码输入与一条隐藏解锁组合键。密码以 **PBKDF2-HMAC-SHA256 + 随机盐**
形式存储，配置文件里不存在任何明文或可逆信息。

交付物：

- `ClassLock.exe` — 单文件、静态链接（约 250 KB），无需 .NET / VC 运行库。
  子系统是 CONSOLE（`-mconsole`）：在 cmd / PowerShell 里运行会**正常等待**
  并显示提示符；双击直接锁屏时开局 `FreeConsole()`，不残留黑窗。
  （上一版是 `-mwindows`，cmd 不会等 GUI 进程，于是一敲回车就回到 `C:\>`，
  看起来像进程被杀 —— 已修掉。）
- `src/classlock.cpp` — 全部源码，单文件约 700 行
- `build.sh` — 交叉编译脚本（Linux → Windows）
- `安装到开机自启.bat` / `移除开机自启.bat` / `自检.bat` / `设置密码.bat` — 双击即可
- `tests/e2e_wine.sh` — 端到端验证脚本（Linux + wine + Xvfb，见第六节）
- `tests/shots/` — 验证时的实拍截图

---

## 一、目标机上的使用流程

1. 把 `ClassLock.exe` 放到一个固定目录，例如 `D:\Tools\ClassLock\`。
2. **先设密码**（在 cmd 或 PowerShell 中执行）：

   ```
   ClassLock.exe --set-password
   ClassLock.exe --set-password --hint "本机属于高二(3)班，勿动"
   ```

   输入时显示为 `*`，不回显、不进命令历史。完成后同目录生成 `classlock.cfg`。
3. **锁定**：双击 `ClassLock.exe`（或 `ClassLock.exe --lock`）。
   从 cmd / PowerShell 里执行时，命令行会一直挂到解锁为止，属正常。

未设置密码时程序会拒绝锁定并弹提示 —— 这是有意的，防止把自己锁在门外。

批量部署（多台机器，或脚本化）可以让密码取自文件首行，避免密码出现在命令行历史里：

```
ClassLock.exe --set-password --passfile D:\tmp\pw.txt
```

用完记得删掉那个 txt。程序所有失败原因都会追加写到同目录的 `classlock.log`
（GUI 子系统进程看不到控制台输出，排错靠它）。

### 解锁

- 在锁屏界面输入密码，回车。
- 隐藏组合键：`Ctrl + Alt + Shift + Q`（不需要密码，直接解锁）。
- `Ctrl + Alt + Del` → 任务管理器 → 结束 `ClassLock.exe`。
- 或者直接重启 / 注销 / 关机。

---

## 二、拦截范围（实测设计目标）

被吞掉的输入：

- 鼠标：移动、左/中/右键、侧键、滚轮（`WH_MOUSE_LL` 全量返回 1，另外把指针
  用 `ClipCursor` 夹在屏幕中心 1×1 区域）
- `Win`、`Win+任意键`、`Win+D/E/I/L/R/Tab`、菜单键
- `Alt+Tab`、`Alt+Esc`、`Alt+F4`、`Alt+Space`
- `Ctrl+Esc`、`Ctrl+Shift+Esc`（任务管理器快捷键）
- 全部 `F1`–`F24`
- `PrintScreen`（截屏键）、媒体键、浏览器键、睡眠键
- 窗口层面：`WM_CLOSE`、`WM_SYSCOMMAND`（关闭/最小化/屏保/显示器休眠）、
  `Alt+F4` 的系统菜单退出路径
- 焦点层面：每 200 ms 抢回前台（`AttachThreadInput` + `SetForegroundWindow`），
  叠加 `WS_EX_TOPMOST` 覆盖整个虚拟桌面（多显示器一起盖）
- IME：`ImmAssociateContext(hwnd, NULL)`，中文输入法候选窗不会弹出

有意**不**拦的：

- `Ctrl+Alt+Del`。这是 Windows 的安全注意序列（SAS），由 `winlogon` 在独立桌面
  处理，用户态进程无法拦截。要拦只能写内核驱动做键盘过滤，属于另一个风险等级，
  本工具不做。它同时也是最可靠的逃生口。
- 关机 / 重启 / 注销（`WM_QUERYENDSESSION` 返回 TRUE）。

关于"任何 HID"：手柄、方向盘、触摸屏这类非键鼠 HID 设备没有独立的输入劫持层，
它们在 Windows 上最终要么映射成键鼠消息（已被拦），要么只向拥有焦点的窗口发
`WM_INPUT` —— 而焦点窗口是锁屏本身，所以同样无效。真正的设备级拦截需要驱动。

---

## 三、逃生与恢复手册（重要，先读再玩）

按可靠度排序：

1. **Ctrl + Alt + Del** → 任务管理器 → 详细信息 → 结束 `ClassLock.exe`。
   注意：极域电子教室等管理端可能禁用任务管理器；被策略禁用时用第 3 条。
2. **重启**电脑。未装自启的话，重启后即恢复正常。
3. 装了自启又进不去桌面？重启时进安全模式，或用另一个管理员账号登录，
   删掉注册表项 `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
   里的 `ClassLock`，再删除 `%LOCALAPPDATA%\ClassLock\`。
4. 实在不行：PE 启动盘 / 另一台机器挂载硬盘，删掉上述文件与注册表项。

密码忘了怎么办：`classlock.cfg` 删掉后程序拒绝锁定（因为无密码不允许锁），
所以"删配置"本身就是一条恢复路径 —— 前提是你能操作到那个文件。

**不要把 `classlock.cfg` 和 exe 一起发到班群。** 谁拿到 cfg 也没用（盐+派生值
无法反推密码），但拿到 exe 的人可以自己设一个新密码来锁你。

---

## 四、配置文件格式

`classlock.cfg`（UTF-8，纯文本）：

```
format=classlock-v1
algo=PBKDF2-HMAC-SHA256
iter=200000
salt=<base64, 16 字节随机>
hash=<base64, 32 字节派生值>
hint=<可选，锁屏界面显示的提示语>
```

- 盐：每次 `--set-password` 用 `BCryptGenRandom` 重新生成 16 字节。
- 迭代：200000 次，目标机上单次校验约 0.2–0.5 秒（老机型可能到 1 秒）。
- 校验：`ConstantTimeEq` 逐字节异或累积，避免时序侧信道。
- 密码只存在于进程栈上的局部变量，校验完 `SecureZeroMemory` 清零；全程不进
  命令行参数、不进注册表、不进日志。
- 只支持 ASCII 可见字符、长度 1–64（控制台掩码输入的限制）。
  要更强就自己改 `kIterations` 并重新编译。

---

## 五、自启动（可选，默认不装）

```
ClassLock.exe --install      # 复制到 %LOCALAPPDATA%\ClassLock\ 并写 HKCU Run 键
ClassLock.exe --uninstall    # 撤销
```

`--install` 装的是"开机即锁"。**装之前务必确认密码记得住**，否则每次开机都要走
第三节的恢复流程。学生机房大多有还原卡/冰点还原，`--install` 的效果会被还原掉，
所以默认不建议装。

---

## 六、自己编译

```bash
sudo apt-get install -y --no-install-recommends g++-mingw-w64-x86-64
./build.sh
```

`build.sh` 用的是：

```
x86_64-w64-mingw32-g++ -std=c++17 -O2 -mconsole -static -static-libgcc \
  -static-libstdc++ -s -Wl,--no-insert-timestamp src/classlock.cpp -o ClassLock.exe \
  -lbcrypt -limm32 -lshell32 -luser32 -lgdi32 -ladvapi32
```

`-mconsole` 是必须的（见第一节）。`-Wl,--no-insert-timestamp` 让构建可复现：
同样的源码编译两次得到逐字节相同的 exe，SHA-256 恒定（约为
`eb0aa41b…`），便于核对"手上这份到底是哪一版"。

自检（Linux 上无法执行 PE，需要 wine）：

```bash
wine ClassLock.exe --selftest
```

自检覆盖：base64 往返、PBKDF2 已知测试向量（RFC 向量族）、真实迭代耗时、
配置写入/读回、盐复算、错误密码必须被拒绝。

---

## 六之二、已完成的实测记录（2026-10-22）

源码用 mingw-w64 (GCC 14, win32 线程模型) 交叉编译，PE64 / GUI 子系统 / 静态链接，
导入表只剩系统 DLL（KERNEL32、USER32、GDI32、ADVAPI32、bcrypt、IMM32、SHELL32、msvcrt）。

在 Linux 上用 wine 11.13 + Xvfb 1920×1080 跑了三轮真实执行：

1. `--selftest`：8 项全 PASS。PBKDF2 结果与 RFC 向量逐字节一致
   （`password`/`salt`/1 迭代 → `120fb6cf…be17b`），200000 次迭代耗时 16 ms。
2. 端到端：`--passfile` 设密码 → 生成的 cfg 里查不到明文 → `--lock` 起锁屏
   → 输错密码后进程仍存活并显示红色错误行 → 输入正确密码 + Enter 后进程退出（解锁成功）。
3. 热键通道：锁屏期间按 Super / F4 / Alt+Tab / Ctrl+Shift+Esc / PrintScreen / Esc
   均未使进程异常退出；`Ctrl+Alt+Shift+Q` 成功解锁退出。
4. 控制台行为（第 3 版修复）：`cmd /c "ClassLock.exe --lock & echo AFTER"` 在锁屏期间
   cmd 持续等待、AFTER 不出现；解锁后 cmd 才继续执行到 echo —— 证明不再是
   「GUI 子系统不等子进程」的老行为。`--selftest > file` 重定向也能正常落盘。

截图见 `tests/shots/`（wine 环境缺中文字体，所以是方框；Windows 上走
Microsoft YaHei，显示正常）。

未覆盖的部分：`Ctrl+Alt+Del` 与真实任务管理器行为、极域/组策略环境、
真实显卡多显示器下的焦点抢占 —— 这些只能在真机上验证。

---

## 七、边界与合规

- 只在**你有权限管理**的机器上使用。锁别人的电脑（老师办公室、同学自己的本子）
  在国内语境下可能构成"非法控制计算机信息系统"的客观行为，也可能违反校规。
- 学校机房通常有还原卡、极域电子教室（可远程锁屏/关机/查看屏幕）、以及
  组策略限制。本工具在那种环境下既可能失效，也可能被管理端一键解锁，别指望它
  能"制裁"到谁。
- 本工具不做持久化对抗、不做驱动、不写引导区、不触碰用户数据 —— 它的全部效果
  在进程被杀或机器重启后归零。这是刻意保留的可逆性。
