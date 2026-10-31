// ClassLock — Windows 全屏锁屏 / 输入劫持器
// 目标：Windows 10/11 x64。密码以 PBKDF2-HMAC-SHA256(盐, 迭代) 存储，配置文件不含明文。
//
// 模式：
//   ClassLock.exe                  锁定（默认）
//   ClassLock.exe --set-password   交互式设置/更换密码（掩码输入，控制台）
//   ClassLock.exe --set-password --hint "本机归 xx 所有"
//   ClassLock.exe --install        复制到 %LOCALAPPDATA%\ClassLock 并写入开机自启(Run)
//   ClassLock.exe --uninstall      移除自启并删除安装目录
//   ClassLock.exe --selftest       加密/配置自检（供交叉编译后验证）
//
// 子系统：CONSOLE。cmd/pwsh 会等到本进程退出才返回提示符（GUI 子系统不会等，
// 看起来就像"进程被结束"）。锁定模式开局 FreeConsole()，不残留黑窗。
//
// 保留的逃生通道（有意设计，不做成不可逆）：
//   1) 解锁密码
//   2) 隐藏组合键 Ctrl+Alt+Shift+Q
//   3) Ctrl+Alt+Del（Windows 安全序列，用户态无法拦截）→ 任务管理器结束 ClassLock.exe
//   4) 直接重启 / 注销
#define _WIN32_WINNT 0x0A00
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <bcrypt.h>
#include <imm.h>
#include <shellapi.h>
#include <conio.h>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <string>
#include <vector>

// ---------------------------------------------------------------- 基础工具

static const wchar_t* kAppName = L"ClassLock";
static const wchar_t* kVersion = L"1.2";

static std::string W2U8(const std::wstring& s) {
    if (s.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), NULL, 0, NULL, NULL);
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), &out[0], n, NULL, NULL);
    return out;
}

static std::wstring U82W(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), NULL, 0);
    std::wstring out(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &out[0], n);
    return out;
}

static std::string ToHex(const BYTE* d, size_t n) {
    static const char* H = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; ++i) {
        s.push_back(H[d[i] >> 4]);
        s.push_back(H[d[i] & 15]);
    }
    return s;
}

// ---------------------------------------------------------------- Base64

static const char kB64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string B64Enc(const BYTE* d, size_t n) {
    std::string out;
    out.reserve((n + 2) / 3 * 4);
    size_t i = 0;
    while (i + 3 <= n) {
        unsigned v = (d[i] << 16) | (d[i + 1] << 8) | d[i + 2];
        out.push_back(kB64[(v >> 18) & 63]);
        out.push_back(kB64[(v >> 12) & 63]);
        out.push_back(kB64[(v >> 6) & 63]);
        out.push_back(kB64[v & 63]);
        i += 3;
    }
    if (n - i == 1) {
        unsigned v = d[i] << 16;
        out.push_back(kB64[(v >> 18) & 63]);
        out.push_back(kB64[(v >> 12) & 63]);
        out += "==";
    } else if (n - i == 2) {
        unsigned v = (d[i] << 16) | (d[i + 1] << 8);
        out.push_back(kB64[(v >> 18) & 63]);
        out.push_back(kB64[(v >> 12) & 63]);
        out.push_back(kB64[(v >> 6) & 63]);
        out.push_back('=');
    }
    return out;
}

static bool B64Dec(const std::string& s, std::vector<BYTE>& out) {
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    out.clear();
    unsigned buf = 0;
    int bits = 0;
    for (char c : s) {
        if (c == '=' || c == '\r' || c == '\n' || c == ' ') continue;
        int v = val(c);
        if (v < 0) return false;
        buf = (buf << 6) | (unsigned)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((BYTE)((buf >> bits) & 0xFF));
        }
    }
    return true;
}

// ---------------------------------------------------------------- 密码派生
// PBKDF2-HMAC-SHA256 via CNG。密码按 UTF-8 字节参与派生。

static bool DeriveKey(const std::string& pass, const BYTE* salt, ULONG saltLen,
                      UINT64 iter, BYTE* out, ULONG outLen) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL,
                                              BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(st)) return false;
    st = BCryptDeriveKeyPBKDF2(hAlg, (PUCHAR)pass.data(), (ULONG)pass.size(),
                               (PUCHAR)salt, saltLen, iter, out, outLen, 0);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return BCRYPT_SUCCESS(st);
}

static bool ConstantTimeEq(const BYTE* a, const BYTE* b, size_t n) {
    volatile BYTE diff = 0;
    for (size_t i = 0; i < n; ++i) diff |= (BYTE)(a[i] ^ b[i]);
    return diff == 0;
}

static std::vector<BYTE> RandomBytes(size_t n) {
    std::vector<BYTE> v(n);
    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, v.data(), (ULONG)n,
                                       BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        v.clear();
    }
    return v;
}

// ---------------------------------------------------------------- 配置

static const UINT64 kIterations = 200000;
static const size_t kSaltLen = 16;
static const size_t kHashLen = 32;

struct Config {
    bool ok = false;
    UINT64 iter = kIterations;
    std::vector<BYTE> salt;
    std::vector<BYTE> hash;
    std::wstring hint;
};

static std::wstring g_exeDir;

static std::wstring ExePath() {
    wchar_t buf[MAX_PATH * 2] = {0};
    DWORD n = GetModuleFileNameW(NULL, buf, MAX_PATH * 2);
    return std::wstring(buf, n);
}

static std::wstring ExeDir() {
    std::wstring p = ExePath();
    size_t k = p.find_last_of(L"\\/");
    return (k == std::wstring::npos) ? L"." : p.substr(0, k);
}

static std::wstring LocalAppDir() {
    wchar_t buf[MAX_PATH] = {0};
    DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", buf, MAX_PATH);
    std::wstring base = (n > 0 && n < MAX_PATH) ? std::wstring(buf, n) : ExeDir();
    std::wstring dir = base + L"\\ClassLock";
    CreateDirectoryW(dir.c_str(), NULL);
    return dir;
}

static bool FileExists(const std::wstring& p) {
    DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static bool ReadFileUtf8(const std::wstring& path, std::string& out) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    char buf[4096];
    DWORD got = 0;
    out.clear();
    while (ReadFile(h, buf, sizeof(buf), &got, NULL) && got > 0) out.append(buf, got);
    CloseHandle(h);
    return true;
}

static bool WriteFileUtf8(const std::wstring& path, const std::string& data) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD wrote = 0;
    bool ok = WriteFile(h, data.data(), (DWORD)data.size(), &wrote, NULL) != 0;
    CloseHandle(h);
    return ok && wrote == (DWORD)data.size();
}

static void LogDiag(const char* fmt, ...) {
    char body[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);
    std::wstring path = ExeDir() + L"\\classlock.log";
    std::string line = body;
    line += "\r\n";
    HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD wrote = 0;
        WriteFile(h, line.data(), (DWORD)line.size(), &wrote, NULL);
        CloseHandle(h);
    }
    fprintf(stderr, "%s\n", body);
}

static std::wstring PrimaryCfgPath() { return ExeDir() + L"\\classlock.cfg"; }
static std::wstring FallbackCfgPath() { return LocalAppDir() + L"\\classlock.cfg"; }

static std::wstring FindCfgPath() {
    std::wstring a = PrimaryCfgPath();
    if (FileExists(a)) return a;
    std::wstring b = FallbackCfgPath();
    if (FileExists(b)) return b;
    return L"";
}

static Config LoadConfig() {
    Config c;
    std::wstring path = FindCfgPath();
    if (path.empty()) return c;
    std::string text;
    if (!ReadFileUtf8(path, text)) return c;

    size_t pos = 0;
    while (pos <= text.size()) {
        size_t nl = text.find('\n', pos);
        std::string line = text.substr(pos, (nl == std::string::npos) ? std::string::npos : nl - pos);
        pos = (nl == std::string::npos) ? text.size() + 1 : nl + 1;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = line.substr(0, eq), v = line.substr(eq + 1);
        if (k == "iter") {
            c.iter = _strtoui64(v.c_str(), NULL, 10);
        } else if (k == "salt") {
            B64Dec(v, c.salt);
        } else if (k == "hash") {
            B64Dec(v, c.hash);
        } else if (k == "hint") {
            c.hint = U82W(v);
        }
    }
    c.ok = (c.salt.size() >= 8 && c.hash.size() >= 16 && c.iter >= 1000);
    return c;
}

static std::string BuildCfgText(const std::vector<BYTE>& salt, const std::vector<BYTE>& hash,
                                UINT64 iter, const std::wstring& hint) {
    std::string s;
    s += "format=classlock-v1\n";
    s += "algo=PBKDF2-HMAC-SHA256\n";
    s += "iter=" + std::to_string((unsigned long long)iter) + "\n";
    s += "salt=" + B64Enc(salt.data(), salt.size()) + "\n";
    s += "hash=" + B64Enc(hash.data(), hash.size()) + "\n";
    if (!hint.empty()) s += "hint=" + W2U8(hint) + "\n";
    return s;
}

// ---------------------------------------------------------------- 控制台辅助

// 控制台子系统：从 cmd/pwsh 启动时控制台已就绪，直接复用（这时 cmd 会等我们退出）。
// 双击启动时系统会新建一个控制台，也在这里统一接管。
static void EnsureConsole() {
    if (!GetConsoleWindow()) {
        if (!AttachConsole(ATTACH_PARENT_PROCESS)) AllocConsole();
    }
    // 已有标准句柄（cmd 启动、含重定向 >file 的情况）就不要重新绑定 CONOUT$，
    // 否则会绕过重定向、也把 wine/管道下的输出吃掉。
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == NULL || hOut == INVALID_HANDLE_VALUE) {
        FILE* f = NULL;
        freopen_s(&f, "CONOUT$", "w", stdout);
        freopen_s(&f, "CONOUT$", "w", stderr);
        freopen_s(&f, "CONIN$", "r", stdin);
    }
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    SetConsoleTitleW(L"ClassLock");
}

static std::string ReadLineMasked(const char* prompt) {
    printf("%s", prompt);
    fflush(stdout);
    std::string s;
    for (;;) {
        int ch = _getch();
        if (ch == EOF) break;
        if (ch == 0 || ch == 0xE0) {  // 功能键前缀，丢弃后续
            _getch();
            continue;
        }
        if (ch == '\r' || ch == '\n') break;
        if (ch == 3) {  // Ctrl+C
            exit(3);
        }
        if (ch == 8 || ch == 127) {
            if (!s.empty()) {
                s.pop_back();
                printf("\b \b");
                fflush(stdout);
            }
            continue;
        }
        if (ch >= 32 && ch < 127 && s.size() < 64) {
            s.push_back((char)ch);
            printf("*");
            fflush(stdout);
        }
    }
    printf("\n");
    return s;
}

// ---------------------------------------------------------------- 全局状态

static HHOOK g_kbHook = NULL;
static HHOOK g_msHook = NULL;
static HWND g_hwnd = NULL;
static HFONT g_fTitle = NULL, g_fSub = NULL, g_fSmall = NULL, g_fDots = NULL, g_fBox = NULL;
static std::wstring g_input;
static int g_failCount = 0;
static bool g_showError = false;
static std::wstring g_startedAt;
static Config g_cfg;  // 启动时读一次，重绘复用
static SYSTEMTIME g_startTime;

static const UINT_PTR kTimerId = 1;
static const int kHotkeyId = 0xC1A5;

// ---------------------------------------------------------------- 字体

static HFONT MakeFont(int px, int weight) {
    static const wchar_t* kFaces[] = {L"Microsoft YaHei UI", L"Microsoft YaHei", L"SimHei",
                                      L"Segoe UI", NULL};
    HFONT f = NULL;
    for (int i = 0; kFaces[i]; ++i) {
        f = CreateFontW(-px, 0, 0, 0, weight, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                        OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                        DEFAULT_PITCH | FF_DONTCARE, kFaces[i]);
        if (f) return f;
    }
    return CreateFontW(-px, 0, 0, 0, weight, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                       OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                       DEFAULT_PITCH | FF_DONTCARE, L"System");
}

// ---------------------------------------------------------------- 绘制

static void TextC(HDC hdc, HFONT f, COLORREF col, int cy, const std::wstring& s, int w) {
    HFONT old = (HFONT)SelectObject(hdc, f);
    SetTextColor(hdc, col);
    SetBkMode(hdc, TRANSPARENT);
    SIZE sz = {0, 0};
    GetTextExtentPoint32W(hdc, s.c_str(), (int)s.size(), &sz);
    TextOutW(hdc, (w - sz.cx) / 2, cy - sz.cy / 2, s.c_str(), (int)s.size());
    SelectObject(hdc, old);
}

static void PaintLock(HDC hdc, int W, int H) {
    RECT all = {0, 0, W, H};
    HBRUSH bg = CreateSolidBrush(RGB(9, 11, 17));
    FillRect(hdc, &all, bg);
    DeleteObject(bg);

    // 顶部/底部渐层色带（纯 FillRect 叠加，避免依赖 msimg32）
    for (int i = 0; i < 60; ++i) {
        int a = 26 - i / 3;
        if (a < 0) a = 0;
        HBRUSH b = CreateSolidBrush(RGB(9 + a / 2, 11 + a, 17 + a * 2));
        RECT r = {0, i * 2, W, i * 2 + 2};
        FillRect(hdc, &r, b);
        DeleteObject(b);
    }

    int cx = W / 2;
    int base = H / 2;

    // 锁定图标（简笔挂锁）
    {
        int iw = 64;
        int x = cx - iw / 2, y = base - 300;
        HPEN pen = CreatePen(PS_SOLID, 5, RGB(96, 128, 180));
        HPEN oldPen = (HPEN)SelectObject(hdc, pen);
        HGDIOBJ oldBr = SelectObject(hdc, GetStockObject(NULL_BRUSH));
        Arc(hdc, x + 12, y, x + 52, y + 42, x + 52, y + 21, x + 12, y + 21);
        SelectObject(hdc, oldPen);
        DeleteObject(pen);
        HBRUSH body = CreateSolidBrush(RGB(150, 40, 55));
        SelectObject(hdc, body);
        RoundRect(hdc, x + 6, y + 24, x + 58, y + 62, 12, 12);
        SelectObject(hdc, oldBr);
        DeleteObject(body);
    }

    TextC(hdc, g_fTitle, RGB(236, 241, 250), base - 190, L"此 计 算 机 已 被 锁 定", W);
    TextC(hdc, g_fSub, RGB(150, 162, 184), base - 128,
          L"检测到未授权的桌面操作，输入解锁密码以继续", W);

    if (g_cfg.ok && !g_cfg.hint.empty()) {
        TextC(hdc, g_fSmall, RGB(120, 132, 152), base - 92, L"提示：" + g_cfg.hint, W);
    }

    // 密码框
    int bw = 460, bh = 72;
    int bx = cx - bw / 2, by = base + 8;
    RECT box = {bx, by, bx + bw, by + bh};
    COLORREF borderCol = g_showError ? RGB(200, 60, 70) : RGB(58, 74, 104);
    if (!g_input.empty()) borderCol = g_showError ? RGB(200, 60, 70) : RGB(96, 128, 180);
    HBRUSH fbg = CreateSolidBrush(RGB(16, 19, 27));
    FillRect(hdc, &box, fbg);
    DeleteObject(fbg);
    HPEN bp = CreatePen(PS_SOLID, 2, borderCol);
    HPEN obp = (HPEN)SelectObject(hdc, bp);
    HGDIOBJ obb = SelectObject(hdc, GetStockObject(NULL_BRUSH));
    RoundRect(hdc, bx, by, bx + bw, by + bh, 10, 10);
    SelectObject(hdc, obp);
    SelectObject(hdc, obb);
    DeleteObject(bp);

    // 掩码点（不显示任何明文）
    {
        HFONT old = (HFONT)SelectObject(hdc, g_fDots);
        SetTextColor(hdc, RGB(220, 228, 242));
        SetBkMode(hdc, TRANSPARENT);
        int px = bx + 26;
        if (g_input.empty()) {
            HFONT olds = (HFONT)SelectObject(hdc, g_fBox);
            SetTextColor(hdc, RGB(88, 98, 118));
            std::wstring ph = L"输入解锁密码";
            SIZE sz = {0, 0};
            GetTextExtentPoint32W(hdc, ph.c_str(), (int)ph.size(), &sz);
            TextOutW(hdc, px, by + (bh - sz.cy) / 2, ph.c_str(), (int)ph.size());
            SelectObject(hdc, olds);
        } else {
            SIZE ds = {0, 0};
            GetTextExtentPoint32W(hdc, L"\u25CF", 1, &ds);
            int py = by + (bh - ds.cy) / 2;
            for (size_t i = 0; i < g_input.size(); ++i)
                TextOutW(hdc, px + (int)i * 22, py, L"\u25CF", 1);
            // 光标闪烁
            if (((GetTickCount64() / 500) % 2) == 0) {
                HPEN cp = CreatePen(PS_SOLID, 2, RGB(200, 215, 240));
                HPEN ocp = (HPEN)SelectObject(hdc, cp);
                int caretX = px + (int)g_input.size() * 22;
                MoveToEx(hdc, caretX, by + 18, NULL);
                LineTo(hdc, caretX, by + bh - 18);
                SelectObject(hdc, ocp);
                DeleteObject(cp);
            }
        }
        SelectObject(hdc, old);
    }

    if (g_showError) {
        wchar_t msg[128];
        swprintf(msg, 128, L"密码错误 · 第 %d 次", g_failCount);
        TextC(hdc, g_fSmall, RGB(214, 78, 88), by + bh + 44, msg, W);
    }

    // 底部信息
    wchar_t foot[256];
    swprintf(foot, 256, L"ClassLock %s · 锁定开始 %s · PRTS", kVersion, g_startedAt.c_str());
    HFONT of = (HFONT)SelectObject(hdc, g_fSmall);
    SetTextColor(hdc, RGB(92, 102, 122));
    SetBkMode(hdc, TRANSPARENT);
    SIZE fs = {0, 0};
    GetTextExtentPoint32W(hdc, foot, (int)wcslen(foot), &fs);
    TextOutW(hdc, (W - fs.cx) / 2, H - 52, foot, (int)wcslen(foot));
    SelectObject(hdc, of);
}

// ---------------------------------------------------------------- 输入钩子

static bool g_allowAll = false;  // 解锁过程中临时放行

static LRESULT CALLBACK KbProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && !g_allowAll) {
        KBDLLHOOKSTRUCT* kb = (KBDLLHOOKSTRUCT*)lParam;
        DWORD vk = kb->vkCode;
        bool ctrl = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
        bool alt = (GetAsyncKeyState(VK_MENU) & 0x8000) != 0;
        bool shift = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;

        bool hotkey = ctrl && alt && shift && (vk == 'Q');
        bool isModifier = (vk == VK_LSHIFT || vk == VK_RSHIFT || vk == VK_SHIFT ||
                           vk == VK_LCONTROL || vk == VK_RCONTROL || vk == VK_CONTROL ||
                           vk == VK_LMENU || vk == VK_RMENU || vk == VK_MENU);
        bool block = false;
        if (isModifier || hotkey) {
            block = false;  // 修饰键与热键都放行，否则 RegisterHotKey 收不到完整序列
        } else if (vk == VK_LWIN || vk == VK_RWIN || vk == VK_APPS || vk == VK_SNAPSHOT ||
                   vk == VK_TAB || vk == VK_ESCAPE || vk == VK_SLEEP) {
            block = true;
        } else if (vk >= VK_F1 && vk <= VK_F24) {
            block = true;
        } else if (vk == VK_BROWSER_BACK || vk == VK_BROWSER_FORWARD ||
                   vk == VK_BROWSER_REFRESH || vk == VK_MEDIA_PLAY_PAUSE ||
                   vk == VK_MEDIA_NEXT_TRACK || vk == VK_MEDIA_PREV_TRACK ||
                   vk == VK_VOLUME_MUTE || vk == VK_VOLUME_DOWN || vk == VK_VOLUME_UP ||
                   vk == VK_LAUNCH_MAIL || vk == VK_LAUNCH_MEDIA_SELECT) {
            block = true;
        } else if (alt) {
            block = true;  // Alt+任意键（含 Alt+Tab / Alt+F4 / Alt+Space）
        }
        if (block) {
            return 1;
        }
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

static LRESULT CALLBACK MsProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && !g_allowAll) {
        return 1;  // 吞掉全部鼠标消息：点击、拖动、滚轮一并失效
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

static void ClipPointer() {
    POINT pt = {0, 0};
    pt.x = GetSystemMetrics(SM_CXSCREEN) / 2;
    pt.y = GetSystemMetrics(SM_CYSCREEN) / 2;
    RECT r = {pt.x, pt.y, pt.x + 1, pt.y + 1};
    ClipCursor(&r);
}

// ---------------------------------------------------------------- 锁定窗口

static void PlaceWindow(HWND hwnd) {
    int x = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int y = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int w = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int h = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    if (w <= 0 || h <= 0) {
        x = 0; y = 0; w = GetSystemMetrics(SM_CXSCREEN); h = GetSystemMetrics(SM_CYSCREEN);
    }
    SetWindowPos(hwnd, HWND_TOPMOST, x, y, w, h, SWP_SHOWWINDOW);
}

static void RegrabForeground() {
    HWND fg = GetForegroundWindow();
    if (fg == g_hwnd) return;
    DWORD fgThread = fg ? GetWindowThreadProcessId(fg, NULL) : 0;
    DWORD myThread = GetCurrentThreadId();
    bool attached = false;
    if (fgThread && fgThread != myThread) {
        attached = AttachThreadInput(myThread, fgThread, TRUE) != 0;
    }
    SetForegroundWindow(g_hwnd);
    BringWindowToTop(g_hwnd);
    SetActiveWindow(g_hwnd);
    SetFocus(g_hwnd);
    if (attached) AttachThreadInput(myThread, fgThread, FALSE);
    SetWindowPos(g_hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    ClipPointer();
}

static int g_exitCode = 0;

static void Unlock() {
    if (g_allowAll) return;
    g_allowAll = true;
    KillTimer(g_hwnd, kTimerId);
    UnregisterHotKey(g_hwnd, kHotkeyId);
    if (g_kbHook) UnhookWindowsHookEx(g_kbHook);
    if (g_msHook) UnhookWindowsHookEx(g_msHook);
    g_kbHook = g_msHook = NULL;
    ClipCursor(NULL);
    if (g_hwnd) DestroyWindow(g_hwnd);
    g_hwnd = NULL;
    PostQuitMessage(0);
}

static void TryUnlock() {
    const Config& cfg = g_cfg;
    if (!cfg.ok || cfg.hash.size() != kHashLen) return;
    std::string pass = W2U8(g_input);
    std::vector<BYTE> derived(kHashLen);
    if (!DeriveKey(pass, cfg.salt.data(), (ULONG)cfg.salt.size(), cfg.iter, derived.data(),
                   (ULONG)derived.size())) {
        return;
    }
    SecureZeroMemory(&pass[0], pass.size());
    if (ConstantTimeEq(derived.data(), cfg.hash.data(), kHashLen)) {
        g_input.clear();
        Unlock();
    } else {
        ++g_failCount;
        g_showError = true;
        g_input.clear();
    }
    InvalidateRect(g_hwnd, NULL, FALSE);
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE:
            g_hwnd = hwnd;
            return 0;
        case WM_ERASEBKGND:
            return 1;
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            RECT rc;
            GetClientRect(hwnd, &rc);
            HDC mem = CreateCompatibleDC(hdc);
            HBITMAP bmp = CreateCompatibleBitmap(hdc, rc.right, rc.bottom);
            HGDIOBJ ob = SelectObject(mem, bmp);
            PaintLock(mem, rc.right, rc.bottom);
            BitBlt(hdc, 0, 0, rc.right, rc.bottom, mem, 0, 0, SRCCOPY);
            SelectObject(mem, ob);
            DeleteObject(bmp);
            DeleteDC(mem);
            EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_CHAR: {
            wchar_t ch = (wchar_t)wParam;
            if (ch == L'\r' || ch == L'\n') {
                TryUnlock();
                return 0;
            }
            if (ch == L'\b') {
                if (!g_input.empty()) g_input.pop_back();
                InvalidateRect(hwnd, NULL, FALSE);
                return 0;
            }
            if (ch >= 32 && ch < 127 && g_input.size() < 64) {
                if (g_showError) {
                    g_showError = false;
                }
                g_input.push_back(ch);
                InvalidateRect(hwnd, NULL, FALSE);
            }
            return 0;
        }
        case WM_TIMER:
            if (wParam == kTimerId) {
                RegrabForeground();
                InvalidateRect(hwnd, NULL, FALSE);  // 光标闪烁
            }
            return 0;
        case WM_HOTKEY:
            if (wParam == kHotkeyId) {
                Unlock();
            }
            return 0;
        case WM_ACTIVATE:
        case WM_KILLFOCUS:
            PostMessageW(hwnd, WM_APP + 1, 0, 0);
            return 0;
        case WM_APP + 1:
            RegrabForeground();
            return 0;
        case WM_DISPLAYCHANGE:
        case WM_SETTINGCHANGE:
            PlaceWindow(hwnd);
            ClipPointer();
            return 0;
        case WM_CLOSE:
        case WM_DESTROY:
            return 0;
        case WM_SYSCOMMAND:
            return 0;  // 屏蔽 SC_CLOSE / SC_MINIMIZE / 屏保 / 显示器休眠
        case WM_QUERYENDSESSION:
            return TRUE;  // 允许关机/重启（保命通道之一）
        case WM_ENDSESSION:
            if (wParam) {
                g_allowAll = true;
                if (g_kbHook) UnhookWindowsHookEx(g_kbHook);
                if (g_msHook) UnhookWindowsHookEx(g_msHook);
                ClipCursor(NULL);
            }
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static int RunLock() {
    g_exeDir = ExeDir();
    g_cfg = LoadConfig();
    // 锁屏不需要控制台：脱离它。若这个控制台是双击时系统为本进程新建的，会一并销毁。
    FreeConsole();
    if (!g_cfg.ok) {
        MessageBoxW(NULL,
                    L"尚未设置解锁密码。\n\n请先运行：\n    ClassLock.exe --set-password\n\n"
                    L"（未设置密码时不允许锁定，避免把自己锁在门外。）",
                    L"ClassLock", MB_ICONWARNING | MB_OK | MB_TOPMOST);
        return 2;
    }

    SetProcessDPIAware();

    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.hCursor = NULL;
    wc.hbrBackground = NULL;
    wc.lpszClassName = L"ClassLockWnd";
    if (!RegisterClassExW(&wc)) return 3;

    int x = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int y = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int w = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int h = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    if (w <= 0 || h <= 0) {
        x = 0; y = 0; w = GetSystemMetrics(SM_CXSCREEN); h = GetSystemMetrics(SM_CYSCREEN);
    }

    HWND hwnd = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW, L"ClassLockWnd", L"ClassLock",
        WS_POPUP, x, y, w, h, NULL, NULL, GetModuleHandleW(NULL), NULL);
    if (!hwnd) return 4;
    g_hwnd = hwnd;

    g_fTitle = MakeFont(52, FW_SEMIBOLD);
    g_fSub = MakeFont(20, FW_NORMAL);
    g_fSmall = MakeFont(15, FW_NORMAL);
    g_fDots = MakeFont(26, FW_NORMAL);
    g_fBox = MakeFont(18, FW_NORMAL);

    GetLocalTime(&g_startTime);
    wchar_t tbuf[64];
    swprintf(tbuf, 64, L"%02d:%02d", g_startTime.wHour, g_startTime.wMinute);
    g_startedAt = tbuf;

    ShowWindow(hwnd, SW_SHOW);
    PlaceWindow(hwnd);
    ImmAssociateContext(hwnd, NULL);  // 关掉 IME 候选窗
    RegrabForeground();

    // 钩子必须在消息循环所在线程上安装
    g_kbHook = SetWindowsHookExW(WH_KEYBOARD_LL, KbProc, GetModuleHandleW(NULL), 0);
    g_msHook = SetWindowsHookExW(WH_MOUSE_LL, MsProc, GetModuleHandleW(NULL), 0);
    if (!g_kbHook || !g_msHook) {
        DWORD err = GetLastError();
        if (g_kbHook) UnhookWindowsHookEx(g_kbHook);
        if (g_msHook) UnhookWindowsHookEx(g_msHook);
        g_allowAll = true;
        DestroyWindow(hwnd);
        wchar_t msg[256];
        swprintf(msg, 256, L"输入钩子安装失败（错误码 %lu），已放弃锁定。", err);
        LogDiag("lock: hook install failed err=%lu", err);
        MessageBoxW(NULL, msg, L"ClassLock", MB_ICONERROR | MB_OK);
        return 5;
    }

    if (!RegisterHotKey(hwnd, kHotkeyId, MOD_CONTROL | MOD_ALT | MOD_SHIFT | MOD_NOREPEAT, 'Q')) {
        // 热键被占用不算致命：密码通道仍在
    }

    SetTimer(hwnd, kTimerId, 200, NULL);
    ClipPointer();

    MSG m;
    while (GetMessageW(&m, NULL, 0, 0) > 0) {
        if (m.message == WM_KEYDOWN && (m.wParam == VK_RETURN || m.wParam == VK_BACK)) {
            // 交给 WM_CHAR
        }
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    return g_exitCode;
}

// ---------------------------------------------------------------- 子命令

static int CmdSetPassword(const std::wstring& hint, const std::wstring& passFile) {
    if (!passFile.empty()) {
        // 非交互模式：密码取自文件首行（便于批量部署/自动化测试，密码不进 argv）
        std::string content;
        if (!ReadFileUtf8(passFile, content)) {
            LogDiag("setpass: cannot read passfile (err=%lu)", GetLastError());
            return 11;
        }
        size_t nl = content.find_first_of("\r\n");
        std::string p = content.substr(0, nl);
        if (p.empty()) {
            LogDiag("setpass: empty password");
            return 12;
        }
        std::vector<BYTE> salt = RandomBytes(kSaltLen);
        std::vector<BYTE> hash(kHashLen);
        if (salt.size() != kSaltLen ||
            !DeriveKey(p, salt.data(), (ULONG)salt.size(), kIterations, hash.data(),
                       (ULONG)hash.size())) {
            LogDiag("setpass: derive failed");
            return 13;
        }
        SecureZeroMemory(&p[0], p.size());
        SecureZeroMemory(&content[0], content.size());
        std::string text = BuildCfgText(salt, hash, kIterations, hint);
        std::wstring path = PrimaryCfgPath();
        if (!WriteFileUtf8(path, text)) {
            path = FallbackCfgPath();
            if (!WriteFileUtf8(path, text)) {
                LogDiag("setpass: write failed (err=%lu)", GetLastError());
                return 14;
            }
        }
        LogDiag("setpass: saved to %s", W2U8(path).c_str());
        return 0;
    }
    EnsureConsole();
    printf("=== ClassLock 密码设置 ===\n");
    printf("密码仅以 PBKDF2-HMAC-SHA256 派生值 + 随机盐保存，配置文件里没有明文。\n");
    printf("密码字符集：ASCII 可见字符，长度 1-64。\n\n");

    std::string p1 = ReadLineMasked("请输入新密码: ");
    if (p1.empty()) {
        printf("未读到任何按键，已取消。\n"
               "如果这里是没有可交互控制台的运行方式（任务计划、无终端的 IDE、管道），\n"
               "请改用：ClassLock.exe --set-password --passfile <密码文件>\n");
        return 1;
    }
    std::string p2 = ReadLineMasked("再次输入确认: ");
    if (p1 != p2) {
        printf("两次输入不一致，已取消。\n");
        return 1;
    }

    std::vector<BYTE> salt = RandomBytes(kSaltLen);
    if (salt.size() != kSaltLen) {
        printf("随机数生成失败，已取消。\n");
        return 1;
    }
    std::vector<BYTE> hash(kHashLen);
    if (!DeriveKey(p1, salt.data(), (ULONG)salt.size(), kIterations, hash.data(),
                   (ULONG)hash.size())) {
        printf("密钥派生失败，已取消。\n");
        return 1;
    }
    SecureZeroMemory(&p1[0], p1.size());
    SecureZeroMemory(&p2[0], p2.size());

    std::string text = BuildCfgText(salt, hash, kIterations, hint);
    std::wstring path = PrimaryCfgPath();
    bool ok = WriteFileUtf8(path, text);
    if (!ok) {
        path = FallbackCfgPath();
        ok = WriteFileUtf8(path, text);
    }
    if (!ok) {
        printf("写入配置失败（目录不可写）：%ls\n", path.c_str());
        return 1;
    }
    printf("\n已保存：%ls\n", path.c_str());
    printf("迭代次数: %llu  盐长度: %zu 验证串: %s\n",
           (unsigned long long)kIterations, salt.size(), ToHex(hash.data(), 8).c_str());
    printf("\n解锁方式：\n  1) 在锁屏界面输入该密码\n  2) 隐藏组合键 Ctrl+Alt+Shift+Q\n");
    printf("按任意键退出...\n");
    _getch();
    return 0;
}

static std::wstring RunKeyPath() {
    return L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
}

static int CmdInstall() {
    EnsureConsole();
    std::wstring cfg = FindCfgPath();
    if (cfg.empty()) {
        printf("未找到 classlock.cfg，请先执行 --set-password。\n");
        return 1;
    }
    std::wstring dir = LocalAppDir();
    std::wstring dst = dir + L"\\ClassLock.exe";
    std::wstring dstCfg = dir + L"\\classlock.cfg";
    if (!CopyFileW(ExePath().c_str(), dst.c_str(), FALSE)) {
        printf("复制可执行文件失败（%lu）。\n", GetLastError());
        return 1;
    }
    CopyFileW(cfg.c_str(), dstCfg.c_str(), FALSE);

    HKEY hk = NULL;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, RunKeyPath().c_str(), 0, NULL, 0, KEY_SET_VALUE,
                        NULL, &hk, NULL) != ERROR_SUCCESS) {
        printf("写入注册表失败。\n");
        return 1;
    }
    std::wstring val = L"\"" + dst + L"\"";
    LONG r = RegSetValueExW(hk, kAppName, 0, REG_SZ, (const BYTE*)val.c_str(),
                            (DWORD)((val.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(hk);
    if (r != ERROR_SUCCESS) {
        printf("写入注册表失败（%ld）。\n", r);
        return 1;
    }
    printf("已安装：%ls\n开机自启已写入 HKCU\\...\\Run\\ClassLock\n", dst.c_str());
    printf("卸载：ClassLock.exe --uninstall\n按任意键退出...\n");
    _getch();
    return 0;
}

static int CmdUninstall() {
    EnsureConsole();
    HKEY hk = NULL;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, RunKeyPath().c_str(), 0, KEY_SET_VALUE, &hk) ==
        ERROR_SUCCESS) {
        RegDeleteValueW(hk, kAppName);
        RegCloseKey(hk);
    }
    std::wstring dir = LocalAppDir();
    DeleteFileW((dir + L"\\classlock.cfg").c_str());
    if (!DeleteFileW((dir + L"\\ClassLock.exe").c_str())) {
        MoveFileExW((dir + L"\\ClassLock.exe").c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
    }
    printf("已移除开机自启。\n按任意键退出...\n");
    _getch();
    return 0;
}


// ---------------------------------------------------------------- 诊断

static LRESULT CALLBACK DiagHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

static int CmdDiag() {
    EnsureConsole();
    printf("=== ClassLock 诊断 (%s) ===\n", W2U8(kVersion).c_str());
    printf("exe 路径      : %s\n", W2U8(ExePath()).c_str());
    printf("工作目录      : %s\n", W2U8(ExeDir()).c_str());
    printf("控制台窗口    : %p%s\n", (void*)GetConsoleWindow(),
           GetConsoleWindow() ? "" : "  <- 没有控制台，说明不是从 cmd/pwsh 启动的");
    printf("stdin/out/err : %p %p %p\n", (void*)GetStdHandle(STD_INPUT_HANDLE),
           (void*)GetStdHandle(STD_OUTPUT_HANDLE), (void*)GetStdHandle(STD_ERROR_HANDLE));

    OSVERSIONINFOW vi = {0};
    vi.dwOSVersionInfoSize = sizeof(vi);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    GetVersionExW(&vi);
#pragma GCC diagnostic pop
    printf("Windows 版本  : %lu.%lu build %lu\n", vi.dwMajorVersion, vi.dwMinorVersion,
           vi.dwBuildNumber);
    printf("64 位系统     : %s\n", sizeof(void*) == 8 ? "yes(64 位 exe)" : "no(32 位 exe)");

    // 读自身 PE 头，报告子系统：3=CONSOLE（cmd 会等待），2=GUI（cmd 不等，症状就是"回到 C:\\>"）
    {
        HANDLE hf = CreateFileW(ExePath().c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER sz;
            GetFileSizeEx(hf, &sz);
            IMAGE_DOS_HEADER dos;
            DWORD got = 0, sig = 0;
            WORD sub = 0;
            bool ok = false;
            if (ReadFile(hf, &dos, sizeof(dos), &got, NULL) && dos.e_magic == IMAGE_DOS_SIGNATURE) {
                SetFilePointer(hf, dos.e_lfanew, NULL, FILE_BEGIN);
                if (ReadFile(hf, &sig, 4, &got, NULL) && sig == IMAGE_NT_SIGNATURE) {
                    SetFilePointer(hf, dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + 68, NULL,
                                   FILE_BEGIN);
                    ok = ReadFile(hf, &sub, 2, &got, NULL) != 0;
                }
            }
            CloseHandle(hf);
            printf("exe 大小      : %lld 字节\n", (long long)sz.QuadPart);
            if (ok) {
                printf("PE 子系统     : %u (%s)\n", (unsigned)sub,
                       sub == 3 ? "CONSOLE — cmd 会等待，正确"
                                : (sub == 2 ? "GUI — cmd 不会等待，这就是 bug 的来源" : "其它"));
            } else {
                printf("PE 子系统     : 读取失败\n");
            }
        }
    }

    BOOL admin = FALSE;
    PSID grp = NULL;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                 0, 0, 0, 0, 0, 0, &grp)) {
        CheckTokenMembership(NULL, grp, &admin);
        FreeSid(grp);
    }
    printf("管理员权限    : %s\n", admin ? "yes" : "no");

    // 目录可写性
    std::wstring probe = ExeDir() + L"\\__writetest.tmp";
    bool w = WriteFileUtf8(probe, "x");
    printf("目录可写      : %s  (%s)\n", w ? "yes" : "no", W2U8(probe).c_str());
    if (w) DeleteFileW(probe.c_str());

    // 配置
    std::wstring cfgp = FindCfgPath();
    printf("配置文件      : %s\n", cfgp.empty() ? "(未找到，需先 --set-password)" : W2U8(cfgp).c_str());
    Config c = LoadConfig();
    printf("配置可解析    : %s\n", c.ok ? "yes" : "no");

    // CNG 加密可用？
    {
        BCRYPT_ALG_HANDLE h = NULL;
        NTSTATUS st = BCryptOpenAlgorithmProvider(&h, BCRYPT_SHA256_ALGORITHM, NULL,
                                                  BCRYPT_ALG_HANDLE_HMAC_FLAG);
        BYTE out[32];
        bool ok = BCRYPT_SUCCESS(st) &&
                  BCRYPT_SUCCESS(BCryptDeriveKeyPBKDF2(h, (PUCHAR)"p", 1, (PUCHAR)"saltsalt", 8,
                                                       1000, out, 32, 0));
        if (BCRYPT_SUCCESS(st)) BCryptCloseAlgorithmProvider(h, 0);
        printf("PBKDF2 可用   : %s\n", ok ? "yes" : "no");
    }

    // 键盘/鼠标钩子能否安装（杀软拦截在这里会暴露）
    HHOOK kb = SetWindowsHookExW(WH_KEYBOARD_LL, DiagHookProc, GetModuleHandleW(NULL), 0);
    DWORD kbErr = GetLastError();
    HHOOK ms = SetWindowsHookExW(WH_MOUSE_LL, DiagHookProc, GetModuleHandleW(NULL), 0);
    DWORD msErr = GetLastError();
    printf("键盘钩子      : %s (err=%lu)\n", kb ? "OK" : "失败", kb ? 0 : kbErr);
    printf("鼠标钩子      : %s (err=%lu)\n", ms ? "OK" : "失败", ms ? 0 : msErr);
    if (kb) UnhookWindowsHookEx(kb);
    if (ms) UnhookWindowsHookEx(ms);

    printf("\n把以上内容整段发回来即可。\n");
    DWORD cmode = 0;
    if (GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &cmode)) {  // 输出被重定向时不阻塞等待按键
        printf("按任意键退出...\n");
        _getch();
    }
    return 0;
}

// ---------------------------------------------------------------- 自检

static std::string g_stLog;

static void StPrintf(const char* fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    fputs(buf, stdout);
    fflush(stdout);
    g_stLog += buf;
}

static int RunSelfTest() {
    EnsureConsole();
    int fails = 0;
    auto check = [&](const char* name, bool ok, const char* extra) {
        StPrintf("%-28s %s %s\n", name, ok ? "PASS" : "FAIL", extra ? extra : "");
        if (!ok) ++fails;
    };

    // base64
    {
        std::vector<BYTE> src;
        for (int i = 0; i < 32; ++i) src.push_back((BYTE)(i * 7 + 3));
        std::string e = B64Enc(src.data(), src.size());
        std::vector<BYTE> back;
        bool ok = B64Dec(e, back) && back == src && back.size() == 32;
        check("base64 roundtrip(32B)", ok, e.c_str());
    }
    // PBKDF2 已知向量：password/salt/1/32 与 /2/32
    {
        BYTE d1[32], d2[32];
        bool ok = DeriveKey("password", (const BYTE*)"salt", 4, 1, d1, 32);
        std::string h1 = ToHex(d1, 32);
        check("pbkdf2 iter=1",
              ok && h1 == "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
              h1.c_str());
        ok = DeriveKey("password", (const BYTE*)"salt", 4, 2, d2, 32);
        std::string h2 = ToHex(d2, 32);
        check("pbkdf2 iter=2",
              ok && h2 == "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
              h2.c_str());
    }
    // 真实迭代次数耗时（供参考）
    {
        std::vector<BYTE> salt = RandomBytes(16);
        std::vector<BYTE> out(32);
        ULONGLONG t0 = GetTickCount64();
        bool ok = salt.size() == 16 &&
                  DeriveKey("prts-test", salt.data(), 16, kIterations, out.data(), 32);
        char buf[64];
        snprintf(buf, 64, "%llu ms", (unsigned long long)(GetTickCount64() - t0));
        check("pbkdf2 real iterations", ok, buf);
    }
    // 配置写入/读回/校验一致
    {
        std::vector<BYTE> salt = RandomBytes(16);
        std::vector<BYTE> hash(32);
        DeriveKey("S3cret!pass", salt.data(), 16, 1000, hash.data(), 32);
        std::string text = BuildCfgText(salt, hash, 1000, L"\u6d4b\u8bd5\u63d0\u793a");
        std::wstring tmp = LocalAppDir() + L"\\selftest.cfg";
        bool wrote = WriteFileUtf8(tmp, text);
        std::string rb;
        ReadFileUtf8(tmp, rb);
        check("cfg write/read bytes", wrote && rb == text, "");

        // 解析 + 复算
        size_t p = rb.find("salt=");
        std::string saltPart = rb.substr(p + 5, rb.find('\n', p) - p - 5);
        std::vector<BYTE> s2;
        B64Dec(saltPart, s2);
        std::vector<BYTE> h2(32);
        DeriveKey("S3cret!pass", s2.data(), (ULONG)s2.size(), 1000, h2.data(), 32);
        check("cfg salt reparse", s2 == salt, "");
        check("password re-derive match", ConstantTimeEq(h2.data(), hash.data(), 32), "");
        check("wrong password rejected",
              [] {
                  std::vector<BYTE> salt2 = RandomBytes(16);
                  std::vector<BYTE> good(32), bad(32);
                  DeriveKey("right", salt2.data(), 16, 1000, good.data(), 32);
                  DeriveKey("wrong", salt2.data(), 16, 1000, bad.data(), 32);
                  return !ConstantTimeEq(good.data(), bad.data(), 32);
              }(),
              "");
        DeleteFileW(tmp.c_str());
    }
    StPrintf("\nRESULT: %s (%d failed)\n", fails ? "FAILED" : "ALL PASS", fails);
    std::wstring logPath = LocalAppDir() + L"\\selftest.log";
    WriteFileUtf8(logPath, g_stLog);
    StPrintf("log: %ls\n", logPath.c_str());
    return fails ? 1 : 0;
}

// ---------------------------------------------------------------- 入口


// ---------------------------------------------------------------- 启动痕迹
// main 的第一条指令就写这个文件：只要文件没出现，就说明进程根本没被系统启动
// （被 SmartScreen / 杀软 / AppLocker 拦掉），而不是程序自己崩了。
static void TraceStart() {
    wchar_t tmp[MAX_PATH] = {0};
    GetTempPathW(MAX_PATH, tmp);
    std::wstring paths[2] = {std::wstring(tmp) + L"classlock-start.log",
                             ExeDir() + L"classlock-start.log"};
    SYSTEMTIME st;
    GetLocalTime(&st);
    std::string line = "start v1.2 pid=" + std::to_string((unsigned long long)GetCurrentProcessId()) +
                       " time=" + std::to_string(st.wHour) + ":" + std::to_string(st.wMinute) + ":" +
                       std::to_string(st.wSecond) + " cmdline=" + W2U8(GetCommandLineW()) + "\r\n";
    for (int i = 0; i < 2; ++i) {
        HANDLE h = CreateFileW(paths[i].c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                               OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD wrote = 0;
            WriteFile(h, line.data(), (DWORD)line.size(), &wrote, NULL);
            CloseHandle(h);
            return;
        }
    }
}

int main(int, char**) {
    TraceStart();
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    std::vector<std::wstring> args;
    for (int i = 1; i < argc; ++i) args.push_back(argv[i]);
    if (argv) LocalFree(argv);

    g_exeDir = ExeDir();

    std::wstring hint, passFile;
    bool doLock = true, doSet = false, doInstall = false, doUninstall = false, doSelf = false,
         doDiag = false;

    for (size_t i = 0; i < args.size(); ++i) {
        const std::wstring& a = args[i];
        if (a == L"--set-password" || a == L"-p") {
            doSet = true;
            doLock = false;
        } else if (a == L"--lock" || a == L"-l") {
            doLock = true;
        } else if (a == L"--install") {
            doInstall = true;
            doLock = false;
        } else if (a == L"--uninstall") {
            doUninstall = true;
            doLock = false;
        } else if (a == L"--selftest") {
            doSelf = true;
            doLock = false;
        } else if (a == L"--diag") {
            doDiag = true;
            doLock = false;
        } else if (a == L"--passfile" && i + 1 < args.size()) {
            passFile = args[++i];
        } else if (a == L"--hint" && i + 1 < args.size()) {
            hint = args[++i];
        } else if (a == L"--help" || a == L"-h" || a == L"/?") {
            MessageBoxW(NULL,
                        L"ClassLock 用法：\n\n"
                        L"  ClassLock.exe                 锁定屏幕\n"
                        L"  ClassLock.exe --set-password  设置/更换密码\n"
                        L"  ClassLock.exe --install       安装并开机自启\n"
                        L"  ClassLock.exe --uninstall     移除自启\n"
                        L"  ClassLock.exe --selftest      自检\n\n"
                        L"紧急解锁：Ctrl+Alt+Shift+Q 或 Ctrl+Alt+Del 后结束进程。",
                        L"ClassLock", MB_OK | MB_ICONINFORMATION);
            return 0;
        }
    }

    if (doSelf) return RunSelfTest();
    if (doDiag) return CmdDiag();
    if (doSet) return CmdSetPassword(hint, passFile);
    if (doInstall) return CmdInstall();
    if (doUninstall) return CmdUninstall();

    // 单实例
    HANDLE mutex = CreateMutexW(NULL, TRUE, L"Local\\ClassLockSingleton");
    if (mutex && GetLastError() == ERROR_ALREADY_EXISTS) {
        return 0;
    }

    if (doLock) return RunLock();
    return 0;
}
