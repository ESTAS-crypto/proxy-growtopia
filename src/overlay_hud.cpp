#include "overlay_hud.hpp"

#include <objidl.h>
#include <gdiplus.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <sstream>

namespace evan {

namespace {

std::wstring utf8_to_wide(const std::string& s) {
    if (s.empty()) return {};
    int need = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    if (need <= 0) return {};
    std::wstring out(static_cast<size_t>(need), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), out.data(), need);
    return out;
}

void add_round_rect_path(Gdiplus::GraphicsPath& path, float x, float y, float w, float h, float r) {
    const float d = r * 2.0f;
    path.AddArc(x, y, d, d, 180.0f, 90.0f);
    path.AddArc(x + w - d, y, d, d, 270.0f, 90.0f);
    path.AddArc(x + w - d, y + h - d, d, d, 0.0f, 90.0f);
    path.AddArc(x, y + h - d, d, d, 90.0f, 90.0f);
    path.CloseFigure();
}

void fill_round_card(
    Gdiplus::Graphics& g,
    float x,
    float y,
    float w,
    float h,
    float r,
    Gdiplus::Color fill_col,
    Gdiplus::Color border_col,
    float border_w
) {
    Gdiplus::GraphicsPath path;
    add_round_rect_path(path, x, y, w, h, r);
    Gdiplus::SolidBrush fill_brush(fill_col);
    Gdiplus::Pen border_pen(border_col, border_w);
    g.FillPath(&fill_brush, &path);
    g.DrawPath(&border_pen, &path);
}

struct EnumGtCtx {
    DWORD self_pid = 0;
    HWND found = nullptr;
};

BOOL CALLBACK enum_gt_windows_proc(HWND hwnd, LPARAM lparam) {
    auto* ctx = reinterpret_cast<EnumGtCtx*>(lparam);
    if (!IsWindowVisible(hwnd) || IsIconic(hwnd)) {
        return TRUE;
    }
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == ctx->self_pid) {
        return TRUE;
    }
    wchar_t title[128] = {};
    int len = GetWindowTextW(hwnd, title, static_cast<int>(sizeof(title) / sizeof(title[0])));
    if (len <= 0) {
        return TRUE;
    }
    std::wstring wt(title, static_cast<size_t>(len));
    if (wt == L"Growtopia" || wt.rfind(L"Growtopia", 0) == 0) {
        ctx->found = hwnd;
        return FALSE;
    }
    return TRUE;
}

HWND find_growtopia_window() {
    EnumGtCtx ctx;
    ctx.self_pid = GetCurrentProcessId();
    EnumWindows(enum_gt_windows_proc, reinterpret_cast<LPARAM>(&ctx));
    return ctx.found;
}

LRESULT CALLBACK overlay_wnd_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    if (msg == WM_MOUSEACTIVATE) {
        return MA_NOACTIVATE;
    }
    if (msg == WM_NCHITTEST) {
        return HTTRANSPARENT;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

std::string format_mmss(int total_sec) {
    if (total_sec < 0) total_sec = 0;
    const int mins = total_sec / 60;
    const int secs = total_sec % 60;
    char buf[24] = {};
    std::snprintf(buf, sizeof(buf), "%02d:%02d", mins, secs);
    return std::string(buf);
}

} // namespace

OverlayHud::~OverlayHud() {
    destroy();
}

bool OverlayHud::create(HINSTANCE hinst) {
    if (hwnd_) return true;

    const wchar_t* cls_name = L"EvanProxyOverlayHud";
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = overlay_wnd_proc;
    wc.hInstance = hinst;
    wc.lpszClassName = cls_name;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    RegisterClassExW(&wc);

    hwnd_ = CreateWindowExW(
        WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
        cls_name,
        L"EvanProxyHUD",
        WS_POPUP,
        0, 0, 100, 100,
        nullptr,
        nullptr,
        hinst,
        nullptr);

    if (!hwnd_) {
        return false;
    }

    HDC screen_dc = GetDC(nullptr);
    mem_dc_ = CreateCompatibleDC(screen_dc);
    ReleaseDC(nullptr, screen_dc);
    return mem_dc_ != nullptr;
}

void OverlayHud::destroy() {
    hide();
    if (mem_dc_ && old_bmp_) {
        SelectObject(mem_dc_, old_bmp_);
        old_bmp_ = nullptr;
    }
    if (dib_bmp_) {
        DeleteObject(dib_bmp_);
        dib_bmp_ = nullptr;
        dib_bits_ = nullptr;
    }
    if (mem_dc_) {
        DeleteDC(mem_dc_);
        mem_dc_ = nullptr;
    }
    if (hwnd_) {
        DestroyWindow(hwnd_);
        hwnd_ = nullptr;
    }
    dib_w_ = 0;
    dib_h_ = 0;
    last_signature_.clear();
}

void OverlayHud::hide() {
    if (hwnd_ && visible_) {
        ShowWindow(hwnd_, SW_HIDE);
        visible_ = false;
    }
}

void OverlayHud::update(const UiSnapshot& snap, HWND main_gui_hwnd) {
    if (!hwnd_ || !mem_dc_) return;

    if (!snap.hud_overlay) {
        hide();
        return;
    }

    HWND gt_hwnd = find_growtopia_window();
    if (!gt_hwnd) {
        hide();
        return;
    }

    HWND fg = GetForegroundWindow();
    if (fg != gt_hwnd && (!main_gui_hwnd || fg != main_gui_hwnd)) {
        hide();
        return;
    }

    RECT rc{};
    if (!GetClientRect(gt_hwnd, &rc)) {
        hide();
        return;
    }
    POINT tl{rc.left, rc.top};
    ClientToScreen(gt_hwnd, &tl);
    const int w = rc.right - rc.left;
    const int h = rc.bottom - rc.top;
    if (w < 360 || h < 240) {
        hide();
        return;
    }

    std::ostringstream sig;
    sig << tl.x << "," << tl.y << "," << w << "," << h << "|"
        << snap.live_ping_ms << "|" << snap.live_fps << "|"
        << (snap.hud.hotkey_visible ? 1 : 0) << "|" << snap.hud.hotkey_key << "|" << snap.hud.hotkey_cmd << "|"
        << (snap.hud.vend_visible ? 1 : 0) << "|" << snap.hud.vend_rem_stock << "|" << snap.hud.vend_rem_wl << "|"
        << (snap.hud.calc_visible ? 1 : 0) << "|" << snap.hud.calc_title << "|" << snap.hud.calc_value << "|"
        << (snap.hud.timer_active ? 1 : 0) << "|" << snap.hud.timer_remaining_sec;

    const std::string next_sig = sig.str();
    if (visible_ && next_sig == last_signature_) {
        return;
    }
    last_signature_ = next_sig;

    render_bitmap(snap, w, h, tl.x, tl.y);
}

void OverlayHud::render_bitmap(const UiSnapshot& snap, int w, int h, int dst_x, int dst_y) {
    if (w != dib_w_ || h != dib_h_ || !dib_bmp_) {
        if (old_bmp_) {
            SelectObject(mem_dc_, old_bmp_);
            old_bmp_ = nullptr;
        }
        if (dib_bmp_) {
            DeleteObject(dib_bmp_);
            dib_bmp_ = nullptr;
            dib_bits_ = nullptr;
        }
        BITMAPINFO bmi{};
        bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bmi.bmiHeader.biWidth = w;
        bmi.bmiHeader.biHeight = -h; // top-down
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        bmi.bmiHeader.biCompression = BI_RGB;

        HDC screen_dc = GetDC(nullptr);
        dib_bmp_ = CreateDIBSection(screen_dc, &bmi, DIB_RGB_COLORS, &dib_bits_, nullptr, 0);
        ReleaseDC(nullptr, screen_dc);
        if (!dib_bmp_ || !dib_bits_) {
            return;
        }
        old_bmp_ = static_cast<HBITMAP>(SelectObject(mem_dc_, dib_bmp_));
        dib_w_ = w;
        dib_h_ = h;
    }

    std::memset(dib_bits_, 0, static_cast<size_t>(w) * static_cast<size_t>(h) * 4);

    {
        Gdiplus::Bitmap bmp(w, h, w * 4, PixelFormat32bppPARGB, static_cast<BYTE*>(dib_bits_));
        Gdiplus::Graphics g(&bmp);
        g.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
        g.SetTextRenderingHint(Gdiplus::TextRenderingHintAntiAliasGridFit);

        const Gdiplus::Color c_card(236, 10, 26, 44);
        const Gdiplus::Color c_blue_border(255, 111, 183, 230);
        const Gdiplus::Color c_green_border(255, 61, 220, 132);
        const Gdiplus::Color c_gold(255, 255, 210, 74);
        const Gdiplus::Color c_white(255, 255, 255, 255);
        const Gdiplus::Color c_muted(255, 157, 182, 204);
        const Gdiplus::Color c_green_txt(255, 139, 224, 139);
        const Gdiplus::Color c_soft(255, 219, 231, 242);
        const Gdiplus::Color c_cream(255, 255, 233, 176);

        Gdiplus::Font f_brand(L"Segoe UI", 12.5f, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
        Gdiplus::Font f_mono_md(L"Consolas", 13.5f, Gdiplus::FontStyleRegular, Gdiplus::UnitPixel);
        Gdiplus::Font f_mono_bold(L"Consolas", 13.5f, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
        Gdiplus::Font f_tag(L"Segoe UI", 11.0f, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
        Gdiplus::Font f_body(L"Segoe UI", 14.0f, Gdiplus::FontStyleRegular, Gdiplus::UnitPixel);
        Gdiplus::Font f_body_bold(L"Segoe UI", 14.5f, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
        Gdiplus::Font f_timer(L"Consolas", 23.0f, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);

        Gdiplus::SolidBrush b_gold(c_gold);
        Gdiplus::SolidBrush b_white(c_white);
        Gdiplus::SolidBrush b_green(c_green_txt);
        Gdiplus::SolidBrush b_muted(c_muted);
        Gdiplus::SolidBrush b_soft(c_soft);
        Gdiplus::SolidBrush b_cream(c_cream);

        // 1. Top-left HUD chip: EvanProxy [38ms] 60 FPS
        {
            const std::wstring w_ping = L"[" + std::to_wstring(snap.live_ping_ms) + L"ms]";
            const std::wstring w_fps = std::to_wstring(snap.live_fps) + L" FPS";
            const float chip_w = 248.0f;
            const float chip_h = 36.0f;
            fill_round_card(g, 18.0f, 16.0f, chip_w, chip_h, 9.0f, c_card, c_blue_border, 2.0f);
            g.DrawString(L"EvanProxy", -1, &f_brand, Gdiplus::PointF(30.0f, 25.0f), &b_gold);
            g.DrawString(w_ping.c_str(), -1, &f_mono_md, Gdiplus::PointF(112.0f, 26.0f), &b_white);
            g.DrawString(w_fps.c_str(), -1, &f_mono_md, Gdiplus::PointF(186.0f, 26.0f), &b_green);
        }

        // 2. Top-right stack: HOTKEY toast + VEND INFO toast
        float right_x = static_cast<float>(w) - 348.0f;
        float top_y = 16.0f;
        const float card_w = 330.0f;

        if (snap.hud.hotkey_visible) {
            const float hk_h = 58.0f;
            fill_round_card(g, right_x, top_y, card_w, hk_h, 10.0f, c_card, c_blue_border, 2.0f);
            g.DrawString(L"HOTKEY", -1, &f_tag, Gdiplus::PointF(right_x + 14.0f, top_y + 10.0f), &b_muted);
            const std::wstring line = utf8_to_wide(snap.hud.hotkey_key + " ran " + snap.hud.hotkey_cmd);
            g.DrawString(line.c_str(), -1, &f_mono_bold, Gdiplus::PointF(right_x + 14.0f, top_y + 29.0f), &b_cream);
            top_y += hk_h + 10.0f;
        }

        if (snap.hud.vend_visible) {
            const float vh = 88.0f;
            fill_round_card(g, right_x, top_y, card_w, vh, 10.0f, c_card, c_green_border, 2.0f);
            g.DrawString(L"VEND INFO", -1, &f_tag, Gdiplus::PointF(right_x + 14.0f, top_y + 10.0f), &b_green);
            const std::wstring l1 = std::to_wstring(snap.hud.vend_rem_stock) + L" left in this Vending Machine";
            const std::wstring l2 = L"You have " + std::to_wstring(snap.hud.vend_rem_wl) + L" WL left";
            g.DrawString(l1.c_str(), -1, &f_body_bold, Gdiplus::PointF(right_x + 14.0f, top_y + 28.0f), &b_white);
            g.DrawString(l2.c_str(), -1, &f_body, Gdiplus::PointF(right_x + 14.0f, top_y + 47.0f), &b_soft);
            g.DrawString(L"Only you can see this", -1, &f_tag, Gdiplus::PointF(right_x + 14.0f, top_y + 66.0f), &b_muted);
        }

        // 3. Bottom-right stack: CALC /cd + TIMER
        float bot_y = static_cast<float>(h) - 140.0f;
        if (snap.hud.timer_active) {
            const float th = 64.0f;
            bot_y -= th;
            fill_round_card(g, right_x, bot_y, card_w, th, 10.0f, c_card, c_blue_border, 2.0f);
            g.DrawString(L"TIMER \x00B7 /timer", -1, &f_tag, Gdiplus::PointF(right_x + 14.0f, bot_y + 11.0f), &b_muted);
            const std::wstring sub = snap.hud.timer_label.empty() ? L"Countdown active" : utf8_to_wide(snap.hud.timer_label);
            g.DrawString(sub.c_str(), -1, &f_body, Gdiplus::PointF(right_x + 14.0f, bot_y + 31.0f), &b_soft);
            const std::wstring mmss = utf8_to_wide(format_mmss(snap.hud.timer_remaining_sec));
            g.DrawString(mmss.c_str(), -1, &f_timer, Gdiplus::PointF(right_x + 236.0f, bot_y + 18.0f), &b_gold);
            bot_y -= 10.0f;
        }
        if (snap.hud.calc_visible) {
            const float ch = 60.0f;
            bot_y -= ch;
            fill_round_card(g, right_x, bot_y, card_w, ch, 10.0f, c_card, c_blue_border, 2.0f);
            const std::wstring t = utf8_to_wide(snap.hud.calc_title);
            const std::wstring v = utf8_to_wide(snap.hud.calc_value);
            g.DrawString(t.c_str(), -1, &f_tag, Gdiplus::PointF(right_x + 14.0f, bot_y + 10.0f), &b_muted);
            g.DrawString(v.c_str(), -1, &f_body_bold, Gdiplus::PointF(right_x + 14.0f, bot_y + 29.0f), &b_white);
        }

        g.Flush(Gdiplus::FlushIntentionSync);
    }

    POINT pt_dst{dst_x, dst_y};
    SIZE sz{w, h};
    POINT pt_src{0, 0};
    BLENDFUNCTION bf{AC_SRC_OVER, 0, 255, AC_SRC_ALPHA};

    SetWindowPos(hwnd_, HWND_TOPMOST, dst_x, dst_y, w, h,
                 SWP_NOACTIVATE | SWP_SHOWWINDOW);
    UpdateLayeredWindow(hwnd_, nullptr, &pt_dst, &sz, mem_dc_, &pt_src, 0, &bf, ULW_ALPHA);
    visible_ = true;
}

} // namespace evan
