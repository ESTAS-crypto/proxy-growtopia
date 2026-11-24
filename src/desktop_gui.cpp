#include "desktop_gui.hpp"

#include "hosts.hpp"
#include "overlay_hud.hpp"

#include <winsock2.h>
#include <windows.h>
#include <windowsx.h>
#include <objidl.h>
#include <gdiplus.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

namespace evan {

namespace {

constexpr int kLogicalW = 1080;
constexpr int kLogicalH = 680;
constexpr int kTitleH = 56;
constexpr int kFooterH = 38;
constexpr int kSidebarW = 236;

constexpr int IDC_EDIT_WARP = 1001;
constexpr int IDC_EDIT_DOOR = 1002;
constexpr int IDC_EDIT_SEARCH = 1003;
constexpr int IDC_EDIT_HK_KEY = 1004;
constexpr int IDC_EDIT_HK_CMD = 1005;
constexpr int IDC_EDIT_FB_AMT = 1006;
constexpr int IDC_EDIT_CD_AMT = 1007;
constexpr int IDC_EDIT_CMD_QUERY = 1008;

std::wstring utf8_to_w(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

std::string w_to_utf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), out.data(), n, nullptr, nullptr);
    return out;
}

std::string to_lower_ascii(std::string s) {
    for (char& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

std::string trim_ascii(const std::string& s) {
    size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

std::string get_edit_text(HWND edit) {
    if (!edit) return {};
    int len = GetWindowTextLengthW(edit);
    if (len <= 0) return {};
    std::wstring buf(static_cast<size_t>(len + 1), L'\0');
    GetWindowTextW(edit, buf.data(), len + 1);
    buf.resize(static_cast<size_t>(len));
    return w_to_utf8(buf);
}

void set_edit_text(HWND edit, const std::string& text) {
    if (!edit) return;
    const std::wstring w = utf8_to_w(text);
    SetWindowTextW(edit, w.c_str());
}

void copy_text_to_clipboard(HWND hwnd, const std::string& text) {
    if (!OpenClipboard(hwnd)) return;
    EmptyClipboard();
    const std::wstring w = utf8_to_w(text);
    const size_t bytes = (w.size() + 1) * sizeof(wchar_t);
    HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (mem) {
        void* ptr = GlobalLock(mem);
        if (ptr) {
            std::memcpy(ptr, w.c_str(), bytes);
            GlobalUnlock(mem);
            SetClipboardData(CF_UNICODETEXT, mem);
        } else {
            GlobalFree(mem);
        }
    }
    CloseClipboard();
}

void add_rr_path(Gdiplus::GraphicsPath& p, float x, float y, float w, float h, float r) {
    if (r <= 0.5f) {
        p.AddRectangle(Gdiplus::RectF(x, y, w, h));
        return;
    }
    const float d = std::min(r * 2.0f, std::min(w, h));
    p.AddArc(x, y, d, d, 180.0f, 90.0f);
    p.AddArc(x + w - d, y, d, d, 270.0f, 90.0f);
    p.AddArc(x + w - d, y + h - d, d, d, 0.0f, 90.0f);
    p.AddArc(x, y + h - d, d, d, 90.0f, 90.0f);
    p.CloseFigure();
}

void fill_rr(Gdiplus::Graphics& g, float x, float y, float w, float h, float r, Gdiplus::Color fill) {
    Gdiplus::GraphicsPath p;
    add_rr_path(p, x, y, w, h, r);
    Gdiplus::SolidBrush b(fill);
    g.FillPath(&b, &p);
}

void draw_rr(
    Gdiplus::Graphics& g,
    float x,
    float y,
    float w,
    float h,
    float r,
    Gdiplus::Color fill,
    Gdiplus::Color border,
    float border_w = 2.0f
) {
    Gdiplus::GraphicsPath p;
    add_rr_path(p, x, y, w, h, r);
    Gdiplus::SolidBrush b(fill);
    g.FillPath(&b, &p);
    if (border_w > 0.0f && border.GetAlpha() > 0) {
        Gdiplus::Pen pen(border, border_w);
        g.DrawPath(&pen, &p);
    }
}

void draw_toggle_pill(Gdiplus::Graphics& g, float x, float y, bool on) {
    const float w = 48.0f;
    const float h = 26.0f;
    fill_rr(g, x, y, w, h, 13.0f, on ? Gdiplus::Color(255, 61, 220, 132) : Gdiplus::Color(255, 74, 101, 128));
    const float kx = on ? (x + 25.0f) : (x + 3.0f);
    Gdiplus::SolidBrush kb(Gdiplus::Color(255, 255, 255, 255));
    g.FillEllipse(&kb, kx, y + 3.0f, 20.0f, 20.0f);
}

void draw_shield_emblem(Gdiplus::Graphics& g, float x, float y, float size) {
    const float u = size / 16.0f;
    Gdiplus::PointF outer[] = {
        {x + 2 * u, y + 1 * u}, {x + 14 * u, y + 1 * u}, {x + 14 * u, y + 9 * u},
        {x + 11 * u, y + 12 * u}, {x + 8 * u, y + 14.5f * u}, {x + 5 * u, y + 12 * u},
        {x + 2 * u, y + 9 * u}
    };
    Gdiplus::PointF inner[] = {
        {x + 3.2f * u, y + 2.2f * u}, {x + 12.8f * u, y + 2.2f * u}, {x + 12.8f * u, y + 8.6f * u},
        {x + 10.2f * u, y + 11.2f * u}, {x + 8 * u, y + 13.0f * u}, {x + 5.8f * u, y + 11.2f * u},
        {x + 3.2f * u, y + 8.6f * u}
    };
    Gdiplus::SolidBrush bg(Gdiplus::Color(255, 26, 16, 48));
    Gdiplus::SolidBrush gold(Gdiplus::Color(255, 242, 179, 61));
    Gdiplus::SolidBrush hi(Gdiplus::Color(255, 255, 217, 120));
    g.FillPolygon(&bg, outer, 7);
    g.FillPolygon(&gold, inner, 7);
    g.FillRectangle(&hi, x + 3.2f * u, y + 2.2f * u, 9.6f * u, 2.0f * u);

    Gdiplus::Font f(L"Segoe UI", size * 0.5f, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
    Gdiplus::SolidBrush tb(Gdiplus::Color(255, 26, 16, 48));
    Gdiplus::StringFormat sf;
    sf.SetAlignment(Gdiplus::StringAlignmentCenter);
    sf.SetLineAlignment(Gdiplus::StringAlignmentCenter);
    g.DrawString(L"E", -1, &f, Gdiplus::RectF(x, y, size, size * 0.92f), &sf, &tb);
}

enum GtIconKind {
    ICON_TAB_HUB = 0,
    ICON_TAB_WARP,
    ICON_TAB_WARDROBE,
    ICON_TAB_VISUAL,
    ICON_TAB_TITLES,
    ICON_TAB_HOTKEYS,
    ICON_TAB_TOOLS,
    ICON_TAB_PACKETS,
    ICON_TAB_COMMANDS,
    ICON_GEM = 20,
    ICON_PRESET_LEGENDARY,
    ICON_PRESET_RAYMAN,
    ICON_PRESET_ANGEL,
    ICON_TITLE_MAXLEVEL,
    ICON_TITLE_DOCTOR,
    ICON_TITLE_LEGENDARY,
    ICON_TITLE_MOD,
    ICON_TITLE_DEV,
    ICON_TITLE_RESET,
    ICON_NET_LOCK,
    ICON_NET_BOLT,
    ICON_NET_SHIELD
};

void draw_gt_icon(Gdiplus::Graphics& g, int kind, float x, float y, float sz) {
    const float u = sz / 24.0f;
    auto pt = [&](float px, float py) { return Gdiplus::PointF(x + px * u, y + py * u); };

    switch (kind) {
        case ICON_TAB_HUB: {
            // World/Blue Gem Lock icon
            Gdiplus::SolidBrush rim(Gdiplus::Color(255, 34, 211, 238));
            Gdiplus::SolidBrush body(Gdiplus::Color(255, 14, 116, 144));
            Gdiplus::SolidBrush keyhole(Gdiplus::Color(255, 255, 224, 102));
            Gdiplus::Pen arc_pen(Gdiplus::Color(255, 186, 230, 253), std::max(1.8f, 2.2f * u));
            g.DrawArc(&arc_pen, x + 6.5f * u, y + 2.0f * u, 11.0f * u, 10.0f * u, 180.0f, 180.0f);
            fill_rr(g, x + 4.0f * u, y + 8.0f * u, 16.0f * u, 13.0f * u, 3.0f * u, Gdiplus::Color(255, 56, 189, 248));
            fill_rr(g, x + 5.5f * u, y + 9.5f * u, 13.0f * u, 10.0f * u, 2.0f * u, Gdiplus::Color(255, 14, 116, 144));
            g.FillEllipse(&keyhole, x + 9.8f * u, y + 11.5f * u, 4.4f * u, 4.4f * u);
            Gdiplus::PointF tri[] = {pt(12.0f, 14.0f), pt(14.0f, 18.0f), pt(10.0f, 18.0f)};
            g.FillPolygon(&keyhole, tri, 3);
            (void)rim; (void)body;
            break;
        }
        case ICON_TAB_WARP: {
            // Growtopia Door / Swirling Portal
            fill_rr(g, x + 4.5f * u, y + 2.5f * u, 15.0f * u, 19.0f * u, 3.5f * u, Gdiplus::Color(255, 96, 165, 250));
            fill_rr(g, x + 6.5f * u, y + 4.5f * u, 11.0f * u, 15.0f * u, 2.5f * u, Gdiplus::Color(255, 15, 23, 42));
            Gdiplus::Pen sw(Gdiplus::Color(255, 56, 189, 248), std::max(1.5f, 2.0f * u));
            g.DrawEllipse(&sw, x + 8.0f * u, y + 7.5f * u, 8.0f * u, 8.0f * u);
            Gdiplus::SolidBrush dot(Gdiplus::Color(255, 255, 210, 74));
            g.FillEllipse(&dot, x + 10.6f * u, y + 10.2f * u, 2.8f * u, 2.8f * u);
            break;
        }
        case ICON_TAB_WARDROBE:
        case ICON_PRESET_ANGEL: {
            // Angel Wings / Halo
            const Gdiplus::Color wing_col = (kind == ICON_PRESET_ANGEL)
                ? Gdiplus::Color(255, 186, 230, 253)
                : Gdiplus::Color(255, 248, 250, 252);
            Gdiplus::SolidBrush wb(wing_col);
            Gdiplus::PointF lw[] = {pt(11, 14), pt(2, 6), pt(3, 12), pt(6, 16), pt(11, 17)};
            Gdiplus::PointF rw[] = {pt(13, 14), pt(22, 6), pt(21, 12), pt(18, 16), pt(13, 17)};
            g.FillPolygon(&wb, lw, 5);
            g.FillPolygon(&wb, rw, 5);
            Gdiplus::Pen halo(Gdiplus::Color(255, 255, 210, 74), std::max(1.8f, 2.1f * u));
            g.DrawEllipse(&halo, x + 7.0f * u, y + 4.0f * u, 10.0f * u, 4.2f * u);
            break;
        }
        case ICON_TAB_VISUAL: {
            // Vibrant Palette / Weather orb
            Gdiplus::SolidBrush b1(Gdiplus::Color(255, 192, 132, 252));
            Gdiplus::SolidBrush b2(Gdiplus::Color(255, 56, 189, 248));
            Gdiplus::SolidBrush b3(Gdiplus::Color(255, 250, 204, 21));
            Gdiplus::SolidBrush b4(Gdiplus::Color(255, 248, 113, 113));
            g.FillEllipse(&b1, x + 3.0f * u, y + 3.0f * u, 18.0f * u, 18.0f * u);
            g.FillEllipse(&b2, x + 6.0f * u, y + 6.5f * u, 4.5f * u, 4.5f * u);
            g.FillEllipse(&b3, x + 13.0f * u, y + 6.5f * u, 4.5f * u, 4.5f * u);
            g.FillEllipse(&b4, x + 9.5f * u, y + 13.0f * u, 4.5f * u, 4.5f * u);
            break;
        }
        case ICON_TAB_TITLES:
        case ICON_TITLE_LEGENDARY:
        case ICON_PRESET_LEGENDARY: {
            // Golden Trophy / Legendary Orb
            Gdiplus::SolidBrush g1(Gdiplus::Color(255, 255, 210, 74));
            Gdiplus::SolidBrush g2(Gdiplus::Color(255, 249, 115, 22));
            Gdiplus::PointF cup[] = {pt(6, 4), pt(18, 4), pt(16, 13), pt(12, 16), pt(8, 13)};
            g.FillPolygon(&g1, cup, 5);
            g.FillRectangle(&g2, x + 10.2f * u, y + 15.0f * u, 3.6f * u, 4.0f * u);
            fill_rr(g, x + 7.5f * u, y + 18.5f * u, 9.0f * u, 3.0f * u, 1.0f * u, Gdiplus::Color(255, 251, 191, 36));
            Gdiplus::Pen hp(Gdiplus::Color(255, 255, 237, 170), std::max(1.4f, 1.8f * u));
            g.DrawArc(&hp, x + 3.2f * u, y + 5.2f * u, 4.0f * u, 6.0f * u, 90.0f, 180.0f);
            g.DrawArc(&hp, x + 16.8f * u, y + 5.2f * u, 4.0f * u, 6.0f * u, 270.0f, 180.0f);
            break;
        }
        case ICON_TAB_HOTKEYS: {
            // Keycap + Lightning Bolt
            draw_rr(g, x + 2.5f * u, y + 3.0f * u, 19.0f * u, 18.0f * u, 3.5f * u,
                    Gdiplus::Color(255, 24, 58, 92), Gdiplus::Color(255, 74, 222, 128), 1.6f);
            Gdiplus::SolidBrush bolt(Gdiplus::Color(255, 250, 204, 21));
            Gdiplus::PointF bp[] = {pt(13.5f, 5.5f), pt(8.5f, 12.5f), pt(12.2f, 12.5f), pt(10.5f, 18.5f), pt(15.8f, 11.2f), pt(12.0f, 11.2f)};
            g.FillPolygon(&bolt, bp, 6);
            break;
        }
        case ICON_TAB_TOOLS:
        case ICON_TITLE_DEV: {
            // Growtopia Wrench
            Gdiplus::Pen wp(Gdiplus::Color(255, 203, 213, 225), std::max(2.6f, 3.2f * u));
            wp.SetStartCap(Gdiplus::LineCapRound);
            wp.SetEndCap(Gdiplus::LineCapRound);
            g.DrawLine(&wp, x + 6.0f * u, y + 18.0f * u, x + 16.5f * u, y + 7.5f * u);
            Gdiplus::SolidBrush head(Gdiplus::Color(255, 226, 232, 240));
            g.FillEllipse(&head, x + 12.5f * u, y + 2.8f * u, 8.2f * u, 8.2f * u);
            Gdiplus::SolidBrush cut(Gdiplus::Color(255, 11, 28, 48));
            Gdiplus::PointF notch[] = {pt(16, 6), pt(21, 3), pt(21, 7)};
            g.FillPolygon(&cut, notch, 3);
            break;
        }
        case ICON_TAB_PACKETS: {
            // Radar Pulse Wave
            Gdiplus::Pen rp(Gdiplus::Color(255, 248, 113, 113), std::max(1.8f, 2.0f * u));
            rp.SetLineJoin(Gdiplus::LineJoinRound);
            Gdiplus::PointF wave[] = {pt(2, 12), pt(7, 12), pt(9.5f, 5), pt(13.5f, 19), pt(16.5f, 9), pt(18.5f, 12), pt(22, 12)};
            g.DrawLines(&rp, wave, 7);
            break;
        }
        case ICON_TAB_COMMANDS: {
            // Terminal Book
            fill_rr(g, x + 3.0f * u, y + 3.5f * u, 18.0f * u, 17.0f * u, 3.0f * u, Gdiplus::Color(255, 15, 23, 42));
            Gdiplus::Pen bp(Gdiplus::Color(255, 148, 163, 184), 1.5f);
            g.DrawRectangle(&bp, x + 3.5f * u, y + 4.0f * u, 17.0f * u, 16.0f * u);
            Gdiplus::Pen cp(Gdiplus::Color(255, 74, 222, 128), std::max(1.8f, 2.0f * u));
            g.DrawLine(&cp, x + 7.0f * u, y + 9.0f * u, x + 11.0f * u, y + 12.0f * u);
            g.DrawLine(&cp, x + 7.0f * u, y + 15.0f * u, x + 11.0f * u, y + 12.0f * u);
            g.DrawLine(&cp, x + 12.5f * u, y + 15.0f * u, x + 17.0f * u, y + 15.0f * u);
            break;
        }
        case ICON_GEM: {
            // Growtopia Gem Crystal (Multi-facet Cyan/Magenta Emerald)
            Gdiplus::PointF outer[] = {pt(12, 2), pt(20, 8), pt(18, 18), pt(12, 22), pt(6, 18), pt(4, 8)};
            Gdiplus::PointF inner[] = {pt(12, 5.5f), pt(16.8f, 9.5f), pt(15.5f, 16.5f), pt(12, 19.0f), pt(8.5f, 16.5f), pt(7.2f, 9.5f)};
            Gdiplus::SolidBrush c1(Gdiplus::Color(255, 34, 211, 238));
            Gdiplus::SolidBrush c2(Gdiplus::Color(255, 168, 85, 247));
            Gdiplus::SolidBrush hi(Gdiplus::Color(255, 224, 242, 254));
            g.FillPolygon(&c1, outer, 6);
            g.FillPolygon(&c2, inner, 6);
            Gdiplus::PointF shine[] = {pt(12, 3), pt(16, 8), pt(12, 10), pt(8, 8)};
            g.FillPolygon(&hi, shine, 4);
            break;
        }
        case ICON_PRESET_RAYMAN: {
            // Red/Gold Power Fist
            Gdiplus::SolidBrush fb(Gdiplus::Color(255, 239, 68, 68));
            Gdiplus::SolidBrush gd(Gdiplus::Color(255, 250, 204, 21));
            fill_rr(g, x + 4.5f * u, y + 6.0f * u, 15.0f * u, 13.0f * u, 4.0f * u, Gdiplus::Color(255, 239, 68, 68));
            for (int f = 0; f < 4; ++f) {
                fill_rr(g, x + (5.2f + f * 3.4f) * u, y + 4.0f * u, 2.8f * u, 5.0f * u, 1.0f * u, Gdiplus::Color(255, 254, 202, 202));
            }
            g.FillRectangle(&gd, x + 6.0f * u, y + 16.5f * u, 12.0f * u, 3.0f * u);
            (void)fb;
            break;
        }
        case ICON_TITLE_MAXLEVEL: {
            // Glowing Lv.125 Blue Star
            Gdiplus::SolidBrush sb(Gdiplus::Color(255, 56, 189, 248));
            Gdiplus::SolidBrush core(Gdiplus::Color(255, 224, 242, 254));
            Gdiplus::PointF star[] = {
                pt(12, 2), pt(14.8f, 8.5f), pt(21.5f, 9.2f), pt(16.3f, 13.8f), pt(17.9f, 20.5f),
                pt(12, 17.0f), pt(6.1f, 20.5f), pt(7.7f, 13.8f), pt(2.5f, 9.2f), pt(9.2f, 8.5f)
            };
            g.FillPolygon(&sb, star, 10);
            g.FillEllipse(&core, x + 9.0f * u, y + 9.0f * u, 6.0f * u, 6.0f * u);
            break;
        }
        case ICON_TITLE_DOCTOR: {
            // Caduceus Medical Cross
            fill_rr(g, x + 3.0f * u, y + 3.0f * u, 18.0f * u, 18.0f * u, 4.0f * u, Gdiplus::Color(255, 220, 38, 38));
            Gdiplus::SolidBrush wb(Gdiplus::Color(255, 255, 255, 255));
            g.FillRectangle(&wb, x + 10.0f * u, y + 6.0f * u, 4.0f * u, 12.0f * u);
            g.FillRectangle(&wb, x + 6.0f * u, y + 10.0f * u, 12.0f * u, 4.0f * u);
            break;
        }
        case ICON_TITLE_MOD:
        case ICON_NET_SHIELD: {
            // Emerald Shield
            Gdiplus::SolidBrush sb(Gdiplus::Color(255, 34, 197, 94));
            Gdiplus::PointF sh[] = {pt(4, 4), pt(20, 4), pt(20, 12), pt(12, 21), pt(4, 12)};
            g.FillPolygon(&sb, sh, 5);
            Gdiplus::Pen chk(Gdiplus::Color(255, 255, 255, 255), std::max(2.0f, 2.2f * u));
            g.DrawLine(&chk, x + 8.0f * u, y + 12.0f * u, x + 11.0f * u, y + 15.0f * u);
            g.DrawLine(&chk, x + 11.0f * u, y + 15.0f * u, x + 16.5f * u, y + 8.5f * u);
            break;
        }
        case ICON_TITLE_RESET: {
            // Reset Circular Arrow
            Gdiplus::Pen rp(Gdiplus::Color(255, 148, 163, 184), std::max(2.2f, 2.5f * u));
            g.DrawArc(&rp, x + 4.5f * u, y + 4.5f * u, 15.0f * u, 15.0f * u, 35.0f, 285.0f);
            Gdiplus::SolidBrush ab(Gdiplus::Color(255, 203, 213, 225));
            Gdiplus::PointF ah[] = {pt(17, 3), pt(21, 9), pt(14.5f, 9.5f)};
            g.FillPolygon(&ab, ah, 3);
            break;
        }
        case ICON_NET_LOCK: {
            fill_rr(g, x + 5.0f * u, y + 9.0f * u, 14.0f * u, 11.0f * u, 2.5f * u, Gdiplus::Color(255, 56, 189, 248));
            Gdiplus::Pen lp(Gdiplus::Color(255, 224, 242, 254), 2.0f);
            g.DrawArc(&lp, x + 7.5f * u, y + 3.5f * u, 9.0f * u, 9.0f * u, 180.0f, 180.0f);
            break;
        }
        case ICON_NET_BOLT: {
            Gdiplus::SolidBrush lb(Gdiplus::Color(255, 250, 204, 21));
            Gdiplus::PointF bp[] = {pt(14, 2), pt(6, 13), pt(12, 13), pt(10, 22), pt(18, 11), pt(12, 11)};
            g.FillPolygon(&lb, bp, 6);
            break;
        }
        default: {
            Gdiplus::SolidBrush fb(Gdiplus::Color(255, 111, 209, 255));
            g.FillEllipse(&fb, x + 4.0f * u, y + 4.0f * u, 16.0f * u, 16.0f * u);
            break;
        }
    }
}

struct CmdEntry {
    const char* cmd;
    const char* copy_template;
    const char* desc;
};

constexpr CmdEntry kCommands[] = {
    {"/warp <world>", "/warp ", "Jump to a world without going through World Select"},
    {"/back · /re · /exit", "/back", "Quick navigation shortcuts"},
    {"/cd <amount>", "/cd 102", "Break DL/BGL or combine 100 WL into a DL, based on your stock"},
    {"/autobgl", "/autobgl", "Wrench a Telephone to trade 100 DL for 1 BGL"},
    {"/gems [on|off|reset|scan]", "/gems", "Live Gem counter bubble & world floor gems/items scanner"},
    {"/fastbuy [off|quick|auto]", "/fastbuy auto", "Faster Vending Machine purchases (alias /fb)"},
    {"/vendinfo [on|off]", "/vendinfo", "Local notice with remaining stock and your WL"},
    {"/hotkey", "/hotkey", "Open the 12-slot hotkey editor"},
    {"/paction", "/paction", "Log walk, jump, punch and click actions"},
    {"/pmove", "/pmove", "Raw movement output"},
    {"/plog", "/plog", "Verbose console output of all packets"},
    {"/phex", "/phex", "Hex dump of packets"},
    {"/clothes [on|off|clear|preset]", "/clothes", "Visual clothes and wardrobe mode"},
    {"/search <item>", "/search ", "Pull items from items.dat into the visual backpack"},
    {"/title <name>", "/title ", "Apply a title (maxlevel, doctor, legendary, 10y, award, party, winter, immortal, mod, dev)"},
    {"/fps [on|off|boost|bubbles]", "/fps boost", "Ping tags and FPS boost"},
    {"/evantag", "/evantag", "Add the [EvanProxy] tag to chat"},
    {"/evanchat", "/evanchat", "Add a prefix to outgoing chat"},
    {"/wrench [info|pull|kick|ban|off]", "/wrench info", "Wrench shortcuts"},
    {"/hud [on|off]", "/hud", "Toggle the floating in-game HUD overlay"},
    {"/ping", "/ping", "Show live server ping (RTT, min/max, jitter)"},
    {"/winfo", "/winfo", "World & player summary in game"},
    {"/calc <expr>", "/calc ", "Quick calculator with HUD readout"},
    {"/timer <sec>", "/timer 300", "Countdown timer in chat and HUD overlay"},
    {"/convert", "/convert", "Convert 100 WL into 1 DL"},
    {"/banner", "/banner", "Toggle custom EvanProxy banner in /proxy and Gazette"}
};

struct HitItem {
    std::string id;
    float x = 0;
    float y = 0;
    float w = 0;
    float h = 0;
    int arg_int = 0;
    std::string arg_str;
};

enum class AppView {
    Launcher = 0,
    Dashboard
};

enum DashTab {
    TAB_HUB = 0,
    TAB_WARP,
    TAB_WARDROBE,
    TAB_VISUAL,
    TAB_TITLES,
    TAB_HOTKEYS,
    TAB_TOOLS,
    TAB_PACKETS,
    TAB_COMMANDS,
    TAB_COUNT
};

class GuiWindow {
public:
    GuiWindow(ProxyController& controller, bool auto_start)
        : controller_(controller), auto_start_(auto_start) {}

    int run();

private:
    static LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);
    LRESULT handle_msg(UINT msg, WPARAM wparam, LPARAM lparam);

    void on_create();
    void on_paint();
    void on_lbutton_down(int px, int py);
    void on_mouse_move(int px, int py);
    void on_lbutton_up();
    void on_mouse_wheel(int delta);
    void handle_click(const HitItem& item);

    void sync_edit_controls(bool force_reload_fields = false);
    void recreate_edit_font();
    void refresh_dpi();
    void trigger_start_stop();
    void trigger_clean_hosts();
    void update_zoom_from_mouse(float lx);

    ProxyController& controller_;
    bool auto_start_ = false;
    HWND hwnd_ = nullptr;
    HINSTANCE hinst_ = nullptr;
    OverlayHud overlay_hud_;

    float dpi_scale_ = 1.0f;
    AppView view_ = AppView::Launcher;
    int dash_tab_ = TAB_HUB;
    int selected_hk_slot_ = 0;
    int console_scroll_ = 0;
    int pkt_scroll_ = 0;
    int cmd_scroll_ = 0;
    bool console_auto_scroll_ = true;
    bool pkt_auto_scroll_ = true;
    bool dragging_zoom_ = false;
    float zoom_track_x_ = 0.0f;
    float zoom_track_w_ = 1.0f;

    std::string footer_notice_;
    int64_t footer_notice_until_ms_ = 0;

    UiSnapshot snap_;
    std::vector<ConsoleLine> console_lines_;
    std::vector<ConsoleLine> packet_lines_;
    std::vector<HitItem> hits_;
    std::string hover_id_;

    // Child Edit boxes
    HWND edit_warp_ = nullptr;
    HWND edit_door_ = nullptr;
    HWND edit_search_ = nullptr;
    HWND edit_hk_key_ = nullptr;
    HWND edit_hk_cmd_ = nullptr;
    HWND edit_fb_amt_ = nullptr;
    HWND edit_cd_amt_ = nullptr;
    HWND edit_cmd_query_ = nullptr;
    HBRUSH edit_bg_brush_ = nullptr;
    HFONT edit_font_ = nullptr;

    // GDI backbuffer
    HDC back_dc_ = nullptr;
    HBITMAP back_bmp_ = nullptr;
    HBITMAP back_old_bmp_ = nullptr;
    int back_w_ = 0;
    int back_h_ = 0;
    bool needs_repaint_ = true;
    uint64_t last_render_hash_ = 0;
};

uint64_t fnv1a_step(uint64_t h, const void* data, size_t len) {
    const auto* p = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

template <typename T>
void hash_val(uint64_t& h, const T& v) {
    h = fnv1a_step(h, &v, sizeof(v));
}

void hash_str(uint64_t& h, const std::string& s) {
    h = fnv1a_step(h, s.data(), s.size());
    const uint8_t sep = 0xff;
    h = fnv1a_step(h, &sep, 1);
}

int GuiWindow::run() {
    if (auto p_dpi = reinterpret_cast<BOOL(WINAPI*)()>(
            GetProcAddress(GetModuleHandleW(L"user32.dll"), "SetProcessDPIAware"))) {
        p_dpi();
    }

    Gdiplus::GdiplusStartupInput gdi_in;
    ULONG_PTR gdi_token = 0;
    if (Gdiplus::GdiplusStartup(&gdi_token, &gdi_in, nullptr) != Gdiplus::Ok) {
        return 1;
    }

    hinst_ = GetModuleHandleW(nullptr);
    const wchar_t* cls_name = L"EvanProxyDesktopWindow";

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = &GuiWindow::wnd_proc;
    wc.hInstance = hinst_;
    wc.lpszClassName = cls_name;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    RegisterClassExW(&wc);

    HDC screen_dc = GetDC(nullptr);
    const int sys_dpi = GetDeviceCaps(screen_dc, LOGPIXELSX);
    ReleaseDC(nullptr, screen_dc);
    dpi_scale_ = std::max(1.0f, static_cast<float>(sys_dpi) / 96.0f);

    const int init_w = static_cast<int>(kLogicalW * dpi_scale_ + 0.5f);
    const int init_h = static_cast<int>(kLogicalH * dpi_scale_ + 0.5f);
    const int sx = GetSystemMetrics(SM_CXSCREEN);
    const int sy = GetSystemMetrics(SM_CYSCREEN);
    const int init_x = std::max(0, (sx - init_w) / 2);
    const int init_y = std::max(0, (sy - init_h) / 2);

    hwnd_ = CreateWindowExW(
        WS_EX_APPWINDOW,
        cls_name,
        L"EvanProxy - Growtopia Local Proxy",
        WS_POPUP | WS_CLIPCHILDREN | WS_MINIMIZEBOX | WS_SYSMENU,
        init_x, init_y, init_w, init_h,
        nullptr,
        nullptr,
        hinst_,
        this);

    if (!hwnd_) {
        Gdiplus::GdiplusShutdown(gdi_token);
        return 1;
    }

    ShowWindow(hwnd_, SW_SHOWNORMAL);
    UpdateWindow(hwnd_);

    if (auto_start_) {
        trigger_start_stop();
    }

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    overlay_hud_.destroy();
    controller_.stop();

    if (back_dc_ && back_old_bmp_) {
        SelectObject(back_dc_, back_old_bmp_);
        back_old_bmp_ = nullptr;
    }
    if (back_bmp_) {
        DeleteObject(back_bmp_);
        back_bmp_ = nullptr;
    }
    if (back_dc_) {
        DeleteDC(back_dc_);
        back_dc_ = nullptr;
    }
    if (edit_font_) {
        DeleteObject(edit_font_);
        edit_font_ = nullptr;
    }
    if (edit_bg_brush_) {
        DeleteObject(edit_bg_brush_);
        edit_bg_brush_ = nullptr;
    }

    Gdiplus::GdiplusShutdown(gdi_token);
    return static_cast<int>(msg.wParam);
}

LRESULT CALLBACK GuiWindow::wnd_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    GuiWindow* self = nullptr;
    if (msg == WM_NCCREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCTW*>(lparam);
        self = reinterpret_cast<GuiWindow*>(cs->lpCreateParams);
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
        self->hwnd_ = hwnd;
    } else {
        self = reinterpret_cast<GuiWindow*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    }
    if (self) {
        return self->handle_msg(msg, wparam, lparam);
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

void GuiWindow::refresh_dpi() {
    float next_scale = dpi_scale_;
    using GetDpiForWinFn = UINT(WINAPI*)(HWND);
    if (auto fn = reinterpret_cast<GetDpiForWinFn>(
            GetProcAddress(GetModuleHandleW(L"user32.dll"), "GetDpiForWindow"))) {
        const UINT d = fn(hwnd_);
        if (d >= 96) next_scale = static_cast<float>(d) / 96.0f;
    }
    if (std::abs(next_scale - dpi_scale_) > 0.01f) {
        dpi_scale_ = next_scale;
        recreate_edit_font();
    }
}

void GuiWindow::recreate_edit_font() {
    if (edit_font_) {
        DeleteObject(edit_font_);
        edit_font_ = nullptr;
    }
    const int fh = -static_cast<int>(15.0f * dpi_scale_ + 0.5f);
    edit_font_ = CreateFontW(
        fh, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    for (HWND e : {edit_warp_, edit_door_, edit_search_, edit_hk_key_,
                   edit_hk_cmd_, edit_fb_amt_, edit_cd_amt_, edit_cmd_query_}) {
        if (e && edit_font_) {
            SendMessageW(e, WM_SETFONT, reinterpret_cast<WPARAM>(edit_font_), TRUE);
        }
    }
}

void GuiWindow::on_create() {
    edit_bg_brush_ = CreateSolidBrush(RGB(10, 26, 44));
    auto mk_edit = [&](int id, const wchar_t* initial) -> HWND {
        return CreateWindowExW(
            0, L"EDIT", initial,
            WS_CHILD | ES_AUTOHSCROLL,
            0, 0, 100, 24,
            hwnd_,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
            hinst_,
            nullptr);
    };
    edit_warp_ = mk_edit(IDC_EDIT_WARP, L"");
    edit_door_ = mk_edit(IDC_EDIT_DOOR, L"");
    edit_search_ = mk_edit(IDC_EDIT_SEARCH, L"");
    edit_hk_key_ = mk_edit(IDC_EDIT_HK_KEY, L"");
    edit_hk_cmd_ = mk_edit(IDC_EDIT_HK_CMD, L"");
    edit_fb_amt_ = mk_edit(IDC_EDIT_FB_AMT, L"1");
    edit_cd_amt_ = mk_edit(IDC_EDIT_CD_AMT, L"102");
    edit_cmd_query_ = mk_edit(IDC_EDIT_CMD_QUERY, L"");

    recreate_edit_font();
    snap_ = controller_.get_live_snapshot();
    set_edit_text(edit_fb_amt_, std::to_string(snap_.fast_buy_qty));
    if (!snap_.hotkeys.empty()) {
        set_edit_text(edit_hk_key_, snap_.hotkeys[0].key);
        set_edit_text(edit_hk_cmd_, snap_.hotkeys[0].command);
    }
    sync_edit_controls(true);
    overlay_hud_.create(hinst_);
    SetTimer(hwnd_, 1, 100, nullptr);
}

void GuiWindow::sync_edit_controls(bool force_reload_fields) {
    auto place = [&](HWND e, bool show, float lx, float ly, float lw, float lh) {
        if (!e) return;
        if (!show) {
            if (IsWindowVisible(e)) ShowWindow(e, SW_HIDE);
            return;
        }
        const int x = static_cast<int>(lx * dpi_scale_ + 0.5f);
        const int y = static_cast<int>(ly * dpi_scale_ + 0.5f);
        const int w = static_cast<int>(lw * dpi_scale_ + 0.5f);
        const int h = static_cast<int>(lh * dpi_scale_ + 0.5f);
        MoveWindow(e, x, y, w, h, TRUE);
        if (!IsWindowVisible(e)) ShowWindow(e, SW_SHOW);
    };

    const bool is_dash = (view_ == AppView::Dashboard);
    const float cx = static_cast<float>(kSidebarW) + 24.0f;
    const float cw = static_cast<float>(kLogicalW - kSidebarW) - 48.0f;
    const float top = static_cast<float>(kTitleH) + 20.0f;

    // Warp Navigation edits
    place(edit_warp_, is_dash && dash_tab_ == TAB_WARP, cx + 28.0f, top + 107.0f, cw - 178.0f, 24.0f);
    place(edit_door_, is_dash && dash_tab_ == TAB_WARP, cx + 28.0f, top + 349.0f, cw - 178.0f, 24.0f);

    // Wardrobe edit
    place(edit_search_, is_dash && dash_tab_ == TAB_WARDROBE, cx + 14.0f, top + 68.0f, cw - 210.0f, 24.0f);

    // Hotkeys edits
    if (is_dash && dash_tab_ == TAB_HOTKEYS && force_reload_fields) {
        if (selected_hk_slot_ >= 0 && static_cast<size_t>(selected_hk_slot_) < snap_.hotkeys.size()) {
            set_edit_text(edit_hk_key_, snap_.hotkeys[static_cast<size_t>(selected_hk_slot_)].key);
            set_edit_text(edit_hk_cmd_, snap_.hotkeys[static_cast<size_t>(selected_hk_slot_)].command);
        }
    }
    place(edit_hk_key_, is_dash && dash_tab_ == TAB_HOTKEYS, cx + 28.0f, top + 373.0f, 152.0f, 22.0f);
    place(edit_hk_cmd_, is_dash && dash_tab_ == TAB_HOTKEYS, cx + 204.0f, top + 373.0f, cw - 418.0f, 22.0f);

    // Tools edits
    if (is_dash && dash_tab_ == TAB_TOOLS && force_reload_fields) {
        set_edit_text(edit_fb_amt_, std::to_string(snap_.fast_buy_qty));
    }
    const float fb_card_w = (cw - 14.0f) * 0.535f;
    place(edit_fb_amt_, is_dash && dash_tab_ == TAB_TOOLS, cx + 88.0f, top + 240.0f, 74.0f, 22.0f);
    place(edit_cd_amt_, is_dash && dash_tab_ == TAB_TOOLS, cx + 146.0f, top + 340.0f, 86.0f, 22.0f);
    (void)fb_card_w;

    // Commands edit
    place(edit_cmd_query_, is_dash && dash_tab_ == TAB_COMMANDS, cx + 14.0f, top + 68.0f, cw - 28.0f, 24.0f);
}

void GuiWindow::trigger_start_stop() {
    if (controller_.is_running()) {
        controller_.stop();
        snap_ = controller_.get_live_snapshot();
        needs_repaint_ = true;
        InvalidateRect(hwnd_, nullptr, FALSE);
        return;
    }

    std::string err;
    bool port_conflict = false;
    bool needs_admin = false;
    if (!controller_.start(err, port_conflict, needs_admin)) {
        if (needs_admin) {
            int res = MessageBoxW(
                hwnd_,
                L"Editing the Windows hosts file requires Administrator privileges.\n\nRestart EvanProxy as Administrator and start the proxy?",
                L"EvanProxy - Administrator Required",
                MB_YESNO | MB_ICONQUESTION);
            if (res == IDYES) {
                if (hosts::relaunch_as_admin("--autostart")) {
                    PostQuitMessage(0);
                    return;
                }
            }
        }
    }
    snap_ = controller_.get_live_snapshot();
    needs_repaint_ = true;
    InvalidateRect(hwnd_, nullptr, FALSE);
}

void GuiWindow::trigger_clean_hosts() {
    std::string err;
    bool needs_admin = false;
    if (controller_.clean_leftover_hosts(err, needs_admin)) {
        footer_notice_ = "Cleaned leftover EvanProxy hosts entries";
        footer_notice_until_ms_ = steady_now_ms() + 3000;
    } else if (needs_admin) {
        int res = MessageBoxW(
            hwnd_,
            L"Cleaning the Windows hosts file requires Administrator privileges.\n\nRun cleanup as Administrator?",
            L"EvanProxy - Administrator Required",
            MB_YESNO | MB_ICONQUESTION);
        if (res == IDYES) {
            hosts::relaunch_as_admin("--clean-hosts");
        }
    }
    snap_ = controller_.get_live_snapshot();
    needs_repaint_ = true;
    InvalidateRect(hwnd_, nullptr, FALSE);
}

void GuiWindow::update_zoom_from_mouse(float lx) {
    if (zoom_track_w_ <= 10.0f) return;
    float t = (lx - zoom_track_x_) / zoom_track_w_;
    if (t < 0.0f) t = 0.0f;
    if (t > 1.0f) t = 1.0f;
    int pct = 50 + static_cast<int>(std::round((t * 150.0f) / 5.0f)) * 5;
    if (pct < 50) pct = 50;
    if (pct > 200) pct = 200;
    if (pct != snap_.zoom_percent) {
        snap_.zoom_percent = pct;
        UiCommand cmd;
        cmd.kind = UiCommand::Kind::SetZoomPercent;
        cmd.int_arg = pct;
        controller_.dispatch_ui_command(cmd);
        needs_repaint_ = true;
        InvalidateRect(hwnd_, nullptr, FALSE);
    }
}

void GuiWindow::handle_click(const HitItem& item) {
    const std::string& id = item.id;
    auto push_toggle = [&](const char* key, bool next_val) {
        UiCommand cmd;
        cmd.kind = UiCommand::Kind::SetToggle;
        cmd.key = key;
        cmd.bool_arg = next_val;
        controller_.dispatch_ui_command(cmd);
    };
    auto push_chat = [&](const std::string& text) {
        UiCommand cmd;
        cmd.kind = UiCommand::Kind::RunChatCommand;
        cmd.value = text;
        controller_.dispatch_ui_command(cmd);
    };

    if (id == "win_min") {
        ShowWindow(hwnd_, SW_MINIMIZE);
        return;
    }
    if (id == "win_close") {
        PostMessageW(hwnd_, WM_CLOSE, 0, 0);
        return;
    }
    if (id == "nav_launcher") {
        view_ = AppView::Launcher;
        sync_edit_controls(false);
        needs_repaint_ = true;
        InvalidateRect(hwnd_, nullptr, FALSE);
        return;
    }
    if (id == "nav_dashboard") {
        view_ = AppView::Dashboard;
        sync_edit_controls(true);
        needs_repaint_ = true;
        InvalidateRect(hwnd_, nullptr, FALSE);
        return;
    }
    if (id == "hdr_hud_toggle") {
        push_toggle("hud", !snap_.hud_overlay);
    } else if (id == "ln_start_stop") {
        trigger_start_stop();
        return;
    } else if (id == "ln_ca_toggle") {
        std::string err;
        if (controller_.is_ca_installed()) {
            controller_.uninstall_ca(err);
        } else {
            controller_.install_ca(err);
        }
    } else if (id == "ln_hosts_toggle") {
        controller_.set_manage_hosts(!snap_.manage_hosts);
    } else if (id == "ln_clean_hosts") {
        trigger_clean_hosts();
        return;
    } else if (id == "ln_clear_console") {
        controller_.clear_console();
    } else if (id == "tab_pick") {
        dash_tab_ = item.arg_int;
        sync_edit_controls(true);
    } else if (id == "tog") {
        push_toggle(item.arg_str.c_str(), item.arg_int != 0);
    } else if (id == "warp_go") {
        const std::string w = trim_ascii(get_edit_text(edit_warp_));
        if (!w.empty()) push_chat("/warp " + w);
    } else if (id == "door_go") {
        const std::string d = trim_ascii(get_edit_text(edit_door_));
        if (!d.empty()) push_chat("/door " + d);
    } else if (id == "chat_cmd") {
        push_chat(item.arg_str);
    } else if (id == "wardrobe_add") {
        UiCommand cmd;
        cmd.kind = UiCommand::Kind::WardrobeAddItem;
        cmd.value = trim_ascii(get_edit_text(edit_search_));
        controller_.dispatch_ui_command(cmd);
    } else if (id == "wardrobe_preset") {
        if (snap_.active_preset == item.arg_str) {
            push_chat("/clothes off");
        } else {
            push_chat("/clothes preset " + item.arg_str);
        }
    } else if (id == "zoom_slider") {
        // Handled dynamically in on_lbutton_down / on_mouse_move
    } else if (id == "title_pick") {
        push_chat(item.arg_str);
    } else if (id == "hk_toggle_all") {
        push_toggle("hotkeys", !snap_.hotkeys_enabled);
    } else if (id == "hk_reset_all") {
        UiCommand cmd;
        cmd.kind = UiCommand::Kind::ResetHotkeys;
        controller_.dispatch_ui_command(cmd);
        selected_hk_slot_ = 0;
        snap_ = controller_.get_live_snapshot();
        sync_edit_controls(true);
    } else if (id == "hk_slot_pick") {
        selected_hk_slot_ = item.arg_int;
        if (selected_hk_slot_ >= 0 && static_cast<size_t>(selected_hk_slot_) < snap_.hotkeys.size()) {
            set_edit_text(edit_hk_key_, snap_.hotkeys[static_cast<size_t>(selected_hk_slot_)].key);
            set_edit_text(edit_hk_cmd_, snap_.hotkeys[static_cast<size_t>(selected_hk_slot_)].command);
        }
    } else if (id == "hk_slot_save") {
        UiCommand cmd;
        cmd.kind = UiCommand::Kind::SetHotkeySlot;
        cmd.int_arg = selected_hk_slot_;
        cmd.key = trim_ascii(get_edit_text(edit_hk_key_));
        cmd.value = trim_ascii(get_edit_text(edit_hk_cmd_));
        controller_.dispatch_ui_command(cmd);
    } else if (id == "hk_slot_clear") {
        UiCommand cmd;
        cmd.kind = UiCommand::Kind::ClearHotkeySlot;
        cmd.int_arg = selected_hk_slot_;
        controller_.dispatch_ui_command(cmd);
        set_edit_text(edit_hk_key_, "");
        set_edit_text(edit_hk_cmd_, "");
    } else if (id == "fb_mode") {
        UiCommand cmd;
        cmd.kind = UiCommand::Kind::SetFastBuyMode;
        cmd.int_arg = item.arg_int;
        controller_.dispatch_ui_command(cmd);
    } else if (id == "cd_drop") {
        const std::string amt = trim_ascii(get_edit_text(edit_cd_amt_));
        if (!amt.empty()) push_chat("/cd " + amt);
    } else if (id == "pkt_clear") {
        UiCommand cmd;
        cmd.kind = UiCommand::Kind::ClearConsole;
        controller_.dispatch_ui_command(cmd);
    } else if (id == "cmd_copy") {
        copy_text_to_clipboard(hwnd_, item.arg_str);
        footer_notice_ = "Copied: " + item.arg_str;
        footer_notice_until_ms_ = steady_now_ms() + 2500;
    }

    snap_ = controller_.get_live_snapshot();
    needs_repaint_ = true;
    InvalidateRect(hwnd_, nullptr, FALSE);
}

void GuiWindow::on_lbutton_down(int px, int py) {
    SetFocus(hwnd_);
    const float lx = static_cast<float>(px) / dpi_scale_;
    const float ly = static_cast<float>(py) / dpi_scale_;

    for (auto it = hits_.rbegin(); it != hits_.rend(); ++it) {
        if (lx >= it->x && lx <= it->x + it->w && ly >= it->y && ly <= it->y + it->h) {
            if (it->id == "zoom_slider") {
                dragging_zoom_ = true;
                SetCapture(hwnd_);
                update_zoom_from_mouse(lx);
                return;
            }
            handle_click(*it);
            return;
        }
    }

    if (ly <= static_cast<float>(kTitleH)) {
        ReleaseCapture();
        SendMessageW(hwnd_, WM_NCLBUTTONDOWN, HTCAPTION, 0);
    }
}

void GuiWindow::on_mouse_move(int px, int py) {
    const float lx = static_cast<float>(px) / dpi_scale_;
    const float ly = static_cast<float>(py) / dpi_scale_;
    if (dragging_zoom_) {
        update_zoom_from_mouse(lx);
        return;
    }
    std::string next_hover;
    for (auto it = hits_.rbegin(); it != hits_.rend(); ++it) {
        if (lx >= it->x && lx <= it->x + it->w && ly >= it->y && ly <= it->y + it->h) {
            next_hover = it->id + "#" + std::to_string(it->arg_int) + "#" + it->arg_str;
            break;
        }
    }
    if (next_hover != hover_id_) {
        hover_id_ = next_hover;
        needs_repaint_ = true;
        InvalidateRect(hwnd_, nullptr, FALSE);
    }
}

void GuiWindow::on_lbutton_up() {
    if (dragging_zoom_) {
        dragging_zoom_ = false;
        ReleaseCapture();
    }
}

void GuiWindow::on_mouse_wheel(int delta) {
    const int step = (delta > 0) ? -2 : 2;
    if (view_ == AppView::Launcher) {
        console_auto_scroll_ = false;
        console_scroll_ = std::max(0, console_scroll_ + step);
    } else if (dash_tab_ == TAB_PACKETS) {
        pkt_auto_scroll_ = false;
        pkt_scroll_ = std::max(0, pkt_scroll_ + step);
    } else if (dash_tab_ == TAB_COMMANDS) {
        cmd_scroll_ = std::max(0, cmd_scroll_ + step);
    } else {
        return;
    }
    needs_repaint_ = true;
    InvalidateRect(hwnd_, nullptr, FALSE);
}

void GuiWindow::on_paint() {
    PAINTSTRUCT ps{};
    HDC hdc = BeginPaint(hwnd_, &ps);
    RECT rc{};
    GetClientRect(hwnd_, &rc);
    const int cw = std::max(1, static_cast<int>(rc.right - rc.left));
    const int ch = std::max(1, static_cast<int>(rc.bottom - rc.top));

    if (!back_dc_) {
        back_dc_ = CreateCompatibleDC(hdc);
    }
    if (!back_bmp_ || cw != back_w_ || ch != back_h_) {
        if (back_old_bmp_) {
            SelectObject(back_dc_, back_old_bmp_);
            back_old_bmp_ = nullptr;
        }
        if (back_bmp_) {
            DeleteObject(back_bmp_);
            back_bmp_ = nullptr;
        }
        back_bmp_ = CreateCompatibleBitmap(hdc, cw, ch);
        back_old_bmp_ = static_cast<HBITMAP>(SelectObject(back_dc_, back_bmp_));
        back_w_ = cw;
        back_h_ = ch;
    }

    hits_.clear();

    Gdiplus::Graphics g(back_dc_);
    g.ScaleTransform(dpi_scale_, dpi_scale_);
    g.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
    g.SetTextRenderingHint(Gdiplus::TextRenderingHintClearTypeGridFit);

    const Gdiplus::Color c_bg_main(255, 14, 35, 56);      // #0e2338
    const Gdiplus::Color c_bg_bar(255, 10, 26, 44);       // #0a1a2c
    const Gdiplus::Color c_bg_side(255, 11, 28, 48);      // #0b1c30
    const Gdiplus::Color c_bg_term(255, 6, 15, 26);       // #060f1a
    const Gdiplus::Color c_card(255, 21, 50, 83);         // #153253
    const Gdiplus::Color c_tab_act(255, 29, 74, 120);     // #1d4a78
    const Gdiplus::Color c_border_outer(255, 111, 183, 230); // #6fb7e6
    const Gdiplus::Color c_border_card(255, 44, 95, 143); // #2c5f8f
    const Gdiplus::Color c_border_bar(255, 29, 74, 120);  // #1d4a78
    const Gdiplus::Color c_gold(255, 255, 210, 74);       // #ffd24a
    const Gdiplus::Color c_gold_fg(255, 26, 16, 48);      // #1a1030
    const Gdiplus::Color c_cyan(255, 111, 209, 255);      // #6fd1ff
    const Gdiplus::Color c_green(255, 61, 220, 132);      // #3ddc84
    const Gdiplus::Color c_green_txt(255, 139, 224, 139); // #8be08b
    const Gdiplus::Color c_red(255, 179, 38, 30);         // #b3261e
    const Gdiplus::Color c_alert_bg(255, 58, 20, 24);     // #3a1418
    const Gdiplus::Color c_alert_bd(255, 255, 122, 138);  // #ff7a8a
    const Gdiplus::Color c_alert_fg(255, 255, 208, 214);  // #ffd0d6
    const Gdiplus::Color c_white(255, 255, 255, 255);
    const Gdiplus::Color c_soft(255, 219, 231, 242);      // #dbe7f2
    const Gdiplus::Color c_muted(255, 157, 182, 204);     // #9db6cc
    const Gdiplus::Color c_cream(255, 255, 233, 176);     // #ffe9b0
    const Gdiplus::Color c_purple(255, 220, 184, 255);    // #dcb8ff

    g.Clear(c_bg_main);

    Gdiplus::Font f_logo(L"Segoe UI", 21.0f, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
    Gdiplus::Font f_h2(L"Segoe UI", 24.0f, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
    Gdiplus::Font f_h3(L"Segoe UI", 17.0f, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
    Gdiplus::Font f_md(L"Segoe UI", 14.5f, Gdiplus::FontStyleRegular, Gdiplus::UnitPixel);
    Gdiplus::Font f_md_b(L"Segoe UI", 14.5f, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
    Gdiplus::Font f_sm(L"Segoe UI", 12.5f, Gdiplus::FontStyleRegular, Gdiplus::UnitPixel);
    Gdiplus::Font f_sm_b(L"Segoe UI", 12.5f, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
    Gdiplus::Font f_mono(L"Consolas", 12.5f, Gdiplus::FontStyleRegular, Gdiplus::UnitPixel);
    Gdiplus::Font f_mono_b(L"Consolas", 13.0f, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
    Gdiplus::Font f_big_num(L"Segoe UI", 21.0f, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);

    Gdiplus::SolidBrush b_white(c_white);
    Gdiplus::SolidBrush b_soft(c_soft);
    Gdiplus::SolidBrush b_muted(c_muted);
    Gdiplus::SolidBrush b_gold(c_gold);
    Gdiplus::SolidBrush b_gold_fg(c_gold_fg);
    Gdiplus::SolidBrush b_green_txt(c_green_txt);
    Gdiplus::SolidBrush b_cream(c_cream);
    Gdiplus::SolidBrush b_cyan(c_cyan);
    Gdiplus::SolidBrush b_alert_fg(c_alert_fg);

    Gdiplus::StringFormat sf_center;
    sf_center.SetAlignment(Gdiplus::StringAlignmentCenter);
    sf_center.SetLineAlignment(Gdiplus::StringAlignmentCenter);

    Gdiplus::StringFormat sf_vcenter;
    sf_vcenter.SetLineAlignment(Gdiplus::StringAlignmentCenter);
    sf_vcenter.SetTrimming(Gdiplus::StringTrimmingEllipsisCharacter);
    sf_vcenter.SetFormatFlags(Gdiplus::StringFormatFlagsNoWrap);

    const float W = static_cast<float>(kLogicalW);
    const float H = static_cast<float>(kLogicalH);

    // Title Bar
    {
        Gdiplus::SolidBrush b_hdr(c_bg_bar);
        g.FillRectangle(&b_hdr, 0.0f, 0.0f, W, static_cast<float>(kTitleH));
        Gdiplus::Pen sep(c_border_bar, 2.0f);
        g.DrawLine(&sep, 0.0f, static_cast<float>(kTitleH), W, static_cast<float>(kTitleH));

        draw_shield_emblem(g, 16.0f, 12.0f, 32.0f);
        g.DrawString(L"EvanProxy", -1, &f_logo, Gdiplus::PointF(56.0f, 13.0f), &b_gold);

        // Mode switcher pills (Launcher / Dashboard)
        auto draw_mode_btn = [&](const char* id, const wchar_t* lbl, bool active, float bx, float bw) {
            draw_rr(g, bx, 12.0f, bw, 32.0f, 8.0f,
                    active ? c_tab_act : Gdiplus::Color(255, 14, 34, 56),
                    active ? c_gold : c_border_card, 1.5f);
            g.DrawString(lbl, -1, &f_sm_b, Gdiplus::RectF(bx, 12.0f, bw, 32.0f), &sf_center,
                         active ? &b_gold : &b_soft);
            hits_.push_back({id, bx, 12.0f, bw, 32.0f, 0, ""});
        };
        draw_mode_btn("nav_launcher", L"Launcher", view_ == AppView::Launcher, 182.0f, 94.0f);
        draw_mode_btn("nav_dashboard", L"Dashboard", view_ == AppView::Dashboard, 284.0f, 102.0f);

        // Status pill
        {
            const bool run = snap_.proxy_running;
            const bool fail = !run && (snap_.port_conflict || !snap_.last_error.empty());
            const Gdiplus::Color pill_bg = run ? Gdiplus::Color(255, 18, 58, 42)
                : (fail ? c_alert_bg : Gdiplus::Color(255, 21, 38, 58));
            const Gdiplus::Color pill_bd = run ? c_green : (fail ? c_alert_bd : c_border_card);
            const Gdiplus::Color dot_col = run ? c_green : (fail ? c_alert_bd : c_muted);
            const wchar_t* st_w = run ? L"Proxy running" : (fail ? L"Port 443 busy" : L"Proxy stopped");
            draw_rr(g, 622.0f, 13.0f, 152.0f, 30.0f, 15.0f, pill_bg, pill_bd, 1.8f);
            Gdiplus::SolidBrush db(dot_col);
            g.FillEllipse(&db, 634.0f, 23.0f, 10.0f, 10.0f);
            g.DrawString(st_w, -1, &f_sm_b, Gdiplus::RectF(648.0f, 13.0f, 120.0f, 30.0f), &sf_vcenter, &b_soft);
        }

        // HUD Overlay quick pill
        {
            const bool on = snap_.hud_overlay;
            draw_rr(g, 784.0f, 13.0f, 114.0f, 30.0f, 8.0f,
                    on ? Gdiplus::Color(255, 18, 58, 42) : c_card,
                    on ? c_green : c_border_card, 1.5f);
            g.DrawString(on ? L"HUD Overlay: ON" : L"HUD Overlay: OFF", -1, &f_sm_b,
                         Gdiplus::RectF(784.0f, 13.0f, 114.0f, 30.0f), &sf_center,
                         on ? &b_green_txt : &b_muted);
            hits_.push_back({"hdr_hud_toggle", 784.0f, 13.0f, 114.0f, 30.0f, 0, ""});
        }

        // Minimize + Close buttons (Board 2 styled frame + hover glow)
        {
            const bool min_hov = (hover_id_ == "win_min#0#");
            draw_rr(g, W - 96.0f, 12.0f, 36.0f, 32.0f, 7.0f,
                    min_hov ? Gdiplus::Color(255, 36, 76, 120) : Gdiplus::Color(255, 18, 44, 72),
                    c_border_outer, 1.5f);
            Gdiplus::SolidBrush min_bar(c_white);
            g.FillRectangle(&min_bar, W - 85.0f, 27.0f, 14.0f, 3.0f);
            hits_.push_back({"win_min", W - 96.0f, 12.0f, 36.0f, 32.0f, 0, ""});

            const bool cls_hov = (hover_id_ == "win_close#0#");
            draw_rr(g, W - 50.0f, 12.0f, 36.0f, 32.0f, 7.0f,
                    cls_hov ? c_red : Gdiplus::Color(255, 74, 127, 160),
                    cls_hov ? Gdiplus::Color(255, 255, 160, 160) : Gdiplus::Color(255, 184, 220, 240), 1.8f);
            Gdiplus::Pen xp(c_white, 2.5f);
            g.DrawLine(&xp, W - 38.0f, 22.0f, W - 26.0f, 34.0f);
            g.DrawLine(&xp, W - 26.0f, 22.0f, W - 38.0f, 34.0f);
            hits_.push_back({"win_close", W - 50.0f, 12.0f, 36.0f, 32.0f, 0, ""});
        }
    }

    auto make_hover_id = [](const std::string& id, int arg_i, const std::string& arg_s) {
        return id + "#" + std::to_string(arg_i) + "#" + arg_s;
    };

    // Helper for standard toggle card (matching Board 2, with hover glow)
    auto draw_toggle_card = [&](const std::string& toggle_key, const wchar_t* title, const wchar_t* cmd_lbl,
                                bool is_on, float x, float y, float w, float h) {
        const std::string hid = make_hover_id("tog", is_on ? 0 : 1, toggle_key);
        const bool hov = (hover_id_ == hid);
        draw_rr(g, x, y, w, h, 10.0f,
                hov ? Gdiplus::Color(255, 27, 63, 102) : c_card,
                hov ? c_cyan : c_border_card, 2.0f);
        g.DrawString(title, -1, &f_md_b, Gdiplus::PointF(x + 14.0f, y + (h > 55.0f ? 10.0f : 5.0f)), &b_white);
        g.DrawString(cmd_lbl, -1, &f_mono, Gdiplus::PointF(x + 14.0f, y + (h > 55.0f ? 30.0f : 23.0f)), &b_cream);
        draw_toggle_pill(g, x + w - 62.0f, y + (h - 26.0f) * 0.5f, is_on);
        hits_.push_back({"tog", x, y, w, h, is_on ? 0 : 1, toggle_key});
    };

    const float body_y = static_cast<float>(kTitleH);
    const float body_h = H - static_cast<float>(kTitleH) - static_cast<float>(kFooterH);

    // =========================================================================
    // VIEW 1: LAUNCHER (Board 3)
    // =========================================================================
    if (view_ == AppView::Launcher) {
        const float pad = 20.0f;
        const float left_x = pad;
        const float left_w = 340.0f;
        const float right_x = left_x + left_w + 16.0f;
        const float right_w = W - right_x - pad;
        const float top_y = body_y + 18.0f;

        // Status Card
        draw_rr(g, left_x, top_y, left_w, 232.0f, 12.0f, c_card, c_border_card, 2.0f);
        {
            const bool run = snap_.proxy_running;
            const bool fail = !run && (snap_.port_conflict || !snap_.last_error.empty());
            const Gdiplus::Color st_col = run ? c_green : (fail ? c_alert_bd : c_muted);
            Gdiplus::SolidBrush sb(st_col);
            g.FillEllipse(&sb, left_x + 18.0f, top_y + 18.0f, 44.0f, 44.0f);
            Gdiplus::SolidBrush ic(c_bg_bar);
            g.FillRectangle(&ic, left_x + 32.0f, top_y + 32.0f, 16.0f, 16.0f);

            g.DrawString(L"Proxy status", -1, &f_sm, Gdiplus::PointF(left_x + 76.0f, top_y + 18.0f), &b_muted);
            const wchar_t* st_big = run ? L"Running" : (fail ? L"Failed to start" : L"Stopped");
            g.DrawString(st_big, -1, &f_h2, Gdiplus::PointF(left_x + 76.0f, top_y + 36.0f), &b_white);

            // Start / Stop button
            draw_rr(g, left_x + 18.0f, top_y + 78.0f, left_w - 36.0f, 52.0f, 10.0f,
                    run ? c_red : c_gold, Gdiplus::Color(0, 0, 0, 0), 0.0f);
            g.DrawString(run ? L"Stop proxy" : L"Start proxy", -1, &f_h3,
                         Gdiplus::RectF(left_x + 18.0f, top_y + 78.0f, left_w - 36.0f, 52.0f),
                         &sf_center, run ? &b_white : &b_gold_fg);
            hits_.push_back({"ln_start_stop", left_x + 18.0f, top_y + 78.0f, left_w - 36.0f, 52.0f, 0, ""});

            // Bridge rows
            auto draw_bridge_row = [&](float ry, const wchar_t* name, uint16_t port, bool active, bool err_dot) {
                Gdiplus::SolidBrush db(active ? c_green : (err_dot ? c_alert_bd : Gdiplus::Color(255, 95, 114, 136)));
                g.FillEllipse(&db, left_x + 20.0f, ry + 5.0f, 10.0f, 10.0f);
                g.DrawString(name, -1, &f_md, Gdiplus::PointF(left_x + 40.0f, ry), &b_soft);
                const std::wstring pstr = L":" + std::to_wstring(port);
                Gdiplus::StringFormat sf_r;
                sf_r.SetAlignment(Gdiplus::StringAlignmentFar);
                g.DrawString(pstr.c_str(), -1, &f_mono,
                             Gdiplus::RectF(left_x + 180.0f, ry + 1.0f, left_w - 200.0f, 20.0f),
                             &sf_r, &b_cream);
            };
            draw_bridge_row(top_y + 148.0f, L"HTTPS bridge", snap_.http_port, snap_.http_running, snap_.port_conflict);
            draw_bridge_row(top_y + 174.0f, L"ENet UDP bridge", snap_.enet_port, snap_.enet_running, false);

            std::wstring client_st = L"Client: idle";
            if (snap_.client_connected) {
                client_st = snap_.in_world
                    ? utf8_to_w("In world: " + snap_.current_world + " (" + std::to_string(snap_.live_ping_ms) + "ms)")
                    : L"Connected to lobby";
            }
            g.DrawString(client_st.c_str(), -1, &f_sm, Gdiplus::PointF(left_x + 20.0f, top_y + 202.0f),
                         snap_.client_connected ? &b_green_txt : &b_muted);
        }

        // Setup Card
        const float setup_y = top_y + 246.0f;
        const float setup_h = body_y + body_h - setup_y - 16.0f;
        draw_rr(g, left_x, setup_y, left_w, setup_h, 12.0f, c_card, c_border_card, 2.0f);
        {
            g.DrawString(L"Setup", -1, &f_h3, Gdiplus::PointF(left_x + 18.0f, setup_y + 14.0f), &b_gold);

            // Local root CA row
            g.DrawString(L"Local root CA", -1, &f_md_b, Gdiplus::PointF(left_x + 18.0f, setup_y + 46.0f), &b_white);
            Gdiplus::SolidBrush b_ca_col(snap_.ca_installed ? c_green_txt : Gdiplus::Color(255, 255, 180, 189));
            g.DrawString(snap_.ca_installed ? L"Installed in CurrentUser store" : L"Not installed",
                         -1, &f_sm_b, Gdiplus::PointF(left_x + 18.0f, setup_y + 66.0f), &b_ca_col);

            draw_rr(g, left_x + left_w - 112.0f, setup_y + 48.0f, 94.0f, 38.0f, 8.0f, c_bg_bar, c_border_card, 2.0f);
            g.DrawString(snap_.ca_installed ? L"Uninstall" : L"Install", -1, &f_sm_b,
                         Gdiplus::RectF(left_x + left_w - 112.0f, setup_y + 48.0f, 94.0f, 38.0f),
                         &sf_center, &b_white);
            hits_.push_back({"ln_ca_toggle", left_x + left_w - 112.0f, setup_y + 48.0f, 94.0f, 38.0f, 0, ""});

            // Divider
            Gdiplus::SolidBrush divb(c_border_bar);
            g.FillRectangle(&divb, left_x + 18.0f, setup_y + 98.0f, left_w - 36.0f, 2.0f);

            // Edit hosts toggle
            g.DrawString(L"Edit hosts file", -1, &f_md_b, Gdiplus::PointF(left_x + 18.0f, setup_y + 112.0f), &b_white);
            g.DrawString(snap_.manage_hosts ? L"Default" : L"--no-hosts", -1, &f_mono,
                         Gdiplus::PointF(left_x + 18.0f, setup_y + 132.0f), &b_cream);
            draw_toggle_pill(g, left_x + left_w - 66.0f, setup_y + 118.0f, snap_.manage_hosts);
            hits_.push_back({"ln_hosts_toggle", left_x + 16.0f, setup_y + 108.0f, left_w - 32.0f, 46.0f, 0, ""});

            g.DrawString(L"Only its own marked block is edited.\nA backup is saved and restored on exit.",
                         -1, &f_sm, Gdiplus::RectF(left_x + 18.0f, setup_y + 160.0f, left_w - 36.0f, 38.0f),
                         nullptr, &b_muted);

            // Clean leftover hosts entries button
            const float clean_y = setup_y + 206.0f;
            draw_rr(g, left_x + 18.0f, clean_y, left_w - 36.0f, 40.0f, 8.0f, c_bg_bar, c_border_card, 2.0f);
            g.DrawString(L"Clean leftover hosts entries", -1, &f_md_b,
                         Gdiplus::RectF(left_x + 18.0f, clean_y, left_w - 36.0f, 40.0f),
                         &sf_center, &b_white);
            hits_.push_back({"ln_clean_hosts", left_x + 18.0f, clean_y, left_w - 36.0f, 40.0f, 0, ""});

            // Open Dashboard shortcut
            const float dash_y = clean_y + 50.0f;
            draw_rr(g, left_x + 18.0f, dash_y, left_w - 36.0f, 38.0f, 8.0f, c_tab_act, c_border_outer, 1.5f);
            g.DrawString(L"Open /proxy Dashboard ->", -1, &f_sm_b,
                         Gdiplus::RectF(left_x + 18.0f, dash_y, left_w - 36.0f, 38.0f),
                         &sf_center, &b_gold);
            hits_.push_back({"nav_dashboard", left_x + 18.0f, dash_y, left_w - 36.0f, 38.0f, 0, ""});
        }

        // Right column: optional Port 443 / Error alert + Console log
        float con_y = top_y;
        const bool show_alert = !snap_.proxy_running && (snap_.port_conflict || !snap_.last_error.empty());
        if (show_alert) {
            draw_rr(g, right_x, top_y, right_w, 72.0f, 12.0f, c_alert_bg, c_alert_bd, 2.0f);
            const std::wstring title = snap_.port_conflict
                ? L"Port 443 is already in use"
                : L"Proxy failed to start";
            const std::wstring msg = snap_.port_conflict
                ? L"Stop Laragon, Apache, Nginx or IIS, then press Start again."
                : utf8_to_w(snap_.last_error);
            g.DrawString(title.c_str(), -1, &f_md_b, Gdiplus::PointF(right_x + 16.0f, top_y + 12.0f), &b_alert_fg);
            g.DrawString(msg.c_str(), -1, &f_sm,
                         Gdiplus::RectF(right_x + 16.0f, top_y + 34.0f, right_w - 32.0f, 32.0f),
                         nullptr, &b_white);
            con_y = top_y + 84.0f;
        }

        const float con_h = body_y + body_h - con_y - 16.0f;
        draw_rr(g, right_x, con_y, right_w, con_h, 12.0f, c_bg_term, c_border_card, 2.0f);
        {
            draw_rr(g, right_x + 1.0f, con_y + 1.0f, right_w - 2.0f, 42.0f, 10.0f, c_bg_bar, Gdiplus::Color(0, 0, 0, 0), 0.0f);
            Gdiplus::Pen p_b(c_border_bar, 2.0f);
            g.DrawLine(&p_b, right_x + 2.0f, con_y + 43.0f, right_x + right_w - 2.0f, con_y + 43.0f);
            g.DrawString(L"Console", -1, &f_md_b, Gdiplus::PointF(right_x + 16.0f, con_y + 12.0f), &b_white);

            const std::string log_lbl = snap_.log_file_path.empty()
                ? std::string("logs\\packets_YYYYMMDD_HHMMSS.log")
                : snap_.log_file_path;
            Gdiplus::StringFormat sf_r;
            sf_r.SetAlignment(Gdiplus::StringAlignmentFar);
            sf_r.SetLineAlignment(Gdiplus::StringAlignmentCenter);
            sf_r.SetTrimming(Gdiplus::StringTrimmingEllipsisPath);
            sf_r.SetFormatFlags(Gdiplus::StringFormatFlagsNoWrap);
            g.DrawString(utf8_to_w(log_lbl).c_str(), -1, &f_mono,
                         Gdiplus::RectF(right_x + 100.0f, con_y + 4.0f, right_w - 186.0f, 36.0f),
                         &sf_r, &b_muted);

            draw_rr(g, right_x + right_w - 78.0f, con_y + 8.0f, 64.0f, 26.0f, 6.0f, c_card, c_border_card, 1.5f);
            g.DrawString(L"Clear", -1, &f_sm_b,
                         Gdiplus::RectF(right_x + right_w - 78.0f, con_y + 8.0f, 64.0f, 26.0f),
                         &sf_center, &b_soft);
            hits_.push_back({"ln_clear_console", right_x + right_w - 78.0f, con_y + 8.0f, 64.0f, 26.0f, 0, ""});

            const float list_y = con_y + 52.0f;
            const float list_h = con_h - 62.0f;
            const float row_h = 22.0f;
            const int max_rows = std::max(1, static_cast<int>(list_h / row_h));
            const int total = static_cast<int>(console_lines_.size());
            if (console_auto_scroll_) {
                console_scroll_ = std::max(0, total - max_rows);
            } else {
                console_scroll_ = std::max(0, std::min(console_scroll_, std::max(0, total - max_rows)));
                if (console_scroll_ >= std::max(0, total - max_rows)) console_auto_scroll_ = true;
            }

            g.SetClip(Gdiplus::RectF(right_x + 12.0f, list_y, right_w - 24.0f, list_h));
            for (int r = 0; r < max_rows; ++r) {
                const int idx = console_scroll_ + r;
                if (idx >= total) break;
                const auto& ln = console_lines_[static_cast<size_t>(idx)];
                const float ry = list_y + static_cast<float>(r) * row_h;
                Gdiplus::Color tc = c_muted;
                switch (ln.tag) {
                    case LogTag::Ok: tc = c_green; break;
                    case LogTag::Warn: tc = c_gold; break;
                    case LogTag::Error: tc = c_alert_bd; break;
                    case LogTag::Http:
                    case LogTag::Enet: tc = c_cyan; break;
                    case LogTag::Action: tc = c_cream; break;
                    case LogTag::Packet: tc = c_purple; break;
                    default: tc = c_muted; break;
                }
                Gdiplus::SolidBrush b_tc(tc);
                g.DrawString(utf8_to_w(ln.tag_text).c_str(), -1, &f_mono_b,
                             Gdiplus::RectF(right_x + 14.0f, ry, 58.0f, row_h), &sf_vcenter, &b_tc);
                g.DrawString(utf8_to_w(ln.text).c_str(), -1, &f_mono,
                             Gdiplus::RectF(right_x + 76.0f, ry, right_w - 94.0f, row_h), &sf_vcenter, &b_soft);
            }
            g.ResetClip();
        }
    } else {
        // =====================================================================
        // VIEW 2: DASHBOARD (Board 2 — 9 Interactive Tabs)
        // =====================================================================
        Gdiplus::SolidBrush b_side(c_bg_side);
        g.FillRectangle(&b_side, 0.0f, body_y, static_cast<float>(kSidebarW), body_h);
        Gdiplus::Pen sep(c_border_bar, 2.0f);
        g.DrawLine(&sep, static_cast<float>(kSidebarW), body_y, static_cast<float>(kSidebarW), body_y + body_h);

        struct TabDef {
            const wchar_t* label;
            Gdiplus::Color color;
        };
        const TabDef tab_defs[TAB_COUNT] = {
            {L"Main Hub", c_gold},
            {L"Warp Navigation", c_cyan},
            {L"Wardrobe", c_alert_bd},
            {L"Visual & Theme", c_purple},
            {L"Titles", Gdiplus::Color(255, 244, 166, 58)},
            {L"Custom Hotkeys", c_green_txt},
            {L"Tools & Vending", c_cyan},
            {L"Packet Monitor", c_alert_bd},
            {L"Commands", c_white}
        };

        for (int i = 0; i < TAB_COUNT; ++i) {
            const bool active = (dash_tab_ == i);
            const std::string tid = make_hover_id("tab_pick", i, "");
            const bool hov = (hover_id_ == tid);
            const float ty = body_y + 14.0f + static_cast<float>(i) * 52.0f;
            if (active || hov) {
                fill_rr(g, 12.0f, ty, static_cast<float>(kSidebarW) - 24.0f, 46.0f, 8.0f,
                        active ? c_tab_act : Gdiplus::Color(255, 19, 44, 72));
                if (active) {
                    Gdiplus::SolidBrush bar_l(c_gold);
                    g.FillRectangle(&bar_l, 12.0f, ty + 8.0f, 4.0f, 30.0f);
                }
            }
            draw_gt_icon(g, ICON_TAB_HUB + i, 22.0f, ty + 11.0f, 24.0f);
            g.DrawString(tab_defs[i].label, -1, &f_md_b,
                         Gdiplus::RectF(54.0f, ty, static_cast<float>(kSidebarW) - 68.0f, 46.0f),
                         &sf_vcenter, active ? &b_gold : &b_soft);
            hits_.push_back({"tab_pick", 12.0f, ty, static_cast<float>(kSidebarW) - 24.0f, 46.0f, i, ""});
        }

        const float cx = static_cast<float>(kSidebarW) + 24.0f;
        const float cw = W - cx - 24.0f;
        const float top = body_y + 20.0f;

        if (dash_tab_ == TAB_HUB) {
            g.DrawString(L"Main Hub", -1, &f_h2, Gdiplus::PointF(cx, top), &b_white);
            g.DrawString(L"/proxy \x00B7 /gems \x00B7 /news", -1, &f_mono, Gdiplus::PointF(cx, top + 32.0f), &b_muted);

            const float card_w = (cw - 24.0f) / 3.0f;
            auto draw_stat_card = [&](int idx, int icon_k, const wchar_t* k, const wchar_t* v, const wchar_t* sub, bool ok) {
                const float sx = cx + static_cast<float>(idx) * (card_w + 12.0f);
                draw_rr(g, sx, top + 60.0f, card_w, 86.0f, 10.0f, c_card, c_border_card, 2.0f);
                draw_gt_icon(g, icon_k, sx + card_w - 42.0f, top + 74.0f, 26.0f);
                g.DrawString(k, -1, &f_sm, Gdiplus::PointF(sx + 16.0f, top + 72.0f), &b_muted);
                g.DrawString(v, -1, &f_big_num, Gdiplus::PointF(sx + 16.0f, top + 92.0f), &b_white);
                Gdiplus::SolidBrush sb(ok ? c_green_txt : c_alert_bd);
                g.DrawString(sub, -1, &f_sm_b, Gdiplus::PointF(sx + 16.0f, top + 120.0f), &sb);
            };

            const std::wstring http_p = L"Port " + std::to_wstring(snap_.http_port);
            const std::wstring enet_p = L"Port " + std::to_wstring(snap_.enet_port);
            draw_stat_card(0, ICON_NET_LOCK, L"HTTPS bridge", http_p.c_str(),
                           snap_.http_running ? L"Running" : (snap_.port_conflict ? L"Port busy" : L"Stopped"),
                           snap_.http_running);
            draw_stat_card(1, ICON_NET_BOLT, L"ENet UDP bridge", enet_p.c_str(),
                           snap_.enet_running ? L"Running" : L"Stopped", snap_.enet_running);
            draw_stat_card(2, ICON_NET_SHIELD, L"Hosts file",
                           snap_.manage_hosts ? L"Protected" : L"Disabled",
                           snap_.hosts_active ? L"Backup active" : (snap_.manage_hosts ? L"Restored" : L"--no-hosts"),
                           snap_.manage_hosts);

            g.DrawString(L"Quick toggles", -1, &f_h3, Gdiplus::PointF(cx, top + 160.0f), &b_gold);

            const float tw = (cw - 12.0f) * 0.5f;
            draw_toggle_card("evantag", L"EvanTag", L"/evantag", snap_.evan_branding, cx, top + 188.0f, tw, 52.0f);
            draw_toggle_card("evanchat", L"EvanChat prefix", L"/evanchat", snap_.outgoing_evan_prefix, cx + tw + 12.0f, top + 188.0f, tw, 52.0f);
            draw_toggle_card("fps", L"FPS boost", L"/fps boost", snap_.fps_boost, cx, top + 248.0f, tw, 52.0f);
            draw_toggle_card("vendinfo", L"Vend info", L"/vendinfo", snap_.vending_info, cx + tw + 12.0f, top + 248.0f, tw, 52.0f);
            draw_toggle_card("autobgl", L"Auto-BGL", L"/autobgl", snap_.auto_bgl, cx, top + 308.0f, tw, 52.0f);
            draw_toggle_card("hotkeys", L"Custom hotkeys", L"/hotkey on|off", snap_.hotkeys_enabled, cx + tw + 12.0f, top + 308.0f, tw, 52.0f);
            draw_toggle_card("gems", L"Gems Live Bubble", L"/gems on|off", snap_.gems_tracker, cx, top + 368.0f, tw, 52.0f);
            draw_toggle_card("banner", L"Gazette EvanProxy", L"/banner", snap_.custom_banner, cx + tw + 12.0f, top + 368.0f, tw, 52.0f);

            // Live session & Gems summary bar
            draw_rr(g, cx, top + 432.0f, cw, 64.0f, 10.0f, c_card, c_border_card, 2.0f);
            draw_gt_icon(g, ICON_GEM, cx + 16.0f, top + 448.0f, 30.0f);
            std::ostringstream ls1;
            ls1 << "Player: " << (snap_.player_name.empty() ? "-" : snap_.player_name)
                << "   |   World: " << (snap_.in_world ? snap_.current_world : "Menu")
                << " (" << snap_.player_count << " players)"
                << "   |   Wealth: " << snap_.bgl << " BGL / " << snap_.dl << " DL / " << snap_.wl << " WL"
                << "   |   Ping: " << snap_.live_ping_ms << "ms";
            std::ostringstream ls2;
            ls2 << "Gems Balance: " << (snap_.gems >= 0 ? std::to_string(snap_.gems) : "-")
                << "   |   Collected World: +" << snap_.gems_collected_world
                << "   |   Session: +" << snap_.gems_collected_session
                << "   |   Floor Gems: " << snap_.world_floor_gems;
            g.DrawString(utf8_to_w(ls1.str()).c_str(), -1, &f_sm_b,
                         Gdiplus::RectF(cx + 56.0f, top + 438.0f, cw - 72.0f, 24.0f),
                         &sf_vcenter, &b_white);
            g.DrawString(utf8_to_w(ls2.str()).c_str(), -1, &f_mono,
                         Gdiplus::RectF(cx + 56.0f, top + 464.0f, cw - 72.0f, 24.0f),
                         &sf_vcenter, &b_cyan);
        } else if (dash_tab_ == TAB_WARP) {
            g.DrawString(L"Warp Navigation", -1, &f_h2, Gdiplus::PointF(cx, top), &b_white);
            g.DrawString(L"/warp <world>", -1, &f_mono, Gdiplus::PointF(cx, top + 32.0f), &b_muted);

            // Go to a world card
            draw_rr(g, cx, top + 60.0f, cw, 114.0f, 10.0f, c_card, c_border_card, 2.0f);
            g.DrawString(L"Go to a world", -1, &f_md_b, Gdiplus::PointF(cx + 16.0f, top + 72.0f), &b_white);
            draw_rr(g, cx + 16.0f, top + 98.0f, cw - 156.0f, 42.0f, 8.0f, c_bg_bar, c_border_card, 2.0f);
            draw_rr(g, cx + cw - 128.0f, top + 98.0f, 112.0f, 42.0f, 8.0f, c_gold, Gdiplus::Color(0, 0, 0, 0), 0.0f);
            g.DrawString(L"Warp", -1, &f_md_b, Gdiplus::RectF(cx + cw - 128.0f, top + 98.0f, 112.0f, 42.0f),
                         &sf_center, &b_gold_fg);
            hits_.push_back({"warp_go", cx + cw - 128.0f, top + 98.0f, 112.0f, 42.0f, 0, ""});
            g.DrawString(L"Enters the world directly, without going through World Select.",
                         -1, &f_sm, Gdiplus::PointF(cx + 16.0f, top + 148.0f), &b_muted);

            // 4 Quick Tiles
            const float qw = (cw - 36.0f) / 4.0f;
            struct QuickNav { const wchar_t* title; const wchar_t* sub; const char* cmd; };
            const QuickNav qn[4] = {
                {L"Back", L"/back", "/back"},
                {L"Re-enter", L"/re", "/re"},
                {L"Exit", L"/exit", "/exit"},
                {L"Worlds", L"/worlds", "/worlds"}
            };
            for (int i = 0; i < 4; ++i) {
                const float qx = cx + static_cast<float>(i) * (qw + 12.0f);
                draw_rr(g, qx, top + 190.0f, qw, 84.0f, 10.0f, c_card, c_border_card, 2.0f);
                g.DrawString(qn[i].title, -1, &f_h3, Gdiplus::RectF(qx, top + 206.0f, qw, 26.0f), &sf_center, &b_white);
                g.DrawString(qn[i].sub, -1, &f_mono, Gdiplus::RectF(qx, top + 236.0f, qw, 22.0f), &sf_center, &b_cream);
                hits_.push_back({"chat_cmd", qx, top + 190.0f, qw, 84.0f, 0, qn[i].cmd});
            }

            // Use a door card
            draw_rr(g, cx, top + 292.0f, cw, 130.0f, 10.0f, c_card, c_border_card, 2.0f);
            g.DrawString(L"Use a door", -1, &f_md_b, Gdiplus::PointF(cx + 16.0f, top + 306.0f), &b_white);
            draw_rr(g, cx + 16.0f, top + 336.0f, cw - 156.0f, 42.0f, 8.0f, c_bg_bar, c_border_card, 2.0f);
            draw_rr(g, cx + cw - 128.0f, top + 336.0f, 112.0f, 42.0f, 8.0f, c_cyan, Gdiplus::Color(0, 0, 0, 0), 0.0f);
            g.DrawString(L"Go", -1, &f_md_b, Gdiplus::RectF(cx + cw - 128.0f, top + 336.0f, 112.0f, 42.0f),
                         &sf_center, &b_gold_fg);
            hits_.push_back({"door_go", cx + cw - 128.0f, top + 336.0f, 112.0f, 42.0f, 0, ""});

            g.DrawString(L"/door <name>   \x00B7   /sworld [door]", -1, &f_mono, Gdiplus::PointF(cx + 16.0f, top + 390.0f), &b_cream);
            draw_rr(g, cx + cw - 170.0f, top + 386.0f, 154.0f, 28.0f, 6.0f, c_bg_bar, c_border_card, 1.5f);
            g.DrawString(L"Save current world", -1, &f_sm_b,
                         Gdiplus::RectF(cx + cw - 170.0f, top + 386.0f, 154.0f, 28.0f), &sf_center, &b_soft);
            hits_.push_back({"chat_cmd", cx + cw - 170.0f, top + 386.0f, 154.0f, 28.0f, 0, "/sworld"});
        } else if (dash_tab_ == TAB_WARDROBE) {
            g.DrawString(L"Wardrobe", -1, &f_h2, Gdiplus::PointF(cx, top), &b_white);
            g.DrawString(L"/clothes \x00B7 /search <item>", -1, &f_mono, Gdiplus::PointF(cx, top + 32.0f), &b_muted);

            draw_rr(g, cx, top + 60.0f, cw - 188.0f, 42.0f, 8.0f, c_bg_bar, c_border_card, 2.0f);
            draw_rr(g, cx + cw - 176.0f, top + 60.0f, 176.0f, 42.0f, 8.0f, c_gold, Gdiplus::Color(0, 0, 0, 0), 0.0f);
            g.DrawString(L"Add to backpack", -1, &f_md_b, Gdiplus::RectF(cx + cw - 176.0f, top + 60.0f, 176.0f, 42.0f),
                         &sf_center, &b_gold_fg);
            hits_.push_back({"wardrobe_add", cx + cw - 176.0f, top + 60.0f, 176.0f, 42.0f, 0, ""});

            // Live search preview hint
            const std::string sq = trim_ascii(get_edit_text(edit_search_));
            if (!sq.empty()) {
                auto prev = controller_.search_items_preview(sq, 3);
                std::string msg = prev.empty() ? "No match in items.dat" : ("Matches: " + prev[0]);
                for (size_t i = 1; i < prev.size(); ++i) msg += ", " + prev[i];
                g.DrawString(utf8_to_w(msg).c_str(), -1, &f_sm, Gdiplus::PointF(cx, top + 108.0f), &b_muted);
            } else {
                const std::wstring dbmsg = L"items.dat ready (" + std::to_wstring(controller_.items_db_size()) + L" items)";
                g.DrawString(dbmsg.c_str(), -1, &f_sm, Gdiplus::PointF(cx, top + 108.0f), &b_muted);
            }

            g.DrawString(L"Presets", -1, &f_h3, Gdiplus::PointF(cx, top + 138.0f), &b_gold);

            struct PresetDef { const char* id; const wchar_t* lbl; int icon_k; };
            const PresetDef presets[3] = {
                {"legendary", L"Legendary", ICON_PRESET_LEGENDARY},
                {"rayman", L"Rayman", ICON_PRESET_RAYMAN},
                {"angel", L"Angel", ICON_PRESET_ANGEL}
            };
            const float pw = (cw - 24.0f) / 3.0f;
            for (int i = 0; i < 3; ++i) {
                const float px = cx + static_cast<float>(i) * (pw + 12.0f);
                const bool act = (snap_.active_preset == presets[i].id);
                const bool hov = (hover_id_ == make_hover_id("wardrobe_preset", i, presets[i].id));
                draw_rr(g, px, top + 172.0f, pw, 108.0f, 10.0f,
                        hov ? Gdiplus::Color(255, 27, 63, 102) : c_card,
                        act ? c_gold : (hov ? c_cyan : c_border_card), act ? 3.0f : 2.0f);
                draw_gt_icon(g, presets[i].icon_k, px + pw * 0.5f - 18.0f, top + 188.0f, 36.0f);
                g.DrawString(presets[i].lbl, -1, &f_h3, Gdiplus::RectF(px, top + 234.0f, pw, 28.0f), &sf_center,
                             act ? &b_gold : &b_white);
                hits_.push_back({"wardrobe_preset", px, top + 172.0f, pw, 108.0f, i, presets[i].id});
            }

            const float tw = (cw - 12.0f) * 0.5f;
            draw_toggle_card("clothes", L"Visual clothes", L"/clothes on|off", snap_.visual_clothes_mode, cx, top + 300.0f, tw, 64.0f);
            draw_toggle_card("hideclothes", L"Hide clothes", L"/hideclothes", snap_.hide_clothes, cx + tw + 12.0f, top + 300.0f, tw, 64.0f);
        } else if (dash_tab_ == TAB_VISUAL) {
            g.DrawString(L"Visual & Theme", -1, &f_h2, Gdiplus::PointF(cx, top), &b_white);
            g.DrawString(L"/fps \x00B7 /rainbow \x00B7 /weather \x00B7 /zoom", -1, &f_mono, Gdiplus::PointF(cx, top + 32.0f), &b_muted);

            const float tw = (cw - 12.0f) * 0.5f;
            draw_toggle_card("rainbow", L"Rainbow", L"/rainbow", snap_.rainbow_name, cx, top + 64.0f, tw, 64.0f);
            draw_toggle_card("fps", L"FPS boost", L"/fps boost", snap_.fps_boost, cx + tw + 12.0f, top + 64.0f, tw, 64.0f);
            draw_toggle_card("pingtag", L"Ping [ms] tags", L"/fps on", snap_.fps_show_name, cx, top + 140.0f, tw, 64.0f);
            draw_toggle_card("bubbles", L"Bubbles", L"/fps bubbles", snap_.fps_hide_bubbles, cx + tw + 12.0f, top + 140.0f, tw, 64.0f);
            draw_toggle_card("weather", L"Weather", L"/weather", snap_.weather_override, cx, top + 216.0f, tw, 64.0f);
            draw_toggle_card("hideclothes", L"Hide clothes", L"/hideclothes", snap_.hide_clothes, cx + tw + 12.0f, top + 216.0f, tw, 64.0f);

            // Zoom Slider Card
            draw_rr(g, cx, top + 298.0f, cw, 82.0f, 10.0f, c_card, c_border_card, 2.0f);
            g.DrawString(L"Zoom", -1, &f_md_b, Gdiplus::PointF(cx + 16.0f, top + 312.0f), &b_white);
            const std::wstring ztxt = std::to_wstring(snap_.zoom_percent) + L"%";
            Gdiplus::StringFormat sf_r;
            sf_r.SetAlignment(Gdiplus::StringAlignmentFar);
            g.DrawString(ztxt.c_str(), -1, &f_mono_b, Gdiplus::RectF(cx + 200.0f, top + 312.0f, cw - 216.0f, 22.0f), &sf_r, &b_cream);

            zoom_track_x_ = cx + 22.0f;
            zoom_track_w_ = cw - 44.0f;
            const float track_y = top + 350.0f;
            fill_rr(g, zoom_track_x_, track_y, zoom_track_w_, 8.0f, 4.0f, c_bg_bar);
            const float ratio = static_cast<float>(std::clamp(snap_.zoom_percent, 50, 200) - 50) / 150.0f;
            const float fill_w = ratio * zoom_track_w_;
            if (fill_w > 4.0f) {
                fill_rr(g, zoom_track_x_, track_y, fill_w, 8.0f, 4.0f, c_gold);
            }
            Gdiplus::SolidBrush kb(c_gold);
            g.FillEllipse(&kb, zoom_track_x_ + fill_w - 9.0f, track_y - 5.0f, 18.0f, 18.0f);
            hits_.push_back({"zoom_slider", zoom_track_x_ - 10.0f, track_y - 14.0f, zoom_track_w_ + 20.0f, 34.0f, 0, ""});
        } else if (dash_tab_ == TAB_TITLES) {
            g.DrawString(L"Titles", -1, &f_h2, Gdiplus::PointF(cx, top), &b_white);
            g.DrawString(L"/title <name>", -1, &f_mono, Gdiplus::PointF(cx, top + 32.0f), &b_muted);

            struct TitleCard { const wchar_t* label; const char* cmd; bool active; int icon_k; };
            const TitleCard cards[6] = {
                {L"Max Level", "/title maxlevel", snap_.title_maxlevel, ICON_TITLE_MAXLEVEL},
                {L"Doctor", "/title doctor", snap_.title_doctor, ICON_TITLE_DOCTOR},
                {L"Legendary", "/title legendary", snap_.title_legendary, ICON_TITLE_LEGENDARY},
                {L"Mod", "/title mod", snap_.title_moderator, ICON_TITLE_MOD},
                {L"Dev", "/title dev", snap_.title_developer, ICON_TITLE_DEV},
                {L"Reset", "/title reset", false, ICON_TITLE_RESET}
            };
            const float bw = (cw - 28.0f) / 3.0f;
            for (int i = 0; i < 6; ++i) {
                const int col_i = i % 3;
                const int row_i = i / 3;
                const float bx = cx + static_cast<float>(col_i) * (bw + 14.0f);
                const float by = top + 64.0f + static_cast<float>(row_i) * 124.0f;
                const bool hov = (hover_id_ == make_hover_id("title_pick", i, cards[i].cmd));
                draw_rr(g, bx, by, bw, 110.0f, 10.0f,
                        hov ? Gdiplus::Color(255, 27, 63, 102) : c_card,
                        cards[i].active ? c_gold : (hov ? c_cyan : c_border_card), cards[i].active ? 3.0f : 2.0f);
                draw_gt_icon(g, cards[i].icon_k, bx + bw * 0.5f - 18.0f, by + 18.0f, 36.0f);
                g.DrawString(cards[i].label, -1, &f_h3, Gdiplus::RectF(bx, by + 62.0f, bw, 28.0f), &sf_center,
                             cards[i].active ? &b_gold : &b_white);
                hits_.push_back({"title_pick", bx, by, bw, 110.0f, i, cards[i].cmd});
            }

            // GT 5.62 Event & Creator Badges strip
            g.DrawString(L"GT 5.62 Badges & Event Titles", -1, &f_sm_b, Gdiplus::PointF(cx, top + 314.0f), &b_gold);
            const TitleCard badges[10] = {
                {L"10-Year", "/title 10y", snap_.title_anniversary, ICON_TAB_TITLES},
                {L"Award", "/title award", snap_.title_award, ICON_TAB_TITLES},
                {L"Party", "/title party", snap_.title_party, ICON_TAB_VISUAL},
                {L"Winter", "/title winter", snap_.title_royalwinter, ICON_TITLE_MAXLEVEL},
                {L"Immortal", "/title immortal", snap_.title_immortal, ICON_TITLE_LEGENDARY},
                {L"GrowRoyal", "/title royal", snap_.title_growroyal_tier > 0, ICON_TAB_TITLES},
                {L"CC Badge", "/title cc", snap_.title_cc_badge, ICON_NET_SHIELD},
                {L"TikTok", "/title tiktok", snap_.title_tt_badge, ICON_PRESET_RAYMAN},
                {L"Pet League", "/title pbl", snap_.title_pbl_role > 0, ICON_TITLE_MOD},
                {L"G4G", "/title g4g", snap_.title_g4g, ICON_PRESET_ANGEL}
            };
            const float chip_w = (cw - 32.0f) / 5.0f;
            for (int i = 0; i < 10; ++i) {
                const int col_i = i % 5;
                const int row_i = i / 5;
                const float bx = cx + static_cast<float>(col_i) * (chip_w + 8.0f);
                const float by = top + 338.0f + static_cast<float>(row_i) * 42.0f;
                draw_rr(g, bx, by, chip_w, 34.0f, 8.0f,
                        badges[i].active ? c_tab_act : c_card,
                        badges[i].active ? c_gold : c_border_card, 1.8f);
                g.DrawString(badges[i].label, -1, &f_sm_b, Gdiplus::RectF(bx, by, chip_w, 34.0f),
                             &sf_center, badges[i].active ? &b_gold : &b_soft);
                hits_.push_back({"title_pick", bx, by, chip_w, 34.0f, 10 + i, badges[i].cmd});
            }

            draw_rr(g, cx, top + 434.0f, cw, 48.0f, 10.0f, c_card, c_border_card, 2.0f);
            const std::wstring cur = L"Current title: " + utf8_to_w(snap_.active_titles_summary);
            g.DrawString(cur.c_str(), -1, &f_md_b, Gdiplus::RectF(cx + 16.0f, top + 434.0f, cw - 32.0f, 48.0f),
                         &sf_vcenter, &b_gold);
        } else if (dash_tab_ == TAB_HOTKEYS) {
            g.DrawString(L"Custom Hotkeys", -1, &f_h2, Gdiplus::PointF(cx, top), &b_white);
            g.DrawString(L"/hotkey \x00B7 12 slots (CTRL, ALT, SHIFT, A, F1, CTRL+A)", -1, &f_mono,
                         Gdiplus::PointF(cx, top + 32.0f), &b_muted);

            const std::wstring hk_lbl = snap_.hotkeys_enabled ? L"Hotkeys: On" : L"Hotkeys: Off";
            draw_rr(g, cx + cw - 242.0f, top + 6.0f, 128.0f, 38.0f, 8.0f, c_card,
                    snap_.hotkeys_enabled ? c_green : c_border_card, 2.0f);
            g.DrawString(hk_lbl.c_str(), -1, &f_sm_b, Gdiplus::RectF(cx + cw - 242.0f, top + 6.0f, 128.0f, 38.0f),
                         &sf_center, &b_white);
            hits_.push_back({"hk_toggle_all", cx + cw - 242.0f, top + 6.0f, 128.0f, 38.0f, 0, ""});

            draw_rr(g, cx + cw - 104.0f, top + 6.0f, 104.0f, 38.0f, 8.0f, c_card, c_border_card, 2.0f);
            g.DrawString(L"Reset all", -1, &f_sm_b, Gdiplus::RectF(cx + cw - 104.0f, top + 6.0f, 104.0f, 38.0f),
                         &sf_center, &b_white);
            hits_.push_back({"hk_reset_all", cx + cw - 104.0f, top + 6.0f, 104.0f, 38.0f, 0, ""});

            const float sw = (cw - 30.0f) / 4.0f;
            for (int i = 0; i < static_cast<int>(kHotkeySlots); ++i) {
                const int col_i = i % 4;
                const int row_i = i / 4;
                const float sx = cx + static_cast<float>(col_i) * (sw + 10.0f);
                const float sy = top + 62.0f + static_cast<float>(row_i) * 82.0f;
                const bool sel = (selected_hk_slot_ == i);
                const auto& hk = (static_cast<size_t>(i) < snap_.hotkeys.size())
                    ? snap_.hotkeys[static_cast<size_t>(i)]
                    : HotkeyBinding{};
                draw_rr(g, sx, sy, sw, 72.0f, 10.0f, c_card, sel ? c_gold : c_border_card, sel ? 3.0f : 2.0f);

                const std::wstring sl_txt = L"Slot " + std::to_wstring(i + 1);
                g.DrawString(sl_txt.c_str(), -1, &f_sm_b, Gdiplus::PointF(sx + 10.0f, sy + 10.0f), &b_muted);

                const bool has_key = !hk.key.empty();
                draw_rr(g, sx + sw - 78.0f, sy + 8.0f, 68.0f, 20.0f, 4.0f,
                        has_key ? c_gold : c_muted, Gdiplus::Color(0, 0, 0, 0), 0.0f);
                g.DrawString(has_key ? utf8_to_w(hk.key).c_str() : L"Empty", -1, &f_mono_b,
                             Gdiplus::RectF(sx + sw - 78.0f, sy + 8.0f, 68.0f, 20.0f), &sf_center, &b_gold_fg);

                const std::wstring c_txt = hk.command.empty() ? L"No command" : utf8_to_w(hk.command);
                g.DrawString(c_txt.c_str(), -1, &f_mono,
                             Gdiplus::RectF(sx + 10.0f, sy + 38.0f, sw - 20.0f, 22.0f), &sf_vcenter, &b_cream);

                hits_.push_back({"hk_slot_pick", sx, sy, sw, 72.0f, i, ""});
            }

            // Edit slot N bar
            draw_rr(g, cx, top + 322.0f, cw, 92.0f, 10.0f, c_card, c_border_card, 2.0f);
            const std::wstring edit_lbl = L"Edit slot " + std::to_wstring(selected_hk_slot_ + 1);
            g.DrawString(edit_lbl.c_str(), -1, &f_md_b, Gdiplus::PointF(cx + 16.0f, top + 334.0f), &b_white);

            draw_rr(g, cx + 16.0f, top + 362.0f, 174.0f, 40.0f, 8.0f, c_bg_bar, c_border_card, 2.0f);
            draw_rr(g, cx + 196.0f, top + 362.0f, cw - 398.0f, 40.0f, 8.0f, c_bg_bar, c_border_card, 2.0f);

            draw_rr(g, cx + cw - 192.0f, top + 362.0f, 88.0f, 40.0f, 8.0f, c_gold, Gdiplus::Color(0, 0, 0, 0), 0.0f);
            g.DrawString(L"Save", -1, &f_md_b, Gdiplus::RectF(cx + cw - 192.0f, top + 362.0f, 88.0f, 40.0f),
                         &sf_center, &b_gold_fg);
            hits_.push_back({"hk_slot_save", cx + cw - 192.0f, top + 362.0f, 88.0f, 40.0f, 0, ""});

            draw_rr(g, cx + cw - 96.0f, top + 362.0f, 80.0f, 40.0f, 8.0f, c_bg_bar, c_border_card, 2.0f);
            g.DrawString(L"Clear", -1, &f_md_b, Gdiplus::RectF(cx + cw - 96.0f, top + 362.0f, 80.0f, 40.0f),
                         &sf_center, &b_white);
            hits_.push_back({"hk_slot_clear", cx + cw - 96.0f, top + 362.0f, 80.0f, 40.0f, 0, ""});
        } else if (dash_tab_ == TAB_TOOLS) {
            g.DrawString(L"Tools & Vending", -1, &f_h2, Gdiplus::PointF(cx, top), &b_white);
            g.DrawString(L"/fastbuy \x00B7 /autobgl \x00B7 /cd", -1, &f_mono, Gdiplus::PointF(cx, top + 32.0f), &b_muted);

            const float left_cw = (cw - 14.0f) * 0.535f;
            const float right_cx = cx + left_cw + 14.0f;
            const float right_cw = cw - left_cw - 14.0f;

            // Fast Buy card
            draw_rr(g, cx, top + 64.0f, left_cw, 234.0f, 10.0f, c_card, c_border_card, 2.0f);
            g.DrawString(L"Fast Buy", -1, &f_md_b, Gdiplus::PointF(cx + 16.0f, top + 78.0f), &b_white);
            g.DrawString(L"/fastbuy", -1, &f_mono, Gdiplus::PointF(cx + 88.0f, top + 80.0f), &b_cream);

            const float mw = (left_cw - 44.0f) / 3.0f;
            const wchar_t* modes[3] = {L"Off", L"Quick", L"Auto"};
            for (int i = 0; i < 3; ++i) {
                const bool act = (snap_.fast_buy == i);
                const float mx = cx + 16.0f + static_cast<float>(i) * (mw + 6.0f);
                draw_rr(g, mx, top + 110.0f, mw, 42.0f, 8.0f,
                        act ? c_gold : c_bg_bar, Gdiplus::Color(0, 0, 0, 0), 0.0f);
                g.DrawString(modes[i], -1, &f_md_b, Gdiplus::RectF(mx, top + 110.0f, mw, 42.0f),
                             &sf_center, act ? &b_gold_fg : &b_white);
                hits_.push_back({"fb_mode", mx, top + 110.0f, mw, 42.0f, i, ""});
            }

            const wchar_t* fb_help = (snap_.fast_buy == 2)
                ? L"Buys immediately when you wrench a Vending Machine (1-click)."
                : ((snap_.fast_buy == 1)
                    ? L"Pre-fills the purchase and skips the confirmation dialog."
                    : L"Vending Machines behave normally.");
            g.DrawString(fb_help, -1, &f_sm, Gdiplus::RectF(cx + 16.0f, top + 166.0f, left_cw - 32.0f, 44.0f),
                         nullptr, &b_soft);

            g.DrawString(L"Amount", -1, &f_md_b, Gdiplus::PointF(cx + 16.0f, top + 240.0f), &b_white);
            draw_rr(g, cx + 80.0f, top + 232.0f, 90.0f, 38.0f, 8.0f, c_bg_bar, c_border_card, 2.0f);
            g.DrawString(L"(0 = Max)", -1, &f_sm, Gdiplus::PointF(cx + 180.0f, top + 242.0f), &b_muted);

            // Right column toggles (including Gems Live Counter)
            draw_toggle_card("vendinfo", L"Vend info", L"/vendinfo", snap_.vending_info, right_cx, top + 64.0f, right_cw, 43.0f);
            draw_toggle_card("autobgl", L"Auto-BGL (Telephone)", L"/autobgl", snap_.auto_bgl, right_cx, top + 112.0f, right_cw, 43.0f);
            draw_toggle_card("gems", L"Gems Live Counter", L"/gems on|off", snap_.gems_tracker, right_cx, top + 160.0f, right_cw, 43.0f);
            draw_toggle_card("fastdrop", L"Fast drop", L"/fastdrop", snap_.fast_drop, right_cx, top + 208.0f, right_cw, 43.0f);
            draw_toggle_card("fasttrash", L"Fast trash", L"/fasttrash", snap_.fast_trash, right_cx, top + 256.0f, right_cw, 43.0f);

            // Smart Lock /cd bar
            draw_rr(g, cx, top + 312.0f, cw, 74.0f, 10.0f, c_card, c_border_card, 2.0f);
            g.DrawString(L"Smart Lock", -1, &f_md_b, Gdiplus::PointF(cx + 16.0f, top + 330.0f), &b_white);
            g.DrawString(L"/cd", -1, &f_mono, Gdiplus::PointF(cx + 102.0f, top + 332.0f), &b_cream);
            draw_rr(g, cx + 138.0f, top + 328.0f, 102.0f, 40.0f, 8.0f, c_bg_bar, c_border_card, 2.0f);

            long long cd_val = 0;
            try {
                const std::string raw = trim_ascii(get_edit_text(edit_cd_amt_));
                if (!raw.empty()) cd_val = std::stoll(raw);
            } catch (...) {
                cd_val = 0;
            }
            const std::wstring drops_lbl = L"Drops " + utf8_to_w(format_cd_breakdown(cd_val));
            g.DrawString(drops_lbl.c_str(), -1, &f_md_b, Gdiplus::RectF(cx + 256.0f, top + 312.0f, cw - 380.0f, 74.0f),
                         &sf_vcenter, &b_gold);

            draw_rr(g, cx + cw - 112.0f, top + 328.0f, 96.0f, 40.0f, 8.0f, c_gold, Gdiplus::Color(0, 0, 0, 0), 0.0f);
            g.DrawString(L"Drop", -1, &f_md_b, Gdiplus::RectF(cx + cw - 112.0f, top + 328.0f, 96.0f, 40.0f),
                         &sf_center, &b_gold_fg);
            hits_.push_back({"cd_drop", cx + cw - 112.0f, top + 328.0f, 96.0f, 40.0f, 0, ""});

            // Live Gems & Floor Drop Scanner Card (/gems)
            draw_rr(g, cx, top + 398.0f, cw, 82.0f, 10.0f, c_card, c_border_card, 2.0f);
            draw_gt_icon(g, ICON_GEM, cx + 16.0f, top + 422.0f, 32.0f);
            std::ostringstream gs1;
            gs1 << "Gems Tracker (/gems)   |   Saldo: "
                << (snap_.gems >= 0 ? std::to_string(snap_.gems) : "-")
                << " Gems   |   World: +" << snap_.gems_collected_world
                << "   |   Floor: " << snap_.world_floor_gems << " Gems";
            g.DrawString(utf8_to_w(gs1.str()).c_str(), -1, &f_md_b,
                         Gdiplus::RectF(cx + 58.0f, top + 408.0f, cw - 208.0f, 28.0f), &sf_vcenter, &b_white);
            g.DrawString(L"Auto tracks dropped floor Gems (#112) & simultaneous locks in real-time.",
                         -1, &f_sm, Gdiplus::RectF(cx + 58.0f, top + 440.0f, cw - 208.0f, 24.0f), &sf_vcenter, &b_muted);
            draw_rr(g, cx + cw - 138.0f, top + 418.0f, 122.0f, 40.0f, 8.0f, c_tab_act, c_cyan, 1.8f);
            g.DrawString(L"Open /gems", -1, &f_sm_b, Gdiplus::RectF(cx + cw - 138.0f, top + 418.0f, 122.0f, 40.0f),
                         &sf_center, &b_white);
            hits_.push_back({"chat_cmd", cx + cw - 138.0f, top + 418.0f, 122.0f, 40.0f, 0, "/gems"});
        } else if (dash_tab_ == TAB_PACKETS) {
            g.DrawString(L"Packet Monitor", -1, &f_h2, Gdiplus::PointF(cx, top), &b_white);
            g.DrawString(L"/paction \x00B7 /pmove \x00B7 /plog \x00B7 /phex", -1, &f_mono,
                         Gdiplus::PointF(cx, top + 32.0f), &b_muted);

            const float tw = (cw - 12.0f) * 0.5f;
            draw_toggle_card("paction", L"Player actions", L"Walk, jump, punch, click", snap_.log_actions, cx, top + 62.0f, tw, 68.0f);
            draw_toggle_card("pmove", L"Movement", L"Raw movement output", snap_.log_raw_movement, cx + tw + 12.0f, top + 62.0f, tw, 68.0f);
            draw_toggle_card("plog", L"Packet log", L"Verbose console output", snap_.verbose_log, cx, top + 142.0f, tw, 68.0f);
            draw_toggle_card("phex", L"Hex dump", L"Packets as hex", snap_.hex_log, cx + tw + 12.0f, top + 142.0f, tw, 68.0f);

            // Live packet terminal
            draw_rr(g, cx, top + 224.0f, cw, 210.0f, 10.0f, c_bg_term, c_border_card, 2.0f);
            if (packet_lines_.empty()) {
                g.DrawString(L"Waiting for packets...", -1, &f_mono, Gdiplus::PointF(cx + 16.0f, top + 240.0f), &b_muted);
                g.DrawString(L"Turn on a monitor above to see traffic here.", -1, &f_mono,
                             Gdiplus::PointF(cx + 16.0f, top + 262.0f), &b_muted);
            } else {
                const int max_rows = 9;
                const int total = static_cast<int>(packet_lines_.size());
                if (pkt_auto_scroll_) {
                    pkt_scroll_ = std::max(0, total - max_rows);
                } else {
                    pkt_scroll_ = std::max(0, std::min(pkt_scroll_, std::max(0, total - max_rows)));
                    if (pkt_scroll_ >= std::max(0, total - max_rows)) pkt_auto_scroll_ = true;
                }
                g.SetClip(Gdiplus::RectF(cx + 12.0f, top + 232.0f, cw - 24.0f, 194.0f));
                for (int r = 0; r < max_rows; ++r) {
                    const int idx = pkt_scroll_ + r;
                    if (idx >= total) break;
                    const auto& pl = packet_lines_[static_cast<size_t>(idx)];
                    const float py = top + 234.0f + static_cast<float>(r) * 21.0f;
                    g.DrawString(utf8_to_w(pl.text).c_str(), -1, &f_mono,
                                 Gdiplus::RectF(cx + 14.0f, py, cw - 28.0f, 21.0f), &sf_vcenter, &b_soft);
                }
                g.ResetClip();
            }

            const std::string lpath = snap_.log_file_path.empty()
                ? std::string("logs\\packets_YYYYMMDD_HHMMSS.log")
                : snap_.log_file_path;
            g.DrawString(utf8_to_w(lpath).c_str(), -1, &f_mono,
                         Gdiplus::RectF(cx, top + 448.0f, cw - 150.0f, 36.0f), &sf_vcenter, &b_cream);

            draw_rr(g, cx + cw - 140.0f, top + 446.0f, 140.0f, 38.0f, 8.0f, c_card, c_border_card, 2.0f);
            g.DrawString(L"Clear console", -1, &f_sm_b, Gdiplus::RectF(cx + cw - 140.0f, top + 446.0f, 140.0f, 38.0f),
                         &sf_center, &b_white);
            hits_.push_back({"pkt_clear", cx + cw - 140.0f, top + 446.0f, 140.0f, 38.0f, 0, ""});
        } else if (dash_tab_ == TAB_COMMANDS) {
            g.DrawString(L"Commands", -1, &f_h2, Gdiplus::PointF(cx, top), &b_white);
            g.DrawString(L"Type any of these in chat (click a row to copy)", -1, &f_mono,
                         Gdiplus::PointF(cx, top + 32.0f), &b_muted);

            draw_rr(g, cx, top + 60.0f, cw, 42.0f, 8.0f, c_bg_bar, c_border_card, 2.0f);

            const std::string q = to_lower_ascii(trim_ascii(get_edit_text(edit_cmd_query_)));
            std::vector<const CmdEntry*> filtered;
            for (const auto& ce : kCommands) {
                if (q.empty() ||
                    to_lower_ascii(ce.cmd).find(q) != std::string::npos ||
                    to_lower_ascii(ce.desc).find(q) != std::string::npos) {
                    filtered.push_back(&ce);
                }
            }

            const int max_rows = 6;
            const int total = static_cast<int>(filtered.size());
            cmd_scroll_ = std::max(0, std::min(cmd_scroll_, std::max(0, total - max_rows)));

            if (filtered.empty()) {
                g.DrawString(L"No command matches that search.", -1, &f_md,
                             Gdiplus::PointF(cx + 8.0f, top + 124.0f), &b_muted);
            } else {
                for (int r = 0; r < max_rows; ++r) {
                    const int idx = cmd_scroll_ + r;
                    if (idx >= total) break;
                    const CmdEntry* ce = filtered[static_cast<size_t>(idx)];
                    const float ry = top + 114.0f + static_cast<float>(r) * 58.0f;
                    draw_rr(g, cx, ry, cw, 50.0f, 10.0f, c_card, c_border_card, 2.0f);
                    g.DrawString(utf8_to_w(ce->cmd).c_str(), -1, &f_mono_b,
                                 Gdiplus::RectF(cx + 14.0f, ry, 250.0f, 50.0f), &sf_vcenter, &b_cream);
                    g.DrawString(utf8_to_w(ce->desc).c_str(), -1, &f_sm,
                                 Gdiplus::RectF(cx + 270.0f, ry, cw - 284.0f, 50.0f), &sf_vcenter, &b_soft);
                    hits_.push_back({"cmd_copy", cx, ry, cw, 50.0f, idx, ce->copy_template});
                }
            }
        }
    }

    // Footer Status Bar
    {
        const float fy = H - static_cast<float>(kFooterH);
        Gdiplus::SolidBrush b_ftr(c_bg_bar);
        g.FillRectangle(&b_ftr, 0.0f, fy, W, static_cast<float>(kFooterH));
        Gdiplus::Pen sep(c_border_bar, 2.0f);
        g.DrawLine(&sep, 0.0f, fy, W, fy);

        const int64_t now_ms = steady_now_ms();
        std::wstring left_txt = (view_ == AppView::Launcher)
            ? L"Open Growtopia after the proxy shows Running"
            : L"Hosts file is restored when the proxy exits";
        if (!footer_notice_.empty() && now_ms < footer_notice_until_ms_) {
            left_txt = utf8_to_w(footer_notice_);
        }
        g.DrawString(left_txt.c_str(), -1, &f_sm,
                     Gdiplus::RectF(20.0f, fy, 480.0f, static_cast<float>(kFooterH)), &sf_vcenter, &b_muted);

        const wchar_t* right_txt = (view_ == AppView::Launcher)
            ? L"--install-cert \x00B7 --uninstall-cert \x00B7 --clean-hosts \x00B7 --no-hosts"
            : L"Type /proxy in chat to open in-game Dashboard";
        Gdiplus::StringFormat sf_r;
        sf_r.SetAlignment(Gdiplus::StringAlignmentFar);
        sf_r.SetLineAlignment(Gdiplus::StringAlignmentCenter);
        g.DrawString(right_txt, -1, &f_mono,
                     Gdiplus::RectF(W - 560.0f, fy, 540.0f, static_cast<float>(kFooterH)), &sf_r, &b_muted);
    }

    // Outer frame border (#6fb7e6)
    {
        Gdiplus::Pen outer_pen(c_border_outer, 2.5f);
        g.DrawRectangle(&outer_pen, 1.0f, 1.0f, W - 2.0f, H - 2.0f);
    }

    BitBlt(hdc, 0, 0, cw, ch, back_dc_, 0, 0, SRCCOPY);
    EndPaint(hwnd_, &ps);
    needs_repaint_ = false;
}

LRESULT GuiWindow::handle_msg(UINT msg, WPARAM wparam, LPARAM lparam) {
    switch (msg) {
        case WM_CREATE:
            on_create();
            return 0;

        case WM_TIMER: {
            if (wparam == 1) {
                refresh_dpi();
                snap_ = controller_.get_live_snapshot();
                console_lines_ = controller_.get_console_lines();
                packet_lines_ = controller_.get_packet_lines();

                overlay_hud_.update(snap_, hwnd_);

                uint64_t h = 14695981039346656037ULL;
                hash_val(h, view_);
                hash_val(h, dash_tab_);
                hash_val(h, selected_hk_slot_);
                hash_val(h, snap_.proxy_running);
                hash_val(h, snap_.http_running);
                hash_val(h, snap_.enet_running);
                hash_val(h, snap_.port_conflict);
                hash_val(h, snap_.ca_installed);
                hash_val(h, snap_.manage_hosts);
                hash_val(h, snap_.hosts_active);
                hash_val(h, snap_.client_connected);
                hash_val(h, snap_.in_world);
                hash_val(h, snap_.live_ping_ms);
                hash_val(h, snap_.live_fps);
                hash_val(h, snap_.wl);
                hash_val(h, snap_.dl);
                hash_val(h, snap_.bgl);
                hash_val(h, snap_.gems);
                hash_val(h, snap_.gems_collected_world);
                hash_val(h, snap_.gems_collected_session);
                hash_val(h, snap_.world_floor_gems);
                hash_val(h, snap_.gems_tracker);
                hash_val(h, snap_.evan_branding);
                hash_val(h, snap_.outgoing_evan_prefix);
                hash_val(h, snap_.fps_boost);
                hash_val(h, snap_.fps_show_name);
                hash_val(h, snap_.fps_hide_bubbles);
                hash_val(h, snap_.vending_info);
                hash_val(h, snap_.auto_bgl);
                hash_val(h, snap_.hotkeys_enabled);
                hash_val(h, snap_.fast_drop);
                hash_val(h, snap_.fast_trash);
                hash_val(h, snap_.rainbow_name);
                hash_val(h, snap_.unlimited_zoom);
                hash_val(h, snap_.weather_override);
                hash_val(h, snap_.hide_clothes);
                hash_val(h, snap_.visual_clothes_mode);
                hash_val(h, snap_.hud_overlay);
                hash_val(h, snap_.log_actions);
                hash_val(h, snap_.log_raw_movement);
                hash_val(h, snap_.verbose_log);
                hash_val(h, snap_.hex_log);
                hash_val(h, snap_.zoom_percent);
                hash_val(h, snap_.fast_buy);
                hash_val(h, snap_.fast_buy_qty);
                hash_val(h, console_lines_.size());
                hash_val(h, packet_lines_.size());
                hash_str(h, snap_.active_preset);
                hash_str(h, snap_.active_titles_summary);
                hash_str(h, snap_.current_world);
                hash_str(h, snap_.last_error);
                if (!console_lines_.empty()) hash_val(h, console_lines_.back().seq);
                if (!packet_lines_.empty()) hash_val(h, packet_lines_.back().seq);
                if (!footer_notice_.empty() && steady_now_ms() < footer_notice_until_ms_) {
                    hash_str(h, footer_notice_);
                }

                if (needs_repaint_ || h != last_render_hash_) {
                    last_render_hash_ = h;
                    InvalidateRect(hwnd_, nullptr, FALSE);
                }
            }
            return 0;
        }

        case WM_COMMAND: {
            const int cid = LOWORD(wparam);
            const int code = HIWORD(wparam);
            if (code == EN_CHANGE) {
                if (cid == IDC_EDIT_FB_AMT) {
                    const std::string raw = trim_ascii(get_edit_text(edit_fb_amt_));
                    if (!raw.empty()) {
                        try {
                            int q = std::stoi(raw);
                            if (q >= 0 && q <= 200) {
                                UiCommand cmd;
                                cmd.kind = UiCommand::Kind::SetFastBuyQty;
                                cmd.int_arg = q;
                                controller_.dispatch_ui_command(cmd);
                            }
                        } catch (...) {}
                    }
                } else if (cid == IDC_EDIT_CD_AMT || cid == IDC_EDIT_CMD_QUERY || cid == IDC_EDIT_SEARCH) {
                    needs_repaint_ = true;
                    InvalidateRect(hwnd_, nullptr, FALSE);
                }
            }
            return 0;
        }

        case WM_CTLCOLOREDIT: {
            HDC hdc_edit = reinterpret_cast<HDC>(wparam);
            SetTextColor(hdc_edit, RGB(255, 255, 255));
            SetBkColor(hdc_edit, RGB(10, 26, 44));
            return reinterpret_cast<LRESULT>(edit_bg_brush_);
        }

        case WM_PAINT:
            on_paint();
            return 0;

        case WM_ERASEBKGND:
            return 1;

        case WM_LBUTTONDOWN:
            on_lbutton_down(GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam));
            return 0;

        case WM_MOUSEMOVE:
            on_mouse_move(GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam));
            return 0;

        case WM_LBUTTONUP:
            on_lbutton_up();
            return 0;

        case WM_MOUSEWHEEL:
            on_mouse_wheel(GET_WHEEL_DELTA_WPARAM(wparam));
            return 0;

        case WM_CLOSE:
            DestroyWindow(hwnd_);
            return 0;

        case WM_DESTROY:
            KillTimer(hwnd_, 1);
            overlay_hud_.destroy();
            controller_.stop();
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd_, msg, wparam, lparam);
}

} // namespace

int DesktopGui::run(ProxyController& controller, bool auto_start) {
    GuiWindow win(controller, auto_start);
    return win.run();
}

} // namespace evan
