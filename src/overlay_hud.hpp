#pragma once

#include "ui_bridge.hpp"

#include <winsock2.h>
#include <windows.h>

#include <string>

namespace evan {

class OverlayHud {
public:
    OverlayHud() = default;
    ~OverlayHud();

    OverlayHud(const OverlayHud&) = delete;
    OverlayHud& operator=(const OverlayHud&) = delete;

    bool create(HINSTANCE hinst);
    void destroy();

    // Syncs overlay visibility, position, and contents with the foreground Growtopia client window.
    void update(const UiSnapshot& snap, HWND main_gui_hwnd);

private:
    void render_bitmap(const UiSnapshot& snap, int w, int h, int dst_x, int dst_y);
    void hide();

    HWND hwnd_ = nullptr;
    bool visible_ = false;
    std::string last_signature_;

    HDC mem_dc_ = nullptr;
    HBITMAP dib_bmp_ = nullptr;
    HBITMAP old_bmp_ = nullptr;
    void* dib_bits_ = nullptr;
    int dib_w_ = 0;
    int dib_h_ = 0;
};

} // namespace evan
