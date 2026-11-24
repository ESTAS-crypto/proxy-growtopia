#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace evan {

// Custom keyboard shortcut: key text such as "F1", "A", "CTRL+A", "ALT+1" and a
// command/chat text such as "/warp start" executed when the key is pressed.
struct HotkeyBinding {
    std::string key;
    std::string command;
};

constexpr size_t kHotkeySlots = 12;

inline std::vector<HotkeyBinding> default_hotkeys() {
    std::vector<HotkeyBinding> v(kHotkeySlots);
    const char* keys[] = {"F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10", "", ""};
    const char* cmds[] = {"/proxy", "/clothes", "/search", "/fastdrop", "/re",
                          "/back", "/autobgl", "/fpsboost", "/title", "/convert", "", ""};
    for (size_t i = 0; i < kHotkeySlots; ++i) {
        v[i].key = keys[i];
        v[i].command = cmds[i];
    }
    return v;
}

struct ProxyConfig {
    std::string local_ip = "127.0.0.1";
    uint16_t http_port = 443;
    uint16_t enet_port = 17091;
    bool manage_hosts = true;
    std::vector<std::string> server_data_hosts = {"www.growtopia1.com", "www.growtopia2.com"};
    std::string dns_server = "1.1.1.1";
    bool verify_upstream_tls = false;
    bool using_new_packet = true;
    bool log_text_packets = true;
    bool log_variants = true;
    bool log_game_packets = false;
    bool log_to_file = true;
    bool log_hex = false;
    bool log_actions = true;
    bool log_raw_movement = false;

    // QoL & UI feature toggles
    std::string ui_theme = "ocean";
    bool fast_drop = false;
    bool fast_trash = false;
    bool unlimited_zoom = false;
    bool hide_clothes = false;
    bool formalize_chat = false;
    bool style_all_dialogs = false;
    bool auto_bgl = false;
    bool hotkeys_enabled = true;
    int fast_buy = 0;       // 0=Off, 1=Quick (prefill + skip confirmation), 2=Auto (buy on wrench)
    int fast_buy_qty = 0;   // 0 = max affordable
    bool vending_info = true;
    std::vector<HotkeyBinding> hotkeys = default_hotkeys();
    bool title_maxlevel = false;
    bool title_doctor = false;
    bool title_legendary = false;
    bool title_g4g = false;
    bool title_master = false;
    bool title_mentor = false;
    int title_growroyal_tier = 0; // 0=Off, 1=Gold, 2=Silver, 3=Bronze
    bool title_royalwinter = false;
    bool title_thanksgiving = false;
    bool title_anniversary = false;
    bool title_award = false;
    bool title_party = false;
    bool title_cc_badge = false;
    bool title_tt_badge = false;
    int title_pbl_role = 0; // 0=Off, 1=Organizer, 2=Moderator
    bool title_immortal = false;
    bool title_moderator = false;
    bool title_developer = false;
    bool fps_show_name = false;
    bool fps_boost = false;
    bool fps_hide_bubbles = false;
    bool evan_branding = true;
    bool outgoing_evan_prefix = false;
    bool rainbow_name = false;
};

std::filesystem::path get_exe_dir();
ProxyConfig load_or_create_config(const std::filesystem::path& path);
bool save_config(const std::filesystem::path& path, const ProxyConfig& cfg);
bool save_default_config(const std::filesystem::path& path, const ProxyConfig& cfg);

} // namespace evan
