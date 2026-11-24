#pragma once

#include "config.hpp"

#include <chrono>
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

namespace evan {

enum class LogTag {
    Info = 0,
    Ok,
    Warn,
    Error,
    Http,
    Enet,
    Action,
    Packet
};

struct ConsoleLine {
    uint64_t seq = 0;
    LogTag tag = LogTag::Info;
    std::string tag_text;
    std::string text;
};

struct HudToastState {
    bool hotkey_visible = false;
    std::string hotkey_key;
    std::string hotkey_cmd;
    int64_t hotkey_expire_ms = 0;

    bool vend_visible = false;
    int64_t vend_rem_stock = 0;
    int64_t vend_rem_wl = 0;
    std::string vend_item_name;
    int64_t vend_expire_ms = 0;

    bool calc_visible = false;
    std::string calc_title;
    std::string calc_value;
    int64_t calc_expire_ms = 0;

    bool timer_active = false;
    int timer_remaining_sec = 0;
    std::string timer_label;
};

struct UiSnapshot {
    // Runtime
    bool proxy_running = false;
    bool http_running = false;
    bool enet_running = false;
    bool port_conflict = false;
    std::string last_error;
    uint16_t http_port = 443;
    uint16_t enet_port = 17091;
    bool ca_installed = false;
    bool manage_hosts = true;
    bool hosts_active = false;

    // Session
    bool client_connected = false;
    bool in_world = false;
    std::string player_name;
    std::string current_world;
    std::string previous_world;
    std::string world_owner;
    size_t player_count = 0;
    std::string upstream_addr;
    std::string log_file_path;

    // Wealth & Telemetry
    uint32_t wl = 0;
    uint32_t dl = 0;
    uint32_t bgl = 0;
    int64_t gems = -1;
    int64_t gems_collected_world = 0;
    int64_t gems_collected_session = 0;
    int64_t world_floor_gems = 0;
    int live_ping_ms = 0;
    int ping_min_ms = 0;
    int ping_max_ms = 0;
    int ping_jitter_ms = 0;
    int live_fps = 60;
    int proxy_overhead_us = 0;
    uint64_t c2s_packets = 0;
    uint64_t s2c_packets = 0;

    // Toggles & Settings
    bool evan_branding = true;
    bool outgoing_evan_prefix = false;
    bool fps_boost = false;
    bool fps_show_name = false;
    bool fps_hide_bubbles = false;
    bool vending_info = true;
    bool auto_bgl = false;
    bool gems_tracker = true;
    bool hotkeys_enabled = true;
    bool fast_drop = false;
    bool fast_trash = false;
    bool rainbow_name = false;
    bool unlimited_zoom = false;
    bool weather_override = false;
    bool hide_clothes = false;
    bool visual_clothes_mode = false;
    bool custom_banner = true;
    bool hud_overlay = true;
    bool log_actions = true;
    bool log_raw_movement = false;
    bool verbose_log = false;
    bool hex_log = false;

    int zoom_percent = 100;
    uint32_t weather_id = 15;
    int fast_buy = 0;
    int fast_buy_qty = 1;

    std::string active_preset;
    std::string active_titles_summary = "Tidak ada";

    // Individual title states
    bool title_maxlevel = false;
    bool title_doctor = false;
    bool title_legendary = false;
    bool title_g4g = false;
    bool title_master = false;
    bool title_mentor = false;
    bool title_anniversary = false;
    bool title_award = false;
    bool title_party = false;
    bool title_royalwinter = false;
    bool title_immortal = false;
    bool title_thanksgiving = false;
    bool title_cc_badge = false;
    bool title_tt_badge = false;
    bool title_moderator = false;
    bool title_developer = false;
    int title_growroyal_tier = 0;
    int title_pbl_role = 0;

    std::vector<HotkeyBinding> hotkeys = default_hotkeys();
    HudToastState hud;
};

struct UiCommand {
    enum class Kind {
        RunChatCommand = 0,
        SetToggle,
        SetFastBuyMode,
        SetFastBuyQty,
        SetZoomPercent,
        SetWeatherOverride,
        SetHotkeySlot,
        ClearHotkeySlot,
        ResetHotkeys,
        WardrobeAddItem,
        ClearConsole
    };

    Kind kind = Kind::RunChatCommand;
    std::string key;
    std::string value;
    int int_arg = 0;
    bool bool_arg = false;
};

inline std::string format_cd_breakdown(int64_t total_wl) {
    if (total_wl <= 0) {
        return "enter an amount";
    }
    const int64_t bgl = total_wl / 10000;
    const int64_t dl = (total_wl % 10000) / 100;
    const int64_t wl = total_wl % 100;

    std::ostringstream oss;
    bool first = true;
    auto push_part = [&](int64_t n, const char* unit) {
        if (n <= 0) return;
        if (!first) oss << " + ";
        oss << n << " " << unit;
        first = false;
    };
    push_part(bgl, "BGL");
    push_part(dl, "DL");
    push_part(wl, "WL");
    return oss.str();
}

inline int64_t steady_now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

} // namespace evan
