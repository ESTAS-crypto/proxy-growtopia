#include "config.hpp"

#include <winsock2.h>
#include <windows.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

namespace evan {

namespace {

std::string trim(const std::string& s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) {
        ++start;
    }
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) {
        --end;
    }
    return s.substr(start, end - start);
}

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

bool parse_bool(const std::string& v, bool fallback) {
    const std::string low = to_lower(trim(v));
    if (low == "1" || low == "true" || low == "yes" || low == "on") return true;
    if (low == "0" || low == "false" || low == "no" || low == "off") return false;
    return fallback;
}

uint16_t parse_port(const std::string& v, uint16_t fallback) {
    try {
        int p = std::stoi(trim(v));
        if (p > 0 && p <= 65535) {
            return static_cast<uint16_t>(p);
        }
    } catch (...) {
    }
    return fallback;
}

int parse_int_clamped(const std::string& v, int lo, int hi, int fallback) {
    try {
        int val = std::stoi(trim(v));
        if (val < lo) return lo;
        if (val > hi) return hi;
        return val;
    } catch (...) {
        return fallback;
    }
}

std::vector<std::string> split_csv(const std::string& v) {
    std::vector<std::string> out;
    std::stringstream ss(v);
    std::string item;
    while (std::getline(ss, item, ',')) {
        item = trim(item);
        if (!item.empty()) {
            out.push_back(item);
        }
    }
    return out;
}

} // namespace

std::filesystem::path get_exe_dir() {
    char buf[MAX_PATH] = {};
    DWORD len = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        return std::filesystem::current_path();
    }
    return std::filesystem::path(buf).parent_path();
}

bool save_config(const std::filesystem::path& path, const ProxyConfig& cfg) {
    if (path.empty()) return false;
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        return false;
    }
    out << "# EvanProxy Configuration\r\n"
        << "[proxy]\r\n"
        << "local_ip=" << cfg.local_ip << "\r\n"
        << "http_port=" << cfg.http_port << "\r\n"
        << "enet_port=" << cfg.enet_port << "\r\n"
        << "manage_hosts=" << (cfg.manage_hosts ? "true" : "false") << "\r\n"
        << "\r\n"
        << "[upstream]\r\n"
        << "server_data_hosts=";
    for (size_t i = 0; i < cfg.server_data_hosts.size(); ++i) {
        if (i > 0) out << ",";
        out << cfg.server_data_hosts[i];
    }
    out << "\r\n"
        << "dns_server=" << cfg.dns_server << "\r\n"
        << "verify_upstream_tls=" << (cfg.verify_upstream_tls ? "true" : "false") << "\r\n"
        << "using_new_packet=" << (cfg.using_new_packet ? "true" : "false") << "\r\n"
        << "\r\n"
        << "[log]\r\n"
        << "log_text_packets=" << (cfg.log_text_packets ? "true" : "false") << "\r\n"
        << "log_variants=" << (cfg.log_variants ? "true" : "false") << "\r\n"
        << "log_game_packets=" << (cfg.log_game_packets ? "true" : "false") << "\r\n"
        << "log_to_file=" << (cfg.log_to_file ? "true" : "false") << "\r\n"
        << "log_hex=" << (cfg.log_hex ? "true" : "false") << "\r\n"
        << "log_actions=" << (cfg.log_actions ? "true" : "false") << "\r\n"
        << "log_raw_movement=" << (cfg.log_raw_movement ? "true" : "false") << "\r\n"
        << "\r\n"
        << "[features]\r\n"
        << "ui_theme=" << cfg.ui_theme << "\r\n"
        << "fast_drop=" << (cfg.fast_drop ? "true" : "false") << "\r\n"
        << "fast_trash=" << (cfg.fast_trash ? "true" : "false") << "\r\n"
        << "unlimited_zoom=" << (cfg.unlimited_zoom ? "true" : "false") << "\r\n"
        << "hide_clothes=" << (cfg.hide_clothes ? "true" : "false") << "\r\n"
        << "formalize_chat=" << (cfg.formalize_chat ? "true" : "false") << "\r\n"
        << "style_all_dialogs=" << (cfg.style_all_dialogs ? "true" : "false") << "\r\n"
        << "auto_bgl=" << (cfg.auto_bgl ? "true" : "false") << "\r\n"
        << "hotkeys_enabled=" << (cfg.hotkeys_enabled ? "true" : "false") << "\r\n"
        << "fast_buy=" << cfg.fast_buy << "\r\n"
        << "fast_buy_qty=" << cfg.fast_buy_qty << "\r\n"
        << "vending_info=" << (cfg.vending_info ? "true" : "false") << "\r\n"
        << "title_maxlevel=" << (cfg.title_maxlevel ? "true" : "false") << "\r\n"
        << "title_doctor=" << (cfg.title_doctor ? "true" : "false") << "\r\n"
        << "title_legendary=" << (cfg.title_legendary ? "true" : "false") << "\r\n"
        << "title_g4g=" << (cfg.title_g4g ? "true" : "false") << "\r\n"
        << "title_master=" << (cfg.title_master ? "true" : "false") << "\r\n"
        << "title_mentor=" << (cfg.title_mentor ? "true" : "false") << "\r\n"
        << "title_growroyal_tier=" << cfg.title_growroyal_tier << "\r\n"
        << "title_royalwinter=" << (cfg.title_royalwinter ? "true" : "false") << "\r\n"
        << "title_thanksgiving=" << (cfg.title_thanksgiving ? "true" : "false") << "\r\n"
        << "title_anniversary=" << (cfg.title_anniversary ? "true" : "false") << "\r\n"
        << "title_award=" << (cfg.title_award ? "true" : "false") << "\r\n"
        << "title_party=" << (cfg.title_party ? "true" : "false") << "\r\n"
        << "title_cc_badge=" << (cfg.title_cc_badge ? "true" : "false") << "\r\n"
        << "title_tt_badge=" << (cfg.title_tt_badge ? "true" : "false") << "\r\n"
        << "title_pbl_role=" << cfg.title_pbl_role << "\r\n"
        << "title_immortal=" << (cfg.title_immortal ? "true" : "false") << "\r\n"
        << "title_moderator=" << (cfg.title_moderator ? "true" : "false") << "\r\n"
        << "title_developer=" << (cfg.title_developer ? "true" : "false") << "\r\n"
        << "fps_show_name=" << (cfg.fps_show_name ? "true" : "false") << "\r\n"
        << "fps_boost=" << (cfg.fps_boost ? "true" : "false") << "\r\n"
        << "fps_hide_bubbles=" << (cfg.fps_hide_bubbles ? "true" : "false") << "\r\n"
        << "evan_branding=" << (cfg.evan_branding ? "true" : "false") << "\r\n"
        << "outgoing_evan_prefix=" << (cfg.outgoing_evan_prefix ? "true" : "false") << "\r\n"
        << "rainbow_name=" << (cfg.rainbow_name ? "true" : "false") << "\r\n"
        << "\r\n"
        << "[hotkeys]\r\n"
        << "# hotkey_N_key = tombol (F1, A, CTRL+A, ALT+1, NUM1 ...), hotkey_N_cmd = command/chat\r\n";
    for (size_t i = 0; i < cfg.hotkeys.size(); ++i) {
        out << "hotkey_" << (i + 1) << "_key=" << cfg.hotkeys[i].key << "\r\n"
            << "hotkey_" << (i + 1) << "_cmd=" << cfg.hotkeys[i].command << "\r\n";
    }
    return out.good();
}

bool save_default_config(const std::filesystem::path& path, const ProxyConfig& cfg) {
    return save_config(path, cfg);
}

ProxyConfig load_or_create_config(const std::filesystem::path& path) {
    ProxyConfig cfg;
    if (!std::filesystem::exists(path)) {
        save_config(path, cfg);
        return cfg;
    }

    std::ifstream in(path);
    if (!in) {
        return cfg;
    }

    std::string section;
    std::string line;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }
        if (line.front() == '[' && line.back() == ']') {
            section = to_lower(trim(line.substr(1, line.size() - 2)));
            continue;
        }
        size_t eq = line.find('=');
        if (eq == std::string::npos) {
            continue;
        }
        std::string key = to_lower(trim(line.substr(0, eq)));
        std::string val = trim(line.substr(eq + 1));

        if ((section.empty() || section == "proxy") && key == "local_ip" && !val.empty()) {
            cfg.local_ip = val;
        } else if ((section.empty() || section == "proxy") && key == "http_port") {
            cfg.http_port = parse_port(val, cfg.http_port);
        } else if ((section.empty() || section == "proxy") && key == "enet_port") {
            cfg.enet_port = parse_port(val, cfg.enet_port);
        } else if ((section.empty() || section == "proxy") && key == "manage_hosts") {
            cfg.manage_hosts = parse_bool(val, cfg.manage_hosts);
        } else if ((section.empty() || section == "upstream") && key == "server_data_hosts") {
            auto hosts = split_csv(val);
            if (!hosts.empty()) {
                cfg.server_data_hosts = std::move(hosts);
            }
        } else if ((section.empty() || section == "upstream") && key == "dns_server" && !val.empty()) {
            cfg.dns_server = val;
        } else if ((section.empty() || section == "upstream") && key == "verify_upstream_tls") {
            cfg.verify_upstream_tls = parse_bool(val, cfg.verify_upstream_tls);
        } else if ((section.empty() || section == "upstream") && key == "using_new_packet") {
            cfg.using_new_packet = parse_bool(val, cfg.using_new_packet);
        } else if ((section.empty() || section == "log") && key == "log_text_packets") {
            cfg.log_text_packets = parse_bool(val, cfg.log_text_packets);
        } else if ((section.empty() || section == "log") && key == "log_variants") {
            cfg.log_variants = parse_bool(val, cfg.log_variants);
        } else if ((section.empty() || section == "log") && key == "log_game_packets") {
            cfg.log_game_packets = parse_bool(val, cfg.log_game_packets);
        } else if ((section.empty() || section == "log") && key == "log_to_file") {
            cfg.log_to_file = parse_bool(val, cfg.log_to_file);
        } else if ((section.empty() || section == "log") && key == "log_hex") {
            cfg.log_hex = parse_bool(val, cfg.log_hex);
        } else if ((section.empty() || section == "log") && key == "log_actions") {
            cfg.log_actions = parse_bool(val, cfg.log_actions);
        } else if ((section.empty() || section == "log") && key == "log_raw_movement") {
            cfg.log_raw_movement = parse_bool(val, cfg.log_raw_movement);
        } else if ((section.empty() || section == "features") && key == "ui_theme" && !val.empty()) {
            cfg.ui_theme = to_lower(val);
        } else if ((section.empty() || section == "features") && key == "fast_drop") {
            cfg.fast_drop = parse_bool(val, cfg.fast_drop);
        } else if ((section.empty() || section == "features") && key == "fast_trash") {
            cfg.fast_trash = parse_bool(val, cfg.fast_trash);
        } else if ((section.empty() || section == "features") && key == "unlimited_zoom") {
            cfg.unlimited_zoom = parse_bool(val, cfg.unlimited_zoom);
        } else if ((section.empty() || section == "features") && key == "hide_clothes") {
            cfg.hide_clothes = parse_bool(val, cfg.hide_clothes);
        } else if ((section.empty() || section == "features") && key == "formalize_chat") {
            cfg.formalize_chat = parse_bool(val, cfg.formalize_chat);
        } else if ((section.empty() || section == "features") && key == "style_all_dialogs") {
            cfg.style_all_dialogs = parse_bool(val, cfg.style_all_dialogs);
        } else if ((section.empty() || section == "features") && key == "auto_bgl") {
            cfg.auto_bgl = parse_bool(val, cfg.auto_bgl);
        } else if ((section.empty() || section == "features") && key == "hotkeys_enabled") {
            cfg.hotkeys_enabled = parse_bool(val, cfg.hotkeys_enabled);
        } else if ((section.empty() || section == "features") && key == "fast_buy") {
            cfg.fast_buy = parse_int_clamped(val, 0, 2, cfg.fast_buy);
        } else if ((section.empty() || section == "features") && key == "fast_buy_qty") {
            cfg.fast_buy_qty = parse_int_clamped(val, 0, 200, cfg.fast_buy_qty);
        } else if ((section.empty() || section == "features") && key == "vending_info") {
            cfg.vending_info = parse_bool(val, cfg.vending_info);
        } else if (section == "hotkeys" && key.rfind("hotkey_", 0) == 0) {
            // hotkey_<N>_key / hotkey_<N>_cmd
            const size_t us = key.find('_', 7);
            if (us != std::string::npos) {
                try {
                    const size_t idx = static_cast<size_t>(std::stoul(key.substr(7, us - 7)));
                    if (idx >= 1 && idx <= kHotkeySlots) {
                        if (cfg.hotkeys.size() < kHotkeySlots) cfg.hotkeys.resize(kHotkeySlots);
                        const std::string field = key.substr(us + 1);
                        if (field == "key") cfg.hotkeys[idx - 1].key = val;
                        else if (field == "cmd") cfg.hotkeys[idx - 1].command = val;
                    }
                } catch (...) {
                }
            }
        } else if ((section.empty() || section == "features") && key == "title_maxlevel") {
            cfg.title_maxlevel = parse_bool(val, cfg.title_maxlevel);
        } else if ((section.empty() || section == "features") && key == "title_doctor") {
            cfg.title_doctor = parse_bool(val, cfg.title_doctor);
        } else if ((section.empty() || section == "features") && key == "title_legendary") {
            cfg.title_legendary = parse_bool(val, cfg.title_legendary);
        } else if ((section.empty() || section == "features") && key == "title_g4g") {
            cfg.title_g4g = parse_bool(val, cfg.title_g4g);
        } else if ((section.empty() || section == "features") && key == "title_master") {
            cfg.title_master = parse_bool(val, cfg.title_master);
        } else if ((section.empty() || section == "features") && key == "title_mentor") {
            cfg.title_mentor = parse_bool(val, cfg.title_mentor);
        } else if ((section.empty() || section == "features") && key == "title_growroyal") {
            cfg.title_growroyal_tier = parse_bool(val, false) ? 1 : 0;
        } else if ((section.empty() || section == "features") && key == "title_growroyal_tier") {
            cfg.title_growroyal_tier = parse_int_clamped(val, 0, 3, cfg.title_growroyal_tier);
        } else if ((section.empty() || section == "features") && key == "title_royalwinter") {
            cfg.title_royalwinter = parse_bool(val, cfg.title_royalwinter);
        } else if ((section.empty() || section == "features") && key == "title_thanksgiving") {
            cfg.title_thanksgiving = parse_bool(val, cfg.title_thanksgiving);
        } else if ((section.empty() || section == "features") && key == "title_anniversary") {
            cfg.title_anniversary = parse_bool(val, cfg.title_anniversary);
        } else if ((section.empty() || section == "features") && key == "title_award") {
            cfg.title_award = parse_bool(val, cfg.title_award);
        } else if ((section.empty() || section == "features") && key == "title_party") {
            cfg.title_party = parse_bool(val, cfg.title_party);
        } else if ((section.empty() || section == "features") && key == "title_cc_badge") {
            cfg.title_cc_badge = parse_bool(val, cfg.title_cc_badge);
        } else if ((section.empty() || section == "features") && key == "title_tt_badge") {
            cfg.title_tt_badge = parse_bool(val, cfg.title_tt_badge);
        } else if ((section.empty() || section == "features") && key == "title_pbl_role") {
            cfg.title_pbl_role = parse_int_clamped(val, 0, 2, cfg.title_pbl_role);
        } else if ((section.empty() || section == "features") && key == "title_immortal") {
            cfg.title_immortal = parse_bool(val, cfg.title_immortal);
        } else if ((section.empty() || section == "features") && key == "title_moderator") {
            cfg.title_moderator = parse_bool(val, cfg.title_moderator);
        } else if ((section.empty() || section == "features") && key == "title_developer") {
            cfg.title_developer = parse_bool(val, cfg.title_developer);
        } else if ((section.empty() || section == "features") && key == "fps_show_name") {
            cfg.fps_show_name = parse_bool(val, cfg.fps_show_name);
        } else if ((section.empty() || section == "features") && key == "fps_boost") {
            cfg.fps_boost = parse_bool(val, cfg.fps_boost);
        } else if ((section.empty() || section == "features") && key == "fps_hide_bubbles") {
            cfg.fps_hide_bubbles = parse_bool(val, cfg.fps_hide_bubbles);
        } else if ((section.empty() || section == "features") && key == "evan_branding") {
            cfg.evan_branding = parse_bool(val, cfg.evan_branding);
        } else if ((section.empty() || section == "features") && key == "outgoing_evan_prefix") {
            cfg.outgoing_evan_prefix = parse_bool(val, cfg.outgoing_evan_prefix);
        } else if ((section.empty() || section == "features") && key == "rainbow_name") {
            cfg.rainbow_name = parse_bool(val, cfg.rainbow_name);
        }
    }
    return cfg;
}

} // namespace evan
