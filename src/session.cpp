#include "session.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace evan {

namespace {

std::string trim_str(const std::string& s) {
    size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

std::string to_upper_str(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::toupper(c));
    });
    return s;
}

void push_world_history(std::vector<std::string>& hist, const std::string& world) {
    if (world.empty()) return;
    std::string up = to_upper_str(world);
    hist.erase(std::remove(hist.begin(), hist.end(), up), hist.end());
    hist.insert(hist.begin(), up);
    if (hist.size() > 8) {
        hist.resize(8);
    }
}

std::optional<uint32_t> extract_json_uint_field(const std::string& json, const std::string& key) {
    const std::string needle = "\"" + key + "\":";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) return std::nullopt;
    pos += needle.size();
    while (pos < json.size() && std::isspace(static_cast<unsigned char>(json[pos]))) ++pos;
    if (pos >= json.size() || !std::isdigit(static_cast<unsigned char>(json[pos]))) return std::nullopt;
    try {
        return static_cast<uint32_t>(std::stoul(json.substr(pos)));
    } catch (...) {
        return std::nullopt;
    }
}

class CalcParser {
public:
    explicit CalcParser(const std::string& s) : s_(s) {}

    bool parse(double& out, std::string& err) {
        skip_ws();
        if (pos_ >= s_.size()) {
            err = "Ekspresi kosong";
            return false;
        }
        if (!parse_expr(out, err)) return false;
        skip_ws();
        if (pos_ < s_.size()) {
            err = std::string("Karakter tidak valid: '") + s_[pos_] + "'";
            return false;
        }
        return true;
    }

private:
    void skip_ws() {
        while (pos_ < s_.size() && std::isspace(static_cast<unsigned char>(s_[pos_]))) ++pos_;
    }

    bool parse_expr(double& out, std::string& err) {
        if (!parse_term(out, err)) return false;
        while (true) {
            skip_ws();
            if (pos_ < s_.size() && (s_[pos_] == '+' || s_[pos_] == '-')) {
                char op = s_[pos_++];
                double rhs = 0.0;
                if (!parse_term(rhs, err)) return false;
                out = (op == '+') ? (out + rhs) : (out - rhs);
            } else {
                break;
            }
        }
        return true;
    }

    bool parse_term(double& out, std::string& err) {
        if (!parse_unary(out, err)) return false;
        while (true) {
            skip_ws();
            if (pos_ < s_.size() && (s_[pos_] == '*' || s_[pos_] == '/' || s_[pos_] == '%')) {
                char op = s_[pos_++];
                double rhs = 0.0;
                if (!parse_unary(rhs, err)) return false;
                if (op == '*') {
                    out *= rhs;
                } else if (op == '/') {
                    if (std::abs(rhs) < 1e-12) {
                        err = "Pembagian dengan nol";
                        return false;
                    }
                    out /= rhs;
                } else {
                    if (std::abs(rhs) < 1e-12) {
                        err = "Modulo dengan nol";
                        return false;
                    }
                    out = std::fmod(out, rhs);
                }
            } else {
                break;
            }
        }
        return true;
    }

    bool parse_unary(double& out, std::string& err) {
        skip_ws();
        if (pos_ < s_.size() && (s_[pos_] == '+' || s_[pos_] == '-')) {
            char op = s_[pos_++];
            if (!parse_unary(out, err)) return false;
            if (op == '-') out = -out;
            return true;
        }
        return parse_primary(out, err);
    }

    bool parse_primary(double& out, std::string& err) {
        skip_ws();
        if (pos_ >= s_.size()) {
            err = "Ekspresi terpotong";
            return false;
        }
        if (s_[pos_] == '(') {
            ++pos_;
            if (!parse_expr(out, err)) return false;
            skip_ws();
            if (pos_ >= s_.size() || s_[pos_] != ')') {
                err = "Kurung tutup ')' hilang";
                return false;
            }
            ++pos_;
            return true;
        }
        if (std::isdigit(static_cast<unsigned char>(s_[pos_])) || s_[pos_] == '.') {
            size_t start = pos_;
            bool seen_dot = false;
            while (pos_ < s_.size() &&
                   (std::isdigit(static_cast<unsigned char>(s_[pos_])) || s_[pos_] == '.')) {
                if (s_[pos_] == '.') {
                    if (seen_dot) break;
                    seen_dot = true;
                }
                ++pos_;
            }
            try {
                out = std::stod(s_.substr(start, pos_ - start));
                return true;
            } catch (...) {
                err = "Angka tidak valid";
                return false;
            }
        }
        err = std::string("Token tidak dikenal: '") + s_[pos_] + "'";
        return false;
    }

    const std::string& s_;
    size_t pos_ = 0;
};

} // namespace

void Session::apply_config(const ProxyConfig& cfg) {
    log_actions = cfg.log_actions;
    log_raw_movement = cfg.log_raw_movement;
    fast_drop = cfg.fast_drop;
    fast_trash = cfg.fast_trash;
    unlimited_zoom = cfg.unlimited_zoom;
    hide_clothes = cfg.hide_clothes;
    formalize_chat = cfg.formalize_chat;
    style_all_dialogs = cfg.style_all_dialogs;
    ui_theme = cfg.ui_theme;
    auto_bgl = cfg.auto_bgl;
    hotkeys_enabled = cfg.hotkeys_enabled;
    fast_buy = cfg.fast_buy;
    fast_buy_qty = cfg.fast_buy_qty;
    vending_info = cfg.vending_info;
    hotkeys = cfg.hotkeys;
    if (hotkeys.size() < kHotkeySlots) hotkeys.resize(kHotkeySlots);
    title_maxlevel = cfg.title_maxlevel;
    title_doctor = cfg.title_doctor;
    title_legendary = cfg.title_legendary;
    title_g4g = cfg.title_g4g;
    title_master = cfg.title_master;
    title_mentor = cfg.title_mentor;
    title_growroyal_tier = cfg.title_growroyal_tier;
    title_royalwinter = cfg.title_royalwinter;
    title_thanksgiving = cfg.title_thanksgiving;
    title_anniversary = cfg.title_anniversary;
    title_award = cfg.title_award;
    title_party = cfg.title_party;
    title_cc_badge = cfg.title_cc_badge;
    title_tt_badge = cfg.title_tt_badge;
    title_pbl_role = cfg.title_pbl_role;
    title_immortal = cfg.title_immortal;
    title_moderator = cfg.title_moderator;
    title_developer = cfg.title_developer;
    fps_show_name = cfg.fps_show_name;
    fps_boost = cfg.fps_boost;
    fps_hide_bubbles = cfg.fps_hide_bubbles;
    evan_branding = cfg.evan_branding;
    outgoing_evan_prefix = cfg.outgoing_evan_prefix;
    rainbow_name = cfg.rainbow_name;
}

void Session::export_to_config(ProxyConfig& cfg) const {
    cfg.log_actions = log_actions;
    cfg.log_raw_movement = log_raw_movement;
    cfg.fast_drop = fast_drop;
    cfg.fast_trash = fast_trash;
    cfg.unlimited_zoom = unlimited_zoom;
    cfg.hide_clothes = hide_clothes;
    cfg.formalize_chat = formalize_chat;
    cfg.style_all_dialogs = style_all_dialogs;
    cfg.ui_theme = ui_theme;
    cfg.auto_bgl = auto_bgl;
    cfg.hotkeys_enabled = hotkeys_enabled;
    cfg.fast_buy = fast_buy;
    cfg.fast_buy_qty = fast_buy_qty;
    cfg.vending_info = vending_info;
    cfg.hotkeys = hotkeys;
    cfg.title_maxlevel = title_maxlevel;
    cfg.title_doctor = title_doctor;
    cfg.title_legendary = title_legendary;
    cfg.title_g4g = title_g4g;
    cfg.title_master = title_master;
    cfg.title_mentor = title_mentor;
    cfg.title_growroyal_tier = title_growroyal_tier;
    cfg.title_royalwinter = title_royalwinter;
    cfg.title_thanksgiving = title_thanksgiving;
    cfg.title_anniversary = title_anniversary;
    cfg.title_award = title_award;
    cfg.title_party = title_party;
    cfg.title_cc_badge = title_cc_badge;
    cfg.title_tt_badge = title_tt_badge;
    cfg.title_pbl_role = title_pbl_role;
    cfg.title_immortal = title_immortal;
    cfg.title_moderator = title_moderator;
    cfg.title_developer = title_developer;
    cfg.fps_show_name = fps_show_name;
    cfg.fps_boost = fps_boost;
    cfg.fps_hide_bubbles = fps_hide_bubbles;
    cfg.evan_branding = evan_branding;
    cfg.outgoing_evan_prefix = outgoing_evan_prefix;
    cfg.rainbow_name = rainbow_name;
}

bool Session::load_saved_worlds(const std::filesystem::path& path) {
    saved_worlds.clear();
    if (path.empty() || !std::filesystem::exists(path)) {
        return false;
    }
    std::ifstream in(path);
    if (!in) return false;
    std::string line;
    while (std::getline(in, line)) {
        line = trim_str(line);
        if (line.empty() || line[0] == '#') continue;
        size_t pipe = line.find('|');
        SavedWorld sw;
        if (pipe == std::string::npos) {
            sw.name = to_upper_str(line);
        } else {
            sw.name = to_upper_str(trim_str(line.substr(0, pipe)));
            sw.door_id = trim_str(line.substr(pipe + 1));
        }
        if (!sw.name.empty()) {
            saved_worlds.push_back(std::move(sw));
        }
    }
    return true;
}

bool Session::save_saved_worlds(const std::filesystem::path& path) const {
    if (path.empty()) return false;
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out << "# EvanProxy Saved Worlds (WORLD|DOORID)\r\n";
    for (const auto& sw : saved_worlds) {
        out << sw.name << "|" << sw.door_id << "\r\n";
    }
    return out.good();
}

void Session::add_saved_world(const std::string& name, const std::string& door_id) {
    std::string up = to_upper_str(trim_str(name));
    if (up.empty()) return;
    for (auto& sw : saved_worlds) {
        if (sw.name == up) {
            sw.door_id = door_id;
            return;
        }
    }
    saved_worlds.push_back(SavedWorld{up, door_id});
}

bool Session::remove_saved_world(size_t index) {
    if (index >= saved_worlds.size()) return false;
    saved_worlds.erase(saved_worlds.begin() + static_cast<ptrdiff_t>(index));
    return true;
}

void Session::record_action(const std::string& action) {
    if (action.empty()) return;
    recent_actions.push_front(action);
    while (recent_actions.size() > 12) {
        recent_actions.pop_back();
    }
}

void Session::clear_actions() {
    recent_actions.clear();
}

uint32_t Session::wl_count() const {
    auto it = inventory.find(242);
    return it == inventory.end() ? 0 : it->second;
}

uint32_t Session::dl_count() const {
    auto it = inventory.find(1796);
    return it == inventory.end() ? 0 : it->second;
}

uint32_t Session::bgl_count() const {
    auto it = inventory.find(7188);
    return it == inventory.end() ? 0 : it->second;
}

bool Session::has_any_title() const {
    return title_maxlevel || title_doctor || title_legendary || title_g4g || title_master ||
           title_mentor || title_growroyal_tier > 0 || title_royalwinter || title_thanksgiving ||
           title_anniversary || title_award || title_party || title_cc_badge ||
           title_tt_badge || title_pbl_role > 0 || title_immortal ||
           title_moderator || title_developer;
}

bool Session::needs_custom_name() const {
    return !custom_nick.empty() || title_doctor || title_legendary || title_master ||
           title_mentor || title_growroyal_tier > 0 || title_royalwinter || title_thanksgiving ||
           title_anniversary || title_award || title_party || title_pbl_role > 0 ||
           title_immortal || title_moderator || title_developer || rainbow_name || fps_show_name;
}

bool Session::needs_custom_country() const {
    return !custom_country.empty() || has_any_title();
}

bool Session::needs_animated_name() const {
    return rainbow_name || title_immortal || title_royalwinter;
}

uint32_t Session::effective_aura_bits() const {
    uint32_t bits = visual_aura_bits;
    if (title_immortal) {
        bits |= 32768u;
    }
    return bits;
}

std::string Session::active_titles_summary() const {
    std::vector<const char*> parts;
    if (title_maxlevel) parts.push_back("Max Level");
    if (title_doctor) parts.push_back("Doctor");
    if (title_legendary) parts.push_back("Legendary");
    if (title_g4g) parts.push_back("Grow4Good");
    if (title_master) parts.push_back("Master");
    if (title_mentor) parts.push_back("Mentor");
    if (title_anniversary) parts.push_back("10Y Anniv");
    if (title_award) parts.push_back("Award-Winning");
    if (title_party) parts.push_back("Party Animal");
    if (title_royalwinter) parts.push_back("Royal Winter");
    if (title_growroyal_tier == 1) parts.push_back("Gold Grow Royal");
    else if (title_growroyal_tier == 2) parts.push_back("Silver Grow Royal");
    else if (title_growroyal_tier == 3) parts.push_back("Bronze Grow Royal");
    if (title_cc_badge) parts.push_back("Content Creator");
    if (title_tt_badge) parts.push_back("TikTok Creator");
    if (title_pbl_role == 1) parts.push_back("PBL Organizer");
    else if (title_pbl_role == 2) parts.push_back("PBL Mod");
    if (title_immortal) parts.push_back("Immortal");
    if (title_thanksgiving) parts.push_back("Thanksgiving");
    if (title_moderator) parts.push_back("Mod");
    if (title_developer) parts.push_back("Dev");
    if (parts.empty()) return "Tidak ada";
    std::string out;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) out += ", ";
        out += parts[i];
    }
    return out;
}

std::string Session::compose_country_state() const {
    std::string base;
    if (title_developer) {
        base = "rt";
    } else if (title_cc_badge) {
        base = "ccBadge";
    } else if (title_tt_badge) {
        base = "ttBadge";
    } else if (title_legendary || title_immortal) {
        base = "lg";
    } else if (title_g4g && custom_country.empty()) {
        base = "g4g";
    } else if (!custom_country.empty()) {
        base = custom_country;
    } else {
        base = country.empty() ? "us" : country;
    }

    std::string out = base;
    auto append_flag = [&](const std::string& flag) {
        if (out.find("|" + flag) == std::string::npos) {
            out += "|" + flag;
        }
    };
    if (server_country_state.find("|showGuild") != std::string::npos) {
        append_flag("showGuild");
    }
    if (title_maxlevel || title_immortal) append_flag("maxLevel");
    if (title_doctor) append_flag("doctor");
    if (title_g4g) {
        append_flag("donor");
        append_flag("g4g");
    }
    if (title_master) append_flag("master");
    if (title_mentor) append_flag("mentor");
    if (title_legendary) append_flag("legend");
    return out;
}

std::string Session::compose_display_name() const {
    std::string raw_base = !custom_nick.empty()
        ? custom_nick
        : (!raw_player_name.empty() ? raw_player_name : player_name);
    std::string clean = !custom_nick.empty()
        ? proto::strip_growtopia_colors(custom_nick)
        : (!player_name.empty() ? player_name : proto::strip_growtopia_colors(raw_player_name));
    if (clean.empty()) {
        clean = "Player";
    }
    if (raw_base.empty()) {
        raw_base = "`w" + clean;
    }
    while (raw_base.size() >= 2 && raw_base.substr(raw_base.size() - 2) == "``") {
        raw_base.resize(raw_base.size() - 2);
    }

    static constexpr const char* kRainbowColors[] = {"`4", "`6", "`9", "`2", "`1", "`#"};
    static constexpr const char* kPartyColors[] = {"`5", "`9", "`2"};
    static constexpr const char* kImmortalColors[] = {"`1", "`#", "`c", "`w"};
    static constexpr const char* kWinterStarColors[] = {"`#", "`1", "`9", "`5", "`2"};

    std::string body;
    if (rainbow_name) {
        body = std::string(kRainbowColors[rainbow_step % 6]) + clean;
    } else if (title_party) {
        for (size_t i = 0; i < clean.size(); ++i) {
            body += kPartyColors[i % 3];
            body.push_back(clean[i]);
        }
    } else if (title_developer) {
        body = "`6@" + clean;
    } else if (title_moderator) {
        body = "`#@" + clean;
    } else if (title_immortal) {
        body = std::string(kImmortalColors[rainbow_step % 4]) + clean;
    } else if (title_doctor) {
        body = (clean.rfind("Dr.", 0) == 0) ? ("`4" + clean) : ("`4Dr." + clean);
    } else if (title_royalwinter) {
        body = "`1" + clean;
    } else if (title_award || title_thanksgiving) {
        body = "`6" + clean;
    } else {
        body = raw_base;
    }

    // Stackable role prefixes (avoid duplicates)
    if (title_master && proto::strip_growtopia_colors(body).find("Master ") == std::string::npos) {
        body = "`9Master " + body;
    }
    if (title_mentor && proto::strip_growtopia_colors(body).find("[Mentor]") == std::string::npos) {
        body = "`1[Mentor] " + body;
    }
    if (title_pbl_role == 1 && proto::strip_growtopia_colors(body).find("[PBL Organizer]") == std::string::npos) {
        body = "`9\xC4\x99[PBL Organizer] " + body;
    } else if (title_pbl_role == 2 && proto::strip_growtopia_colors(body).find("[PBL Mod]") == std::string::npos) {
        body = "`#\xC4\x99[PBL Mod] " + body;
    }

    // Grow Royal of the Month brackets (// Name //)
    if (title_growroyal_tier == 1) {
        body = "`9\xC4\xAE// " + body + " `9//\xC4\xAE";
    } else if (title_growroyal_tier == 2) {
        body = "`w// " + body + " `w//";
    } else if (title_growroyal_tier == 3) {
        body = "`4// " + body + " `4//";
    }

    // Flanking Growtopia 5.62 icon_font_0.rttex glyphs
    if (title_royalwinter) {
        const char* sc = kWinterStarColors[rainbow_step % 5];
        body = std::string(sc) + "\xC4\xA6 " + body + " " + sc + "\xC4\xA6";
    }
    if (title_award) {
        body = "`9\xC5\x84 " + body + " `9\xC5\x84";
    }
    if (title_anniversary) {
        body = "`9\xC4\xA8 " + body + " `9\xC4\xA8";
    } else if (title_party) {
        body = "`5\xC4\xA8 " + body + " `2\xC4\xA8";
    }
    if (title_immortal) {
        body = "`#\xC4\xBE " + body + " `#\xC4\xBE";
    }

    // Legendary suffix MUST be cleanly at end of string
    if (title_legendary && proto::strip_growtopia_colors(body).find("of Legend") == std::string::npos) {
        body += " of Legend";
    }
    body += "``";

    if (!fps_show_name) {
        return body;
    }

    const char* ping_col = (live_ping_ms < 90) ? "`2" : ((live_ping_ms < 180) ? "`9" : "`4");
    const std::string ping_badge = "`w[" + std::string(ping_col) + std::to_string(live_ping_ms) + "ms`w]``";
    if (title_legendary) {
        return ping_badge + " " + body;
    }
    return body + " " + ping_badge;
}

std::string Session::aura_name() const {
    if (visual_aura_bits == 0) return "Normal";
    std::vector<const char*> parts;
    if (visual_aura_bits & 128u) parts.push_back("Halo");
    if (visual_aura_bits & 64u) parts.push_back("Horns");
    if (visual_aura_bits & 32768u) parts.push_back("Stars");
    if (visual_aura_bits & 2048u) parts.push_back("Frozen");
    if (visual_aura_bits & 262144u) parts.push_back("Shadow");
    if (visual_aura_bits & 524288u) parts.push_back("Irradiated");
    if (visual_aura_bits & 1048576u) parts.push_back("Spotlight");
    if (visual_aura_bits & 1u) parts.push_back("Ghost");
    if (parts.empty()) return "Custom";
    std::string out;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) out += "+";
        out += parts[i];
    }
    return out;
}

void Session::on_server_country_state(const std::string& state) {
    server_country_state = state;
    if (!state.empty()) {
        size_t pipe = state.find('|');
        std::string code = (pipe == std::string::npos) ? state : state.substr(0, pipe);
        if (!code.empty()) {
            country = std::move(code);
        }
    }
}

void Session::on_server_name_changed(const std::string& raw_name, const std::string& extra_json) {
    if (!raw_name.empty()) {
        raw_player_name = raw_name;
        player_name = proto::strip_growtopia_colors(raw_name);
    }
    if (!extra_json.empty()) {
        server_name_extra_json = extra_json;
    }
}

std::optional<std::string> Session::describe_client_game_packet(
    const proto::GameUpdatePacket& gp,
    bool raw_move_mode
) {
    const uint8_t t = gp.type;
    if (t == static_cast<uint8_t>(proto::GamePacketType::PingReply) ||
        t == static_cast<uint8_t>(proto::GamePacketType::PingRequest) ||
        t == static_cast<uint8_t>(proto::GamePacketType::SetIconState) ||
        t == static_cast<uint8_t>(proto::GamePacketType::AppCheckResponse) ||
        t == static_cast<uint8_t>(proto::GamePacketType::AppIntegrityFail) ||
        t == static_cast<uint8_t>(proto::GamePacketType::Disconnect)) {
        return std::nullopt;
    }

    if (t == static_cast<uint8_t>(proto::GamePacketType::State)) {
        auto [tx, ty] = proto::pixel_to_tile(gp.vec_x, gp.vec_y);
        const bool walking = (gp.flags & 0x01u) != 0;
        const bool jumping = (gp.flags & 0x80u) != 0;
        const bool punch = (gp.flags & 0x200u) != 0;
        const bool place = (gp.flags & 0x400u) != 0;
        const bool respawn = (gp.flags & 0x2000u) != 0;
        const bool left = (gp.flags & 0x10u) != 0;

        std::optional<std::string> desc;
        std::ostringstream oss;

        if (punch) {
            oss << "Punch/Click tile (" << gp.int_x << "," << gp.int_y << ")";
            desc = oss.str();
        } else if (place) {
            oss << "Place/Click tile (" << gp.int_x << "," << gp.int_y << ") val=" << gp.value;
            desc = oss.str();
        } else if (respawn) {
            oss << "Respawn di tile (" << tx << "," << ty << ")";
            desc = oss.str();
        } else if (jumping && !was_jumping) {
            oss << "Jump di tile (" << tx << "," << ty << ") pos=("
                << static_cast<int>(gp.vec_x) << "," << static_cast<int>(gp.vec_y) << ")";
            desc = oss.str();
        } else if (!has_pos || tx != tile_x || ty != tile_y) {
            oss << "Walk ke tile (" << tx << "," << ty << ") [" << (left ? "Kiri" : "Kanan") << "]";
            desc = oss.str();
        } else if (raw_move_mode) {
            oss << "Move pos=(" << static_cast<int>(gp.vec_x) << "," << static_cast<int>(gp.vec_y)
                << ") flags=" << proto::format_packet_flags(gp.flags);
            desc = oss.str();
        }

        pos_x = gp.vec_x;
        pos_y = gp.vec_y;
        tile_x = tx;
        tile_y = ty;
        facing_left = left;
        was_jumping = jumping;
        was_walking = walking;
        has_pos = true;
        return desc;
    }

    if (t == static_cast<uint8_t>(proto::GamePacketType::TileChangeRequest)) {
        std::ostringstream oss;
        if (gp.value == 18) {
            oss << "Punch blok di tile (" << gp.int_x << "," << gp.int_y << ")";
        } else {
            oss << "Place/Click item #" << gp.value << " di tile (" << gp.int_x << "," << gp.int_y << ")";
        }
        return oss.str();
    }

    if (t == static_cast<uint8_t>(proto::GamePacketType::TileActivateRequest)) {
        std::ostringstream oss;
        oss << "Activate Door/Tile di (" << gp.int_x << "," << gp.int_y << ")";
        return oss.str();
    }

    if (t == static_cast<uint8_t>(proto::GamePacketType::ItemActivateRequest)) {
        std::ostringstream oss;
        oss << "Use/Equip item #" << gp.value;
        return oss.str();
    }

    if (t == static_cast<uint8_t>(proto::GamePacketType::ItemActivateObjectRequest)) {
        auto [tx, ty] = proto::pixel_to_tile(gp.vec_x, gp.vec_y);
        std::ostringstream oss;
        oss << "Pickup drop uid=" << gp.value << " di tile (" << tx << "," << ty << ")";
        return oss.str();
    }

    if (t == static_cast<uint8_t>(proto::GamePacketType::GotPunched)) {
        return "Terkena punch (netID=" + std::to_string(gp.net_id) + ")";
    }

    std::ostringstream oss;
    oss << proto::game_packet_type_name(t) << " val=" << gp.value
        << " tile=(" << gp.int_x << "," << gp.int_y << ")";
    return oss.str();
}

std::optional<std::string> Session::describe_client_text_action(const proto::TextParse& tp) {
    const std::string action = tp.get("action");
    if (action.empty() || action == "input") {
        return std::nullopt;
    }
    if (action == "wrench") {
        return "Wrench target netID=" + tp.get("netid");
    }
    if (action == "drop") {
        return "Request Drop item #" + tp.get("itemID");
    }
    if (action == "trash") {
        return "Request Trash item #" + tp.get("itemID");
    }
    if (action == "store") {
        return "Buka Store (" + tp.get("location") + ")";
    }
    if (action == "respawn") {
        return "Respawn karakter";
    }
    if (action == "join_request") {
        std::string w = to_upper_str(tp.get("name"));
        std::string d = tp.get("id");
        return "Masuk World: " + w + (d.empty() ? "" : (" (door=" + d + ")"));
    }
    if (action == "quit_to_exit") {
        return "Keluar ke World Select";
    }
    if (action == "dialog_return") {
        const std::string dname = tp.get("dialog_name");
        if (dname.rfind("evanproxy_", 0) == 0) {
            return std::nullopt;
        }
        const std::string btn = tp.get("buttonClicked");
        return "Submit Dialog '" + dname + "'" + (btn.empty() ? "" : (" btn=" + btn));
    }
    return std::nullopt;
}

void Session::on_server_spawn(const std::string& spawn_text, bool& out_is_local) {
    out_is_local = false;
    proto::TextParse tp(spawn_text);
    const std::string type = tp.get("type");
    int32_t nid = -1;
    int32_t uid = 0;
    try {
        if (tp.has("netID")) nid = std::stoi(tp.get("netID"));
        if (tp.has("userID")) uid = std::stoi(tp.get("userID"));
    } catch (...) {
    }

    const std::string raw_name = tp.get("name");
    const std::string clean_name = proto::strip_growtopia_colors(raw_name);

    int tx = 0;
    int ty = 0;
    const std::string pos_x_str = tp.get("posXY", 0);
    const std::string pos_y_str = tp.get("posXY", 1);
    if (!pos_x_str.empty() && !pos_y_str.empty()) {
        try {
            auto pt = proto::pixel_to_tile(std::stof(pos_x_str), std::stof(pos_y_str));
            tx = pt.first;
            ty = pt.second;
        } catch (...) {
        }
    }

    if (type == "local") {
        out_is_local = true;
        if (nid >= 0) local_net_id = nid;
        if (uid > 0) local_user_id = uid;
        if (!raw_name.empty()) {
            raw_player_name = raw_name;
            player_name = clean_name;
        }
        if (tp.has("country")) {
            std::string joined = tp.get_joined("country");
            if (!joined.empty()) {
                on_server_country_state(joined);
            }
        }
        if (tp.has("titleIcon")) {
            std::string ti = tp.get_joined("titleIcon");
            if (!ti.empty()) {
                server_name_extra_json = std::move(ti);
            }
        }
        last_sent_display_name.clear();
        return;
    }

    if (nid >= 0) {
        PlayerInfo pi;
        pi.net_id = nid;
        pi.user_id = uid;
        pi.raw_name = raw_name;
        pi.name = clean_name.empty() ? ("Player#" + std::to_string(nid)) : clean_name;
        pi.tile_x = tx;
        pi.tile_y = ty;
        players[nid] = std::move(pi);
    }
}

void Session::on_server_remove(const std::string& remove_text) {
    proto::TextParse tp(remove_text);
    if (tp.has("netID")) {
        try {
            int32_t nid = std::stoi(tp.get("netID"));
            players.erase(nid);
        } catch (...) {
        }
    }
}

void Session::on_server_state(const proto::GameUpdatePacket& gp) {
    auto it = players.find(gp.net_id);
    if (it != players.end()) {
        auto [tx, ty] = proto::pixel_to_tile(gp.vec_x, gp.vec_y);
        it->second.tile_x = tx;
        it->second.tile_y = ty;
    }
}

void Session::on_server_inventory(const uint8_t* extra, size_t len) {
    std::vector<std::pair<uint16_t, uint8_t>> items;
    uint32_t slots = 0;
    if (!proto::parse_inventory_state(extra, len, items, slots)) {
        return;
    }
    inventory_slots = slots;
    inventory.clear();
    for (const auto& [id, qty] : items) {
        inventory[id] = qty;
    }
}

void Session::on_server_modify_inventory(const proto::GameUpdatePacket& gp) {
    if (gp.value <= 0 || gp.value > 65535) return;
    const uint16_t id = static_cast<uint16_t>(gp.value);
    uint32_t cur = inventory[id];
    if (gp.jump_count > 0) {
        cur = (cur > gp.jump_count) ? (cur - gp.jump_count) : 0;
    }
    if (gp.animation_type > 0) {
        cur += gp.animation_type;
    }
    if (cur == 0) {
        inventory.erase(id);
    } else {
        inventory[id] = cur;
    }
}

void Session::on_server_console_message(const std::string& msg) {
    const std::string clean = proto::strip_growtopia_colors(msg);

    // Example: "World EVILAX [NOPUNCH, IMMUNE] entered."
    if (clean.rfind("World ", 0) == 0 && clean.find("entered") != std::string::npos) {
        size_t start = 6;
        size_t end = start;
        while (end < clean.size() && !std::isspace(static_cast<unsigned char>(clean[end]))) {
            ++end;
        }
        std::string wname = to_upper_str(clean.substr(start, end - start));
        if (!wname.empty()) {
            if (!current_world.empty() && current_world != wname) {
                previous_world = current_world;
            }
            current_world = wname;
            in_world = true;
            world_owner.clear();
            players.clear();
            push_world_history(world_history, wname);
        }
    }

    // Example: "[EVILAX World Locked by clo0x (ACCESS GRANTED)]"
    const std::string lock_marker = "World Locked by ";
    size_t lpos = clean.find(lock_marker);
    if (lpos != std::string::npos) {
        size_t ostart = lpos + lock_marker.size();
        size_t oend = clean.find(" (", ostart);
        if (oend == std::string::npos) oend = clean.find(']', ostart);
        if (oend == std::string::npos) oend = clean.size();
        std::string owner = trim_str(clean.substr(ostart, oend - ostart));
        if (!owner.empty()) {
            world_owner = owner;
        }
    }
}

void Session::on_server_track(const std::string& track_text) {
    proto::TextParse tp(track_text);
    if (tp.has("Gems_balance")) {
        try {
            gems = std::stoll(tp.get("Gems_balance"));
        } catch (...) {
        }
    }
    if (tp.has("Level")) {
        try {
            level = std::stoi(tp.get("Level"));
        } catch (...) {
        }
    }
    if (tp.has("othercurrency")) {
        const std::string oc = tp.get("othercurrency");
        if (auto v = extract_json_uint_field(oc, "242")) inventory[242] = *v;
        if (auto v = extract_json_uint_field(oc, "1796")) inventory[1796] = *v;
        if (auto v = extract_json_uint_field(oc, "7188")) inventory[7188] = *v;
    }
}

void Session::on_leave_world() {
    if (!current_world.empty()) {
        previous_world = current_world;
    }
    in_world = false;
    world_owner.clear();
    players.clear();
    has_pos = false;
    was_jumping = false;
    was_walking = false;
    last_sent_display_name.clear();
    remote_clothes.clear();
    auto_bgl_stage = AutoBglStage::Idle;
    planned_drops.clear();
    active_planned_drop.reset();
    client_icon_state = 0;
    vend.active = false;
    hk_capture_slot = -1;
}

// ---------------------------------------------------------------------------
// Smart lock drop planner (/cd): drops DL + WL (and BGL for >= 10000 WL).
// When the exact change is missing it queues "activate" steps that break a
// DL into 100 WL (or a BGL into 100 DL) / convert 100 WL into 1 DL first.
// ---------------------------------------------------------------------------
bool plan_lock_drops(
    uint32_t total_wl,
    uint32_t have_wl,
    uint32_t have_dl,
    uint32_t have_bgl,
    std::vector<PlannedDrop>& out,
    std::string& err
) {
    out.clear();
    if (total_wl == 0) {
        err = "Jumlah WL harus lebih dari 0.";
        return false;
    }
    const uint64_t avail = static_cast<uint64_t>(have_bgl) * 10000ULL +
                           static_cast<uint64_t>(have_dl) * 100ULL +
                           static_cast<uint64_t>(have_wl);
    if (avail < total_wl) {
        err = "Lock tidak cukup: punya " + std::to_string(avail) + " WL (setara), butuh " +
              std::to_string(total_wl) + ".";
        return false;
    }

    // Target composition: BGL only for >= 10000, otherwise DL (+ WL remainder)
    int64_t bgl_t = std::min<int64_t>(total_wl / 10000u, have_bgl);
    int64_t rem = static_cast<int64_t>(total_wl) - bgl_t * 10000;
    int64_t dl_t = rem / 100;
    int64_t wl_t = rem % 100;

    int64_t bgl = have_bgl;
    int64_t dl = have_dl;
    int64_t wl = have_wl;
    std::vector<PlannedDrop> steps;
    auto step = [&](uint32_t id) {
        PlannedDrop pd;
        pd.item_id = id;
        pd.activate = true;
        steps.push_back(pd);
    };

    // Need more DL? convert spare WL up, or break a spare BGL
    int guard = 0;
    while (dl < dl_t && guard++ < 400) {
        if (wl - wl_t >= 100) {
            step(242);
            wl -= 100;
            dl += 1;
        } else if (bgl - bgl_t > 0) {
            step(7188);
            bgl -= 1;
            dl += 100;
        } else {
            break;
        }
    }
    // Need more WL? break a spare DL (breaking a spare BGL first when no DL is spare)
    while (wl < wl_t && guard++ < 400) {
        if (dl - dl_t > 0) {
            step(1796);
            dl -= 1;
            wl += 100;
        } else if (bgl - bgl_t > 0) {
            step(7188);
            bgl -= 1;
            dl += 100;
        } else {
            break;
        }
    }
    if (dl < dl_t || wl < wl_t) {
        err = "Tidak bisa memecah lock agar pas (butuh " + std::to_string(dl_t) + " DL + " +
              std::to_string(wl_t) + " WL).";
        return false;
    }

    out = steps;
    auto push_chunks = [&](uint32_t id, int64_t qty) {
        while (qty > 0) {
            const uint32_t chunk = static_cast<uint32_t>(std::min<int64_t>(qty, 200));
            PlannedDrop pd;
            pd.item_id = id;
            pd.count = chunk;
            out.push_back(pd);
            qty -= chunk;
        }
    };
    push_chunks(7188u, bgl_t);
    push_chunks(1796u, dl_t);
    push_chunks(242u, wl_t);
    return true;
}

// ---------------------------------------------------------------------------
// Custom hotkeys
// ---------------------------------------------------------------------------
std::optional<HotkeySpec> parse_hotkey(const std::string& text) {
    std::string t;
    for (char c : text) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            t.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
        }
    }
    if (t.empty()) return std::nullopt;

    HotkeySpec spec;
    std::vector<std::string> parts;
    size_t start = 0;
    while (true) {
        size_t p = t.find('+', start);
        if (p == std::string::npos) {
            parts.push_back(t.substr(start));
            break;
        }
        parts.push_back(t.substr(start, p - start));
        start = p + 1;
    }
    if (parts.empty() || parts.back().empty()) return std::nullopt;
    for (size_t i = 0; i + 1 < parts.size(); ++i) {
        const std::string& m = parts[i];
        if (m == "CTRL" || m == "CONTROL") spec.ctrl = true;
        else if (m == "ALT") spec.alt = true;
        else if (m == "SHIFT") spec.shift = true;
        else return std::nullopt;
    }

    const std::string& k = parts.back();
    if (k.size() == 1 && ((k[0] >= 'A' && k[0] <= 'Z') || (k[0] >= '0' && k[0] <= '9'))) {
        spec.vk = k[0];
        return spec;
    }
    if (k[0] == 'F' && k.size() <= 3) {
        try {
            int n = std::stoi(k.substr(1));
            if (n >= 1 && n <= 12) {
                spec.vk = 0x6F + n;
                return spec;
            }
        } catch (...) {
        }
    }
    for (const char* prefix : {"NUMPAD", "NUM"}) {
        const std::string pf(prefix);
        if (k.size() == pf.size() + 1 && k.rfind(pf, 0) == 0 && std::isdigit(static_cast<unsigned char>(k.back()))) {
            spec.vk = 0x60 + (k.back() - '0');
            return spec;
        }
    }
    if (k == "INSERT" || k == "INS") { spec.vk = 0x2D; return spec; }
    if (k == "DELETE" || k == "DEL") { spec.vk = 0x2E; return spec; }
    if (k == "HOME") { spec.vk = 0x24; return spec; }
    if (k == "END") { spec.vk = 0x23; return spec; }
    if (k == "PAGEUP" || k == "PGUP") { spec.vk = 0x21; return spec; }
    if (k == "PAGEDOWN" || k == "PGDN") { spec.vk = 0x22; return spec; }
    return std::nullopt;
}

std::string format_hotkey(const HotkeySpec& s) {
    std::string out;
    if (s.ctrl) out += "CTRL+";
    if (s.alt) out += "ALT+";
    if (s.shift) out += "SHIFT+";
    if ((s.vk >= 'A' && s.vk <= 'Z') || (s.vk >= '0' && s.vk <= '9')) {
        out.push_back(static_cast<char>(s.vk));
    } else if (s.vk >= 0x70 && s.vk <= 0x7B) {
        out += "F" + std::to_string(s.vk - 0x6F);
    } else if (s.vk >= 0x60 && s.vk <= 0x69) {
        out += "NUM" + std::to_string(s.vk - 0x60);
    } else if (s.vk == 0x2D) out += "INSERT";
    else if (s.vk == 0x2E) out += "DELETE";
    else if (s.vk == 0x24) out += "HOME";
    else if (s.vk == 0x23) out += "END";
    else if (s.vk == 0x21) out += "PAGEUP";
    else if (s.vk == 0x22) out += "PAGEDOWN";
    else out += "?";
    return out;
}

const std::vector<int>& hotkey_capture_vks() {
    static const std::vector<int> vks = [] {
        std::vector<int> v;
        for (int c = 'A'; c <= 'Z'; ++c) v.push_back(c);
        for (int c = '0'; c <= '9'; ++c) v.push_back(c);
        for (int c = 0x70; c <= 0x7B; ++c) v.push_back(c);
        for (int c = 0x60; c <= 0x69; ++c) v.push_back(c);
        for (int c : {0x2D, 0x2E, 0x24, 0x23, 0x21, 0x22}) v.push_back(c);
        return v;
    }();
    return vks;
}

// ---------------------------------------------------------------------------
// Vending machine helpers
// ---------------------------------------------------------------------------
namespace {

std::optional<std::string> embed_field(const std::string& markup, const std::string& key) {
    const std::string needle = "embed_data|" + key + "|";
    size_t pos = markup.find(needle);
    if (pos == std::string::npos) return std::nullopt;
    pos += needle.size();
    size_t end = pos;
    while (end < markup.size() && markup[end] != '\r' && markup[end] != '\n' && markup[end] != '|') ++end;
    if (end == pos) return std::nullopt;
    return markup.substr(pos, end - pos);
}

std::optional<int64_t> digits_after(const std::string& text, const std::string& marker) {
    size_t pos = text.find(marker);
    if (pos == std::string::npos) return std::nullopt;
    pos += marker.size();
    while (pos < text.size() && !std::isdigit(static_cast<unsigned char>(text[pos]))) {
        if (text[pos] == '\n') return std::nullopt;
        ++pos;
    }
    int64_t v = 0;
    bool any = false;
    while (pos < text.size() && (std::isdigit(static_cast<unsigned char>(text[pos])) || text[pos] == ',')) {
        if (text[pos] != ',') {
            v = v * 10 + (text[pos] - '0');
            any = true;
        }
        ++pos;
    }
    if (!any) return std::nullopt;
    return v;
}

} // namespace

std::optional<VendingOffer> parse_vending_dialog(const std::string& markup) {
    if (markup.find("end_dialog|vending|") == std::string::npos ||
        markup.find("add_text_input|buycount|") == std::string::npos) {
        return std::nullopt;
    }
    VendingOffer o;
    try {
        if (auto v = embed_field(markup, "tilex")) o.tilex = std::stoi(*v);
        if (auto v = embed_field(markup, "tiley")) o.tiley = std::stoi(*v);
        auto price = embed_field(markup, "expectprice");
        auto item = embed_field(markup, "expectitem");
        if (!price || !item) return std::nullopt;
        o.price = std::stoll(*price);
        o.item_id = std::stoll(*item);
    } catch (...) {
        return std::nullopt;
    }
    const std::string clean = proto::strip_growtopia_colors(markup);
    if (auto s = digits_after(clean, "contains a total of ")) o.stock = *s;
    if (auto w = digits_after(clean, "You have ")) o.wl_have = *w;
    return o;
}

bool vending_cost(const VendingOffer& offer, int64_t want, int64_t& items, int64_t& cost) {
    items = 0;
    cost = 0;
    if (want <= 0 || offer.price == 0) return false;
    if (offer.price > 0) {
        items = want;
        cost = want * offer.price;
        return true;
    }
    const int64_t per_lock = -offer.price;
    if (want < per_lock) return false;
    cost = want / per_lock;
    items = cost * per_lock;
    return true;
}

int64_t vending_max_buy(const VendingOffer& offer) {
    constexpr int64_t kStackCap = 200;
    if (offer.price == 0 || offer.stock <= 0 || offer.wl_have <= 0) return 0;
    if (offer.price > 0) {
        return std::min<int64_t>({offer.stock, offer.wl_have / offer.price, kStackCap});
    }
    const int64_t per_lock = -offer.price;
    const int64_t locks = std::min<int64_t>({offer.wl_have, offer.stock / per_lock, kStackCap / per_lock});
    return locks * per_lock;
}

std::string build_vending_buy_markup(const std::string& markup, int64_t prefill_qty, const std::string& info_line) {
    const std::string key = "add_text_input|buycount|";
    size_t p = markup.find(key);
    if (p == std::string::npos) return markup;
    std::string out = markup;
    if (prefill_qty > 0) {
        const size_t q = out.find('|', p + key.size()); // end of label
        if (q != std::string::npos) {
            const size_t r = out.find('|', q + 1); // end of default value
            if (r != std::string::npos) {
                out.replace(q + 1, r - q - 1, std::to_string(prefill_qty));
            }
        }
    }
    if (!info_line.empty()) {
        out.insert(p, "add_textbox|" + info_line + "|left|\n");
    }
    return out;
}

std::optional<double> evaluate_calc(const std::string& expr, std::string& err) {
    double val = 0.0;
    CalcParser parser(expr);
    if (!parser.parse(val, err)) {
        return std::nullopt;
    }
    return val;
}

std::string formalize_chat_text(const std::string& text) {
    std::string t = trim_str(text);
    if (t.empty() || t[0] == '/') return text;
    for (char& c : t) {
        if (std::isalpha(static_cast<unsigned char>(c))) {
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            break;
        }
    }
    const char last = t.back();
    if (last != '.' && last != '!' && last != '?') {
        t.push_back('.');
    }
    return t;
}

std::string format_number_commas(int64_t val) {
    std::string s = std::to_string(val < 0 ? -val : val);
    std::string out;
    int cnt = 0;
    for (auto it = s.rbegin(); it != s.rend(); ++it) {
        if (cnt > 0 && cnt % 3 == 0) out.push_back(',');
        out.push_back(*it);
        ++cnt;
    }
    if (val < 0) out.push_back('-');
    std::reverse(out.begin(), out.end());
    return out;
}

} // namespace evan
