#include "ui_menu.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <iomanip>
#include <sstream>

namespace evan::ui {

namespace {

std::string trim_s(const std::string& s) {
    size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

std::string to_lower_s(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

std::string to_upper_s(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::toupper(c));
    });
    return s;
}

// Never allow `|` inside Growtopia dialog text fields because Growtopia uses
// `|` as its delimiter and silently truncates everything after an inner `|`.
std::string safe_markup_text(std::string s) {
    for (char& c : s) {
        if (c == '|') c = '/';
        else if (c == '\r' || c == '\n') c = ' ';
    }
    return s;
}

std::string badge(bool on) {
    return on ? "`2[ON]``" : "`4[OFF]``";
}

const char* cb_val(bool on) {
    return on ? "1" : "0";
}

bool parse_cb(const proto::TextParse& tp, const std::string& key, bool fallback) {
    if (!tp.has(key)) return fallback;
    return tp.get(key) == "1";
}

std::string theme_display_name(const std::string& t) {
    if (t == "violet") return "Midnight Violet";
    if (t == "emerald") return "Emerald Cyber";
    if (t == "crimson") return "Crimson Dark";
    if (t == "classic") return "Classic GT";
    return "Ocean Blu";
}

std::string growroyal_label(int tier) {
    switch (tier) {
        case 1: return "`9[Gold]``";
        case 2: return "`w[Silver]``";
        case 3: return "`4[Bronze]``";
        default: return "`4[OFF]``";
    }
}

std::string pbl_label(int role) {
    switch (role) {
        case 1: return "`9[Organizer]``";
        case 2: return "`#[Moderator]``";
        default: return "`4[OFF]``";
    }
}

std::string fastbuy_label(int mode, int qty) {
    const std::string qtxt = (qty > 0) ? (std::to_string(qty) + "x") : "Maks";
    if (mode == 2) return "`2Auto 1-Klik (" + qtxt + ")``";
    if (mode == 1) return "`9Quick (" + qtxt + ")``";
    return "`4OFF``";
}

std::string dialog_header(const Session& session, const std::string& title, int icon_id) {
    std::ostringstream oss;
    oss << "set_default_color|`o\n"
        << get_theme_header(session.ui_theme)
        << "add_quick_exit|\n"
        << "add_label_with_icon|big|" << title << "|left|" << icon_id << "|\n"
        << "add_spacer|small|\n";
    return oss.str();
}

void append_back_home(std::ostringstream& oss) {
    oss << "add_button|nav_go_home|`9<< Kembali ke Dashboard|noflags|0|0|\n"
        << "add_spacer|small|\n";
}

constexpr const char* kBrand = "`9[`#EvanProxy`9]`o ";

void push_msg(UiEffects& out, const std::string& msg) {
    out.to_client.push_back(proto::build_on_console_message(msg));
}

void push_brand(UiEffects& out, const std::string& body) {
    push_msg(out, std::string(kBrand) + body);
}

void push_dialog(UiEffects& out, const std::string& markup) {
    out.to_client.push_back(proto::build_on_dialog_request(markup));
}

void push_visual_sync(Session& session, UiEffects& out, bool sync_name, bool sync_country) {
    if (session.local_net_id < 0) return;
    if (sync_country) {
        out.to_client.push_back(proto::build_on_country_state(
            session.local_net_id, session.compose_country_state()));
    }
    if (sync_name) {
        const std::string composed = session.compose_display_name();
        out.to_client.push_back(proto::build_on_name_changed(
            session.local_net_id, composed, session.server_name_extra_json));
        session.last_sent_display_name = composed;
    }
}

void push_clothes_sync(Session& session, UiEffects& out) {
    if (session.local_net_id < 0) return;
    const ClothingSet& active = session.visual_clothes_mode ? session.visual_clothes : session.real_clothes;
    out.to_client.push_back(proto::build_on_set_clothing(
        session.local_net_id, active.slots, active.skin_color));
}

void enter_visual_clothes_mode(Session& session, UiEffects& out) {
    if (!session.visual_clothes_mode) {
        session.visual_clothes = session.real_clothes;
        session.visual_clothes.valid = true;
        session.visual_clothes_mode = true;
    }
    push_clothes_sync(session, out);
}

void exit_visual_clothes_mode(Session& session, UiEffects& out) {
    session.visual_clothes_mode = false;
    session.active_clothes_preset.clear();
    for (uint32_t id : session.visual_bp_items) {
        out.to_client.push_back(proto::build_modify_item_inventory(id, -1));
    }
    session.visual_bp_items.clear();
    push_clothes_sync(session, out);
}

void give_and_equip_visual_item(Session& session, uint32_t item_id, UiEffects& out) {
    if (!session.visual_clothes_mode) {
        session.visual_clothes = session.real_clothes;
        session.visual_clothes.valid = true;
        session.visual_clothes_mode = true;
    }
    const bool already_owned = session.inventory.find(static_cast<uint16_t>(item_id)) != session.inventory.end();
    if (!already_owned && session.visual_bp_items.find(item_id) == session.visual_bp_items.end()) {
        session.visual_bp_items.insert(item_id);
        out.to_client.push_back(proto::build_modify_item_inventory(item_id, 1));
    }
    const int slot = session.items_db ? session.items_db->get_clothing_slot(item_id) : -1;
    const std::string iname = session.items_db ? session.items_db->name_or_fallback(item_id) : ("item #" + std::to_string(item_id));
    if (slot >= 0) {
        session.visual_clothes.slots[slot] = item_id;
        push_clothes_sync(session, out);
        out.to_client.push_back(proto::build_play_sfx("audio/cloth_equip.wav", 0));
        push_brand(out, "`2Dipakai visual [" + std::string(ItemDatabase::slot_name(slot)) + "]: `w" +
                        iname + " `o(tersedia di BP, klik di BP untuk Equip/Unequip)");
    } else {
        push_brand(out, "`2Ditambahkan ke BP visual: `w" + iname + " `o(ID=" + std::to_string(item_id) + ")");
    }
}

void apply_clothes_preset(Session& session, const std::string& preset, UiEffects& out) {
    if (preset == "restore") {
        exit_visual_clothes_mode(session, out);
        push_brand(out, "`2Visual Clothes OFF. Baju asli server dipulihkan.");
        return;
    }
    std::vector<uint32_t> items;
    std::string label;
    if (preset == "legendary") {
        items = {1784, 1804, 5080, 496};
        label = "Legendary Set";
    } else if (preset == "rayman") {
        items = {5480, 5482, 5484, 5486, 5488};
        label = "Rayman Set";
    } else if (preset == "angel") {
        items = {15188, 8552, 7166};
        label = "Angel of Mercy Set";
    } else {
        return;
    }
    enter_visual_clothes_mode(session, out);
    session.active_clothes_preset = preset;
    std::fill(std::begin(session.visual_clothes.slots), std::end(session.visual_clothes.slots), 0u);
    for (uint32_t id : items) {
        give_and_equip_visual_item(session, id, out);
    }
    push_brand(out, "`2Preset `w" + label + " `2diterapkan secara visual!");
}

void push_aura_sync(Session& session, UiEffects& out) {
    if (!session.has_char_state_pkt) {
        if (session.visual_aura_bits != 0) {
            push_brand(out, "`oAura diset ke `w" + session.aura_name() + " `o(akan tampil saat server mengirim State berikutnya).");
        }
        return;
    }
    proto::GameUpdatePacket gp = session.last_char_state_pkt;
    gp.value = static_cast<int32_t>(static_cast<uint32_t>(gp.value) | session.effective_aura_bits());
    out.to_client.push_back(proto::encode_game_packet(gp));
}

void clear_all_titles(Session& session) {
    session.title_maxlevel = false;
    session.title_doctor = false;
    session.title_legendary = false;
    session.title_g4g = false;
    session.title_master = false;
    session.title_mentor = false;
    session.title_growroyal_tier = 0;
    session.title_royalwinter = false;
    session.title_thanksgiving = false;
    session.title_anniversary = false;
    session.title_award = false;
    session.title_party = false;
    session.title_cc_badge = false;
    session.title_tt_badge = false;
    session.title_pbl_role = 0;
    session.title_immortal = false;
    session.title_moderator = false;
    session.title_developer = false;
}

const char* wrench_mode_label(WrenchMode m) {
    switch (m) {
        case WrenchMode::Info: return "Info/Copy Outfit";
        case WrenchMode::Pull: return "Auto Pull";
        case WrenchMode::Kick: return "Auto Kick";
        case WrenchMode::Ban: return "Auto Ban";
        default: return "Normal";
    }
}

bool toggle_title_by_key(Session& session, const std::string& low, UiEffects& out) {
    if (low == "max" || low == "maxlevel") {
        session.title_maxlevel = !session.title_maxlevel;
        push_brand(out, std::string("Title Max Level: ") + badge(session.title_maxlevel));
    } else if (low == "doc" || low == "doctor") {
        session.title_doctor = !session.title_doctor;
        push_brand(out, std::string("Title Doctor: ") + badge(session.title_doctor));
    } else if (low == "leg" || low == "legend" || low == "legendary") {
        session.title_legendary = !session.title_legendary;
        push_brand(out, std::string("Title Legendary (of Legend + Orb): ") + badge(session.title_legendary));
    } else if (low == "g4g" || low == "grow4good" || low == "donor") {
        session.title_g4g = !session.title_g4g;
        push_brand(out, std::string("Title Grow4Good: ") + badge(session.title_g4g));
    } else if (low == "master") {
        session.title_master = !session.title_master;
        push_brand(out, std::string("Title Master: ") + badge(session.title_master));
    } else if (low == "mentor") {
        session.title_mentor = !session.title_mentor;
        push_brand(out, std::string("Title Mentor: ") + badge(session.title_mentor));
    } else if (low == "royal" || low == "growroyal") {
        session.title_growroyal_tier = (session.title_growroyal_tier + 1) % 4;
        push_brand(out, std::string("Title Grow Royal: ") + growroyal_label(session.title_growroyal_tier));
    } else if (low == "goldroyal") {
        session.title_growroyal_tier = (session.title_growroyal_tier == 1) ? 0 : 1;
        push_brand(out, std::string("Title Gold Grow Royal: ") + growroyal_label(session.title_growroyal_tier));
    } else if (low == "silverroyal") {
        session.title_growroyal_tier = (session.title_growroyal_tier == 2) ? 0 : 2;
        push_brand(out, std::string("Title Silver Grow Royal: ") + growroyal_label(session.title_growroyal_tier));
    } else if (low == "bronzeroyal") {
        session.title_growroyal_tier = (session.title_growroyal_tier == 3) ? 0 : 3;
        push_brand(out, std::string("Title Bronze Grow Royal: ") + growroyal_label(session.title_growroyal_tier));
    } else if (low == "winter" || low == "royalwinter") {
        session.title_royalwinter = !session.title_royalwinter;
        push_brand(out, std::string("Title Royal Winter: ") + badge(session.title_royalwinter));
    } else if (low == "thanks" || low == "thanksgiving") {
        session.title_thanksgiving = !session.title_thanksgiving;
        push_brand(out, std::string("Title Thanksgiving: ") + badge(session.title_thanksgiving));
    } else if (low == "10y" || low == "anniv" || low == "anniversary" || low == "oldtimer") {
        session.title_anniversary = !session.title_anniversary;
        push_brand(out, std::string("Title 10-Year Anniversary: ") + badge(session.title_anniversary));
    } else if (low == "award" || low == "awardwinning") {
        session.title_award = !session.title_award;
        push_brand(out, std::string("Award-Winning Title: ") + badge(session.title_award));
    } else if (low == "party" || low == "partyanimal") {
        session.title_party = !session.title_party;
        push_brand(out, std::string("Party Animal Title: ") + badge(session.title_party));
    } else if (low == "cc" || low == "creator" || low == "ccbadge") {
        session.title_cc_badge = !session.title_cc_badge;
        if (session.title_cc_badge) session.title_tt_badge = false;
        push_brand(out, std::string("Content Creator Badge (ccBadge): ") + badge(session.title_cc_badge));
    } else if (low == "tiktok" || low == "tt" || low == "ttbadge") {
        session.title_tt_badge = !session.title_tt_badge;
        if (session.title_tt_badge) session.title_cc_badge = false;
        push_brand(out, std::string("TikTok Creator Badge (ttBadge): ") + badge(session.title_tt_badge));
    } else if (low == "pbl" || low == "pet") {
        session.title_pbl_role = (session.title_pbl_role + 1) % 3;
        push_brand(out, std::string("Pet Battle League: ") + pbl_label(session.title_pbl_role));
    } else if (low == "pblorg" || low == "organizer") {
        session.title_pbl_role = (session.title_pbl_role == 1) ? 0 : 1;
        push_brand(out, std::string("Pet Battle League Organizer: ") + pbl_label(session.title_pbl_role));
    } else if (low == "pblmod") {
        session.title_pbl_role = (session.title_pbl_role == 2) ? 0 : 2;
        push_brand(out, std::string("Pet Battle League Moderator: ") + pbl_label(session.title_pbl_role));
    } else if (low == "immortal" || low == "imortal") {
        session.title_immortal = !session.title_immortal;
        push_brand(out, std::string("Immortal Title: ") + badge(session.title_immortal));
    } else if (low == "mod" || low == "moderator") {
        session.title_moderator = !session.title_moderator;
        push_brand(out, std::string("Title Moderator (@): ") + badge(session.title_moderator));
    } else if (low == "dev" || low == "developer") {
        session.title_developer = !session.title_developer;
        push_brand(out, std::string("Title Developer (rt): ") + badge(session.title_developer));
    } else if (low == "reset" || low == "off" || low == "clear") {
        clear_all_titles(session);
        push_brand(out, "`2Semua visual title direset.");
    } else {
        return false;
    }
    return true;
}

void parse_world_door(const std::string& raw, std::string& world, std::string& door) {
    size_t colon = raw.find(':');
    if (colon == std::string::npos) {
        world = to_upper_s(trim_s(raw));
        door.clear();
    } else {
        world = to_upper_s(trim_s(raw.substr(0, colon)));
        door = trim_s(raw.substr(colon + 1));
    }
}

uint32_t parse_skin_preset(const std::string& arg, bool& ok) {
    ok = true;
    const std::string low = to_lower_s(trim_s(arg));
    if (low == "normal" || low == "default") return 0xC8B5A1FFu;
    if (low == "tan") return 0xA67B5BFFu;
    if (low == "dark") return 0x5C3A21FFu;
    if (low == "pale") return 0xFFE4D6FFu;
    if (low == "gold") return 0xFFD700FFu;
    if (low == "ghost") return 0xFFFFFF7Fu;
    if (low == "neon" || low == "cyan") return 0x38BDF8FFu;
    try {
        if (low.rfind("0x", 0) == 0) {
            return static_cast<uint32_t>(std::stoul(low.substr(2), nullptr, 16));
        }
        return static_cast<uint32_t>(std::stoul(low));
    } catch (...) {
        ok = false;
        return 0;
    }
}

std::optional<uint32_t> parse_positive_u32(const std::string& s) {
    const std::string t = trim_s(s);
    if (t.empty()) return std::nullopt;
    for (char c : t) {
        if (!std::isdigit(static_cast<unsigned char>(c))) return std::nullopt;
    }
    try {
        unsigned long v = std::stoul(t);
        if (v == 0 || v > 100000000UL) return std::nullopt;
        return static_cast<uint32_t>(v);
    } catch (...) {
        return std::nullopt;
    }
}

void trigger_convert_wl_to_dl(Session& session, UiEffects& out) {
    if (!session.inventory.empty() && session.wl_count() < 100) {
        push_brand(out, "`4World Lock kurang! Punya `w" + std::to_string(session.wl_count()) + " WL`4, butuh minimal `w100 WL`4.");
        return;
    }
    proto::GameUpdatePacket gp{};
    gp.type = static_cast<uint8_t>(proto::GamePacketType::ItemActivateRequest);
    gp.value = 242; // World Lock
    out.to_server.push_back(proto::encode_game_packet(gp));
    out.to_client.push_back(proto::build_play_sfx("audio/dialog_confirm.wav", 0));
    push_brand(out, "`2Mengubah `w100 World Lock `2-> `11 Diamond Lock``!");
}

void schedule_single_lock_drop(Session& session, uint32_t item_id, const char* label, const std::string& arg, UiEffects& out) {
    auto qty = parse_positive_u32(arg);
    if (!qty || *qty > 200u) {
        push_brand(out, std::string("`4Pakai: /") + label + " <1..200>");
        return;
    }
    if (!session.inventory.empty()) {
        uint32_t owned = 0;
        if (item_id == 242u) owned = session.wl_count();
        else if (item_id == 1796u) owned = session.dl_count();
        else if (item_id == 7188u) owned = session.bgl_count();
        if (owned < *qty) {
            push_brand(out, "`4Jumlah tidak cukup! Punya `w" + std::to_string(owned) + "`4, minta `w" + std::to_string(*qty) + "`4.");
            return;
        }
    }
    PlannedDrop pd;
    pd.item_id = item_id;
    pd.count = *qty;
    session.planned_drops.push_back(pd);
    push_brand(out, "`2Menjatuhkan `w" + std::to_string(*qty) + " " + to_upper_s(label) + " `2secara otomatis...");
}

void schedule_custom_wl_drop(Session& session, const std::string& arg, UiEffects& out) {
    auto total = parse_positive_u32(arg);
    if (!total) {
        push_brand(out, "`4Pakai: /cd <jumlah_wl> (contoh: /cd 102 = 1 DL 2 WL)");
        return;
    }
    std::vector<PlannedDrop> plan;
    std::string perr;
    if (!session.inventory.empty()) {
        if (!plan_lock_drops(*total, session.wl_count(), session.dl_count(), session.bgl_count(), plan, perr)) {
            push_brand(out, "`4" + perr);
            return;
        }
    } else {
        const uint32_t bgl = *total / 10000u;
        const uint32_t dl = (*total % 10000u) / 100u;
        const uint32_t wl = *total % 100u;
        auto push_chunks = [&](uint32_t id, uint32_t qty) {
            while (qty > 0) {
                uint32_t c = std::min<uint32_t>(qty, 200u);
                PlannedDrop pd;
                pd.item_id = id;
                pd.count = c;
                plan.push_back(pd);
                qty -= c;
            }
        };
        push_chunks(7188u, bgl);
        push_chunks(1796u, dl);
        push_chunks(242u, wl);
    }
    uint32_t sum_bgl = 0, sum_dl = 0, sum_wl = 0;
    int act_conv = 0, act_break = 0;
    for (const auto& d : plan) {
        session.planned_drops.push_back(d);
        if (d.activate) {
            if (d.item_id == 242u) ++act_conv;
            else ++act_break;
        } else {
            if (d.item_id == 7188u) sum_bgl += d.count;
            else if (d.item_id == 1796u) sum_dl += d.count;
            else if (d.item_id == 242u) sum_wl += d.count;
        }
    }
    std::ostringstream msg;
    msg << "`2Custom Drop `w" << *total << " WL`2: ";
    if (sum_bgl) msg << "`2" << sum_bgl << " BGL ";
    if (sum_dl) msg << "`1" << sum_dl << " DL ";
    if (sum_wl) msg << "`6" << sum_wl << " WL ";
    if (act_conv > 0) msg << "`o(" << act_conv << "x convert WL->DL) ";
    if (act_break > 0) msg << "`o(" << act_break << "x pecah lock) ";
    push_brand(out, msg.str());
    out.calc_toast = std::make_pair(
        "CALC · /cd " + std::to_string(*total),
        format_cd_breakdown(static_cast<int64_t>(*total)));
}

void trigger_auto_bgl_toggle(Session& session, UiEffects& out) {
    session.auto_bgl = !session.auto_bgl;
    session.auto_bgl_stage = AutoBglStage::Idle;
    out.save_config = true;
    push_brand(out, std::string("Auto-Exchange Telephone -> BGL: ") + badge(session.auto_bgl) +
                    (session.auto_bgl ? " `o(Pegang Wrench & klik Telephone untuk tukar 100 DL -> 1 BGL)" : ""));
}

} // namespace

std::string get_theme_header(const std::string& theme_name) {
    if (theme_name == "classic") {
        return "";
    }
    if (theme_name == "violet") {
        return "set_bg_color|20,14,42,235|\nset_border_color|167,139,250,255|\n";
    }
    if (theme_name == "emerald") {
        return "set_bg_color|8,30,24,235|\nset_border_color|52,211,153,255|\n";
    }
    if (theme_name == "crimson") {
        return "set_bg_color|34,12,18,235|\nset_border_color|248,113,113,255|\n";
    }
    return "set_bg_color|11,25,44,235|\nset_border_color|56,189,248,255|\n";
}

std::string apply_theme_to_dialog(const std::string& markup, const std::string& theme_name) {
    const std::string hdr = get_theme_header(theme_name);
    if (hdr.empty()) return markup;
    if (markup.find("set_bg_color|") != std::string::npos) return markup;
    return hdr + markup;
}

std::string build_home_dialog(const Session& session, const SharedState& shared) {
    auto cur_up = shared.get_current_upstream();
    const uint64_t total_wl_eq = static_cast<uint64_t>(session.bgl_count()) * 10000ULL +
                                 static_cast<uint64_t>(session.dl_count()) * 100ULL +
                                 static_cast<uint64_t>(session.wl_count());
    std::ostringstream oss;
    oss << dialog_header(session, "`wEvanProxy `9Dashboard``", 7188);
    if (session.custom_banner) {
        oss << "add_image_button|nav_go_changelog|interface/large/evanproxy_banner.rttex|bannerlayout||\n"
            << "add_spacer|small|\n";
    }

    // Compact 3-line status summary (ZERO inner `|` characters!)
    oss << "add_smalltext|`9Player: `w"
        << (session.player_name.empty() ? "-" : safe_markup_text(session.player_name))
        << "   `9World: `2" << (session.in_world ? safe_markup_text(session.current_world) : "Menu")
        << (session.world_owner.empty() ? "" : (" `o(Owner: `w" + safe_markup_text(session.world_owner) + "`o)"))
        << "|left|\n";

    oss << "add_smalltext|`9Wealth: `2" << session.bgl_count() << " BGL `o/ `1"
        << session.dl_count() << " DL `o/ `6" << session.wl_count() << " WL `o(=`9"
        << format_number_commas(static_cast<int64_t>(total_wl_eq)) << " WL`o)   `9Gems: `5"
        << (session.gems >= 0 ? format_number_commas(session.gems) : "-")
        << " `o(`2+" << format_number_commas(session.gems_collected_world)
        << " World`o / `9" << format_number_commas(session.world_floor_gems_total())
        << " Lantai`o)|left|\n";

    oss << "add_smalltext|`9Server: `2"
        << (cur_up ? (cur_up->first + ":" + std::to_string(cur_up->second)) : "none")
        << "   `9Ping: `w" << session.live_ping_ms << "ms `o(Jitter +/-" << session.ping_jitter_ms << "ms)"
        << "   `9Players: `w" << (session.in_world ? (session.players.size() + 1) : 0)
        << "   `9FastBuy: " << fastbuy_label(session.fast_buy, session.fast_buy_qty)
        << "|left|\n"
        << "add_spacer|small|\n";

    // Row 1: Main Navigation Icons (6 vibrant Growtopia item icons)
    oss << "add_button_with_icon|nav_go_nav|`w  Warp  |staticBlueFrame|242||\n"
        << "add_button_with_icon|nav_go_clothes|`wClothes |staticBlueFrame|2390||\n"
        << "add_button_with_icon|nav_go_search|`wSearchBP|staticBlueFrame|6140||\n"
        << "add_button_with_icon|nav_go_title|`w Titles |staticBlueFrame|1486||\n"
        << "add_button_with_icon|nav_go_hotkeys|`wHotkeys |staticBlueFrame|3802||\n"
        << "add_button_with_icon|nav_go_tools|`w Tools  |staticBlueFrame|32||\n"
        << "add_button_with_icon||END_LIST|noflags|0||\n"
        << "add_spacer|big|\n";

    // Row 2: Live Scanners & Info Icons
    oss << "add_button_with_icon|nav_go_gems|`5  Gems  |staticYellowFrame|112||\n"
        << "add_button_with_icon|nav_go_visual|`w Visual |staticPurpleFrame|5250||\n"
        << "add_button_with_icon|nav_go_worldinfo|`w WInfo  |staticBlueFrame|3898||\n"
        << "add_button_with_icon|nav_go_players|`wPlayers |staticBlueFrame|1750||\n"
        << "add_button_with_icon|nav_go_packets|`wPackets |staticBlueFrame|226||\n"
        << "add_button_with_icon|nav_go_changelog|`wGazette |staticPurpleFrame|5016||\n"
        << "add_button_with_icon||END_LIST|noflags|0||\n"
        << "add_spacer|big|\n";

    // 1-Click Quick Toggle Icon Strip (Gold frame = ON, Blue frame = OFF)
    auto qframe = [](bool on) { return on ? "staticYellowFrame" : "staticBlueFrame"; };
    oss << "add_label_with_icon|small|`wQuick Toggles (Klik Ikon Langsung ON/OFF)``|left|32|\n"
        << "add_button_with_icon|home_tog_fastbuy|" << (session.fast_buy > 0 ? "`2FastBuy " : "`oFastBuy ") << "|" << qframe(session.fast_buy > 0) << "|9268||\n"
        << "add_button_with_icon|home_tog_autobgl|" << (session.auto_bgl ? "`2AutoBGL " : "`oAutoBGL ") << "|" << qframe(session.auto_bgl) << "|7188||\n"
        << "add_button_with_icon|home_tog_gems|" << (session.gems_tracker ? "`2GemTrack" : "`oGemTrack") << "|" << qframe(session.gems_tracker) << "|112||\n"
        << "add_button_with_icon|home_tog_fps_boost|" << (session.fps_boost ? "`2AntiLag " : "`oAntiLag ") << "|" << qframe(session.fps_boost) << "|226||\n"
        << "add_button_with_icon|home_tog_fps_name|" << (session.fps_show_name ? "`2PingTag " : "`oPingTag ") << "|" << qframe(session.fps_show_name) << "|3802||\n"
        << "add_button_with_icon|home_tog_hotkeys|" << (session.hotkeys_enabled ? "`2Hotkeys " : "`oHotkeys ") << "|" << qframe(session.hotkeys_enabled) << "|18||\n"
        << "add_button_with_icon||END_LIST|noflags|0||\n"
        << "add_spacer|big|\n"
        << "add_button|nav_go_commands|`9Daftar Command Lengkap (/phelp & /gems)|noflags|0|0|\n"
        << "add_spacer|small|\n";

    oss << "add_label_with_icon|small|`wPengaturan Detail (Centang lalu klik Simpan)``|left|226|\n"
        << "add_checkbox|chk_home_autobgl|Auto-Exchange Telephone -> BGL (Wrench #3898)|" << cb_val(session.auto_bgl) << "|\n"
        << "add_checkbox|chk_home_fastbuy|Vending Fast Buy 1-Klik Auto (/fastbuy)|" << cb_val(session.fast_buy > 0) << "|\n"
        << "add_checkbox|chk_home_gems|Gems Live Pickup Bubble & World Drop Scanner (/gems)|" << cb_val(session.gems_tracker) << "|\n"
        << "add_checkbox|chk_home_fastdrop|Fast Drop (Auto Konfirmasi Jumlah Penuh)|" << cb_val(session.fast_drop) << "|\n"
        << "add_checkbox|chk_home_hotkeys|Keyboard Hotkeys Custom Aktif (/hotkey)|" << cb_val(session.hotkeys_enabled) << "|\n"
        << "add_checkbox|chk_home_fps_name|Tampilkan Ping (ms) di Sebelah Nama (/fps)|" << cb_val(session.fps_show_name) << "|\n"
        << "add_checkbox|chk_home_fps_boost|FPS & Signal Boost (Anti-Lag World Ramai)|" << cb_val(session.fps_boost) << "|\n"
        << "add_checkbox|chk_home_branding|Tag [EvanProxy] di Semua Chat (/evantag)|" << cb_val(session.evan_branding) << "|\n"
        << "add_checkbox|chk_home_zoom|Unlimited Zoom (Aktif saat masuk world)|" << cb_val(session.unlimited_zoom) << "|\n"
        << "add_spacer|small|\n"
        << "end_dialog|evanproxy_home|Tutup|Simpan|\n";
    return oss.str();
}

std::string build_nav_dialog(const Session& session) {
    std::ostringstream oss;
    oss << dialog_header(session, "`wNavigasi & Portal Warp``", 242);
    append_back_home(oss);

    oss << "add_text_input|warp_target|`wTujuan Warp (WORLD atau WORLD:DOORID):||32|\n"
        << "add_button|btn_warp_submit|`2Warp Sekarang (Mode Portal)|noflags|0|0|\n"
        << "add_spacer|small|\n"
        << "add_button|btn_rejoin|`wRejoin World Saat Ini (/re)|noflags|0|0|\n"
        << "add_button|btn_back_world|`wKembali ke World Sebelumnya ("
        << (session.previous_world.empty() ? "-" : safe_markup_text(session.previous_world))
        << ")|noflags|0|0|\n"
        << "add_button|btn_save_current|`2Simpan World Ini ke Favorit (/sworld)|noflags|0|0|\n"
        << "add_button|btn_exit_world|`4Keluar ke World Select Menu (/exit)|noflags|0|0|\n"
        << "add_spacer|small|\n";

    oss << "add_label_with_icon|small|`wWorld Favorit (" << session.saved_worlds.size() << ")``|left|242|\n";
    if (session.saved_worlds.empty()) {
        oss << "add_smalltext|`oBelum ada world tersimpan. Klik Simpan World di atas atau ketik /sworld.|left|\n";
    } else {
        for (size_t i = 0; i < session.saved_worlds.size() && i < 8; ++i) {
            const auto& sw = session.saved_worlds[i];
            std::string label = sw.name + (sw.door_id.empty() ? "" : (":" + sw.door_id));
            oss << "add_button|warp_saved_" << i << "|`2Warp -> `w" << safe_markup_text(label) << "|noflags|0|0|\n"
                << "add_button|del_saved_" << i << "|`4Hapus " << safe_markup_text(sw.name) << "|noflags|0|0|\n";
        }
    }

    oss << "add_spacer|small|\n"
        << "add_label_with_icon|small|`wRiwayat World Terakhir``|left|3802|\n";
    if (session.world_history.empty()) {
        oss << "add_smalltext|`oBelum ada riwayat world di sesi ini.|left|\n";
    } else {
        for (size_t i = 0; i < session.world_history.size() && i < 6; ++i) {
            oss << "add_button|warp_hist_" << i << "|`9Warp -> `w"
                << safe_markup_text(session.world_history[i]) << "|noflags|0|0|\n";
        }
    }

    oss << "add_spacer|small|\n"
        << "end_dialog|evanproxy_nav||Tutup|\n";
    return oss.str();
}

std::string build_packets_dialog(const Session& session, const SharedState& shared) {
    const std::string log_path = shared.get_log_file_path();
    std::ostringstream oss;
    oss << dialog_header(session, "`wPacket & Action Monitor``", 226);
    append_back_home(oss);

    oss << "add_smalltext|`9File Log: `w"
        << (log_path.empty() ? "Nonaktif" : safe_markup_text(log_path)) << "|left|\n"
        << "add_smalltext|`9Statistik Paket: `wC->S " << shared.c2s_packets.load()
        << "   S->C " << shared.s2c_packets.load() << "|left|\n"
        << "add_spacer|small|\n";

    oss << "add_checkbox|chk_pkt_actions|Action Monitor (Walk, Jump, Punch, Click, Wrench)|" << cb_val(session.log_actions) << "|\n"
        << "add_checkbox|chk_pkt_raw_move|Raw Movement Per-Frame (/pmove)|" << cb_val(session.log_raw_movement) << "|\n"
        << "add_checkbox|chk_pkt_verbose|Verbose Console Semua Paket (/plog)|" << cb_val(shared.verbose_log.load()) << "|\n"
        << "add_checkbox|chk_pkt_hex|Hex Dump Paket Mentah (/phex)|" << cb_val(shared.hex_log.load()) << "|\n"
        << "add_spacer|small|\n";

    oss << "add_label_with_icon|small|`wAksi Pemain Terakhir (" << session.recent_actions.size() << ")``|left|18|\n";
    if (session.recent_actions.empty()) {
        oss << "add_smalltext|`oBelum ada aksi terekam. Coba jalan, lompat, atau pukul blok!|left|\n";
    } else {
        size_t shown = 0;
        for (const auto& act : session.recent_actions) {
            oss << "add_smalltext|`2> `w" << safe_markup_text(act) << "|left|\n";
            if (++shown >= 8) break;
        }
    }
    oss << "add_button|btn_clear_actions|`4Bersihkan Riwayat Aksi|noflags|0|0|\n"
        << "add_spacer|small|\n"
        << "end_dialog|evanproxy_packets|Tutup|Simpan|\n";
    return oss.str();
}

std::string build_visual_dialog(const Session& session) {
    std::ostringstream oss;
    oss << dialog_header(session, "`wVisual, Kulit, Cuaca & Tema UI``", 5250);
    append_back_home(oss);

    oss << "add_button|nav_go_title|`9Buka Visual Titles (/title) - Aktif: `w"
        << safe_markup_text(session.active_titles_summary()) << "|noflags|0|0|\n"
        << "add_button|nav_go_clothes|`#Buka Visual Wardrobe (/clothes) - " << badge(session.visual_clothes_mode) << "|noflags|0|0|\n"
        << "add_button|nav_go_fps|`2Buka Ping & Anti-Lag (/fps) - `w" << session.live_ping_ms << "ms|noflags|0|0|\n"
        << "add_spacer|small|\n";

    const std::string cur_nick = session.custom_nick.empty() ? session.player_name : session.custom_nick;
    const std::string cur_flag = session.custom_country.empty() ? session.country : session.custom_country;

    oss << "add_text_input|nick_input|`wNick Lokal (Client-side):|" << safe_markup_text(cur_nick) << "|32|\n"
        << "add_button|btn_nick_apply|`2Terapkan Nick|noflags|0|0|\n"
        << "add_button|btn_nick_reset|`4Reset Nick|noflags|0|0|\n"
        << "add_text_input|flag_input|`wKode Bendera (id, us, jp, kr):|" << safe_markup_text(cur_flag) << "|10|\n"
        << "add_button|btn_flag_apply|`2Terapkan Bendera|noflags|0|0|\n"
        << "add_spacer|small|\n";

    oss << "add_label_with_icon|small|`wPreset Warna Kulit & Cuaca``|left|1750|\n"
        << "add_button|skin_normal|Kulit Normal|noflags|0|0|\n"
        << "add_button|skin_tan|Kulit Tan|noflags|0|0|\n"
        << "add_button|skin_dark|Kulit Dark|noflags|0|0|\n"
        << "add_button|skin_gold|Kulit Gold|noflags|0|0|\n"
        << "add_button|skin_ghost|Kulit Ghost|noflags|0|0|\n"
        << "add_button|skin_reset|`4Reset Kulit Asli|noflags|0|0|\n"
        << "add_button|weather_0|Cuaca Sunny|noflags|0|0|\n"
        << "add_button|weather_2|Cuaca Night|noflags|0|0|\n"
        << "add_button|weather_4|Cuaca Rainy|noflags|0|0|\n"
        << "add_button|weather_11|Cuaca Spooky|noflags|0|0|\n"
        << "add_button|weather_15|Cuaca Snow|noflags|0|0|\n"
        << "add_spacer|small|\n";

    oss << "add_label_with_icon|small|`wTema UI Proxy (Aktif: " << theme_display_name(session.ui_theme) << ")``|left|1486|\n"
        << "add_button|theme_ocean|" << (session.ui_theme == "ocean" ? "`2* " : "") << "Ocean Blu|noflags|0|0|\n"
        << "add_button|theme_violet|" << (session.ui_theme == "violet" ? "`2* " : "") << "Midnight Violet|noflags|0|0|\n"
        << "add_button|theme_emerald|" << (session.ui_theme == "emerald" ? "`2* " : "") << "Emerald Cyber|noflags|0|0|\n"
        << "add_button|theme_crimson|" << (session.ui_theme == "crimson" ? "`2* " : "") << "Crimson Dark|noflags|0|0|\n"
        << "add_button|theme_classic|" << (session.ui_theme == "classic" ? "`2* " : "") << "Classic GT|noflags|0|0|\n"
        << "add_spacer|small|\n"
        << "add_checkbox|chk_vis_rainbow|Rainbow Name Berwarna (/rainbow)|" << cb_val(session.rainbow_name) << "|\n"
        << "add_checkbox|chk_vis_zoom|Unlimited Zoom (Aktif saat masuk world)|" << cb_val(session.unlimited_zoom) << "|\n"
        << "add_checkbox|chk_vis_hideclothes|Sembunyikan Baju Pemain Lain (/hideclothes)|" << cb_val(session.hide_clothes) << "|\n"
        << "add_checkbox|chk_vis_styleall|Terapkan Tema Proxy ke Semua Dialog Game|" << cb_val(session.style_all_dialogs) << "|\n"
        << "add_checkbox|chk_vis_banner|Banner Custom EvanProxy di Hub & Gazette (/banner)|" << cb_val(session.custom_banner) << "|\n"
        << "add_spacer|small|\n"
        << "end_dialog|evanproxy_visual|Tutup|Simpan|\n";
    return oss.str();
}

std::string build_title_dialog(const Session& session) {
    std::ostringstream oss;
    oss << dialog_header(session, "`wVisual Titles & Badges (GT 5.62)``", 1486);
    append_back_home(oss);

    oss << "add_smalltext|`9Preview Nama: `w" << safe_markup_text(session.compose_display_name()) << "|left|\n"
        << "add_smalltext|`9Flag & State: `w" << safe_markup_text(session.compose_country_state()) << "|left|\n"
        << "add_smalltext|`9Aktif: `2" << safe_markup_text(session.active_titles_summary()) << "|left|\n"
        << "add_spacer|small|\n";

    oss << "add_label_with_icon|small|`wClassic & Prestige Titles``|left|1784|\n"
        << "add_checkbox|chk_title_maxlevel|Max Level (Lv.125 Glowing Blue)|" << cb_val(session.title_maxlevel) << "|\n"
        << "add_checkbox|chk_title_doctor|Doctor (Dr. + Caduceus Flag)|" << cb_val(session.title_doctor) << "|\n"
        << "add_checkbox|chk_title_legendary|Legendary (of Legend + Orb Flag)|" << cb_val(session.title_legendary) << "|\n"
        << "add_checkbox|chk_title_g4g|Grow4Good (G4G Angel Badge)|" << cb_val(session.title_g4g) << "|\n"
        << "add_checkbox|chk_title_master|Master (Master Title + Icon)|" << cb_val(session.title_master) << "|\n"
        << "add_checkbox|chk_title_mentor|Mentor ([Mentor] + Badge)|" << cb_val(session.title_mentor) << "|\n"
        << "add_spacer|small|\n";

    oss << "add_label_with_icon|small|`wEvent & Titles Terbaru (5.62)``|left|5080|\n"
        << "add_checkbox|chk_title_anniversary|10-Year Anniversary / Old Timer (Party Popper)|" << cb_val(session.title_anniversary) << "|\n"
        << "add_checkbox|chk_title_award|Award-Winning Title (Golden Trophy)|" << cb_val(session.title_award) << "|\n"
        << "add_checkbox|chk_title_party|Party Animal Title (Purple / Yellow / Green)|" << cb_val(session.title_party) << "|\n"
        << "add_checkbox|chk_title_royalwinter|Royal Winter Title (Rainbow Shooting Star)|" << cb_val(session.title_royalwinter) << "|\n"
        << "add_checkbox|chk_title_immortal|Immortal Title (Glow + Orb + Stars Aura)|" << cb_val(session.title_immortal) << "|\n"
        << "add_checkbox|chk_title_thanksgiving|Thanksgiving Title (Amber)|" << cb_val(session.title_thanksgiving) << "|\n"
        << "add_button|title_cycle_growroyal|Grow Royal of the Month (Ganti Tier): " << growroyal_label(session.title_growroyal_tier) << "|noflags|0|0|\n"
        << "add_spacer|small|\n";

    oss << "add_label_with_icon|small|`wCreator Badges, Pet League & Staff``|left|226|\n"
        << "add_checkbox|chk_title_cc_badge|Content Creator Badge (ccBadge Blue Checkmark)|" << cb_val(session.title_cc_badge) << "|\n"
        << "add_checkbox|chk_title_tt_badge|TikTok Creator Badge (ttBadge Checkmark)|" << cb_val(session.title_tt_badge) << "|\n"
        << "add_checkbox|chk_title_moderator|Moderator (@Name)|" << cb_val(session.title_moderator) << "|\n"
        << "add_checkbox|chk_title_developer|Developer (rt Flag + @Dev)|" << cb_val(session.title_developer) << "|\n"
        << "add_button|title_cycle_pbl|Pet Battle League (Ganti Role): " << pbl_label(session.title_pbl_role) << "|noflags|0|0|\n"
        << "add_spacer|small|\n"
        << "add_button|title_reset_all|`4Reset Semua Title|noflags|0|0|\n"
        << "add_spacer|small|\n"
        << "end_dialog|evanproxy_title|Tutup|Terapkan|\n";
    return oss.str();
}

std::string build_fps_dialog(const Session& session) {
    std::ostringstream oss;
    oss << dialog_header(session, "`wPing Display & Anti-Lag Optimizer``", 226);
    append_back_home(oss);

    oss << "add_smalltext|`9Ping Server (ENet RTT Real-Time): `2" << session.live_ping_ms
        << " ms   `o(Min: `w" << session.ping_min_ms << "ms  `oMax: `w" << session.ping_max_ms
        << "ms  `oJitter: +/-" << session.ping_jitter_ms << "ms)|left|\n"
        << "add_smalltext|`9Overhead Proxy Lokal: `2"
        << (session.proxy_overhead_us > 0 ? (std::to_string(session.proxy_overhead_us) + " us (<1ms)") : "<1ms")
        << " `o(Async Logger + 1MB UDP + 0ms Throttle)|left|\n"
        << "add_spacer|small|\n";

    oss << "add_checkbox|chk_fps_name|Tampilkan Ping (ms) di Sebelah Nama (/fps)|" << cb_val(session.fps_show_name) << "|\n"
        << "add_checkbox|chk_fps_boost|FPS & Signal Boost (Anti-Lag World Ramai)|" << cb_val(session.fps_boost) << "|\n"
        << "add_checkbox|chk_fps_bubbles|Sembunyikan Chat Bubble Pemain Lain (Mode Ekstrem)|" << cb_val(session.fps_hide_bubbles) << "|\n"
        << "add_spacer|small|\n"
        << "add_smalltext|`oSaat FPS & Signal Boost aktif: memblokir partikel efek, emote, baju orang lain, dan cuaca berat agar koneksi stabil.|left|\n"
        << "add_spacer|small|\n"
        << "end_dialog|evanproxy_fps|Tutup|Simpan|\n";
    return oss.str();
}

std::string build_clothes_dialog(const Session& session) {
    std::ostringstream oss;
    oss << dialog_header(session, "`wVisual Wardrobe (/clothes)``", 2390);
    append_back_home(oss);

    const size_t db_count = session.items_db ? session.items_db->size() : 0;
    oss << "add_smalltext|`9Mode Visual: " << badge(session.visual_clothes_mode)
        << "   `9items.dat: `w" << db_count
        << "   `9BP Visual: `2" << session.visual_bp_items.size() << " item|left|\n"
        << "add_smalltext|`oKlik item di Backpack untuk Equip/Unequip visual tanpa mengubah inventory server asli.|left|\n"
        << "add_spacer|small|\n";

    oss << "add_text_input|clothes_search_input|`wCari Item Cepat (/search):|"
        << safe_markup_text(session.last_search_query) << "|32|\n"
        << "add_button|btn_clothes_search|`2Cari Item (/search)|noflags|0|0|\n"
        << "add_button|clothes_toggle_mode|"
        << (session.visual_clothes_mode ? "`4Matikan Visual & Pulihkan Baju Asli" : "`2Aktifkan Mode Visual Clothes")
        << "|noflags|0|0|\n"
        << "add_button|clothes_clear_all|`4Lepas Semua Baju Visual|noflags|0|0|\n"
        << "add_spacer|small|\n";

    oss << "add_label_with_icon|small|`wOutfit Presets``|left|1784|\n"
        << "add_button|preset_legendary|Preset: Legendary Set|noflags|0|0|\n"
        << "add_button|preset_rayman|Preset: Rayman Full Set|noflags|0|0|\n"
        << "add_button|preset_angel|Preset: Angel of Mercy Set|noflags|0|0|\n"
        << "add_button|preset_restore|`4Pulihkan Baju Asli Server|noflags|0|0|\n"
        << "add_spacer|small|\n";

    oss << "add_label_with_icon|small|`wSlot Terpasang Saat Ini``|left|5484|\n";
    const ClothingSet& active = session.visual_clothes_mode ? session.visual_clothes : session.real_clothes;
    size_t equipped_cnt = 0;
    for (int slot = 0; slot < 10; ++slot) {
        const uint32_t item_id = active.slots[slot];
        if (item_id == 0) continue;
        const std::string iname = session.items_db ? session.items_db->name_or_fallback(item_id) : ("#" + std::to_string(item_id));
        oss << "add_button|unequip_slot_" << slot << "|`9[" << ItemDatabase::slot_name(slot)
            << "] `w" << safe_markup_text(iname) << " `4(Lepas)|noflags|0|0|\n";
        ++equipped_cnt;
    }
    if (equipped_cnt == 0) {
        oss << "add_smalltext|`oBelum ada baju terpasang. Pakai Cari Item atau pilih Preset di atas.|left|\n";
    }

    oss << "add_spacer|small|\n"
        << "end_dialog|evanproxy_clothes||Tutup|\n";
    return oss.str();
}

std::string build_search_dialog(const Session& session, const std::string& query, bool clothes_only) {
    std::ostringstream oss;
    oss << dialog_header(session, "`wCari Item Visual ke BP (/search)``", 6140);
    append_back_home(oss);

    oss << "add_button|nav_go_clothes|`9<< Kembali ke Wardrobe (/clothes)|noflags|0|0|\n"
        << "add_text_input|search_query_input|`wKata Kunci Item / ID:|"
        << safe_markup_text(query) << "|32|\n"
        << "add_button|btn_search_go|`2Cari Item|noflags|0|0|\n"
        << "add_button|btn_search_filter|Filter: "
        << (clothes_only ? "`2Hanya Baju/Wearable" : "`9Semua Item (Non-Seed)") << "|noflags|0|0|\n"
        << "add_spacer|small|\n";

    if (!session.items_db || session.items_db->size() == 0) {
        oss << "add_textbox|`4Database items.dat tidak ditemukan di %LOCALAPPDATA%\\Growtopia\\cache\\items.dat.|left|\n";
    } else {
        auto hits = session.items_db->search(query, clothes_only, 24);
        oss << "add_smalltext|`9Hasil (" << hits.size() << "): `oKlik ikon item untuk masuk BP & Equip visual!|left|\n"
            << "add_spacer|small|\n";
        if (hits.empty()) {
            oss << "add_smalltext|`4Tidak ada item yang cocok dengan pencarian tersebut.|left|\n";
        } else {
            size_t col = 0;
            for (const ItemEntry* item : hits) {
                const int slot = session.items_db->get_clothing_slot(item->id);
                std::string label = item->name;
                if (label.size() > 14) label = label.substr(0, 13) + ".";
                if (slot >= 0) label += " [" + std::string(ItemDatabase::slot_name(slot)) + "]";
                oss << "add_button_with_icon|vpick_" << item->id << "|`w"
                    << safe_markup_text(label) << "|staticBlueFrame|" << item->id << "||\n";
                if (++col % 6 == 0) {
                    oss << "add_button_with_icon||END_LIST|noflags|0||\n"
                        << "add_spacer|big|\n";
                }
            }
            if (col % 6 != 0) {
                oss << "add_button_with_icon||END_LIST|noflags|0||\n"
                    << "add_spacer|big|\n";
            }
        }
    }

    oss << "add_spacer|small|\n"
        << "end_dialog|evanproxy_search||Tutup|\n";
    return oss.str();
}

std::string build_worldinfo_dialog(const Session& session, const SharedState& shared) {
    auto cur_up = shared.get_current_upstream();
    std::ostringstream oss;
    oss << dialog_header(session, "`wInformasi World & Sesi``", 3898);
    append_back_home(oss);

    oss << "add_smalltext|`9World Saat Ini: `w" << (session.in_world ? safe_markup_text(session.current_world) : "Menu") << "|left|\n"
        << "add_smalltext|`9World Sebelumnya: `w" << (session.previous_world.empty() ? "-" : safe_markup_text(session.previous_world)) << "|left|\n"
        << "add_smalltext|`9Pemilik Lock: `2" << (session.world_owner.empty() ? "Tidak diketahui / Tidak di-lock" : safe_markup_text(session.world_owner)) << "|left|\n"
        << "add_smalltext|`9Jumlah Pemain: `w" << (session.in_world ? (session.players.size() + 1) : 0) << "|left|\n"
        << "add_smalltext|`9Posisi Anda: `w(" << session.tile_x << "," << session.tile_y << ") `o- netID=" << session.local_net_id << "|left|\n"
        << "add_smalltext|`9Level: `w" << (session.level >= 0 ? std::to_string(session.level) : "-")
        << "   `9Gems: `5" << (session.gems >= 0 ? format_number_commas(session.gems) : "-") << "|left|\n"
        << "add_smalltext|`9Locks: `2" << session.bgl_count() << " BGL / `1" << session.dl_count() << " DL / `6" << session.wl_count() << " WL|left|\n"
        << "add_smalltext|`9Upstream: `2" << (cur_up ? (cur_up->first + ":" + std::to_string(cur_up->second)) : "none")
        << "   `9Ping: `2" << session.live_ping_ms << "ms `o(Jitter +/-" << session.ping_jitter_ms << "ms)|left|\n"
        << "add_spacer|small|\n"
        << "add_button|nav_go_players|`9Lihat Daftar Pemain di World (" << (session.in_world ? (session.players.size() + 1) : 0) << ")|noflags|0|0|\n"
        << "add_spacer|small|\n"
        << "end_dialog|evanproxy_worldinfo||Tutup|\n";
    return oss.str();
}

std::string build_player_inspect_dialog(const Session& session, const PlayerInfo& p) {
    std::ostringstream oss;
    oss << dialog_header(session, "`wWrench: " + safe_markup_text(p.name) + "``", 1750);
    oss << "add_smalltext|`9Player: `w" << safe_markup_text(p.name)
        << " `o(netID=" << p.net_id << ", userID=" << p.user_id
        << ", tile=(" << p.tile_x << "," << p.tile_y << "))|left|\n"
        << "add_spacer|small|\n";

    auto it = session.remote_clothes.find(p.net_id);
    if (it != session.remote_clothes.end() && it->second.valid) {
        oss << "add_label_with_icon|small|`wOutfit Pemain (/wrench info)``|left|5484|\n";
        for (int s = 0; s < 10; ++s) {
            if (it->second.slots[s] != 0) {
                std::string iname = session.items_db
                    ? session.items_db->name_or_fallback(it->second.slots[s])
                    : ("#" + std::to_string(it->second.slots[s]));
                oss << "add_smalltext|`9" << ItemDatabase::slot_name(s) << ": `w"
                    << safe_markup_text(iname) << "|left|\n";
            }
        }
        oss << "add_button|copy_outfit_" << p.net_id << "|`2Copy Outfit ke Visual Clothes|noflags|0|0|\n"
            << "add_spacer|small|\n";
    } else {
        oss << "add_smalltext|`oOutfit belum terekam.|left|\n";
    }

    oss << "add_button|wrench_act_pull_" << p.net_id << "|`wPull  `9(/wrench pull)|noflags|0|0|\n"
        << "add_button|wrench_act_kick_" << p.net_id << "|`wKick  `9(/wrench kick)|noflags|0|0|\n"
        << "add_button|wrench_act_ban_" << p.net_id << "|`4Ban   `w(/wrench ban)|noflags|0|0|\n"
        << "add_spacer|small|\n"
        << "add_button|wrench_turn_off|`oTurn wrench shortcuts off|noflags|0|0|\n"
        << "add_spacer|small|\n"
        << "end_dialog|evanproxy_inspect||Tutup|\n";
    return oss.str();
}

std::string build_tools_dialog(const Session& session) {
    std::ostringstream oss;
    oss << dialog_header(session, "`wTools, Vending & Lock Manager``", 32);
    append_back_home(oss);

    oss << "add_label_with_icon|small|`wVending Machine Fast Buy (/fastbuy)``|left|9268|\n"
        << "add_button|btn_fastbuy_cycle|Mode Fast Buy (Klik Ganti): " << fastbuy_label(session.fast_buy, session.fast_buy_qty) << "|noflags|0|0|\n"
        << "add_button|fb_qty_1|" << (session.fast_buy_qty == 1 ? "`2* " : "") << "1x (1-Klik)|noflags|0|0|\n"
        << "add_button|fb_qty_5|" << (session.fast_buy_qty == 5 ? "`2* " : "") << "5x|noflags|0|0|\n"
        << "add_button|fb_qty_10|" << (session.fast_buy_qty == 10 ? "`2* " : "") << "10x|noflags|0|0|\n"
        << "add_button|fb_qty_50|" << (session.fast_buy_qty == 50 ? "`2* " : "") << "50x|noflags|0|0|\n"
        << "add_button|fb_qty_200|" << (session.fast_buy_qty == 200 ? "`2* " : "") << "200x|noflags|0|0|\n"
        << "add_button|fb_qty_0|" << (session.fast_buy_qty == 0 ? "`2* " : "") << "Maks|noflags|0|0|\n"
        << "add_text_input|fb_qty_input|`wJumlah Custom Fast Buy (0 = Maks, 1..200 = Otomatis Beli):|" << session.fast_buy_qty << "|4|\n"
        << "add_checkbox|chk_vend_info|Info Privat Sisa Stok Vend & Sisa WL Anda (Hanya Anda Lihat)|" << cb_val(session.vending_info) << "|\n"
        << "add_spacer|small|\n";

    oss << "add_label_with_icon|small|`wTelephone Auto-BGL & Lock Manager``|left|3898|\n"
        << "add_checkbox|chk_auto_bgl|Auto-Exchange Telephone -> BGL (Wrench #3898)|" << cb_val(session.auto_bgl) << "|\n"
        << "add_checkbox|chk_fast_drop|Fast Drop (Auto Konfirmasi Jumlah Penuh)|" << cb_val(session.fast_drop) << "|\n"
        << "add_checkbox|chk_fast_trash|Fast Trash (Auto Konfirmasi Jumlah Dimiliki)|" << cb_val(session.fast_trash) << "|\n"
        << "add_button|btn_convert_dl|`2Convert 100 WL -> 1 DL (/convert) [Punya " << session.wl_count()
        << " WL / " << session.dl_count() << " DL / " << session.bgl_count() << " BGL]|noflags|0|0|\n"
        << "add_text_input|cd_input|`wCustom Drop WL (/cd 102 = 1 DL 2 WL):||12|\n"
        << "add_button|btn_cd_drop|`2Drop Locks Otomatis (/cd)|noflags|0|0|\n"
        << "add_spacer|small|\n";

    oss << "add_label_with_icon|small|`wChat, Wrench & Aura``|left|1750|\n"
        << "add_checkbox|chk_formalize|Formalize Chat (Kapital & Titik Otomatis)|" << cb_val(session.formalize_chat) << "|\n"
        << "add_checkbox|chk_chat_prefix|Prefix Emoji (^_^) di Chat Keluar|" << cb_val(session.chat_prefix_enabled) << "|\n"
        << "add_checkbox|chk_evan_branding|Tag [EvanProxy] di Chat Masuk (/evantag)|" << cb_val(session.evan_branding) << "|\n"
        << "add_checkbox|chk_evan_outchat|Prefix [EvanProxy] di Chat Keluar (/evanchat)|" << cb_val(session.outgoing_evan_prefix) << "|\n"
        << "add_checkbox|chk_rainbow|Rainbow Name Berwarna (/rainbow)|" << cb_val(session.rainbow_name) << "|\n"
        << "add_button|btn_wrench_cycle|Wrench Mode (/wrench): `w" << wrench_mode_label(session.wrench_mode) << "|noflags|0|0|\n"
        << "add_button|btn_aura_cycle|Aura Visual (/aura): `w" << safe_markup_text(session.aura_name()) << "|noflags|0|0|\n"
        << "add_spacer|small|\n";

    oss << "add_label_with_icon|small|`wKalkulator & Timer``|left|3802|\n"
        << "add_text_input|calc_input|`wKalkulator Cepat (misal 250*17+50):||32|\n"
        << "add_button|btn_calc_go|`2Hitung|noflags|0|0|\n"
        << "add_button|timer_30|Timer 30 Detik|noflags|0|0|\n"
        << "add_button|timer_60|Timer 1 Menit|noflags|0|0|\n"
        << "add_button|timer_180|Timer 3 Menit|noflags|0|0|\n"
        << "add_button|timer_cancel|`4Batalkan Timer|noflags|0|0|\n"
        << "add_spacer|small|\n"
        << "add_button|nav_go_gems|`5Buka Gems Tracker & Scanner (/gems)|noflags|0|0|\n"
        << "add_button|nav_go_players|`9Daftar Pemain di World (" << (session.in_world ? (session.players.size() + 1) : 0) << ")|noflags|0|0|\n"
        << "add_button|nav_go_worldinfo|`9Info World & Lock (/winfo)|noflags|0|0|\n"
        << "add_button|btn_open_news|`9Buka EvanProxy Gazette (/news)|noflags|0|0|\n"
        << "add_spacer|small|\n"
        << "end_dialog|evanproxy_tools|Tutup|Simpan|\n";
    return oss.str();
}

std::string build_gems_dialog(const Session& session) {
    const int64_t floor_gems = session.world_floor_gems_total();
    const size_t floor_clusters = session.world_floor_gems_clusters();
    const auto top_tiles = session.world_gem_tiles_top(8);
    const auto floor_items = session.world_floor_items_summary();

    std::ostringstream oss;
    oss << dialog_header(session, "`wGems Tracker & World Drop Scanner (/gems)``", 112);
    append_back_home(oss);

    oss << "add_smalltext|`9Saldo Gems Anda: `5"
        << (session.gems >= 0 ? format_number_commas(session.gems) : "-") << " Gems"
        << "   `9World Ini: `2+" << format_number_commas(session.gems_collected_world)
        << "   `9Sesi Ini: `2+" << format_number_commas(session.gems_collected_session) << "|left|\n"
        << "add_smalltext|`9Gems di Lantai World ("
        << (session.in_world ? safe_markup_text(session.current_world) : "Menu")
        << "): `5" << format_number_commas(floor_gems) << " Gems `o(" << floor_clusters << " drop)|left|\n"
        << "add_spacer|small|\n";

    oss << "add_checkbox|chk_gems_tracker|Live Gem Pickup Bubble & Counter (tampilkan +Gems saat pungut)|"
        << cb_val(session.gems_tracker) << "|\n"
        << "add_spacer|small|\n";

    oss << "add_button_with_icon|gems_refresh|`2Scan/Refresh|staticBlueFrame|112||\n"
        << "add_button_with_icon|gems_show_bubble|`9Show Saldo|staticYellowFrame|9436||\n"
        << "add_button_with_icon|gems_reset_stats|`4Reset Sesi|staticBlueFrame|32||\n"
        << "add_button_with_icon||END_LIST|noflags|0||\n"
        << "add_spacer|big|\n";

    oss << "add_label_with_icon|small|`wLokasi Gems di Lantai World``|left|112|\n";
    if (top_tiles.empty()) {
        oss << "add_smalltext|`oBelum ada gem baru yang terdeteksi jatuh di lantai sejak masuk world.|left|\n";
    } else {
        for (const auto& [coord, cnt] : top_tiles) {
            oss << "add_smalltext|`2> `wTile (" << coord.first << ", " << coord.second << ")`o: `5"
                << format_number_commas(static_cast<int64_t>(cnt)) << " Gems|left|\n";
        }
    }

    oss << "add_spacer|small|\n"
        << "add_label_with_icon|small|`wItem & Lock Jatuh di Lantai World``|left|242|\n";
    if (floor_items.empty()) {
        oss << "add_smalltext|`oTidak ada drop item/lock baru yang tersisa di lantai.|left|\n";
    } else {
        size_t shown = 0;
        for (const auto& [iid, cnt] : floor_items) {
            const std::string iname = session.items_db
                ? session.items_db->name_or_fallback(iid)
                : ("Item #" + std::to_string(iid));
            oss << "add_smalltext|`9> `w" << format_number_commas(static_cast<int64_t>(cnt))
                << "x `2" << safe_markup_text(iname) << " `o(#" << iid << ")|left|\n";
            if (++shown >= 10) break;
        }
    }

    oss << "add_spacer|small|\n"
        << "end_dialog|evanproxy_gems|Tutup|Simpan|\n";
    return oss.str();
}

std::string build_hotkeys_dialog(const Session& session) {
    std::ostringstream oss;
    oss << dialog_header(session, "`wCustom Keyboard Hotkeys (/hotkey)``", 3802);
    append_back_home(oss);

    oss << "add_checkbox|chk_hotkeys_enabled|Aktifkan Keyboard Hotkeys (Saat Growtopia Fokus)|"
        << cb_val(session.hotkeys_enabled) << "|\n"
        << "add_smalltext|`oKlik slot di bawah untuk mengatur tombol TUNGGAL (CTRL, ALT, SHIFT, TAB, SPACE, A, F1) atau kombinasi (CTRL+A) & command (misal /warp clunxz).|left|\n"
        << "add_spacer|small|\n";

    for (size_t i = 0; i < kHotkeySlots; ++i) {
        std::string k;
        std::string c;
        if (i < session.hotkeys.size()) {
            k = trim_s(session.hotkeys[i].key);
            c = trim_s(session.hotkeys[i].command);
        }
        oss << "add_button|hk_edit_" << i << "|";
        if (!k.empty() && !c.empty()) {
            oss << "`9#" << (i + 1) << " [" << safe_markup_text(k) << "] `w-> `2" << safe_markup_text(c);
        } else {
            oss << "`o#" << (i + 1) << " [Kosong] -> Klik untuk atur custom hotkey";
        }
        oss << "|noflags|0|0|\n";
    }

    oss << "add_spacer|small|\n"
        << "add_button|hk_reset_all|`4Reset Semua Hotkey ke Default|noflags|0|0|\n"
        << "add_spacer|small|\n"
        << "end_dialog|evanproxy_hotkeys|Tutup|Simpan|\n";
    return oss.str();
}

std::string build_hotkey_edit_dialog(const Session& session, int slot) {
    if (slot < 0) slot = 0;
    if (slot >= static_cast<int>(kHotkeySlots)) slot = static_cast<int>(kHotkeySlots) - 1;
    const std::string cur_key = (static_cast<size_t>(slot) < session.hotkeys.size()) ? session.hotkeys[slot].key : "";
    const std::string cur_cmd = (static_cast<size_t>(slot) < session.hotkeys.size()) ? session.hotkeys[slot].command : "";

    std::ostringstream oss;
    oss << dialog_header(session, "`wEdit Custom Hotkey #" + std::to_string(slot + 1) + "``", 3802);
    oss << "embed_data|hk_slot|" << slot << "\n"
        << "add_smalltext|`9Slot: `w#" << (slot + 1)
        << "   `9Tombol Saat Ini: `2" << (cur_key.empty() ? "Kosong" : safe_markup_text(cur_key)) << "|left|\n"
        << "add_spacer|small|\n"
        << "add_text_input|hk_key_input|`wTombol Shortcut (CTRL, ALT, SHIFT, TAB, SPACE, A, F1, CTRL+A):|"
        << safe_markup_text(cur_key) << "|16|\n"
        << "add_button|hk_record_key|`9Rekam Tombol Langsung dari Keyboard (Tekan 1 Tombol atau Combo)|noflags|0|0|\n"
        << "add_spacer|small|\n"
        << "add_text_input|hk_cmd_input|`wPerintah / Chat (contoh /warp clunxz atau /cd 102):|"
        << safe_markup_text(cur_cmd) << "|80|\n"
        << "add_smalltext|`oTips: Bisa pakai 1 tombol saja seperti CTRL / ALT / SHIFT / TAB / A. Huruf biasa & CTRL dijeda otomatis saat chat atau dialog terbuka.|left|\n"
        << "add_spacer|small|\n"
        << "add_button|hk_test|`2Test Jalankan Sekarang|noflags|0|0|\n"
        << "add_button|hk_clear|`4Kosongkan Slot Ini|noflags|0|0|\n"
        << "add_button|nav_go_hotkeys|`9<< Kembali ke Daftar Hotkey|noflags|0|0|\n"
        << "add_spacer|small|\n"
        << "end_dialog|evanproxy_hk_edit|Batal|Simpan|\n";
    return oss.str();
}

std::string build_players_dialog(const Session& session, int page) {
    std::ostringstream oss;
    const size_t remote_count = session.players.size();
    const size_t total_count = session.in_world ? (remote_count + 1) : 0;
    constexpr size_t kPerPage = 25;
    const int total_pages = std::max(1, static_cast<int>((remote_count + kPerPage - 1) / kPerPage));
    if (page < 0) page = 0;
    if (page >= total_pages) page = total_pages - 1;

    oss << dialog_header(
        session,
        "`wDaftar Pemain di World (" + std::to_string(total_count) + " - Hal " +
        std::to_string(page + 1) + "/" + std::to_string(total_pages) + ")``",
        1750);
    append_back_home(oss);

    if (!session.in_world) {
        oss << "add_textbox|`oAnda sedang tidak berada di dalam world.|left|\n";
    } else {
        oss << "add_smalltext|`2[Anda] `w"
            << (session.player_name.empty() ? "Local" : safe_markup_text(session.player_name))
            << " `o- netID=" << session.local_net_id
            << " - userID=" << session.local_user_id
            << " - tile=(" << session.tile_x << "," << session.tile_y << ")|left|\n";

        if (session.players.empty()) {
            oss << "add_smalltext|`oTidak ada pemain lain terdeteksi di world ini.|left|\n";
        } else {
            const size_t start_idx = static_cast<size_t>(page) * kPerPage;
            size_t idx = 0;
            size_t shown = 0;
            for (const auto& [nid, p] : session.players) {
                if (idx >= start_idx && shown < kPerPage) {
                    oss << "add_smalltext|`w" << safe_markup_text(p.name)
                        << " `o- netID=" << nid
                        << " - userID=" << p.user_id
                        << " - tile=(" << p.tile_x << "," << p.tile_y << ")|left|\n";
                    ++shown;
                }
                ++idx;
            }
            if (total_pages > 1) {
                oss << "add_spacer|small|\n";
                if (page > 0) {
                    oss << "add_button|players_page_" << (page - 1)
                        << "|`9<< Halaman Sebelumnya|noflags|0|0|\n";
                }
                if (page + 1 < total_pages) {
                    oss << "add_button|players_page_" << (page + 1)
                        << "|`2Halaman Berikutnya >>|noflags|0|0|\n";
                }
            }
        }
    }
    oss << "add_spacer|small|\n"
        << "end_dialog|evanproxy_players||Tutup|\n";
    return oss.str();
}

std::string build_changelog_dialog(const Session& session) {
    std::ostringstream oss;
    oss << dialog_header(session, "`wThe EvanProxy Gazette``", 5016);
    oss << "add_image_button|banner|interface/large/evanproxy_banner.rttex|bannerlayout|||\n"
        << "add_spacer|small|\n";

    oss << "add_label_with_icon|medium|`wNovember 24th: `#EvanProxy v2.5 Latest Updates``|left|7188|\n"
        << "add_spacer|small|\n"
        << "add_image_button|evanproxy_card1|interface/large/evanproxy_card1.rttex|3imageslayout|OPENDASH||\n"
        << "add_image_button|evanproxy_card2|interface/large/evanproxy_card2.rttex|3imageslayout|OPENTOOLS||\n"
        << "add_image_button|evanproxy_card3|interface/large/evanproxy_card3.rttex|3imageslayout|OPENHOTKEYS||\n"
        << "add_spacer|small|\n";

    oss << "add_button_with_icon|nav_go_home|`wDashboard|staticYellowFrame|7188||\n"
        << "add_button_with_icon|nav_go_gems|`5  Gems  |staticBlueFrame|112||\n"
        << "add_button_with_icon|nav_go_clothes|`wClothes |staticBlueFrame|2390||\n"
        << "add_button_with_icon|nav_go_title|`w Titles |staticBlueFrame|1486||\n"
        << "add_button_with_icon|nav_go_tools|`w Tools  |staticBlueFrame|32||\n"
        << "add_button_with_icon|nav_go_hotkeys|`wHotkeys |staticBlueFrame|3802||\n"
        << "add_button_with_icon||END_LIST|noflags|0||\n"
        << "add_spacer|big|\n";

    oss << "add_label_with_icon|small|`4[UPDATE] `wCore Proxy & Protocol 5.62``|left|242|\n"
        << "add_smalltext|`w- Dual ENet UDP 17091 + HTTPS 443 bridge, auto sub-server redirect & Hosts Backup Guard.|left|\n"
        << "add_smalltext|`w- Real-time ENet RTT Ping & DWM 144Hz FPS Overlay + Variant Int64 OnSetBux sync.|left|\n"
        << "add_spacer|small|\n"
        << "add_label_with_icon|small|`9[IMPROVE] `wUI/UX Dashboard, Wardrobe & World Scanner``|left|2390|\n"
        << "add_smalltext|`w- Desktop GUI 9 tab & In-Game /proxy ikon interaktif dengan quick toggle 1-klik.|left|\n"
        << "add_smalltext|`w- Visual Wardrobe /clothes & /search (16,580+ item langsung masuk Backpack & equip).|left|\n"
        << "add_spacer|small|\n"
        << "add_label_with_icon|small|`2[NEW] `wFastBuy 1-Klik, Auto-BGL, Hotkeys & /gems``|left|112|\n"
        << "add_smalltext|`w- /gems Live Pickup Bubble counter (+Gems dunia & sesi) + scanner gems & lock di lantai.|left|\n"
        << "add_smalltext|`w- /fastbuy Auto 1-Klik tanpa konfirmasi + /vendinfo privat sisa stok & sisa WL Anda.|left|\n"
        << "add_smalltext|`w- /autobgl Wrench Telephone -> BGL otomatis, /hotkey 12 slot (CTRL/ALT/A/F1), /cd pecah lock.|left|\n"
        << "add_spacer|small|\n"
        << "add_label_with_icon|small|`6[FIXED] `wBug Fixes & Sync``|left|32|\n"
        << "add_smalltext|`w- Sinkronisasi lock pickup lantai ganda (DL+WL sekaligus) untuk /cd tanpa salah hitung.|left|\n"
        << "add_smalltext|`w- Fix semua 18 Visual Titles GT 5.62 (10-Year, Award, Party, Winter, Immortal aura, CC/TT, PBL).|left|\n"
        << "add_spacer|small|\n"
        << "add_button|nav_go_home|`2Buka EvanProxy Dashboard (/proxy)|noflags|0|0|\n"
        << "add_button|nav_go_gems|`5Buka Gems Tracker & Scanner (/gems)|noflags|0|0|\n";
    if (!session.last_news_markup.empty()) {
        oss << "add_button|btn_open_raw_news|`oLihat Gazette Asli Server Growtopia (/rawnews)|noflags|0|0|\n";
    }
    oss << "add_spacer|small|\n"
        << "end_dialog|evanproxy_changelog|Tutup|Buka Dashboard|\n";
    return oss.str();
}

std::string build_commands_dialog(const Session& session) {
    std::ostringstream oss;
    oss << dialog_header(session, "`wDaftar Command Lengkap``", 1486);
    append_back_home(oss);

    oss << "add_smalltext|`9[Navigasi Portal]``|left|\n"
        << "add_smalltext|`2/warp <world[:door]> `w- Pindah langsung seperti portal tanpa ke menu|left|\n"
        << "add_smalltext|`2/re `w- Rejoin world   `2/back `w- World sebelumnya   `2/door <id>   `2/exit   `2/sworld|left|\n"
        << "add_spacer|small|\n";

    oss << "add_smalltext|`9[Vending, Telephone, Locks & Custom Hotkeys]``|left|\n"
        << "add_smalltext|`2/fastbuy [off/quick/auto/max/<qty>] `w- Fast Buy vending & info sisa stok/WL privat|left|\n"
        << "add_smalltext|`2/vendinfo `w- Toggle info privat sisa stok vending & sisa WL Anda|left|\n"
        << "add_smalltext|`2/autobgl `watau `2/change `w- Auto-exchange Wrench+Telephone -> BGL (100 DL)|left|\n"
        << "add_smalltext|`2/cd <wl> `w- Smart Drop (contoh /cd 102 -> otomatis 1 DL + 2 WL, auto pecah/convert)|left|\n"
        << "add_smalltext|`2/wl <n>   /dl <n>   /bgl <n>   /convert `w(100 WL -> 1 DL)|left|\n"
        << "add_smalltext|`2/hotkey `w- UI Custom Hotkey 1..12 (atau /hotkey set 1 A /warp clunxz)|left|\n"
        << "add_spacer|small|\n";

    oss << "add_smalltext|`9[Visual Titles & Clothes]``|left|\n"
        << "add_smalltext|`2/title [opsi] `w- maxlevel, doctor, legendary, g4g, master, mentor, 10y, award, party, winter, goldroyal, silverroyal, bronzeroyal, cc, tiktok, pblorg, pblmod, immortal, mod, dev, reset|left|\n"
        << "add_smalltext|`2/clothes [on/off/clear/preset] `w- Mode Visual   `2/search <nama/id> `w- Ambil item ke BP|left|\n"
        << "add_smalltext|`2/copy <nama>   /aura <efek>   /fps [on/off/boost/bubbles]   /rainbow   /nick   /skin   /flag|left|\n"
        << "add_spacer|small|\n";

    oss << "add_smalltext|`9[Packet Monitor, Gems & Utilitas]``|left|\n"
        << "add_smalltext|`2/gems [on/off/reset/scan] `w- Live Gem Counter bubble & scanner gem/lock jatuh di lantai|left|\n"
        << "add_smalltext|`2/paction   /pmove   /plog   /phex   /pstatus   /evantag   /evanchat|left|\n"
        << "add_smalltext|`2/wrench [info/pull/kick/ban/off]   /winfo   /news   /fastdrop   /fasttrash   /calc   /bal   /timer|left|\n"
        << "add_spacer|small|\n"
        << "end_dialog|evanproxy_commands||Tutup|\n";
    return oss.str();
}

void hotkey_capture_finish(Session& session, const std::string& key_text, UiEffects& out) {
    int slot = session.hk_capture_slot;
    session.hk_capture_slot = -1;
    if (slot < 0 || slot >= static_cast<int>(kHotkeySlots)) {
        return;
    }
    if (session.hotkeys.size() < kHotkeySlots) {
        session.hotkeys.resize(kHotkeySlots);
    }
    session.hotkeys[slot].key = key_text;
    session.hk_edit_slot = slot;
    out.save_config = true;
    out.to_client.push_back(proto::build_play_sfx("audio/dialog_confirm.wav", 0));
    push_brand(out, "`2Tombol Hotkey #" + std::to_string(slot + 1) + " direkam: `9[" + key_text + "]");
    push_dialog(out, build_hotkey_edit_dialog(session, slot));
}

void run_hotkey_command(const std::string& command, Session& session, SharedState& shared, UiEffects& out) {
    const std::string cmd = trim_s(command);
    if (cmd.empty()) return;
    if (!handle_chat_command(cmd, session, shared, out)) {
        out.to_server.push_back(proto::encode_text_packet(
            proto::MessageType::GenericText, "action|input\n|text|" + cmd));
    }
}

bool handle_dialog_return(
    const proto::TextParse& tp,
    Session& session,
    SharedState& shared,
    UiEffects& out
) {
    const std::string dname = tp.get("dialog_name");
    if (dname.rfind("evanproxy_", 0) != 0) {
        return false;
    }

    const std::string btn = tp.get("buttonClicked");

    // -----------------------------------------------------------------------
    // Form submissions (Simpan / Terapkan when buttonClicked is empty)
    // -----------------------------------------------------------------------
    if (btn.empty()) {
        if (dname == "evanproxy_home" && tp.has("chk_home_autobgl")) {
            session.auto_bgl = parse_cb(tp, "chk_home_autobgl", session.auto_bgl);
            if (!session.auto_bgl) session.auto_bgl_stage = AutoBglStage::Idle;
            const bool want_fb = parse_cb(tp, "chk_home_fastbuy", session.fast_buy > 0);
            if (want_fb && session.fast_buy == 0) session.fast_buy = 2;
            else if (!want_fb) session.fast_buy = 0;
            session.gems_tracker = parse_cb(tp, "chk_home_gems", session.gems_tracker);
            session.fast_drop = parse_cb(tp, "chk_home_fastdrop", session.fast_drop);
            session.hotkeys_enabled = parse_cb(tp, "chk_home_hotkeys", session.hotkeys_enabled);
            const bool old_fps_name = session.fps_show_name;
            session.fps_show_name = parse_cb(tp, "chk_home_fps_name", session.fps_show_name);
            session.fps_boost = parse_cb(tp, "chk_home_fps_boost", session.fps_boost);
            session.evan_branding = parse_cb(tp, "chk_home_branding", session.evan_branding);
            session.unlimited_zoom = parse_cb(tp, "chk_home_zoom", session.unlimited_zoom);
            out.save_config = true;
            if (old_fps_name != session.fps_show_name) push_visual_sync(session, out, true, false);
            if (session.fps_boost) out.to_client.push_back(proto::build_on_set_current_weather(0));
            push_brand(out, "`2Pengaturan Dashboard disimpan.");
            return true;
        }
        if (dname == "evanproxy_changelog") {
            push_dialog(out, build_home_dialog(session, shared));
            return true;
        }
        if (dname == "evanproxy_gems" && tp.has("chk_gems_tracker")) {
            session.gems_tracker = parse_cb(tp, "chk_gems_tracker", session.gems_tracker);
            out.save_config = true;
            push_brand(out, std::string("Gems Tracker: ") + badge(session.gems_tracker));
            return true;
        }
        if (dname == "evanproxy_title" && tp.has("chk_title_maxlevel")) {
            const bool prev_tt = session.title_tt_badge;
            session.title_maxlevel = parse_cb(tp, "chk_title_maxlevel", session.title_maxlevel);
            session.title_doctor = parse_cb(tp, "chk_title_doctor", session.title_doctor);
            session.title_legendary = parse_cb(tp, "chk_title_legendary", session.title_legendary);
            session.title_g4g = parse_cb(tp, "chk_title_g4g", session.title_g4g);
            session.title_master = parse_cb(tp, "chk_title_master", session.title_master);
            session.title_mentor = parse_cb(tp, "chk_title_mentor", session.title_mentor);
            session.title_anniversary = parse_cb(tp, "chk_title_anniversary", session.title_anniversary);
            session.title_award = parse_cb(tp, "chk_title_award", session.title_award);
            session.title_party = parse_cb(tp, "chk_title_party", session.title_party);
            session.title_royalwinter = parse_cb(tp, "chk_title_royalwinter", session.title_royalwinter);
            session.title_immortal = parse_cb(tp, "chk_title_immortal", session.title_immortal);
            session.title_thanksgiving = parse_cb(tp, "chk_title_thanksgiving", session.title_thanksgiving);
            const bool req_cc = parse_cb(tp, "chk_title_cc_badge", session.title_cc_badge);
            const bool req_tt = parse_cb(tp, "chk_title_tt_badge", session.title_tt_badge);
            if (req_cc && req_tt) {
                session.title_tt_badge = !prev_tt;
                session.title_cc_badge = prev_tt;
            } else {
                session.title_cc_badge = req_cc;
                session.title_tt_badge = req_tt;
            }
            session.title_moderator = parse_cb(tp, "chk_title_moderator", session.title_moderator);
            session.title_developer = parse_cb(tp, "chk_title_developer", session.title_developer);
            out.save_config = true;
            push_visual_sync(session, out, true, true);
            push_aura_sync(session, out);
            push_brand(out, "`2Visual Titles diterapkan: `w" + session.active_titles_summary());
            return true;
        }
        if (dname == "evanproxy_hotkeys" && tp.has("chk_hotkeys_enabled")) {
            session.hotkeys_enabled = parse_cb(tp, "chk_hotkeys_enabled", session.hotkeys_enabled);
            out.save_config = true;
            push_brand(out, std::string("Keyboard Hotkeys: ") + badge(session.hotkeys_enabled));
            return true;
        }
        if (dname == "evanproxy_hk_edit" && tp.has("hk_key_input")) {
            int slot = session.hk_edit_slot;
            if (tp.has("hk_slot")) {
                try { slot = std::stoi(tp.get("hk_slot")); } catch (...) {}
            }
            if (slot < 0 || slot >= static_cast<int>(kHotkeySlots)) slot = 0;
            if (session.hotkeys.size() < kHotkeySlots) session.hotkeys.resize(kHotkeySlots);

            const std::string raw_key = trim_s(tp.get("hk_key_input"));
            const std::string raw_cmd = trim_s(tp.get("hk_cmd_input"));
            std::string canonical_key;
            if (!raw_key.empty()) {
                auto spec = parse_hotkey(raw_key);
                if (!spec) {
                    push_brand(out, "`4Tombol '" + raw_key + "' tidak valid! Contoh: CTRL, ALT, SHIFT, TAB, SPACE, A, F1, CTRL+A.");
                    push_dialog(out, build_hotkey_edit_dialog(session, slot));
                    return true;
                }
                canonical_key = format_hotkey(*spec);
            }
            session.hotkeys[slot].key = canonical_key;
            session.hotkeys[slot].command = raw_cmd;
            out.save_config = true;
            push_brand(out, "`2Hotkey #" + std::to_string(slot + 1) + " disimpan: `9[" +
                            (canonical_key.empty() ? "Kosong" : canonical_key) + "] `w-> " +
                            (raw_cmd.empty() ? "(kosong)" : raw_cmd));
            push_dialog(out, build_hotkeys_dialog(session));
            return true;
        }
        if (dname == "evanproxy_tools" && tp.has("chk_vend_info")) {
            session.vending_info = parse_cb(tp, "chk_vend_info", session.vending_info);
            session.auto_bgl = parse_cb(tp, "chk_auto_bgl", session.auto_bgl);
            if (!session.auto_bgl) session.auto_bgl_stage = AutoBglStage::Idle;
            session.fast_drop = parse_cb(tp, "chk_fast_drop", session.fast_drop);
            session.fast_trash = parse_cb(tp, "chk_fast_trash", session.fast_trash);
            session.formalize_chat = parse_cb(tp, "chk_formalize", session.formalize_chat);
            session.chat_prefix_enabled = parse_cb(tp, "chk_chat_prefix", session.chat_prefix_enabled);
            session.evan_branding = parse_cb(tp, "chk_evan_branding", session.evan_branding);
            session.outgoing_evan_prefix = parse_cb(tp, "chk_evan_outchat", session.outgoing_evan_prefix);
            const bool old_rb = session.rainbow_name;
            session.rainbow_name = parse_cb(tp, "chk_rainbow", session.rainbow_name);
            if (tp.has("fb_qty_input")) {
                try {
                    int q = std::stoi(trim_s(tp.get("fb_qty_input")));
                    if (q < 0) q = 0;
                    if (q > 200) q = 200;
                    session.fast_buy_qty = q;
                } catch (...) {}
            }
            out.save_config = true;
            if (old_rb != session.rainbow_name) push_visual_sync(session, out, true, false);
            push_brand(out, "`2Pengaturan Tools & Vending disimpan.");
            return true;
        }
        if (dname == "evanproxy_visual" && tp.has("chk_vis_rainbow")) {
            const bool old_rb = session.rainbow_name;
            session.rainbow_name = parse_cb(tp, "chk_vis_rainbow", session.rainbow_name);
            session.unlimited_zoom = parse_cb(tp, "chk_vis_zoom", session.unlimited_zoom);
            session.hide_clothes = parse_cb(tp, "chk_vis_hideclothes", session.hide_clothes);
            session.style_all_dialogs = parse_cb(tp, "chk_vis_styleall", session.style_all_dialogs);
            session.custom_banner = parse_cb(tp, "chk_vis_banner", session.custom_banner);
            out.save_config = true;
            if (old_rb != session.rainbow_name) push_visual_sync(session, out, true, false);
            push_brand(out, "`2Pengaturan Visual disimpan.");
            return true;
        }
        if (dname == "evanproxy_packets" && tp.has("chk_pkt_actions")) {
            session.log_actions = parse_cb(tp, "chk_pkt_actions", session.log_actions);
            session.log_raw_movement = parse_cb(tp, "chk_pkt_raw_move", session.log_raw_movement);
            shared.verbose_log.store(parse_cb(tp, "chk_pkt_verbose", shared.verbose_log.load()));
            shared.hex_log.store(parse_cb(tp, "chk_pkt_hex", shared.hex_log.load()));
            out.save_config = true;
            push_brand(out, "`2Pengaturan Packet Monitor disimpan.");
            return true;
        }
        if (dname == "evanproxy_fps" && tp.has("chk_fps_name")) {
            const bool old_fn = session.fps_show_name;
            session.fps_show_name = parse_cb(tp, "chk_fps_name", session.fps_show_name);
            session.fps_boost = parse_cb(tp, "chk_fps_boost", session.fps_boost);
            session.fps_hide_bubbles = parse_cb(tp, "chk_fps_bubbles", session.fps_hide_bubbles);
            out.save_config = true;
            if (old_fn != session.fps_show_name) push_visual_sync(session, out, true, false);
            if (session.fps_boost) out.to_client.push_back(proto::build_on_set_current_weather(0));
            push_brand(out, "`2Pengaturan FPS & Ping disimpan.");
            return true;
        }
        return true; // Closed via X / Tutup / Batal
    }

    // Navigation buttons
    if (btn == "nav_go_home" || btn == "evanproxy_card1") { push_dialog(out, build_home_dialog(session, shared)); return true; }
    if (btn == "nav_go_nav") { push_dialog(out, build_nav_dialog(session)); return true; }
    if (btn == "nav_go_packets") { push_dialog(out, build_packets_dialog(session, shared)); return true; }
    if (btn == "nav_go_visual") { push_dialog(out, build_visual_dialog(session)); return true; }
    if (btn == "nav_go_title") { push_dialog(out, build_title_dialog(session)); return true; }
    if (btn == "nav_go_clothes") { push_dialog(out, build_clothes_dialog(session)); return true; }
    if (btn == "nav_go_search") { push_dialog(out, build_search_dialog(session, session.last_search_query, session.last_search_clothes_only)); return true; }
    if (btn == "nav_go_fps") { push_dialog(out, build_fps_dialog(session)); return true; }
    if (btn == "nav_go_tools" || btn == "evanproxy_card2") { push_dialog(out, build_tools_dialog(session)); return true; }
    if (btn == "nav_go_hotkeys" || btn == "evanproxy_card3") { push_dialog(out, build_hotkeys_dialog(session)); return true; }
    if (btn == "nav_go_gems" || btn == "gems_refresh") { push_dialog(out, build_gems_dialog(session)); return true; }
    if (btn == "gems_reset_stats") {
        session.gems_collected_world = 0;
        session.gems_collected_session = 0;
        session.gem_pickup_burst = 0;
        push_brand(out, "`2Statistik pengumpulan Gems sesi & world di-reset.");
        push_dialog(out, build_gems_dialog(session));
        return true;
    }
    if (btn == "gems_show_bubble") {
        std::ostringstream gb;
        gb << "`9[`#EvanProxy`9] `5Saldo: " << (session.gems >= 0 ? format_number_commas(session.gems) : "-")
           << " Gems `o(World: `2+" << format_number_commas(session.gems_collected_world)
           << " `o| Lantai: `9" << format_number_commas(session.world_floor_gems_total()) << "`o)";
        if (session.local_net_id >= 0) {
            out.to_client.push_back(proto::build_on_talk_bubble(session.local_net_id, gb.str()));
        }
        push_msg(out, gb.str());
        push_dialog(out, build_gems_dialog(session));
        return true;
    }
    if (btn == "nav_go_players") { session.players_page = 0; push_dialog(out, build_players_dialog(session, 0)); return true; }
    if (btn.rfind("players_page_", 0) == 0) {
        try {
            session.players_page = std::stoi(btn.substr(13));
        } catch (...) {
            session.players_page = 0;
        }
        push_dialog(out, build_players_dialog(session, session.players_page));
        return true;
    }
    if (btn == "nav_go_changelog" || btn == "evanproxy_banner_top" || btn == "banner") {
        push_dialog(out, build_changelog_dialog(session));
        return true;
    }
    if (btn == "nav_go_worldinfo") { push_dialog(out, build_worldinfo_dialog(session, shared)); return true; }
    if (btn == "nav_go_commands") { push_dialog(out, build_commands_dialog(session)); return true; }

    // Hotkey manager buttons
    if (btn.rfind("hk_edit_", 0) == 0) {
        try {
            int slot = std::stoi(btn.substr(8));
            if (slot >= 0 && slot < static_cast<int>(kHotkeySlots)) {
                session.hk_edit_slot = slot;
                push_dialog(out, build_hotkey_edit_dialog(session, slot));
                return true;
            }
        } catch (...) {
        }
    }
    if (btn == "hk_record_key") {
        int slot = session.hk_edit_slot;
        if (tp.has("hk_slot")) {
            try { slot = std::stoi(tp.get("hk_slot")); } catch (...) {}
        }
        if (slot < 0 || slot >= static_cast<int>(kHotkeySlots)) slot = 0;
        if (session.hotkeys.size() < kHotkeySlots) session.hotkeys.resize(kHotkeySlots);
        if (tp.has("hk_cmd_input")) {
            session.hotkeys[slot].command = trim_s(tp.get("hk_cmd_input"));
        }
        session.hk_edit_slot = slot;
        session.hk_capture_slot = slot;
        session.hk_capture_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        out.to_client.push_back(proto::build_on_text_overlay(
            "`9[Hotkey #" + std::to_string(slot + 1) + "] `2Tekan 1 tombol (CTRL/ALT/A/F1) atau combo... `o(ESC batal)"));
        push_brand(out, "`9[Hotkey #" + std::to_string(slot + 1) + "] `2Tekan tombol keyboard sekarang (misal CTRL, ALT, SHIFT, TAB, A, F1, CTRL+A)... Tekan ESC untuk batal.");
        return true;
    }
    if (btn == "hk_test") {
        int slot = session.hk_edit_slot;
        if (tp.has("hk_slot")) {
            try { slot = std::stoi(tp.get("hk_slot")); } catch (...) {}
        }
        std::string cmd = trim_s(tp.get("hk_cmd_input"));
        if (cmd.empty() && slot >= 0 && static_cast<size_t>(slot) < session.hotkeys.size()) {
            cmd = trim_s(session.hotkeys[slot].command);
        }
        if (!cmd.empty()) {
            run_hotkey_command(cmd, session, shared, out);
        } else {
            push_brand(out, "`4Perintah hotkey masih kosong.");
        }
        return true;
    }
    if (btn == "hk_clear") {
        int slot = session.hk_edit_slot;
        if (tp.has("hk_slot")) {
            try { slot = std::stoi(tp.get("hk_slot")); } catch (...) {}
        }
        if (slot >= 0 && slot < static_cast<int>(kHotkeySlots)) {
            if (session.hotkeys.size() < kHotkeySlots) session.hotkeys.resize(kHotkeySlots);
            session.hotkeys[slot] = HotkeyBinding{};
            out.save_config = true;
            push_brand(out, "`2Hotkey #" + std::to_string(slot + 1) + " dikosongkan.");
        }
        push_dialog(out, build_hotkeys_dialog(session));
        return true;
    }
    if (btn == "hk_reset_all") {
        session.hotkeys = default_hotkeys();
        out.save_config = true;
        push_brand(out, "`2Semua hotkey dikembalikan ke default (F1-F10).");
        push_dialog(out, build_hotkeys_dialog(session));
        return true;
    }

    // Quick toggle icon buttons in /proxy Dashboard
    if (btn == "home_tog_fastbuy") {
        session.fast_buy = (session.fast_buy > 0) ? 0 : 2;
        out.save_config = true;
        push_brand(out, "Mode Fast Buy Vending: " + fastbuy_label(session.fast_buy, session.fast_buy_qty));
        push_dialog(out, build_home_dialog(session, shared));
        return true;
    }
    if (btn == "home_tog_gems") {
        session.gems_tracker = !session.gems_tracker;
        out.save_config = true;
        push_brand(out, std::string("Gems Tracker: ") + badge(session.gems_tracker));
        push_dialog(out, build_home_dialog(session, shared));
        return true;
    }
    if (btn == "home_tog_autobgl") {
        trigger_auto_bgl_toggle(session, out);
        push_dialog(out, build_home_dialog(session, shared));
        return true;
    }
    if (btn == "home_tog_hotkeys") {
        session.hotkeys_enabled = !session.hotkeys_enabled;
        out.save_config = true;
        push_dialog(out, build_home_dialog(session, shared));
        return true;
    }
    if (btn == "home_tog_fastdrop") {
        session.fast_drop = !session.fast_drop;
        out.save_config = true;
        push_dialog(out, build_home_dialog(session, shared));
        return true;
    }
    if (btn == "home_tog_zoom") {
        session.unlimited_zoom = !session.unlimited_zoom;
        out.save_config = true;
        push_dialog(out, build_home_dialog(session, shared));
        return true;
    }
    if (btn == "home_tog_fps_name") {
        session.fps_show_name = !session.fps_show_name;
        out.save_config = true;
        push_visual_sync(session, out, true, false);
        push_dialog(out, build_home_dialog(session, shared));
        return true;
    }
    if (btn == "home_tog_fps_boost") {
        session.fps_boost = !session.fps_boost;
        out.save_config = true;
        if (session.fps_boost) out.to_client.push_back(proto::build_on_set_current_weather(0));
        push_dialog(out, build_home_dialog(session, shared));
        return true;
    }
    if (btn == "home_tog_branding") {
        session.evan_branding = !session.evan_branding;
        out.save_config = true;
        push_dialog(out, build_home_dialog(session, shared));
        return true;
    }

    // Nav page actions
    if (btn == "btn_warp_submit") {
        std::string w, d;
        parse_world_door(tp.get("warp_target"), w, d);
        if (w.empty()) {
            push_msg(out, "`4[EvanProxy] Masukkan nama world tujuan terlebih dahulu.");
            push_dialog(out, build_nav_dialog(session));
        } else {
            out.trigger_warp = std::make_pair(w, d);
        }
        return true;
    }
    if (btn == "btn_rejoin") {
        if (!session.current_world.empty()) {
            out.trigger_warp = std::make_pair(session.current_world, std::string{});
        } else {
            push_msg(out, "`4[EvanProxy] Belum ada world aktif untuk di-rejoin.");
        }
        return true;
    }
    if (btn == "btn_back_world") {
        if (!session.previous_world.empty()) {
            out.trigger_warp = std::make_pair(session.previous_world, std::string{});
        } else {
            push_msg(out, "`4[EvanProxy] Belum ada world sebelumnya.");
        }
        return true;
    }
    if (btn == "btn_exit_world") {
        out.to_server.push_back(proto::encode_text_packet(proto::MessageType::GameMessage, "action|quit_to_exit"));
        return true;
    }
    if (btn == "btn_save_current") {
        if (session.current_world.empty()) {
            push_msg(out, "`4[EvanProxy] Masuk ke suatu world dulu sebelum menyimpan.");
        } else {
            session.add_saved_world(session.current_world, "");
            out.save_worlds = true;
            push_msg(out, "`2[EvanProxy] World `w" + session.current_world + " `2disimpan ke favorit.");
        }
        push_dialog(out, build_nav_dialog(session));
        return true;
    }
    if (btn.rfind("warp_saved_", 0) == 0) {
        try {
            size_t idx = std::stoul(btn.substr(11));
            if (idx < session.saved_worlds.size()) {
                out.trigger_warp = std::make_pair(session.saved_worlds[idx].name, session.saved_worlds[idx].door_id);
                return true;
            }
        } catch (...) {
        }
    }
    if (btn.rfind("del_saved_", 0) == 0) {
        try {
            size_t idx = std::stoul(btn.substr(10));
            if (session.remove_saved_world(idx)) out.save_worlds = true;
        } catch (...) {
        }
        push_dialog(out, build_nav_dialog(session));
        return true;
    }
    if (btn.rfind("warp_hist_", 0) == 0) {
        try {
            size_t idx = std::stoul(btn.substr(10));
            if (idx < session.world_history.size()) {
                out.trigger_warp = std::make_pair(session.world_history[idx], std::string{});
                return true;
            }
        } catch (...) {
        }
    }

    // Packets page actions
    if (btn == "btn_clear_actions") {
        session.clear_actions();
        push_dialog(out, build_packets_dialog(session, shared));
        return true;
    }

    // Visual page
    if (btn == "btn_nick_apply") {
        std::string nick = trim_s(tp.get("nick_input"));
        if (!nick.empty()) {
            session.custom_nick = nick;
            push_visual_sync(session, out, true, false);
            push_msg(out, "`2[EvanProxy] Nick lokal diubah ke: `w" + nick);
        }
        push_dialog(out, build_visual_dialog(session));
        return true;
    }
    if (btn == "btn_nick_reset") {
        session.custom_nick.clear();
        push_visual_sync(session, out, true, false);
        push_msg(out, "`2[EvanProxy] Nick lokal dikembalikan ke nama asli.");
        push_dialog(out, build_visual_dialog(session));
        return true;
    }
    if (btn == "btn_flag_apply") {
        std::string flag = to_lower_s(trim_s(tp.get("flag_input")));
        if (flag == "reset" || flag == "off") {
            session.custom_country.clear();
            push_visual_sync(session, out, false, true);
            push_msg(out, "`2[EvanProxy] Bendera lokal dikembalikan.");
        } else if (!flag.empty()) {
            session.custom_country = flag;
            push_visual_sync(session, out, false, true);
            push_msg(out, "`2[EvanProxy] Bendera lokal diubah ke: `w" + flag);
        }
        push_dialog(out, build_visual_dialog(session));
        return true;
    }

    // Title dialog actions
    if (btn == "title_tog_maxlevel") toggle_title_by_key(session, "maxlevel", out);
    else if (btn == "title_tog_doctor") toggle_title_by_key(session, "doctor", out);
    else if (btn == "title_tog_legendary") toggle_title_by_key(session, "legendary", out);
    else if (btn == "title_tog_g4g") toggle_title_by_key(session, "g4g", out);
    else if (btn == "title_tog_master") toggle_title_by_key(session, "master", out);
    else if (btn == "title_tog_mentor") toggle_title_by_key(session, "mentor", out);
    else if (btn == "title_tog_anniversary") toggle_title_by_key(session, "10y", out);
    else if (btn == "title_tog_award") toggle_title_by_key(session, "award", out);
    else if (btn == "title_tog_party") toggle_title_by_key(session, "party", out);
    else if (btn == "title_tog_royalwinter") toggle_title_by_key(session, "winter", out);
    else if (btn == "title_cycle_growroyal") toggle_title_by_key(session, "royal", out);
    else if (btn == "title_tog_immortal") toggle_title_by_key(session, "immortal", out);
    else if (btn == "title_tog_thanksgiving") toggle_title_by_key(session, "thanks", out);
    else if (btn == "title_tog_cc_badge") toggle_title_by_key(session, "cc", out);
    else if (btn == "title_tog_tt_badge") toggle_title_by_key(session, "tiktok", out);
    else if (btn == "title_cycle_pbl") toggle_title_by_key(session, "pbl", out);
    else if (btn == "title_tog_moderator") toggle_title_by_key(session, "mod", out);
    else if (btn == "title_tog_developer") toggle_title_by_key(session, "dev", out);
    else if (btn == "title_reset_all") toggle_title_by_key(session, "reset", out);

    if (btn.rfind("title_", 0) == 0) {
        out.save_config = true;
        push_visual_sync(session, out, true, true);
        if (btn == "title_tog_immortal" || btn == "title_reset_all") {
            push_aura_sync(session, out);
        }
        push_dialog(out, build_title_dialog(session));
        return true;
    }

    if (btn == "clothes_toggle_mode") {
        if (session.visual_clothes_mode) {
            exit_visual_clothes_mode(session, out);
            push_brand(out, "`2Visual Clothes OFF. Baju asli server dipulihkan.");
        } else {
            enter_visual_clothes_mode(session, out);
            push_brand(out, "`2Visual Clothes ON! Pakai /search untuk mengambil item ke BP.");
        }
        push_dialog(out, build_clothes_dialog(session));
        return true;
    }
    if (btn == "clothes_clear_all") {
        enter_visual_clothes_mode(session, out);
        std::fill(std::begin(session.visual_clothes.slots), std::end(session.visual_clothes.slots), 0u);
        push_clothes_sync(session, out);
        push_brand(out, "`oSemua baju visual dilepas.");
        push_dialog(out, build_clothes_dialog(session));
        return true;
    }
    if (btn == "btn_clothes_search") {
        session.last_search_query = trim_s(tp.get("clothes_search_input"));
        push_dialog(out, build_search_dialog(session, session.last_search_query, session.last_search_clothes_only));
        return true;
    }
    if (btn == "btn_search_go") {
        session.last_search_query = trim_s(tp.get("search_query_input"));
        push_dialog(out, build_search_dialog(session, session.last_search_query, session.last_search_clothes_only));
        return true;
    }
    if (btn == "btn_search_filter") {
        if (tp.has("search_query_input")) {
            session.last_search_query = trim_s(tp.get("search_query_input"));
        }
        session.last_search_clothes_only = !session.last_search_clothes_only;
        push_dialog(out, build_search_dialog(session, session.last_search_query, session.last_search_clothes_only));
        return true;
    }
    if (btn.rfind("vpick_", 0) == 0) {
        try {
            uint32_t item_id = static_cast<uint32_t>(std::stoul(btn.substr(6)));
            give_and_equip_visual_item(session, item_id, out);
        } catch (...) {
        }
        push_dialog(out, build_search_dialog(session, session.last_search_query, session.last_search_clothes_only));
        return true;
    }
    if (btn.rfind("unequip_slot_", 0) == 0) {
        try {
            int slot = std::stoi(btn.substr(13));
            if (slot >= 0 && slot < 10) {
                enter_visual_clothes_mode(session, out);
                session.visual_clothes.slots[slot] = 0;
                push_clothes_sync(session, out);
            }
        } catch (...) {
        }
        push_dialog(out, build_clothes_dialog(session));
        return true;
    }
    if (btn.rfind("preset_", 0) == 0) {
        apply_clothes_preset(session, btn.substr(7), out);
        push_dialog(out, build_clothes_dialog(session));
        return true;
    }
    if (btn.rfind("copy_outfit_", 0) == 0) {
        try {
            int32_t nid = std::stoi(btn.substr(12));
            auto it = session.remote_clothes.find(nid);
            if (it != session.remote_clothes.end() && it->second.valid) {
                enter_visual_clothes_mode(session, out);
                for (int s = 0; s < 10; ++s) {
                    const uint32_t id = it->second.slots[s];
                    session.visual_clothes.slots[s] = id;
                    if (id != 0 &&
                        session.inventory.find(static_cast<uint16_t>(id)) == session.inventory.end() &&
                        session.visual_bp_items.find(id) == session.visual_bp_items.end()) {
                        session.visual_bp_items.insert(id);
                        out.to_client.push_back(proto::build_modify_item_inventory(id, 1));
                    }
                }
                push_clothes_sync(session, out);
                push_brand(out, "`2Outfit pemain berhasil disalin ke Visual Clothes & BP!");
            }
        } catch (...) {
        }
        return true;
    }
    if (btn == "wrench_turn_off") {
        session.wrench_mode = WrenchMode::Off;
        push_brand(out, "`oWrench Shortcuts dimatikan (`4OFF`o).");
        return true;
    }
    if (btn.rfind("wrench_act_", 0) == 0) {
        std::string rest = btn.substr(11);
        size_t us = rest.find('_');
        if (us != std::string::npos) {
            std::string act = rest.substr(0, us);
            try {
                int32_t nid = std::stoi(rest.substr(us + 1));
                auto pit = session.players.find(nid);
                if (pit != session.players.end()) {
                    out.to_server.push_back(proto::encode_text_packet(
                        proto::MessageType::GenericText, "action|input\n|text|/" + act + " " + pit->second.name));
                    push_brand(out, "`oMenjalankan `w/" + act + " " + pit->second.name);
                }
            } catch (...) {
            }
        }
        return true;
    }
    if (btn.rfind("skin_", 0) == 0) {
        std::string preset = btn.substr(5);
        if (session.local_net_id >= 0) {
            if (preset == "reset") {
                if (session.has_original_skin) {
                    out.to_client.push_back(proto::build_on_change_skin(session.local_net_id, session.original_skin));
                }
            } else {
                bool ok = false;
                uint32_t col = parse_skin_preset(preset, ok);
                if (ok) {
                    out.to_client.push_back(proto::build_on_change_skin(session.local_net_id, col));
                }
            }
        }
        push_dialog(out, build_visual_dialog(session));
        return true;
    }
    if (btn.rfind("weather_", 0) == 0) {
        try {
            uint32_t wid = static_cast<uint32_t>(std::stoul(btn.substr(8)));
            out.to_client.push_back(proto::build_on_set_current_weather(wid));
        } catch (...) {
        }
        push_dialog(out, build_visual_dialog(session));
        return true;
    }
    if (btn.rfind("theme_", 0) == 0) {
        session.ui_theme = btn.substr(6);
        out.save_config = true;
        push_dialog(out, build_visual_dialog(session));
        return true;
    }

    // Tools page actions
    if (btn == "btn_fastbuy_cycle") {
        if (session.fast_buy == 0) session.fast_buy = 2;
        else if (session.fast_buy == 2) session.fast_buy = 1;
        else session.fast_buy = 0;
        if (tp.has("fb_qty_input")) {
            try {
                int q = std::stoi(trim_s(tp.get("fb_qty_input")));
                if (q >= 0 && q <= 200) session.fast_buy_qty = q;
            } catch (...) {}
        }
        out.save_config = true;
        push_brand(out, "Mode Fast Buy Vending: " + fastbuy_label(session.fast_buy, session.fast_buy_qty));
        push_dialog(out, build_tools_dialog(session));
        return true;
    }
    if (btn.rfind("fb_qty_", 0) == 0) {
        try {
            int q = std::stoi(btn.substr(7));
            if (q < 0) q = 0;
            if (q > 200) q = 200;
            session.fast_buy = 2;
            session.fast_buy_qty = q;
            out.save_config = true;
            push_brand(out, "Mode Fast Buy Vending: " + fastbuy_label(session.fast_buy, session.fast_buy_qty));
        } catch (...) {
        }
        push_dialog(out, build_tools_dialog(session));
        return true;
    }
    if (btn == "btn_convert_dl") {
        trigger_convert_wl_to_dl(session, out);
        push_dialog(out, build_tools_dialog(session));
        return true;
    }
    if (btn == "btn_cd_drop") {
        schedule_custom_wl_drop(session, tp.get("cd_input"), out);
        return true;
    }
    if (btn == "btn_wrench_cycle") {
        int next = (static_cast<int>(session.wrench_mode) + 1) % 5;
        session.wrench_mode = static_cast<WrenchMode>(next);
        push_brand(out, std::string("Wrench Mode: `w") + wrench_mode_label(session.wrench_mode));
        push_dialog(out, build_tools_dialog(session));
        return true;
    }
    if (btn == "btn_aura_cycle") {
        static constexpr uint32_t kAuras[] = {0u, 128u, 64u, 32768u, 2048u, 262144u, 524288u, 1048576u, 1u};
        size_t idx = 0;
        for (size_t i = 0; i < sizeof(kAuras) / sizeof(kAuras[0]); ++i) {
            if (kAuras[i] == session.visual_aura_bits) {
                idx = (i + 1) % (sizeof(kAuras) / sizeof(kAuras[0]));
                break;
            }
        }
        session.visual_aura_bits = kAuras[idx];
        push_aura_sync(session, out);
        push_dialog(out, build_tools_dialog(session));
        return true;
    }
    if (btn == "btn_open_news") {
        push_dialog(out, build_changelog_dialog(session));
        return true;
    }
    if (btn == "btn_open_raw_news") {
        if (session.last_news_markup.empty()) {
            push_brand(out, "`oGazette server asli belum diterima di sesi ini.");
        } else {
            push_dialog(out, apply_theme_to_dialog(session.last_news_markup, session.ui_theme));
        }
        return true;
    }
    if (btn == "btn_calc_go") {
        std::string expr = trim_s(tp.get("calc_input"));
        std::string cerr;
        auto val = evaluate_calc(expr, cerr);
        if (!val) {
            push_msg(out, "`4[Calc] Error: " + cerr);
        } else {
            std::ostringstream res;
            res << std::setprecision(12) << *val;
            push_msg(out, "`2[Calc] `w" + expr + " = `9" + res.str());
            out.calc_toast = std::make_pair("CALC · " + expr, "= " + res.str());
        }
        push_dialog(out, build_tools_dialog(session));
        return true;
    }
    if (btn == "timer_cancel") {
        session.timer_active = false;
        push_msg(out, "`o[Timer] Timer dibatalkan.");
        push_dialog(out, build_tools_dialog(session));
        return true;
    }
    if (btn.rfind("timer_", 0) == 0) {
        try {
            int secs = std::stoi(btn.substr(6));
            if (secs > 0) {
                session.timer_active = true;
                session.timer_end = std::chrono::steady_clock::now() + std::chrono::seconds(secs);
                session.timer_label = std::to_string(secs) + " detik";
                push_msg(out, "`2[Timer] Pengingat dipasang selama `w" + session.timer_label + "``.");
            }
        } catch (...) {
        }
        push_dialog(out, build_tools_dialog(session));
        return true;
    }

    return true;
}

bool handle_chat_command(
    const std::string& chat,
    Session& session,
    SharedState& shared,
    UiEffects& out
) {
    if (chat.empty() || chat[0] != '/') {
        return false;
    }

    std::string cmd;
    std::string arg;
    size_t sp = chat.find(' ');
    if (sp == std::string::npos) {
        cmd = to_lower_s(chat);
    } else {
        cmd = to_lower_s(chat.substr(0, sp));
        arg = trim_s(chat.substr(sp + 1));
    }

    if (cmd == "/proxy" || cmd == "/phelp") {
        push_dialog(out, build_home_dialog(session, shared));
        return true;
    }
    if (cmd == "/worlds") {
        push_dialog(out, build_nav_dialog(session));
        return true;
    }
    if (cmd == "/autobgl" || cmd == "/change") {
        trigger_auto_bgl_toggle(session, out);
        return true;
    }
    if (cmd == "/fastbuy" || cmd == "/fb") {
        const std::string low = to_lower_s(arg);
        if (low.empty()) {
            session.fast_buy = (session.fast_buy == 0) ? 2 : 0;
        } else if (low == "off") {
            session.fast_buy = 0;
        } else if (low == "quick") {
            session.fast_buy = 1;
        } else if (low == "auto") {
            session.fast_buy = 2;
        } else if (low == "max") {
            session.fast_buy = 2;
            session.fast_buy_qty = 0;
        } else {
            size_t sp2 = low.find(' ');
            std::string sub = (sp2 == std::string::npos) ? low : low.substr(0, sp2);
            std::string qarg = (sp2 == std::string::npos) ? std::string{} : trim_s(low.substr(sp2 + 1));
            if (sub == "auto" || sub == "quick") {
                session.fast_buy = (sub == "auto") ? 2 : 1;
                if (qarg == "max") {
                    session.fast_buy_qty = 0;
                } else if (auto q = parse_positive_u32(qarg); q && *q <= 200u) {
                    session.fast_buy_qty = static_cast<int>(*q);
                } else {
                    push_brand(out, "`4Pakai: /fastbuy [off|quick|auto|max|<1..200>]");
                    return true;
                }
            } else if (auto q = parse_positive_u32(low); q && *q <= 200u) {
                session.fast_buy = 2;
                session.fast_buy_qty = static_cast<int>(*q);
            } else {
                push_brand(out, "`4Pakai: /fastbuy [off|quick|auto|max|<1..200>]");
                return true;
            }
        }
        out.save_config = true;
        push_brand(out, "Mode Fast Buy Vending: " + fastbuy_label(session.fast_buy, session.fast_buy_qty));
        return true;
    }
    if (cmd == "/vendinfo") {
        session.vending_info = !session.vending_info;
        out.save_config = true;
        push_brand(out, std::string("Info Privat Sisa Stok Vending & WL: ") + badge(session.vending_info));
        return true;
    }
    if (cmd == "/hotkey" || cmd == "/hotkeys") {
        const std::string low = to_lower_s(arg);
        if (low.empty()) {
            push_dialog(out, build_hotkeys_dialog(session));
        } else if (low == "on") {
            session.hotkeys_enabled = true;
            out.save_config = true;
            push_brand(out, "Keyboard Hotkeys Custom: `2[ON]``");
        } else if (low == "off") {
            session.hotkeys_enabled = false;
            out.save_config = true;
            push_brand(out, "Keyboard Hotkeys Custom: `4[OFF]``");
        } else if (low == "reset") {
            session.hotkeys = default_hotkeys();
            out.save_config = true;
            push_brand(out, "`2Semua hotkey dikembalikan ke default (F1-F10).");
        } else if (low.rfind("clear ", 0) == 0) {
            if (auto s = parse_positive_u32(low.substr(6)); s && *s <= kHotkeySlots) {
                if (session.hotkeys.size() < kHotkeySlots) session.hotkeys.resize(kHotkeySlots);
                session.hotkeys[*s - 1] = HotkeyBinding{};
                out.save_config = true;
                push_brand(out, "`2Hotkey #" + std::to_string(*s) + " dikosongkan.");
            } else {
                push_brand(out, "`4Pakai: /hotkey clear <1..12>");
            }
        } else if (low.rfind("set ", 0) == 0) {
            std::istringstream iss(trim_s(arg.substr(4)));
            std::string slot_s, key_s;
            iss >> slot_s >> key_s;
            std::string rest;
            std::getline(iss, rest);
            rest = trim_s(rest);
            auto s = parse_positive_u32(slot_s);
            auto spec = parse_hotkey(key_s);
            if (!s || *s > kHotkeySlots || !spec || rest.empty()) {
                push_brand(out, "`4Pakai: /hotkey set <1..12> <tombol> <perintah> (misal /hotkey set 1 A /warp clunxz)");
                return true;
            }
            if (session.hotkeys.size() < kHotkeySlots) session.hotkeys.resize(kHotkeySlots);
            const std::string fmt_key = format_hotkey(*spec);
            session.hotkeys[*s - 1] = HotkeyBinding{fmt_key, rest};
            out.save_config = true;
            push_brand(out, "`2Hotkey #" + std::to_string(*s) + " diset: `9[" + fmt_key + "] `w-> " + rest);
        } else {
            push_brand(out, "`4Pakai: /hotkey [on|off|reset|set <1..12> <tombol> <cmd>|clear <1..12>]");
        }
        return true;
    }
    if (cmd == "/convert") {
        trigger_convert_wl_to_dl(session, out);
        return true;
    }
    if (cmd == "/cd") {
        schedule_custom_wl_drop(session, arg, out);
        return true;
    }
    if (cmd == "/wl" || cmd == "/wd") {
        schedule_single_lock_drop(session, 242u, "wl", arg, out);
        return true;
    }
    if (cmd == "/dl" || cmd == "/dd") {
        schedule_single_lock_drop(session, 1796u, "dl", arg, out);
        return true;
    }
    if (cmd == "/bgl") {
        schedule_single_lock_drop(session, 7188u, "bgl", arg, out);
        return true;
    }
    if (cmd == "/warp") {
        if (arg.empty()) {
            push_msg(out, "`4[EvanProxy] Pakai: /warp <nama_world> atau /warp <world>:<doorID>");
            return true;
        }
        std::string w, d;
        parse_world_door(arg, w, d);
        if (w.empty() || w.size() > 23) {
            push_msg(out, "`4[EvanProxy] Nama world tidak valid (maksimal 23 karakter).");
            return true;
        }
        if (w == "EXIT") {
            push_msg(out, "`4[EvanProxy] Gunakan /exit untuk keluar ke World Select Menu.");
            return true;
        }
        out.trigger_warp = std::make_pair(w, d);
        return true;
    }
    if (cmd == "/re" || cmd == "/relog") {
        if (session.current_world.empty()) {
            push_msg(out, "`4[EvanProxy] Anda belum berada di dalam world.");
        } else {
            out.trigger_warp = std::make_pair(session.current_world, std::string{});
        }
        return true;
    }
    if (cmd == "/back") {
        if (session.previous_world.empty()) {
            push_msg(out, "`4[EvanProxy] Belum ada world sebelumnya.");
        } else {
            out.trigger_warp = std::make_pair(session.previous_world, std::string{});
        }
        return true;
    }
    if (cmd == "/door") {
        if (session.current_world.empty() || arg.empty()) {
            push_msg(out, "`4[EvanProxy] Pakai /door <id> saat berada di dalam world.");
        } else {
            out.trigger_warp = std::make_pair(session.current_world, arg);
        }
        return true;
    }
    if (cmd == "/exit") {
        out.to_server.push_back(proto::encode_text_packet(proto::MessageType::GameMessage, "action|quit_to_exit"));
        return true;
    }
    if (cmd == "/sworld") {
        if (session.current_world.empty()) {
            push_msg(out, "`4[EvanProxy] Masuk ke world dulu untuk menyimpannya.");
        } else {
            session.add_saved_world(session.current_world, arg);
            out.save_worlds = true;
            push_msg(out, "`2[EvanProxy] World `w" + session.current_world + " `2disimpan ke favorit.");
        }
        return true;
    }
    if (cmd == "/paction") {
        session.log_actions = !session.log_actions;
        out.save_config = true;
        push_msg(out, std::string("`o[EvanProxy] Action Logger: ") + badge(session.log_actions));
        return true;
    }
    if (cmd == "/pmove") {
        session.log_raw_movement = !session.log_raw_movement;
        out.save_config = true;
        push_msg(out, std::string("`o[EvanProxy] Raw Movement Logger: ") + badge(session.log_raw_movement));
        return true;
    }
    if (cmd == "/plog") {
        bool next = !shared.verbose_log.load();
        shared.verbose_log.store(next);
        push_msg(out, std::string("`o[EvanProxy] Verbose Console Log: ") + badge(next));
        return true;
    }
    if (cmd == "/phex") {
        bool next = !shared.hex_log.load();
        shared.hex_log.store(next);
        push_msg(out, std::string("`o[EvanProxy] Hex Dump: ") + badge(next));
        return true;
    }
    if (cmd == "/pstatus") {
        auto cur = shared.get_current_upstream();
        const std::string log_path = shared.get_log_file_path();
        std::ostringstream oss;
        oss << "`o[EvanProxy] Upstream: `2"
            << (cur ? (cur->first + ":" + std::to_string(cur->second)) : "none")
            << "`o | C->S: `5" << shared.c2s_packets.load()
            << "`o | S->C: `5" << shared.s2c_packets.load();
        if (!log_path.empty()) {
            oss << "`o | Log: `w" << log_path;
        }
        push_msg(out, oss.str());
        return true;
    }
    if (cmd == "/title" || cmd == "/tittle") {
        if (arg.empty()) {
            push_dialog(out, build_title_dialog(session));
            return true;
        }
        const std::string low = to_lower_s(arg);
        if (!toggle_title_by_key(session, low, out)) {
            push_brand(out, "`4Pakai: /title [maxlevel|doctor|legendary|g4g|master|mentor|10y|award|party|winter|royal|goldroyal|silverroyal|bronzeroyal|cc|tiktok|pblorg|pblmod|immortal|mod|dev|reset]");
            return true;
        }
        out.save_config = true;
        push_visual_sync(session, out, true, true);
        if (low == "immortal" || low == "imortal" || low == "reset" || low == "off" || low == "clear") {
            push_aura_sync(session, out);
        }
        return true;
    }
    if (cmd == "/clothes" || cmd == "/cloth") {
        const std::string low = to_lower_s(arg);
        if (arg.empty()) {
            if (!session.visual_clothes_mode) {
                enter_visual_clothes_mode(session, out);
            }
            push_dialog(out, build_clothes_dialog(session));
        } else if (low == "off" || low == "exit" || low == "reset") {
            exit_visual_clothes_mode(session, out);
            push_brand(out, "`2Visual Clothes OFF. Baju asli server & BP dipulihkan.");
        } else if (low == "on") {
            enter_visual_clothes_mode(session, out);
            push_brand(out, "`2Visual Clothes ON! Pakai /search <item> untuk menambah item ke BP.");
        } else if (low == "clear") {
            enter_visual_clothes_mode(session, out);
            session.active_clothes_preset.clear();
            std::fill(std::begin(session.visual_clothes.slots), std::end(session.visual_clothes.slots), 0u);
            push_clothes_sync(session, out);
            push_brand(out, "`oSemua baju visual dilepas.");
        } else if (low.rfind("preset ", 0) == 0) {
            apply_clothes_preset(session, trim_s(low.substr(7)), out);
        } else {
            apply_clothes_preset(session, low, out);
        }
        return true;
    }
    if (cmd == "/search" || cmd == "/find") {
        std::string q = arg;
        bool clothes_only = true;
        if (to_lower_s(q).rfind("all ", 0) == 0) {
            clothes_only = false;
            q = trim_s(q.substr(4));
        } else if (to_lower_s(q) == "all") {
            clothes_only = false;
            q.clear();
        }
        session.last_search_query = q;
        session.last_search_clothes_only = clothes_only;
        push_dialog(out, build_search_dialog(session, q, clothes_only));
        return true;
    }
    if (cmd == "/copy") {
        if (arg.empty()) {
            push_brand(out, "`4Pakai: /copy <nama_pemain>");
            return true;
        }
        const std::string q = to_lower_s(arg);
        const PlayerInfo* target_p = nullptr;
        for (const auto& [nid, p] : session.players) {
            if (to_lower_s(p.name).find(q) != std::string::npos) {
                target_p = &p;
                break;
            }
        }
        if (!target_p) {
            push_brand(out, "`4Pemain '" + arg + "' tidak ditemukan di world.");
            return true;
        }
        auto it = session.remote_clothes.find(target_p->net_id);
        if (it == session.remote_clothes.end() || !it->second.valid) {
            push_brand(out, "`4Outfit " + target_p->name + " belum terekam.");
            return true;
        }
        enter_visual_clothes_mode(session, out);
        for (int s = 0; s < 10; ++s) {
            const uint32_t id = it->second.slots[s];
            session.visual_clothes.slots[s] = id;
            if (id != 0 &&
                session.inventory.find(static_cast<uint16_t>(id)) == session.inventory.end() &&
                session.visual_bp_items.find(id) == session.visual_bp_items.end()) {
                session.visual_bp_items.insert(id);
                out.to_client.push_back(proto::build_modify_item_inventory(id, 1));
            }
        }
        push_clothes_sync(session, out);
        push_brand(out, "`2Outfit `w" + target_p->name + " `2disalin ke Visual Clothes & BP!");
        return true;
    }
    if (cmd == "/aura") {
        const std::string low = to_lower_s(arg);
        if (low.empty() || low == "help") {
            push_brand(out, "`oPakai: /aura <none|halo|horns|stars|frozen|shadow|irradiated|spotlight|ghost>");
            return true;
        }
        if (low == "none" || low == "off" || low == "reset") session.visual_aura_bits = 0;
        else if (low == "halo") session.visual_aura_bits = 128u;
        else if (low == "horns") session.visual_aura_bits = 64u;
        else if (low == "stars") session.visual_aura_bits = 32768u;
        else if (low == "frozen") session.visual_aura_bits = 2048u;
        else if (low == "shadow") session.visual_aura_bits = 262144u;
        else if (low == "irradiated") session.visual_aura_bits = 524288u;
        else if (low == "spotlight") session.visual_aura_bits = 1048576u;
        else if (low == "ghost") session.visual_aura_bits = 1u;
        else {
            push_brand(out, "`4Aura tidak dikenal. Pilihan: none, halo, horns, stars, frozen, shadow, irradiated, spotlight, ghost");
            return true;
        }
        push_aura_sync(session, out);
        push_brand(out, "`2Aura visual diset ke: `w" + session.aura_name());
        return true;
    }
    if (cmd == "/rainbow") {
        session.rainbow_name = !session.rainbow_name;
        out.save_config = true;
        push_visual_sync(session, out, true, false);
        push_brand(out, std::string("Rainbow Name: ") + badge(session.rainbow_name));
        return true;
    }
    if (cmd == "/wrench") {
        const std::string low = to_lower_s(arg);
        if (low.empty()) {
            session.wrench_mode = (session.wrench_mode == WrenchMode::Off) ? WrenchMode::Info : WrenchMode::Off;
        } else if (low == "info") session.wrench_mode = WrenchMode::Info;
        else if (low == "pull") session.wrench_mode = WrenchMode::Pull;
        else if (low == "kick") session.wrench_mode = WrenchMode::Kick;
        else if (low == "ban") session.wrench_mode = WrenchMode::Ban;
        else if (low == "off") session.wrench_mode = WrenchMode::Off;
        else {
            push_brand(out, "`4Pakai: /wrench [info|pull|kick|ban|off]");
            return true;
        }
        push_brand(out, std::string("Wrench Mode: `w") + wrench_mode_label(session.wrench_mode));
        return true;
    }
    if (cmd == "/evantag" || cmd == "/branding") {
        session.evan_branding = !session.evan_branding;
        out.save_config = true;
        push_brand(out, std::string("Tag [EvanProxy] di semua chat: ") + badge(session.evan_branding));
        return true;
    }
    if (cmd == "/evanchat") {
        session.outgoing_evan_prefix = !session.outgoing_evan_prefix;
        out.save_config = true;
        push_brand(out, std::string("Prefix [EvanProxy] chat keluar: ") + badge(session.outgoing_evan_prefix));
        return true;
    }
    if (cmd == "/worldinfo" || cmd == "/winfo") {
        push_dialog(out, build_worldinfo_dialog(session, shared));
        return true;
    }
    if (cmd == "/gems" || cmd == "/gem") {
        const std::string low = to_lower_s(arg);
        if (low.empty()) {
            push_dialog(out, build_gems_dialog(session));
        } else if (low == "on") {
            session.gems_tracker = true;
            out.save_config = true;
            push_brand(out, "Gems Tracker & Live Bubble: `2[ON]``");
        } else if (low == "off") {
            session.gems_tracker = false;
            out.save_config = true;
            push_brand(out, "Gems Tracker & Live Bubble: `4[OFF]``");
        } else if (low == "reset") {
            session.gems_collected_world = 0;
            session.gems_collected_session = 0;
            session.gem_pickup_burst = 0;
            push_brand(out, "`2Statistik pengumpulan Gems sesi & world di-reset.");
        } else if (low == "scan") {
            const int64_t fg = session.world_floor_gems_total();
            const auto top = session.world_gem_tiles_top(3);
            std::ostringstream gs;
            gs << "Saldo: `5" << (session.gems >= 0 ? format_number_commas(session.gems) : "-")
               << " Gems `o| Terkumpul World: `2+" << format_number_commas(session.gems_collected_world)
               << " `o| Lantai: `9" << format_number_commas(fg) << " Gems";
            if (!top.empty()) {
                gs << " `o(Top tile: (" << top[0].first.first << "," << top[0].first.second
                   << ")=" << top[0].second << ")";
            }
            push_brand(out, gs.str());
        } else {
            push_brand(out, "`4Pakai: /gems [on|off|reset|scan]");
        }
        return true;
    }
    if (cmd == "/news" || cmd == "/gazette") {
        push_dialog(out, build_changelog_dialog(session));
        return true;
    }
    if (cmd == "/rawnews") {
        if (session.last_news_markup.empty()) {
            push_brand(out, "`oGazette server asli belum diterima di sesi ini.");
        } else {
            push_dialog(out, apply_theme_to_dialog(session.last_news_markup, session.ui_theme));
        }
        return true;
    }
    if (cmd == "/bubble") {
        if (session.local_net_id >= 0 && !arg.empty()) {
            out.to_client.push_back(proto::build_on_talk_bubble(session.local_net_id, std::string(kBrand) + arg));
        } else {
            push_brand(out, "`4Pakai: /bubble <teks>");
        }
        return true;
    }
    if (cmd == "/overlay") {
        if (!arg.empty()) {
            out.to_client.push_back(proto::build_on_text_overlay(std::string(kBrand) + arg));
        } else {
            push_brand(out, "`4Pakai: /overlay <teks>");
        }
        return true;
    }
    if (cmd == "/fps") {
        if (arg.empty()) {
            push_dialog(out, build_fps_dialog(session));
            return true;
        }
        const std::string low = to_lower_s(arg);
        if (low == "on" || low == "show") {
            session.fps_show_name = true;
            out.save_config = true;
            push_visual_sync(session, out, true, false);
            push_brand(out, "Ping (ms) di sebelah nama: `2[ON]``");
        } else if (low == "off" || low == "hide") {
            session.fps_show_name = false;
            out.save_config = true;
            push_visual_sync(session, out, true, false);
            push_brand(out, "Ping (ms) di sebelah nama: `4[OFF]``");
        } else if (low == "boost") {
            session.fps_boost = !session.fps_boost;
            out.save_config = true;
            if (session.fps_boost) {
                out.to_client.push_back(proto::build_on_set_current_weather(0));
            }
            push_brand(out, std::string("FPS & Signal Boost: ") + badge(session.fps_boost));
        } else if (low == "bubbles") {
            session.fps_hide_bubbles = !session.fps_hide_bubbles;
            out.save_config = true;
            push_brand(out, std::string("Sembunyikan Chat Bubble Lain: ") + badge(session.fps_hide_bubbles));
        } else {
            push_brand(out, "`4Pakai: /fps [on|off|boost|bubbles]");
        }
        return true;
    }
    if (cmd == "/fpsboost") {
        session.fps_boost = !session.fps_boost;
        out.save_config = true;
        if (session.fps_boost) {
            out.to_client.push_back(proto::build_on_set_current_weather(0));
        }
        push_brand(out, std::string("FPS & Signal Boost: ") + badge(session.fps_boost));
        return true;
    }
    if (cmd == "/ping") {
        std::ostringstream oss;
        oss << "Ping Server (ENet RTT Real-Time): `2" << session.live_ping_ms << " ms `o("
            << "Min " << session.ping_min_ms << "ms, Max " << session.ping_max_ms
            << "ms, Jitter +/-" << session.ping_jitter_ms << "ms, Overhead "
            << (session.proxy_overhead_us > 0 ? (std::to_string(session.proxy_overhead_us) + "us") : "<1ms")
            << ")";
        push_brand(out, oss.str());
        return true;
    }
    if (cmd == "/nick" || cmd == "/pnick") {
        if (arg.empty() || to_lower_s(arg) == "reset") {
            session.custom_nick.clear();
            push_visual_sync(session, out, true, false);
            push_msg(out, "`2[EvanProxy] Nick dikembalikan ke nama asli.");
        } else {
            session.custom_nick = arg;
            push_visual_sync(session, out, true, false);
            push_msg(out, "`2[EvanProxy] Nick lokal diubah ke: `w" + arg);
        }
        return true;
    }
    if (cmd == "/skin") {
        if (session.local_net_id < 0) {
            push_msg(out, "`4[EvanProxy] Masuk world dulu sebelum pakai /skin.");
            return true;
        }
        if (to_lower_s(arg) == "reset") {
            if (session.has_original_skin) {
                out.to_client.push_back(proto::build_on_change_skin(session.local_net_id, session.original_skin));
                push_msg(out, "`2[EvanProxy] Skin lokal dikembalikan.");
            }
            return true;
        }
        bool ok = false;
        uint32_t col = parse_skin_preset(arg, ok);
        if (!ok) {
            push_msg(out, "`4[EvanProxy] Pakai: /skin <normal|tan|dark|pale|gold|ghost|cyan|0xRRGGBBAA|reset>");
        } else {
            out.to_client.push_back(proto::build_on_change_skin(session.local_net_id, col));
            push_msg(out, "`2[EvanProxy] Skin lokal diubah.");
        }
        return true;
    }
    if (cmd == "/flag") {
        if (arg.empty()) {
            push_msg(out, "`4[EvanProxy] Pakai: /flag <kode_negara|reset> (misal: id, us, jp)");
        } else if (to_lower_s(arg) == "reset" || to_lower_s(arg) == "off") {
            session.custom_country.clear();
            push_visual_sync(session, out, false, true);
            push_msg(out, "`2[EvanProxy] Bendera lokal dikembalikan.");
        } else {
            std::string code = to_lower_s(arg);
            session.custom_country = code;
            push_visual_sync(session, out, false, true);
            push_msg(out, "`2[EvanProxy] Bendera lokal diubah ke: `w" + code);
        }
        return true;
    }
    if (cmd == "/weather") {
        const std::string low = to_lower_s(arg);
        if (low.empty() || low == "toggle") {
            session.weather_override = !session.weather_override;
            const uint32_t wid = session.weather_override ? session.weather_id : 0u;
            out.to_client.push_back(proto::build_on_set_current_weather(wid));
            out.save_config = true;
            push_msg(out, std::string("`o[EvanProxy] Weather Override: ") + badge(session.weather_override) +
                          (session.weather_override ? (" `o(ID=" + std::to_string(session.weather_id) + ")") : ""));
            return true;
        }
        if (low == "on") {
            session.weather_override = true;
            out.to_client.push_back(proto::build_on_set_current_weather(session.weather_id));
            out.save_config = true;
            push_msg(out, "`2[EvanProxy] Weather Override: ON (ID=" + std::to_string(session.weather_id) + ")");
            return true;
        }
        if (low == "off") {
            session.weather_override = false;
            out.to_client.push_back(proto::build_on_set_current_weather(0));
            out.save_config = true;
            push_msg(out, "`o[EvanProxy] Weather Override: `4[OFF]``");
            return true;
        }
        try {
            uint32_t wid = static_cast<uint32_t>(std::stoul(arg));
            session.weather_id = wid;
            session.weather_override = (wid != 0);
            out.to_client.push_back(proto::build_on_set_current_weather(wid));
            out.save_config = true;
            push_msg(out, "`2[EvanProxy] Cuaca lokal diset ke ID `w" + std::to_string(wid));
        } catch (...) {
            push_msg(out, "`4[EvanProxy] Pakai: /weather [on|off|<id>] (0=Sunny, 2=Night, 4=Rainy, 11=Spooky, 15=Snow)");
        }
        return true;
    }
    if (cmd == "/hud") {
        const std::string low = to_lower_s(arg);
        if (low == "on") session.hud_overlay = true;
        else if (low == "off") session.hud_overlay = false;
        else session.hud_overlay = !session.hud_overlay;
        out.save_config = true;
        push_brand(out, std::string("HUD Overlay In-Game: ") + badge(session.hud_overlay));
        return true;
    }
    if (cmd == "/zoom") {
        session.unlimited_zoom = !session.unlimited_zoom;
        out.save_config = true;
        push_msg(out, std::string("`o[EvanProxy] Unlimited Zoom: ") + badge(session.unlimited_zoom) + " `o(aktif saat masuk world berikutnya)");
        return true;
    }
    if (cmd == "/hideclothes") {
        session.hide_clothes = !session.hide_clothes;
        out.save_config = true;
        push_msg(out, std::string("`o[EvanProxy] Hide Other Clothes: ") + badge(session.hide_clothes));
        return true;
    }
    if (cmd == "/ui") {
        std::string t = to_lower_s(arg);
        if (t != "ocean" && t != "violet" && t != "emerald" && t != "crimson" && t != "classic") {
            push_msg(out, "`4[EvanProxy] Tema tersedia: ocean, violet, emerald, crimson, classic");
            return true;
        }
        session.ui_theme = t;
        out.save_config = true;
        push_msg(out, "`2[EvanProxy] Tema UI diubah ke: `w" + theme_display_name(t));
        return true;
    }
    if (cmd == "/fastdrop") {
        session.fast_drop = !session.fast_drop;
        out.save_config = true;
        push_msg(out, std::string("`o[EvanProxy] Fast Drop: ") + badge(session.fast_drop));
        return true;
    }
    if (cmd == "/fasttrash") {
        session.fast_trash = !session.fast_trash;
        out.save_config = true;
        push_msg(out, std::string("`o[EvanProxy] Fast Trash: ") + badge(session.fast_trash));
        return true;
    }
    if (cmd == "/calc") {
        std::string cerr;
        auto val = evaluate_calc(arg, cerr);
        if (!val) {
            push_brand(out, "`4[Calc] Error: " + cerr);
        } else {
            std::ostringstream res;
            res << std::setprecision(12) << *val;
            push_brand(out, "`2[Calc] `w" + arg + " = `9" + res.str());
            out.calc_toast = std::make_pair("CALC · " + arg, "= " + res.str());
        }
        return true;
    }
    if (cmd == "/bal" || cmd == "/balance") {
        std::ostringstream oss;
        oss << "[Balance] `2" << session.bgl_count() << " BGL `o- `1"
            << session.dl_count() << " DL `o- `6" << session.wl_count() << " WL `o- Gems: `5"
            << (session.gems >= 0 ? format_number_commas(session.gems) : "-");
        push_brand(out, oss.str());
        return true;
    }
    if (cmd == "/players" || cmd == "/who") {
        session.players_page = 0;
        push_dialog(out, build_players_dialog(session, 0));
        return true;
    }
    if (cmd == "/banner") {
        const std::string low = to_lower_s(arg);
        if (low == "on") session.custom_banner = true;
        else if (low == "off") session.custom_banner = false;
        else session.custom_banner = !session.custom_banner;
        out.save_config = true;
        push_brand(out, std::string("Banner Custom EvanProxy: ") + badge(session.custom_banner));
        return true;
    }
    if (cmd == "/owner") {
        if (session.world_owner.empty()) {
            push_brand(out, "Pemilik world tidak diketahui / world tidak di-lock.");
        } else {
            push_brand(out, "Pemilik world `w" + session.current_world + "`o: `2" + session.world_owner);
        }
        return true;
    }
    if (cmd == "/timer") {
        if (to_lower_s(arg) == "off" || to_lower_s(arg) == "cancel") {
            session.timer_active = false;
            push_brand(out, "[Timer] Timer dibatalkan.");
            return true;
        }
        try {
            int secs = std::stoi(arg);
            if (secs > 0 && secs <= 86400) {
                session.timer_active = true;
                session.timer_end = std::chrono::steady_clock::now() + std::chrono::seconds(secs);
                session.timer_label = std::to_string(secs) + " detik";
                push_brand(out, "`2[Timer] Pengingat dipasang selama `w" + session.timer_label + "``.");
                return true;
            }
        } catch (...) {
        }
        push_brand(out, "`4Pakai: /timer <detik> atau /timer off");
        return true;
    }
    if (cmd == "/formalize") {
        session.formalize_chat = !session.formalize_chat;
        out.save_config = true;
        push_msg(out, std::string("`o[EvanProxy] Formalize Chat: ") + badge(session.formalize_chat));
        return true;
    }
    if (cmd == "/me") {
        if (!arg.empty()) {
            const std::string emote = "* " + arg + " *";
            out.to_server.push_back(proto::encode_text_packet(
                proto::MessageType::GenericText, "action|input\n|text|" + emote));
        }
        return true;
    }

    return false;
}

bool apply_ui_command(
    const UiCommand& cmd,
    Session& session,
    SharedState& shared,
    UiEffects& out
) {
    switch (cmd.kind) {
        case UiCommand::Kind::RunChatCommand: {
            run_hotkey_command(cmd.value, session, shared, out);
            return true;
        }
        case UiCommand::Kind::SetToggle: {
            const std::string k = to_lower_s(cmd.key);
            const bool val = cmd.bool_arg;
            if (k == "evantag") {
                session.evan_branding = val;
            } else if (k == "evanchat") {
                session.outgoing_evan_prefix = val;
            } else if (k == "fps") {
                session.fps_boost = val;
                if (val) {
                    out.to_client.push_back(proto::build_on_set_current_weather(0));
                }
            } else if (k == "pingtag") {
                session.fps_show_name = val;
                push_visual_sync(session, out, true, false);
            } else if (k == "bubbles") {
                session.fps_hide_bubbles = val;
            } else if (k == "vendinfo") {
                session.vending_info = val;
            } else if (k == "autobgl") {
                session.auto_bgl = val;
                if (!val) session.auto_bgl_stage = AutoBglStage::Idle;
            } else if (k == "gems" || k == "gems_tracker") {
                session.gems_tracker = val;
            } else if (k == "hotkeys") {
                session.hotkeys_enabled = val;
            } else if (k == "fastdrop") {
                session.fast_drop = val;
            } else if (k == "fasttrash") {
                session.fast_trash = val;
            } else if (k == "rainbow") {
                session.rainbow_name = val;
                push_visual_sync(session, out, true, false);
            } else if (k == "weather") {
                session.weather_override = val;
                out.to_client.push_back(proto::build_on_set_current_weather(val ? session.weather_id : 0u));
            } else if (k == "hideclothes") {
                session.hide_clothes = val;
            } else if (k == "clothes") {
                if (val) {
                    enter_visual_clothes_mode(session, out);
                } else {
                    exit_visual_clothes_mode(session, out);
                }
            } else if (k == "hud") {
                session.hud_overlay = val;
            } else if (k == "banner") {
                session.custom_banner = val;
            } else if (k == "zoom") {
                session.unlimited_zoom = val;
                if (val && session.zoom_percent == 100) session.zoom_percent = 125;
                if (!val) session.zoom_percent = 100;
            } else if (k == "paction") {
                session.log_actions = val;
            } else if (k == "pmove") {
                session.log_raw_movement = val;
            } else if (k == "plog") {
                shared.verbose_log.store(val);
            } else if (k == "phex") {
                shared.hex_log.store(val);
            } else {
                return false;
            }
            out.save_config = true;
            return true;
        }
        case UiCommand::Kind::SetFastBuyMode: {
            int mode = cmd.int_arg;
            if (mode < 0) mode = 0;
            if (mode > 2) mode = 2;
            session.fast_buy = mode;
            out.save_config = true;
            push_brand(out, "Mode Fast Buy Vending: " + fastbuy_label(session.fast_buy, session.fast_buy_qty));
            return true;
        }
        case UiCommand::Kind::SetFastBuyQty: {
            int q = cmd.int_arg;
            if (q < 0) q = 0;
            if (q > 200) q = 200;
            session.fast_buy_qty = q;
            out.save_config = true;
            return true;
        }
        case UiCommand::Kind::SetZoomPercent: {
            int z = cmd.int_arg;
            if (z < 50) z = 50;
            if (z > 200) z = 200;
            session.zoom_percent = z;
            session.unlimited_zoom = (z != 100);
            out.save_config = true;
            return true;
        }
        case UiCommand::Kind::SetWeatherOverride: {
            session.weather_override = cmd.bool_arg;
            session.weather_id = static_cast<uint32_t>(std::max(0, cmd.int_arg));
            out.to_client.push_back(proto::build_on_set_current_weather(
                session.weather_override ? session.weather_id : 0u));
            out.save_config = true;
            return true;
        }
        case UiCommand::Kind::SetHotkeySlot: {
            const int slot = cmd.int_arg;
            if (slot < 0 || slot >= static_cast<int>(kHotkeySlots)) {
                return false;
            }
            if (session.hotkeys.size() < kHotkeySlots) {
                session.hotkeys.resize(kHotkeySlots);
            }
            const std::string raw_key = trim_s(cmd.key);
            const std::string raw_cmd = trim_s(cmd.value);
            std::string canonical_key;
            if (!raw_key.empty()) {
                auto spec = parse_hotkey(raw_key);
                if (!spec) {
                    shared.push_console_line(LogTag::Warn, "WARN", "Invalid hotkey key: " + raw_key);
                    return false;
                }
                canonical_key = format_hotkey(*spec);
            }
            session.hotkeys[static_cast<size_t>(slot)] = HotkeyBinding{canonical_key, raw_cmd};
            out.save_config = true;
            shared.push_console_line(
                LogTag::Ok,
                "OK",
                "Saved hotkey slot #" + std::to_string(slot + 1) + ": [" +
                    (canonical_key.empty() ? "Empty" : canonical_key) + "] -> " + raw_cmd);
            return true;
        }
        case UiCommand::Kind::ClearHotkeySlot: {
            const int slot = cmd.int_arg;
            if (slot < 0 || slot >= static_cast<int>(kHotkeySlots)) {
                return false;
            }
            if (session.hotkeys.size() < kHotkeySlots) {
                session.hotkeys.resize(kHotkeySlots);
            }
            session.hotkeys[static_cast<size_t>(slot)] = HotkeyBinding{};
            out.save_config = true;
            return true;
        }
        case UiCommand::Kind::ResetHotkeys: {
            session.hotkeys = default_hotkeys();
            out.save_config = true;
            return true;
        }
        case UiCommand::Kind::WardrobeAddItem: {
            const std::string q = trim_s(cmd.value);
            if (!session.items_db || session.items_db->size() == 0) {
                push_brand(out, "`4Database items.dat tidak tersedia untuk pencarian.");
                shared.push_console_line(LogTag::Warn, "WARN", "items.dat not loaded for Wardrobe search");
                return true;
            }
            if (q.empty()) {
                if (session.local_net_id >= 0) {
                    push_dialog(out, build_search_dialog(session, "", true));
                }
                return true;
            }
            session.last_search_query = q;
            auto hits = session.items_db->search(q, true, 1);
            if (hits.empty()) {
                hits = session.items_db->search(q, false, 1);
            }
            if (!hits.empty()) {
                give_and_equip_visual_item(session, hits[0]->id, out);
                shared.push_console_line(
                    LogTag::Ok,
                    "OK",
                    "Wardrobe added item #" + std::to_string(hits[0]->id) + " (" + hits[0]->name + ")");
            } else {
                push_brand(out, "`4Item '" + q + "' tidak ditemukan di items.dat.");
                shared.push_console_line(LogTag::Warn, "WARN", "Wardrobe item not found: " + q);
            }
            return true;
        }
        case UiCommand::Kind::ClearConsole: {
            shared.clear_packet_lines();
            session.clear_actions();
            return true;
        }
    }
    return false;
}

} // namespace evan::ui
