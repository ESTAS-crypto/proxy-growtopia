#pragma once

#include "config.hpp"
#include "items_db.hpp"
#include "protocol.hpp"

#include <chrono>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace evan {

struct ClothingSet {
    uint32_t slots[10] = {};
    uint32_t skin_color = 0xC8B5A1FFu;
    bool valid = false;
};

enum class WrenchMode {
    Off = 0,
    Info,
    Pull,
    Kick,
    Ban
};

enum class AutoBglStage {
    Idle = 0,
    Dialled,
    Buying,
    Confirming
};

struct PlannedDrop {
    uint32_t item_id = 0;
    uint32_t count = 0;
    bool activate = false; // true = double-click item (break/convert locks) instead of dropping
};

struct VendPending {
    // Filled when a vending buy dialog is seen
    int64_t item_id = 0;
    int64_t price = 0;
    int64_t stock_before = 0;
    int64_t wl_before = 0;
    int tilex = 0;
    int tiley = 0;
    // Armed when the purchase is confirmed
    bool active = false;
    int64_t items = 0;
    int64_t cost = 0;
    std::chrono::steady_clock::time_point deadline{};
};

struct HotkeySpec {
    int vk = 0;
    bool ctrl = false;
    bool alt = false;
    bool shift = false;
};

struct VendingOffer {
    int tilex = 0;
    int tiley = 0;
    int64_t stock = 0;
    int64_t price = 0;   // expectprice: >0 WL per item, <0 items per WL
    int64_t item_id = 0;
    int64_t wl_have = 0; // total World Lock equivalent shown by the dialog
};

struct PlayerInfo {
    int32_t net_id = 0;
    int32_t user_id = 0;
    std::string name;
    std::string raw_name;
    int tile_x = 0;
    int tile_y = 0;
};

struct SavedWorld {
    std::string name;
    std::string door_id;
};

struct WorldDropObject {
    int32_t uid = 0;
    uint32_t seq_idx = 0;
    uint32_t item_id = 0;
    uint32_t count = 1;
    float x = 0.0f;
    float y = 0.0f;
    bool collected = false;
};

class Session {
public:
    // Local player state
    int32_t local_net_id = -1;
    int32_t local_user_id = 0;
    std::string player_name;
    std::string raw_player_name;
    std::string country = "us";
    float pos_x = 0.0f;
    float pos_y = 0.0f;
    int tile_x = 0;
    int tile_y = 0;
    bool facing_left = false;
    bool was_jumping = false;
    bool was_walking = false;
    bool has_pos = false;
    uint32_t original_skin = 0xFFFFFFFFu;
    bool has_original_skin = false;

    // World state
    bool in_world = false;
    std::string current_world;
    std::string previous_world;
    std::string world_owner;
    std::vector<std::string> world_history;
    std::map<int32_t, PlayerInfo> players;

    // Economy & inventory
    int64_t gems = -1;
    int32_t level = -1;
    uint32_t inventory_slots = 0;
    std::map<uint16_t, uint32_t> inventory;

    // Feature & logging toggles
    bool log_actions = true;
    bool log_raw_movement = false;
    bool fast_drop = false;
    bool fast_trash = false;
    bool unlimited_zoom = false;
    bool hide_clothes = false;
    bool formalize_chat = false;
    bool chat_prefix_enabled = false;
    bool style_all_dialogs = false;
    bool custom_banner = true;
    bool hud_overlay = true;
    int zoom_percent = 100;
    bool weather_override = false;
    uint32_t weather_id = 15;
    std::string ui_theme = "ocean";
    bool auto_bgl = false;
    bool gems_tracker = true;
    bool hotkeys_enabled = true;
    int fast_buy = 0;
    int fast_buy_qty = 1;
    bool vending_info = true;
    std::vector<HotkeyBinding> hotkeys = default_hotkeys();
    int hk_edit_slot = -1;
    int hk_capture_slot = -1;
    std::chrono::steady_clock::time_point hk_capture_deadline{};
    int client_icon_state = 0; // 0=normal, 1=typing chat, 2=dialog open
    VendPending vend;

    // Visual overrides & live telemetry
    std::string custom_nick;
    std::string custom_country;
    std::string server_country_state;
    std::string server_name_extra_json;
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
    uint8_t rainbow_step = 0;
    bool welcomed_banner_sent = false;
    WrenchMode wrench_mode = WrenchMode::Off;
    std::string last_news_markup;
    uint32_t visual_aura_bits = 0;
    proto::GameUpdatePacket last_char_state_pkt{};
    bool has_char_state_pkt = false;
    int live_fps = 60;
    int live_ping_ms = 0;
    int ping_min_ms = 0;
    int ping_max_ms = 0;
    int ping_jitter_ms = 0;
    int proxy_overhead_us = 0;
    int players_page = 0;
    std::string last_sent_display_name;

    // Auto-BGL Telephone state machine
    AutoBglStage auto_bgl_stage = AutoBglStage::Idle;
    int auto_bgl_tile_x = 0;
    int auto_bgl_tile_y = 0;
    std::chrono::steady_clock::time_point auto_bgl_deadline{};

    // Planned exact lock drops (/cd, /wl, /dl, /bgl)
    std::deque<PlannedDrop> planned_drops;
    std::optional<PlannedDrop> active_planned_drop;
    std::chrono::steady_clock::time_point planned_drop_next_at{};
    std::chrono::steady_clock::time_point active_drop_deadline{};

    // Visual clothes & backpack state
    bool visual_clothes_mode = false;
    std::string active_clothes_preset;
    ClothingSet real_clothes;
    ClothingSet visual_clothes;
    std::set<uint32_t> visual_bp_items;
    std::map<int32_t, ClothingSet> remote_clothes;
    std::string last_search_query;
    bool last_search_clothes_only = true;
    const ItemDatabase* items_db = nullptr;

    // Pending item dialog IDs
    int32_t pending_drop_item_id = -1;
    int32_t pending_trash_item_id = -1;

    // Warp state machine
    bool warp_active = false;
    bool warp_waiting_menu = false;
    bool warp_suppress_menu = false;
    std::string warp_world;
    std::string warp_door;
    std::chrono::steady_clock::time_point warp_deadline{};
    std::chrono::steady_clock::time_point warp_suppress_deadline{};
    std::vector<uint8_t> suppressed_world_menu_pkt;

    // Timer state
    bool timer_active = false;
    std::chrono::steady_clock::time_point timer_end{};
    std::string timer_label;

    // Gems & world floor drop tracking (/gems)
    struct PickupReqPos {
        float x = 0.0f;
        float y = 0.0f;
    };
    int64_t gems_collected_world = 0;
    int64_t gems_collected_session = 0;
    int64_t gem_pickup_burst = 0;
    std::chrono::steady_clock::time_point last_gem_pickup_time{};
    std::vector<WorldDropObject> world_drops;
    bool drop_uid_calibrated = false;
    int32_t drop_base_uid = 1;
    std::map<int32_t, PickupReqPos> recent_pickup_reqs;
    uint16_t last_obj_credit_item = 0;
    uint32_t last_obj_credit_count = 0;
    std::chrono::steady_clock::time_point last_obj_credit_time{};

    // Saved worlds & action feed
    std::vector<SavedWorld> saved_worlds;
    std::deque<std::string> recent_actions;

    void apply_config(const ProxyConfig& cfg);
    void export_to_config(ProxyConfig& cfg) const;

    bool load_saved_worlds(const std::filesystem::path& path);
    bool save_saved_worlds(const std::filesystem::path& path) const;
    void add_saved_world(const std::string& name, const std::string& door_id);
    bool remove_saved_world(size_t index);

    void record_action(const std::string& action);
    void clear_actions();

    uint32_t wl_count() const;
    uint32_t dl_count() const;
    uint32_t bgl_count() const;

    bool has_any_title() const;
    bool needs_custom_name() const;
    bool needs_custom_country() const;
    bool needs_animated_name() const;
    uint32_t effective_aura_bits() const;
    std::string active_titles_summary() const;
    std::string compose_country_state() const;
    std::string compose_display_name() const;
    std::string aura_name() const;
    void on_server_country_state(const std::string& state);
    void on_server_name_changed(const std::string& raw_name, const std::string& extra_json);

    std::optional<std::string> describe_client_game_packet(
        const proto::GameUpdatePacket& gp,
        bool raw_move_mode
    );
    std::optional<std::string> describe_client_text_action(const proto::TextParse& tp);

    void on_server_spawn(const std::string& spawn_text, bool& out_is_local);
    void on_server_remove(const std::string& remove_text);
    void on_server_state(const proto::GameUpdatePacket& gp);
    void on_server_inventory(const uint8_t* extra, size_t len);
    void on_server_modify_inventory(const proto::GameUpdatePacket& gp);
    void on_server_console_message(const std::string& msg);
    void on_enter_world_map(const uint8_t* extra, size_t len);
    void on_server_track(const std::string& track_text);
    void on_client_pickup_request(const proto::GameUpdatePacket& gp);
    int64_t on_server_item_change_object(const proto::GameUpdatePacket& gp);
    void on_leave_world();

    int64_t world_floor_gems_total() const;
    size_t world_floor_gems_clusters() const;
    std::vector<std::pair<std::pair<int, int>, uint32_t>> world_gem_tiles_top(size_t max_tiles = 8) const;
    std::vector<std::pair<uint32_t, uint32_t>> world_floor_items_summary() const;
};

std::optional<double> evaluate_calc(const std::string& expr, std::string& err);
std::string formalize_chat_text(const std::string& text);
std::string format_number_commas(int64_t val);
bool plan_lock_drops(
    uint32_t total_wl,
    uint32_t have_wl,
    uint32_t have_dl,
    uint32_t have_bgl,
    std::vector<PlannedDrop>& out,
    std::string& err
);

// Custom hotkeys
bool is_modifier_vk(int vk);
int canonical_modifier_vk(int vk);
std::optional<HotkeySpec> parse_hotkey(const std::string& text);
std::string format_hotkey(const HotkeySpec& spec);
const std::vector<int>& hotkey_capture_vks();

// Vending machine helpers (Fast Buy)
std::optional<VendingOffer> parse_vending_dialog(const std::string& markup);
int64_t vending_max_buy(const VendingOffer& offer);
bool vending_cost(const VendingOffer& offer, int64_t want, int64_t& items, int64_t& cost);
std::string build_vending_buy_markup(const std::string& markup, int64_t prefill_qty, const std::string& info_line);

} // namespace evan
