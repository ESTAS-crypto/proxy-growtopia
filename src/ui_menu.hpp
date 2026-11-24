#pragma once

#include "http_bridge.hpp"
#include "protocol.hpp"
#include "session.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace evan::ui {

struct UiEffects {
    std::vector<std::vector<uint8_t>> to_client;
    std::vector<std::vector<uint8_t>> to_server;
    std::optional<std::pair<std::string, std::string>> trigger_warp;
    std::optional<std::pair<std::string, std::string>> calc_toast;
    bool save_config = false;
    bool save_worlds = false;
};

std::string get_theme_header(const std::string& theme_name);
std::string apply_theme_to_dialog(const std::string& markup, const std::string& theme_name);

std::string build_home_dialog(const Session& session, const SharedState& shared);
std::string build_nav_dialog(const Session& session);
std::string build_packets_dialog(const Session& session, const SharedState& shared);
std::string build_visual_dialog(const Session& session);
std::string build_title_dialog(const Session& session);
std::string build_fps_dialog(const Session& session);
std::string build_clothes_dialog(const Session& session);
std::string build_search_dialog(const Session& session, const std::string& query, bool clothes_only);
std::string build_tools_dialog(const Session& session);
std::string build_gems_dialog(const Session& session);
std::string build_hotkeys_dialog(const Session& session);
std::string build_hotkey_edit_dialog(const Session& session, int slot);
std::string build_players_dialog(const Session& session, int page = 0);
std::string build_worldinfo_dialog(const Session& session, const SharedState& shared);
std::string build_player_inspect_dialog(const Session& session, const PlayerInfo& p);
std::string build_commands_dialog(const Session& session);
std::string build_changelog_dialog(const Session& session);

bool handle_dialog_return(
    const proto::TextParse& tp,
    Session& session,
    SharedState& shared,
    UiEffects& out
);

bool handle_chat_command(
    const std::string& chat,
    Session& session,
    SharedState& shared,
    UiEffects& out
);

// Called by the proxy when a key was captured for a hotkey slot (record-key mode).
void hotkey_capture_finish(Session& session, const std::string& key_text, UiEffects& out);

// Runs a hotkey command: proxy commands locally, anything else is sent as chat.
void run_hotkey_command(const std::string& command, Session& session, SharedState& shared, UiEffects& out);

// Applies an interactive command/toggle sent from the Desktop GUI or Dashboard.
bool apply_ui_command(const UiCommand& cmd, Session& session, SharedState& shared, UiEffects& out);

} // namespace evan::ui
