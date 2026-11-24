#include "enet_proxy.hpp"

#include "banner.hpp"
#include "packet_logger.hpp"
#include "items_db.hpp"
#include "protocol.hpp"
#include "session.hpp"
#include "ui_menu.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <dwmapi.h>
#include <mmsystem.h>
#include <enet/enet.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstring>
#include <iostream>
#include <sstream>
#include <thread>

namespace evan {

namespace {

std::string format_enet_ip(const ENetAddress& addr) {
    char buf[ENET_ADDRESS_MAX_LENGTH] = {};
    if (enet_address_get_host_ip(&addr, buf, sizeof(buf)) == 0) {
        return std::string(buf);
    }
    return "0.0.0.0";
}

bool send_enet_bytes(ENetPeer* peer, uint8_t channel, const std::vector<uint8_t>& bytes, uint32_t flags) {
    if (!peer || peer->state != ENET_PEER_STATE_CONNECTED) {
        return false;
    }
    ENetPacket* pkt = enet_packet_create(bytes.data(), bytes.size(), flags);
    if (!pkt) return false;
    if (enet_peer_send(peer, channel, pkt) != 0) {
        enet_packet_destroy(pkt);
        return false;
    }
    return true;
}

std::string build_join_request_str(const std::string& world, const std::string& door) {
    std::ostringstream oss;
    oss << "action|join_request\nname|" << world;
    if (!door.empty()) {
        oss << "|" << door;
    }
    oss << "\ninvitedWorld|0\n";
    return oss.str();
}

struct DwmFpsSampler {
    bool initialized = false;
    UINT64 prev_refresh = 0;
    std::chrono::steady_clock::time_point prev_time{};

    static int detect_display_hz(const DWM_TIMING_INFO* ti) {
        if (ti && ti->rateRefresh.uiDenominator > 0 && ti->rateRefresh.uiNumerator > 0) {
            const int hz = static_cast<int>(
                (ti->rateRefresh.uiNumerator + ti->rateRefresh.uiDenominator / 2) /
                ti->rateRefresh.uiDenominator);
            if (hz >= 30 && hz <= 360) {
                return hz;
            }
        }
        DEVMODEW dm{};
        dm.dmSize = sizeof(dm);
        if (EnumDisplaySettingsW(nullptr, ENUM_CURRENT_SETTINGS, &dm) &&
            dm.dmDisplayFrequency >= 30 && dm.dmDisplayFrequency <= 360) {
            return static_cast<int>(dm.dmDisplayFrequency);
        }
        return 60;
    }

    int sample_fps() {
        DWM_TIMING_INFO ti{};
        ti.cbSize = sizeof(ti);
        if (DwmGetCompositionTimingInfo(nullptr, &ti) != S_OK) {
            return detect_display_hz(nullptr);
        }
        const int max_hz = detect_display_hz(&ti);
        const auto now = std::chrono::steady_clock::now();
        if (!initialized) {
            initialized = true;
            prev_refresh = ti.cRefresh;
            prev_time = now;
            return max_hz;
        }
        const double dt = std::chrono::duration<double>(now - prev_time).count();
        if (dt < 0.2) {
            return max_hz;
        }
        const UINT64 d_ref = (ti.cRefresh >= prev_refresh) ? (ti.cRefresh - prev_refresh) : 0;
        prev_refresh = ti.cRefresh;
        prev_time = now;
        int fps = (d_ref > 0) ? static_cast<int>(static_cast<double>(d_ref) / dt + 0.5) : max_hz;
        if (fps < 30 || fps > max_hz) {
            fps = max_hz;
        }
        return fps;
    }
};

std::optional<int32_t> extract_embed_item_id(const std::string& markup) {
    const std::string key = "embed_data|itemID|";
    size_t pos = markup.find(key);
    if (pos == std::string::npos) return std::nullopt;
    pos += key.size();
    try {
        return std::stoi(markup.substr(pos));
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<int32_t> extract_drop_count(const std::string& markup) {
    const std::string key = "add_text_input|count||";
    size_t pos = markup.find(key);
    if (pos == std::string::npos) return std::nullopt;
    pos += key.size();
    try {
        return std::stoi(markup.substr(pos));
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<int32_t> extract_trash_owned_count(const std::string& markup) {
    std::string low = markup;
    for (char& c : low) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    const std::string needle = "you have ";
    size_t pos = low.find(needle);
    if (pos == std::string::npos) return std::nullopt;
    pos += needle.size();
    try {
        return std::stoi(low.substr(pos));
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<std::string> extract_embed_str(const std::string& markup, const std::string& key) {
    const std::string needle = "embed_data|" + key + "|";
    size_t pos = markup.find(needle);
    if (pos == std::string::npos) return std::nullopt;
    pos += needle.size();
    size_t end = pos;
    while (end < markup.size() && markup[end] != '\r' && markup[end] != '\n' && markup[end] != '|') {
        ++end;
    }
    if (end == pos) return std::nullopt;
    return markup.substr(pos, end - pos);
}

void configure_low_latency_udp(ENetSocket sock) {
    if (sock == ENET_SOCKET_NULL) return;
    enet_socket_set_option(sock, ENET_SOCKOPT_RCVBUF, 1024 * 1024);
    enet_socket_set_option(sock, ENET_SOCKOPT_SNDBUF, 1024 * 1024);
    constexpr DWORD kSioUdpConnreset = _WSAIOW(IOC_VENDOR, 12);
    BOOL new_behavior = FALSE;
    DWORD bytes_returned = 0;
    WSAIoctl(static_cast<SOCKET>(sock), kSioUdpConnreset, &new_behavior, sizeof(new_behavior),
             nullptr, 0, &bytes_returned, nullptr, nullptr);
}

bool is_growtopia_foreground() {
    HWND fg = GetForegroundWindow();
    if (!fg) return false;
    char title[128] = {};
    int len = GetWindowTextA(fg, title, static_cast<int>(sizeof(title)));
    if (len <= 0) return false;
    std::string s(title, static_cast<size_t>(len));
    return s.find("Growtopia") != std::string::npos;
}

std::vector<uint8_t> build_drop_request_packet(uint32_t item_id) {
    return proto::encode_text_packet(
        proto::MessageType::GenericText,
        "action|drop\n|itemID|" + std::to_string(item_id)
    );
}

uint32_t variant_f32_to_id(const proto::Variant& v, size_t idx) {
    if (v.type != proto::Variant::Type::Vec3 || !std::holds_alternative<proto::Vec3>(v.value)) {
        return 0;
    }
    const auto& p = std::get<proto::Vec3>(v.value);
    const float f = (idx == 0) ? p.x : ((idx == 1) ? p.y : p.z);
    if (f <= 0.5f) return 0;
    return static_cast<uint32_t>(f + 0.5f);
}

void extract_clothing_from_vl(const proto::VariantList& vl, ClothingSet& out) {
    if (vl.items.size() < 5) return;
    out.slots[0] = variant_f32_to_id(vl.items[1], 0);
    out.slots[1] = variant_f32_to_id(vl.items[1], 1);
    out.slots[2] = variant_f32_to_id(vl.items[1], 2);
    out.slots[3] = variant_f32_to_id(vl.items[2], 0);
    out.slots[4] = variant_f32_to_id(vl.items[2], 1);
    out.slots[5] = variant_f32_to_id(vl.items[2], 2);
    out.slots[6] = variant_f32_to_id(vl.items[3], 0);
    out.slots[7] = variant_f32_to_id(vl.items[3], 1);
    out.slots[8] = variant_f32_to_id(vl.items[3], 2);
    if (auto s = vl.items[4].as_int()) {
        out.skin_color = static_cast<uint32_t>(*s);
    }
    out.slots[9] = (vl.items.size() >= 6) ? variant_f32_to_id(vl.items[5], 0) : 0;
    out.valid = true;
}

} // namespace

EnetProxy::EnetProxy(
    const ProxyConfig& cfg,
    SharedState& shared,
    std::filesystem::path log_dir,
    std::filesystem::path config_path,
    std::filesystem::path worlds_path
)
    : cfg_(cfg)
    , shared_(shared)
    , log_dir_(std::move(log_dir))
    , config_path_(std::move(config_path))
    , worlds_path_(std::move(worlds_path)) {}

bool EnetProxy::run(std::string& err) {
    if (enet_initialize() != 0) {
        err = "Gagal inisialisasi ENet";
        return false;
    }

    struct EnetInitGuard {
        ~EnetInitGuard() { enet_deinitialize(); }
    } init_guard;

    struct TimerResGuard {
        TimerResGuard() { timeBeginPeriod(1); }
        ~TimerResGuard() { timeEndPeriod(1); }
    } timer_res_guard;

    struct ThreadPriorityGuard {
        int prev_prio = THREAD_PRIORITY_NORMAL;
        ThreadPriorityGuard() {
            prev_prio = GetThreadPriority(GetCurrentThread());
            SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
        }
        ~ThreadPriorityGuard() {
            SetThreadPriority(GetCurrentThread(), prev_prio);
        }
    } thread_prio_guard;

    ENetAddress bind_addr{};
    enet_address_build_any(&bind_addr, ENET_ADDRESS_TYPE_IPV4);
    bind_addr.port = cfg_.enet_port;

    // Downstream uses 4 slots so overlapping sub-server reconnects never get dropped
    constexpr size_t kServerPeerCount = 4;
    ENetHost* server_host = enet_host_create(ENET_ADDRESS_TYPE_IPV4, &bind_addr, kServerPeerCount, 2, 0, 0);
    if (!server_host) {
        err = "Gagal membuat ENet server host di UDP port " + std::to_string(cfg_.enet_port);
        return false;
    }
    if (enet_host_compress_with_range_coder(server_host) != 0) {
        enet_host_destroy(server_host);
        err = "Gagal mengaktifkan range coder pada ENet server host";
        return false;
    }
    server_host->checksum = enet_crc32;
    server_host->usingNewPacketForServer = cfg_.using_new_packet ? 1 : 0;
    configure_low_latency_udp(server_host->socket);

    // Upstream uses 1 slot as required by ZTzTopia/enet usingNewPacket integrity calculation
    ENetHost* client_host = enet_host_create(ENET_ADDRESS_TYPE_IPV4, nullptr, 1, 2, 0, 0);
    if (!client_host) {
        enet_host_destroy(server_host);
        err = "Gagal membuat ENet client host";
        return false;
    }
    if (enet_host_compress_with_range_coder(client_host) != 0) {
        enet_host_destroy(client_host);
        enet_host_destroy(server_host);
        err = "Gagal mengaktifkan range coder pada ENet client host";
        return false;
    }
    client_host->checksum = enet_crc32;
    client_host->usingNewPacket = cfg_.using_new_packet ? 1 : 0;
    configure_low_latency_udp(client_host->socket);

    shared_.hex_log.store(cfg_.log_hex);
    PacketLogger logger(log_dir_, cfg_.log_to_file,
                        [&](LogTag tag, const std::string& tag_txt, const std::string& msg) {
                            shared_.push_console_line(tag, tag_txt, msg);
                        });
    if (logger.is_file_open()) {
        shared_.set_log_file_path(logger.log_file_path().string());
        std::cout << "[Log] Semua paket detail direkam ke: " << logger.log_file_path().string() << "\n";
    }

    Session session;
    session.apply_config(cfg_);
    if (!worlds_path_.empty()) {
        session.load_saved_worlds(worlds_path_);
    }

    ItemDatabase items_db;
    if (items_db.load_default_cache()) {
        std::cout << "[ItemsDB] Memuat " << items_db.size() << " item dari: "
                  << items_db.loaded_path().string() << "\n";
    } else {
        std::cout << "[ItemsDB] items.dat tidak ditemukan; /search memakai mode terbatas.\n";
    }
    session.items_db = &items_db;

    ENetPeer* downstream_peer = nullptr;
    ENetPeer* upstream_peer = nullptr;
    std::vector<PendingPacket> pending_c2s;
    std::array<bool, kServerPeerCount> slot_ack_logged{};
    uint64_t packet_seq = 0;

    auto log_both = [&](const std::string& line) {
        std::cout << line << "\n";
        logger.log_event(line);
        LogTag tag = LogTag::Info;
        std::string ttxt = "INFO";
        if (line.rfind("[!]", 0) == 0) {
            tag = LogTag::Error;
            ttxt = "ERROR";
        } else if (line.rfind("[ENet]", 0) == 0) {
            tag = LogTag::Enet;
            ttxt = "ENET";
        } else if (line.rfind("[Log]", 0) == 0 || line.rfind("[Redirect]", 0) == 0) {
            tag = LogTag::Ok;
            ttxt = "OK";
        }
        shared_.push_console_line(tag, ttxt, line);
    };

    auto persist_config_if_needed = [&](const ui::UiEffects& eff) {
        if (eff.save_config && !config_path_.empty()) {
            ProxyConfig updated = cfg_;
            session.export_to_config(updated);
            save_config(config_path_, updated);
        }
        if (eff.save_worlds && !worlds_path_.empty()) {
            session.save_saved_worlds(worlds_path_);
        }
    };

    auto queue_to_upstream = [&](uint8_t chan, std::vector<uint8_t> buf, uint32_t flags) {
        if (upstream_peer && upstream_peer->state == ENET_PEER_STATE_CONNECTED) {
            send_enet_bytes(upstream_peer, chan, buf, flags);
        } else if (upstream_peer) {
            pending_c2s.push_back(PendingPacket{std::move(buf), chan, flags});
        }
    };

    auto apply_ui_effects = [&](const ui::UiEffects& eff) {
        persist_config_if_needed(eff);
        if (eff.calc_toast) {
            shared_.notify_calc_toast(eff.calc_toast->first, eff.calc_toast->second);
        }
        for (const auto& pkt : eff.to_client) {
            if (downstream_peer) {
                send_enet_bytes(downstream_peer, 0, pkt, ENET_PACKET_FLAG_RELIABLE);
            }
        }
        for (const auto& pkt : eff.to_server) {
            queue_to_upstream(0, pkt, ENET_PACKET_FLAG_RELIABLE);
        }
        if (eff.trigger_warp) {
            const auto& [target_world, target_door] = *eff.trigger_warp;
            if (session.in_world) {
                const auto now_warp = std::chrono::steady_clock::now();
                session.warp_active = true;
                session.warp_waiting_menu = true;
                session.warp_suppress_menu = true;
                session.suppressed_world_menu_pkt.clear();
                session.warp_world = target_world;
                session.warp_door = target_door;
                session.warp_deadline = now_warp + std::chrono::milliseconds(1200);
                session.warp_suppress_deadline = now_warp + std::chrono::milliseconds(4500);
                queue_to_upstream(0, proto::encode_text_packet(proto::MessageType::GameMessage, "action|quit_to_exit"),
                                  ENET_PACKET_FLAG_RELIABLE);
            } else {
                session.warp_active = false;
                session.warp_waiting_menu = false;
                session.warp_suppress_menu = false;
                session.suppressed_world_menu_pkt.clear();
                queue_to_upstream(0, proto::encode_text_packet(proto::MessageType::GameMessage,
                                                               build_join_request_str(target_world, target_door)),
                                  ENET_PACKET_FLAG_RELIABLE);
            }
            if (downstream_peer) {
                send_enet_bytes(downstream_peer, 0,
                                proto::build_on_console_message("`9[`#EvanProxy`9]`2 Warping ke `w" + target_world +
                                                                (target_door.empty() ? "" : (":" + target_door)) + "``..."),
                                ENET_PACKET_FLAG_RELIABLE);
            }
        }
        enet_host_flush(server_host);
        if (upstream_peer) enet_host_flush(client_host);
    };

    auto teardown_upstream_now = [&]() {
        if (upstream_peer) {
            upstream_peer->nonce = 0;
            enet_peer_disconnect_now(upstream_peer, 0);
            enet_host_flush(client_host);
            upstream_peer = nullptr;
        }
        pending_c2s.clear();
    };

    auto last_ping_tick = std::chrono::steady_clock::now();
    auto last_anim_tick = last_ping_tick;
    auto last_ping_name_push = last_ping_tick;
    auto last_hotkey_tick = last_ping_tick;
    auto last_snapshot_tick = last_ping_tick;
    auto last_fps_tick = last_ping_tick;
    DwmFpsSampler fps_sampler;
    std::array<bool, kHotkeySlots> prev_hk_down{};
    std::array<bool, kHotkeySlots> hk_mod_dirty{};
    std::array<bool, 256> prev_cap_down{};
    bool cap_initialized = false;
    int cap_pending_mod_vk = 0;
    bool cap_mod_combo_used = false;
    double ovh_ema_us = 0.0;

    auto publish_live_snapshot = [&]() {
        UiSnapshot snap;
        snap.proxy_running = true;
        snap.http_running = true;
        snap.enet_running = true;
        snap.port_conflict = false;
        snap.http_port = cfg_.http_port;
        snap.enet_port = cfg_.enet_port;
        snap.manage_hosts = cfg_.manage_hosts;

        snap.client_connected = (downstream_peer != nullptr && downstream_peer->state == ENET_PEER_STATE_CONNECTED);
        snap.in_world = session.in_world;
        snap.player_name = session.player_name;
        snap.current_world = session.current_world;
        snap.previous_world = session.previous_world;
        snap.world_owner = session.world_owner;
        snap.player_count = session.in_world ? (session.players.size() + 1) : 0;
        if (auto cur_up = shared_.get_current_upstream()) {
            snap.upstream_addr = cur_up->first + ":" + std::to_string(cur_up->second);
        }
        snap.log_file_path = shared_.get_log_file_path();

        snap.wl = session.wl_count();
        snap.dl = session.dl_count();
        snap.bgl = session.bgl_count();
        snap.gems = session.gems;
        snap.gems_collected_world = session.gems_collected_world;
        snap.gems_collected_session = session.gems_collected_session;
        snap.world_floor_gems = session.world_floor_gems_total();
        snap.live_ping_ms = session.live_ping_ms;
        snap.ping_min_ms = session.ping_min_ms;
        snap.ping_max_ms = session.ping_max_ms;
        snap.ping_jitter_ms = session.ping_jitter_ms;
        snap.live_fps = session.live_fps;
        snap.proxy_overhead_us = session.proxy_overhead_us;
        snap.c2s_packets = shared_.c2s_packets.load(std::memory_order_relaxed);
        snap.s2c_packets = shared_.s2c_packets.load(std::memory_order_relaxed);

        snap.evan_branding = session.evan_branding;
        snap.outgoing_evan_prefix = session.outgoing_evan_prefix;
        snap.fps_boost = session.fps_boost;
        snap.fps_show_name = session.fps_show_name;
        snap.fps_hide_bubbles = session.fps_hide_bubbles;
        snap.vending_info = session.vending_info;
        snap.auto_bgl = session.auto_bgl;
        snap.gems_tracker = session.gems_tracker;
        snap.hotkeys_enabled = session.hotkeys_enabled;
        snap.fast_drop = session.fast_drop;
        snap.fast_trash = session.fast_trash;
        snap.rainbow_name = session.rainbow_name;
        snap.unlimited_zoom = session.unlimited_zoom;
        snap.weather_override = session.weather_override;
        snap.hide_clothes = session.hide_clothes;
        snap.visual_clothes_mode = session.visual_clothes_mode;
        snap.custom_banner = session.custom_banner;
        snap.hud_overlay = session.hud_overlay;
        snap.log_actions = session.log_actions;
        snap.log_raw_movement = session.log_raw_movement;
        snap.verbose_log = shared_.verbose_log.load(std::memory_order_relaxed);
        snap.hex_log = shared_.hex_log.load(std::memory_order_relaxed);

        snap.zoom_percent = session.zoom_percent;
        snap.weather_id = session.weather_id;
        snap.fast_buy = session.fast_buy;
        snap.fast_buy_qty = session.fast_buy_qty;

        snap.active_preset = session.active_clothes_preset;
        snap.active_titles_summary = session.active_titles_summary();
        snap.title_maxlevel = session.title_maxlevel;
        snap.title_doctor = session.title_doctor;
        snap.title_legendary = session.title_legendary;
        snap.title_g4g = session.title_g4g;
        snap.title_master = session.title_master;
        snap.title_mentor = session.title_mentor;
        snap.title_anniversary = session.title_anniversary;
        snap.title_award = session.title_award;
        snap.title_party = session.title_party;
        snap.title_royalwinter = session.title_royalwinter;
        snap.title_immortal = session.title_immortal;
        snap.title_thanksgiving = session.title_thanksgiving;
        snap.title_cc_badge = session.title_cc_badge;
        snap.title_tt_badge = session.title_tt_badge;
        snap.title_moderator = session.title_moderator;
        snap.title_developer = session.title_developer;
        snap.title_growroyal_tier = session.title_growroyal_tier;
        snap.title_pbl_role = session.title_pbl_role;
        snap.hotkeys = session.hotkeys;

        if (session.timer_active) {
            const auto rem = std::chrono::duration_cast<std::chrono::seconds>(
                session.timer_end - std::chrono::steady_clock::now()).count();
            shared_.update_timer_hud(true, static_cast<int>(std::max<long long>(0, rem)), session.timer_label);
        } else {
            shared_.update_timer_hud(false, 0, "");
        }
        shared_.publish_snapshot(snap);
    };

    log_both("[ENet] Proxy UDP aktif di 0.0.0.0:" + std::to_string(cfg_.enet_port) +
             " (usingNewPacket=" + (cfg_.using_new_packet ? "true" : "false") +
             ", slots=" + std::to_string(kServerPeerCount) + ")");
    publish_live_snapshot();

    while (!shared_.stop_requested.load()) {
        if (shared_.has_pending_ui_commands()) {
            const auto cmds = shared_.drain_ui_commands();
            ui::UiEffects ui_eff;
            for (const auto& cmd : cmds) {
                ui::apply_ui_command(cmd, session, shared_, ui_eff);
            }
            apply_ui_effects(ui_eff);
            publish_live_snapshot();
        }
        ENetEvent event{};
        bool any_event = false;
        bool queued_c2s_now = false;
        bool queued_s2c_now = false;

        // 1. Drain downstream (game client -> proxy)
        while (enet_host_service(server_host, &event, 0) > 0) {
            any_event = true;
            switch (event.type) {
                case ENET_EVENT_TYPE_CONNECT: {
                    log_both("[ENet] Klien Growtopia terhubung dari " + format_enet_ip(event.peer->address));
                    enet_peer_ping_interval(event.peer, 250);
                    enet_peer_throttle_configure(event.peer, 500, 0, 0);
                    enet_peer_timeout(event.peer, 0, ENET_PEER_TIMEOUT_MAXIMUM / 2, 0);

                    if (downstream_peer && downstream_peer != event.peer) {
                        log_both("[ENet] Memutus sesi klien lama untuk koneksi sub-server baru.");
                        downstream_peer->nonce = 0;
                        enet_peer_disconnect_now(downstream_peer, 0);
                        enet_host_flush(server_host);
                    }
                    downstream_peer = event.peer;

                    teardown_upstream_now();

                    auto target = shared_.take_or_reuse_upstream();
                    if (!target) {
                        log_both("[!] Belum ada target server upstream dari server_data.php.");
                        downstream_peer->nonce = 0;
                        enet_peer_disconnect_now(downstream_peer, 0);
                        downstream_peer = nullptr;
                        break;
                    }

                    ENetAddress up_addr{};
                    enet_address_set_host(&up_addr, ENET_ADDRESS_TYPE_IPV4, target->first.c_str());
                    up_addr.port = target->second;
                    upstream_peer = enet_host_connect(client_host, &up_addr, 2, 0);
                    if (!upstream_peer) {
                        log_both("[!] Gagal memulai koneksi ENet ke " + target->first + ":" + std::to_string(target->second));
                        downstream_peer->nonce = 0;
                        enet_peer_disconnect_now(downstream_peer, 0);
                        downstream_peer = nullptr;
                    } else {
                        shared_.set_current_upstream(target->first, target->second);
                        log_both("[ENet] Menghubungkan ke server Growtopia " + target->first + ":" +
                                 std::to_string(target->second) + "...");
                        enet_host_flush(client_host);
                    }
                    break;
                }

                case ENET_EVENT_TYPE_RECEIVE: {
                    if (event.peer != downstream_peer) {
                        enet_packet_destroy(event.packet);
                        break;
                    }
                    const auto pkt_t0 = std::chrono::steady_clock::now();

                    shared_.c2s_packets.fetch_add(1, std::memory_order_relaxed);
                    const uint64_t seq = ++packet_seq;
                    const uint8_t* raw = event.packet->data;
                    const size_t len = event.packet->dataLength;
                    const uint32_t flags = (event.packet->flags & ENET_PACKET_FLAG_RELIABLE)
                        ? ENET_PACKET_FLAG_RELIABLE
                        : 0;
                    const uint8_t chan = event.channelID;

                    const bool verbose = shared_.verbose_log.load();
                    const bool hex = shared_.hex_log.load();
                    logger.log_packet(
                        seq,
                        "C->S",
                        chan,
                        flags,
                        raw,
                        len,
                        cfg_.log_text_packets || verbose,
                        cfg_.log_variants || verbose,
                        cfg_.log_game_packets || verbose,
                        hex,
                        session.fps_boost && !verbose
                    );

                    bool swallowed = false;
                    bool force_quit = false;
                    std::optional<std::vector<uint8_t>> replacement;

                    auto msg_type = proto::read_message_type(raw, len);
                    if (msg_type && (*msg_type == proto::MessageType::GenericText ||
                                     *msg_type == proto::MessageType::GameMessage)) {
                        std::string text = proto::decode_text_payload(raw, len);
                        proto::TextParse tp(text);
                        const std::string action = tp.get("action");

                        if (action == "drop") {
                            try {
                                session.pending_drop_item_id = std::stoi(tp.get("itemID"));
                            } catch (...) {
                            }
                            if (session.visual_clothes_mode && session.pending_drop_item_id > 0 &&
                                session.visual_bp_items.count(static_cast<uint32_t>(session.pending_drop_item_id))) {
                                if (downstream_peer) {
                                    send_enet_bytes(downstream_peer, 0,
                                        proto::build_on_console_message(
                                            "`9[`#EvanProxy`9]`4 Item visual di BP tidak bisa di-drop. Gunakan Trash di BP untuk menghapusnya."),
                                        ENET_PACKET_FLAG_RELIABLE);
                                }
                                swallowed = true;
                            }
                        } else if (action == "trash") {
                            try {
                                session.pending_trash_item_id = std::stoi(tp.get("itemID"));
                            } catch (...) {
                            }
                            if (session.visual_clothes_mode && session.pending_trash_item_id > 0 &&
                                session.visual_bp_items.count(static_cast<uint32_t>(session.pending_trash_item_id))) {
                                const uint32_t vid = static_cast<uint32_t>(session.pending_trash_item_id);
                                session.visual_bp_items.erase(vid);
                                bool unequipped = false;
                                for (int s = 0; s < 10; ++s) {
                                    if (session.visual_clothes.slots[s] == vid) {
                                        session.visual_clothes.slots[s] = 0;
                                        unequipped = true;
                                    }
                                }
                                if (downstream_peer) {
                                    send_enet_bytes(downstream_peer, 0,
                                        proto::build_modify_item_inventory(vid, -1),
                                        ENET_PACKET_FLAG_RELIABLE);
                                    if (unequipped) {
                                        send_enet_bytes(downstream_peer, 0,
                                            proto::build_on_set_clothing(
                                                session.local_net_id, session.visual_clothes.slots, session.visual_clothes.skin_color),
                                            ENET_PACKET_FLAG_RELIABLE);
                                    }
                                    send_enet_bytes(downstream_peer, 0,
                                        proto::build_on_console_message(
                                            "`9[`#EvanProxy`9]`o Item visual `w" + items_db.name_or_fallback(vid) + " `odihapus dari BP."),
                                        ENET_PACKET_FLAG_RELIABLE);
                                }
                                swallowed = true;
                            }
                        }

                        if (auto act_desc = session.describe_client_text_action(tp)) {
                            session.record_action(*act_desc);
                            logger.log_action(*act_desc, session.log_actions);
                        }

                        if (swallowed) {
                            // Handled locally above (e.g. visual BP drop/trash)
                        } else if (action == "quit") {
                            force_quit = true;
                        } else if (action == "wrench" && session.wrench_mode != WrenchMode::Off) {
                            int32_t target_nid = -1;
                            try {
                                target_nid = std::stoi(tp.get("netid"));
                            } catch (...) {
                            }
                            if (target_nid >= 0 && target_nid != session.local_net_id) {
                                auto pit = session.players.find(target_nid);
                                if (pit != session.players.end()) {
                                    if (session.wrench_mode == WrenchMode::Info) {
                                        if (downstream_peer) {
                                            send_enet_bytes(downstream_peer, 0,
                                                proto::build_on_dialog_request(
                                                    ui::build_player_inspect_dialog(session, pit->second)),
                                                ENET_PACKET_FLAG_RELIABLE);
                                        }
                                    } else {
                                        const char* wcmd = (session.wrench_mode == WrenchMode::Pull) ? "pull"
                                            : ((session.wrench_mode == WrenchMode::Kick) ? "kick" : "ban");
                                        queue_to_upstream(0, proto::encode_text_packet(
                                            proto::MessageType::GenericText,
                                            "action|input\n|text|/" + std::string(wcmd) + " " + pit->second.name),
                                            ENET_PACKET_FLAG_RELIABLE);
                                        if (downstream_peer) {
                                            send_enet_bytes(downstream_peer, 0,
                                                proto::build_on_console_message(
                                                    "`9[`#EvanProxy`9]`2 Auto-" + std::string(wcmd) + ": `w" + pit->second.name),
                                                ENET_PACKET_FLAG_RELIABLE);
                                        }
                                    }
                                    swallowed = true;
                                }
                            }
                        } else if (action == "input") {
                            const std::string chat = tp.get("text");
                            ui::UiEffects eff;
                            if (ui::handle_chat_command(chat, session, shared_, eff)) {
                                apply_ui_effects(eff);
                                swallowed = true;
                            } else if (!chat.empty() && chat[0] != '/') {
                                std::string rewritten_chat = chat;
                                bool changed = false;
                                if (session.formalize_chat) {
                                    rewritten_chat = formalize_chat_text(rewritten_chat);
                                    changed = (rewritten_chat != chat);
                                }
                                if (session.chat_prefix_enabled) {
                                    rewritten_chat = "^_^ " + rewritten_chat;
                                    changed = true;
                                }
                                if (session.outgoing_evan_prefix && rewritten_chat.find("[EvanProxy]") == std::string::npos) {
                                    rewritten_chat = "[EvanProxy] " + rewritten_chat;
                                    changed = true;
                                }
                                if (changed) {
                                    replacement = proto::encode_text_packet(
                                        *msg_type, "action|input\n|text|" + rewritten_chat);
                                }
                            }
                        } else if (action == "dialog_return") {
                            if (session.vending_info && tp.get("dialog_name") == "vending" &&
                                tp.get("verify") == "1") {
                                try {
                                    int64_t bc = std::stoll(tp.get("buycount"));
                                    int64_t ep = std::stoll(tp.get("expectprice"));
                                    VendingOffer tmp;
                                    tmp.price = ep;
                                    int64_t items = 0, cost = 0;
                                    if (vending_cost(tmp, bc, items, cost)) {
                                        session.vend.active = true;
                                        session.vend.items = items;
                                        session.vend.cost = cost;
                                        session.vend.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(4);
                                    }
                                } catch (...) {
                                }
                            }
                            ui::UiEffects eff;
                            if (ui::handle_dialog_return(tp, session, shared_, eff)) {
                                apply_ui_effects(eff);
                                swallowed = true;
                            }
                        }
                    } else if (msg_type && *msg_type == proto::MessageType::GamePacket &&
                               len >= 4 + sizeof(proto::GameUpdatePacket)) {
                        proto::GameUpdatePacket gp{};
                        std::memcpy(&gp, raw + 4, sizeof(gp));
                        if (gp.type == static_cast<uint8_t>(proto::GamePacketType::SetIconState)) {
                            session.client_icon_state = gp.int_x;
                        } else if (gp.type == static_cast<uint8_t>(proto::GamePacketType::ItemActivateObjectRequest)) {
                            session.on_client_pickup_request(gp);
                        }
                        if (auto act_desc = session.describe_client_game_packet(gp, session.log_raw_movement)) {
                            session.record_action(*act_desc);
                            logger.log_action(*act_desc, session.log_actions);
                        }
                        if (session.visual_clothes_mode &&
                            gp.type == static_cast<uint8_t>(proto::GamePacketType::ItemActivateRequest) &&
                            gp.value > 0) {
                            const uint32_t item_id = static_cast<uint32_t>(gp.value);
                            const int slot = items_db.get_clothing_slot(item_id);
                            if (slot >= 0 || session.visual_bp_items.count(item_id)) {
                                swallowed = true;
                                if (slot >= 0 && session.local_net_id >= 0) {
                                    const bool removing = (session.visual_clothes.slots[slot] == item_id);
                                    session.visual_clothes.slots[slot] = removing ? 0u : item_id;
                                    if (downstream_peer) {
                                        send_enet_bytes(downstream_peer, 0,
                                            proto::build_on_set_clothing(
                                                session.local_net_id, session.visual_clothes.slots, session.visual_clothes.skin_color),
                                            ENET_PACKET_FLAG_RELIABLE);
                                        send_enet_bytes(downstream_peer, 0,
                                            proto::build_play_sfx("audio/cloth_equip.wav", 0),
                                            ENET_PACKET_FLAG_RELIABLE);
                                        send_enet_bytes(downstream_peer, 0,
                                            proto::build_on_console_message(
                                                std::string("`9[`#EvanProxy`9]`o ") +
                                                (removing ? "`4Unequipped " : "`2Equipped ") +
                                                "[" + ItemDatabase::slot_name(slot) + "]: `w" +
                                                items_db.name_or_fallback(item_id)),
                                            ENET_PACKET_FLAG_RELIABLE);
                                    }
                                } else if (downstream_peer) {
                                    send_enet_bytes(downstream_peer, 0,
                                        proto::build_on_console_message(
                                            "`9[`#EvanProxy`9]`o Item visual `w" + items_db.name_or_fallback(item_id) +
                                            " `obukan item pakaian (hanya tampilan BP)."),
                                        ENET_PACKET_FLAG_RELIABLE);
                                }
                            }
                        } else if (session.visual_clothes_mode &&
                                   gp.type == static_cast<uint8_t>(proto::GamePacketType::TileChangeRequest) &&
                                   gp.value > 0 &&
                                   session.visual_bp_items.count(static_cast<uint32_t>(gp.value))) {
                            swallowed = true;
                        }
                    }

                    if (!swallowed) {
                        std::vector<uint8_t> buf = replacement
                            ? std::move(*replacement)
                            : std::vector<uint8_t>(raw, raw + len);
                        queue_to_upstream(chan, std::move(buf), flags);
                        queued_c2s_now = true;
                    }

                    const auto pkt_t1 = std::chrono::steady_clock::now();
                    const double pkt_us = std::chrono::duration<double, std::micro>(pkt_t1 - pkt_t0).count();
                    ovh_ema_us = (ovh_ema_us <= 0.0) ? pkt_us : (ovh_ema_us * 0.85 + pkt_us * 0.15);
                    session.proxy_overhead_us = static_cast<int>(ovh_ema_us + 0.5);

                    enet_packet_destroy(event.packet);

                    if (force_quit) {
                        if (downstream_peer) {
                            enet_peer_disconnect_later(downstream_peer, 0);
                        }
                        teardown_upstream_now();
                    }
                    break;
                }

                case ENET_EVENT_TYPE_DISCONNECT: {
                    event.peer->nonce = 0;
                    if (event.peer == downstream_peer) {
                        log_both("[ENet] Klien Growtopia terputus.");
                        downstream_peer = nullptr;
                        teardown_upstream_now();
                    }
                    break;
                }

                default:
                    break;
            }
        }
        if (queued_c2s_now && upstream_peer) {
            enet_host_flush(client_host);
        }

        // Track incoming half-open ENet handshakes for diagnostics
        for (size_t i = 0; i < kServerPeerCount; ++i) {
            const ENetPeer* p = &server_host->peers[i];
            if (p->state == ENET_PEER_STATE_ACKNOWLEDGING_CONNECT) {
                if (!slot_ack_logged[i]) {
                    slot_ack_logged[i] = true;
                    log_both("[ENet] Handshake masuk dari " + format_enet_ip(p->address) +
                             " (slot " + std::to_string(i) + ")");
                }
            } else {
                slot_ack_logged[i] = false;
            }
        }

        // 2. Drain upstream (proxy -> real server) ONLY when upstream_peer exists
        if (upstream_peer) {
            while (enet_host_service(client_host, &event, 0) > 0) {
                any_event = true;
                switch (event.type) {
                    case ENET_EVENT_TYPE_CONNECT: {
                        log_both("[ENet] Terhubung ke server Growtopia " + format_enet_ip(event.peer->address));
                        enet_peer_ping_interval(event.peer, 250);
                        enet_peer_throttle_configure(event.peer, 500, 0, 0);
                        enet_peer_ping(event.peer);
                        if (event.peer->roundTripTime > 0 &&
                            event.peer->roundTripTime != ENET_PEER_DEFAULT_ROUND_TRIP_TIME) {
                            session.live_ping_ms = static_cast<int>(event.peer->roundTripTime);
                            session.ping_min_ms = session.live_ping_ms;
                            session.ping_max_ms = session.live_ping_ms;
                        }
                        for (const auto& p : pending_c2s) {
                            send_enet_bytes(upstream_peer, p.channel, p.data, p.flags);
                        }
                        pending_c2s.clear();
                        enet_host_flush(client_host);
                        break;
                    }

                    case ENET_EVENT_TYPE_RECEIVE: {
                        const auto pkt_t0 = std::chrono::steady_clock::now();
                        shared_.s2c_packets.fetch_add(1, std::memory_order_relaxed);
                        const uint64_t seq = ++packet_seq;
                        const uint8_t* raw = event.packet->data;
                        const size_t len = event.packet->dataLength;
                        const uint32_t flags = (event.packet->flags & ENET_PACKET_FLAG_RELIABLE)
                            ? ENET_PACKET_FLAG_RELIABLE
                            : 0;
                        const uint8_t chan = event.channelID;

                        const bool verbose = shared_.verbose_log.load();
                        const bool hex = shared_.hex_log.load();
                        logger.log_packet(
                            seq,
                            "S->C",
                            chan,
                            flags,
                            raw,
                            len,
                            cfg_.log_text_packets || verbose,
                            cfg_.log_variants || verbose,
                            cfg_.log_game_packets || verbose,
                            hex,
                            session.fps_boost && !verbose
                        );

                        bool forwarded = false;
                        auto msg_type = proto::read_message_type(raw, len);

                        if (msg_type && *msg_type == proto::MessageType::Track) {
                            session.on_server_track(proto::decode_text_payload(raw, len));
                        } else if (msg_type && *msg_type == proto::MessageType::GamePacket &&
                                   len >= 4 + sizeof(proto::GameUpdatePacket)) {
                            proto::GameUpdatePacket gp{};
                            std::memcpy(&gp, raw + 4, sizeof(gp));
                            const bool has_extra = ((gp.flags & proto::PACKET_FLAG_EXTENDED) != 0) &&
                                                   gp.extra_data_size > 0 &&
                                                   (4 + sizeof(gp) + gp.extra_data_size <= len);

                            if (gp.type == static_cast<uint8_t>(proto::GamePacketType::State)) {
                                session.on_server_state(gp);
                            } else if (gp.type == static_cast<uint8_t>(proto::GamePacketType::SendMapData)) {
                                session.on_enter_world_map(
                                    has_extra ? (raw + 4 + sizeof(gp)) : nullptr,
                                    has_extra ? gp.extra_data_size : 0
                                );
                                session.warp_active = false;
                                session.warp_waiting_menu = false;
                                session.warp_suppress_menu = false;
                                session.suppressed_world_menu_pkt.clear();
                                if (session.fps_boost && downstream_peer) {
                                    std::vector<uint8_t> buf(raw, raw + len);
                                    send_enet_bytes(downstream_peer, chan, buf, flags);
                                    send_enet_bytes(downstream_peer, 0,
                                                    proto::build_on_set_current_weather(0),
                                                    ENET_PACKET_FLAG_RELIABLE);
                                    forwarded = true;
                                } else if (session.weather_override && downstream_peer) {
                                    std::vector<uint8_t> buf(raw, raw + len);
                                    send_enet_bytes(downstream_peer, chan, buf, flags);
                                    send_enet_bytes(downstream_peer, 0,
                                                    proto::build_on_set_current_weather(session.weather_id),
                                                    ENET_PACKET_FLAG_RELIABLE);
                                    forwarded = true;
                                }
                            } else if ((gp.type == static_cast<uint8_t>(proto::GamePacketType::SendParticleEffect) ||
                                        gp.type == static_cast<uint8_t>(proto::GamePacketType::SendParticleEffectV2) ||
                                        gp.type == static_cast<uint8_t>(proto::GamePacketType::ItemEffect)) &&
                                       session.fps_boost) {
                                forwarded = true;
                            } else if (gp.type == static_cast<uint8_t>(proto::GamePacketType::SendInventoryState) && has_extra) {
                                session.on_server_inventory(raw + 4 + sizeof(gp), gp.extra_data_size);
                                if (session.visual_clothes_mode && !session.visual_bp_items.empty() && downstream_peer) {
                                    std::vector<uint8_t> buf(raw, raw + len);
                                    send_enet_bytes(downstream_peer, chan, buf, flags);
                                    for (uint32_t vid : session.visual_bp_items) {
                                        if (session.inventory.find(static_cast<uint16_t>(vid)) == session.inventory.end()) {
                                            send_enet_bytes(downstream_peer, 0,
                                                            proto::build_modify_item_inventory(vid, 1),
                                                            ENET_PACKET_FLAG_RELIABLE);
                                        }
                                    }
                                    forwarded = true;
                                }
                            } else if (gp.type == static_cast<uint8_t>(proto::GamePacketType::ModifyItemInventory)) {
                                session.on_server_modify_inventory(gp);
                            } else if (gp.type == static_cast<uint8_t>(proto::GamePacketType::ItemChangeObject)) {
                                const int64_t picked_gems = session.on_server_item_change_object(gp);
                                if (picked_gems > 0 && session.gems_tracker &&
                                    downstream_peer && session.local_net_id >= 0) {
                                    std::ostringstream gb;
                                    gb << "`9[`#EvanProxy`9] `2+" << format_number_commas(session.gem_pickup_burst)
                                       << " Gems `o(World: `2+" << format_number_commas(session.gems_collected_world)
                                       << " `o| Total: `5" << format_number_commas(session.gems) << " Gems`o)";
                                    send_enet_bytes(downstream_peer, 0,
                                                    proto::build_on_talk_bubble(session.local_net_id, gb.str()),
                                                    ENET_PACKET_FLAG_RELIABLE);
                                }
                            } else if (gp.type == static_cast<uint8_t>(proto::GamePacketType::SetCharacterState)) {
                                if (gp.net_id == session.local_net_id) {
                                    session.last_char_state_pkt = gp;
                                    session.has_char_state_pkt = true;
                                    const uint32_t aura = session.effective_aura_bits();
                                    if (aura != 0 && downstream_peer) {
                                        proto::GameUpdatePacket mod_gp = gp;
                                        mod_gp.value = static_cast<int32_t>(
                                            static_cast<uint32_t>(mod_gp.value) | aura);
                                        send_enet_bytes(downstream_peer, chan, proto::encode_game_packet(mod_gp), flags);
                                        forwarded = true;
                                    }
                                }
                            } else if (gp.type == static_cast<uint8_t>(proto::GamePacketType::CallFunction) && has_extra) {
                                auto vl = proto::VariantList::parse(raw + 4 + sizeof(gp), gp.extra_data_size);
                                if (vl) {
                                    const std::string fn = vl->function_name();
                                    if (fn == "OnSpawn" && vl->items.size() >= 2) {
                                        bool is_local = false;
                                        std::string spawn_str = vl->items[1].as_string();
                                        session.on_server_spawn(spawn_str, is_local);
                                        if (is_local) {
                                            shared_.set_local_net_id(session.local_net_id);
                                            const bool mod_zoom = session.unlimited_zoom;
                                            const bool mod_country = session.needs_custom_country();
                                            const bool mod_name = session.needs_custom_name();
                                            if (mod_zoom || mod_country || mod_name) {
                                                proto::TextParse sp_tp(spawn_str);
                                                if (mod_zoom) sp_tp.set("mstate", "1");
                                                if (mod_country) sp_tp.set("country", session.compose_country_state());
                                                if (mod_name) {
                                                    std::string dn = session.compose_display_name();
                                                    sp_tp.set("name", dn);
                                                    session.last_sent_display_name = dn;
                                                }
                                                vl->items[1].value = sp_tp.render();
                                                auto mod = proto::build_call_function_packet(gp.net_id, gp.value, *vl);
                                                if (downstream_peer) {
                                                    send_enet_bytes(downstream_peer, chan, mod, flags);
                                                }
                                                forwarded = true;
                                            }
                                            if (!session.welcomed_banner_sent && downstream_peer) {
                                                session.welcomed_banner_sent = true;
                                                if (!forwarded) {
                                                    std::vector<uint8_t> buf(raw, raw + len);
                                                    send_enet_bytes(downstream_peer, chan, buf, flags);
                                                    forwarded = true;
                                                }
                                                send_enet_bytes(downstream_peer, 0,
                                                    proto::build_on_console_message(
                                                        "`9[`#EvanProxy`9]`2 Aktif! Ketik `w/proxy `2untuk Dashboard, `w/clothes `2untuk Visual Baju & Search BP, `w/title `2untuk Title."),
                                                    ENET_PACKET_FLAG_RELIABLE);
                                            }
                                        }
                                    } else if (fn == "OnRemove" && vl->items.size() >= 2) {
                                        session.on_server_remove(vl->items[1].as_string());
                                    } else if (fn == "OnSetBux" && vl->items.size() >= 2) {
                                        if (auto g = vl->items[1].as_int()) {
                                            session.gems = *g;
                                        }
                                    } else if (fn == "OnConsoleMessage" && vl->items.size() >= 2) {
                                        const std::string msg = vl->items[1].as_string();
                                        session.on_server_console_message(msg);
                                        if (session.warp_suppress_menu &&
                                            msg.find("Where would you like to go?") != std::string::npos) {
                                            forwarded = true;
                                        } else {
                                            const auto now_cm = std::chrono::steady_clock::now();
                                            bool send_vend_summary = false;
                                            if (session.vend.active) {
                                                if (now_cm >= session.vend.deadline) {
                                                    session.vend.active = false;
                                                } else {
                                                    const std::string clean_cm = proto::strip_growtopia_colors(msg);
                                                    if (clean_cm.find(" bought ") != std::string::npos &&
                                                        (session.player_name.empty() ||
                                                         clean_cm.find(session.player_name) != std::string::npos)) {
                                                        session.vend.active = false;
                                                        send_vend_summary = session.vending_info;
                                                    }
                                                }
                                            }
                                            if (session.evan_branding && downstream_peer) {
                                                std::string branded = proto::apply_evan_brand_to_console_msg(msg);
                                                if (branded != msg) {
                                                    vl->items[1].value = branded;
                                                    auto mod = proto::build_call_function_packet(gp.net_id, gp.value, *vl);
                                                    send_enet_bytes(downstream_peer, chan, mod, flags);
                                                    forwarded = true;
                                                }
                                            }
                                            if (send_vend_summary && downstream_peer) {
                                                if (!forwarded) {
                                                    std::vector<uint8_t> buf(raw, raw + len);
                                                    send_enet_bytes(downstream_peer, chan, buf, flags);
                                                    forwarded = true;
                                                }
                                                const int64_t rem_stock = std::max<int64_t>(0, session.vend.stock_before - session.vend.items);
                                                const int64_t rem_wl = std::max<int64_t>(0, session.vend.wl_before - session.vend.cost);
                                                const int64_t rem_dl = rem_wl / 100;
                                                const int64_t rem_wl_part = rem_wl % 100;
                                                const std::string iname = items_db.name_or_fallback(static_cast<uint32_t>(session.vend.item_id));
                                                shared_.notify_vend_toast(rem_stock, rem_wl, iname);
                                                std::ostringstream vm;
                                                vm << "`9[`#EvanProxy`9]`2 [Vending Privat] `wBeli " << session.vend.items
                                                   << "x " << iname << " `o(-" << session.vend.cost << " WL) - `9Sisa Stok Vend: `2"
                                                   << rem_stock << " `o- `9Sisa WL Anda: `6" << rem_wl << " WL ("
                                                   << rem_dl << " DL " << rem_wl_part << " WL)";
                                                send_enet_bytes(downstream_peer, 0,
                                                    proto::build_on_console_message(vm.str()),
                                                    ENET_PACKET_FLAG_RELIABLE);
                                                if (session.local_net_id >= 0) {
                                                    std::ostringstream vb;
                                                    vb << "`9[Privat] `2Sisa Stok: `w" << rem_stock
                                                       << " `o- `9Sisa WL: `6" << rem_wl << " WL";
                                                    send_enet_bytes(downstream_peer, 0,
                                                        proto::build_on_talk_bubble(session.local_net_id, vb.str()),
                                                        ENET_PACKET_FLAG_RELIABLE);
                                                }
                                            }
                                        }
                                    } else if (fn == "OnCountryState" && gp.net_id == session.local_net_id && vl->items.size() >= 2) {
                                        session.on_server_country_state(vl->items[1].as_string());
                                        if (session.needs_custom_country()) {
                                            vl->items[1].value = session.compose_country_state();
                                            auto mod = proto::build_call_function_packet(gp.net_id, gp.value, *vl);
                                            if (downstream_peer) {
                                                send_enet_bytes(downstream_peer, chan, mod, flags);
                                            }
                                            forwarded = true;
                                        }
                                    } else if (fn == "OnNameChanged" && vl->items.size() >= 2) {
                                        const std::string extra_json = (vl->items.size() >= 3) ? vl->items[2].as_string() : std::string{};
                                        if (gp.net_id == session.local_net_id) {
                                            session.on_server_name_changed(vl->items[1].as_string(), extra_json);
                                            if (session.needs_custom_name()) {
                                                std::string dn = session.compose_display_name();
                                                vl->items[1].value = dn;
                                                session.last_sent_display_name = dn;
                                                auto mod = proto::build_call_function_packet(gp.net_id, gp.value, *vl);
                                                if (downstream_peer) {
                                                    send_enet_bytes(downstream_peer, chan, mod, flags);
                                                }
                                                forwarded = true;
                                            }
                                        } else {
                                            auto pit = session.players.find(gp.net_id);
                                            if (pit != session.players.end()) {
                                                pit->second.raw_name = vl->items[1].as_string();
                                                const std::string clean_rn = proto::strip_growtopia_colors(pit->second.raw_name);
                                                if (!clean_rn.empty()) pit->second.name = clean_rn;
                                            }
                                        }
                                    } else if (fn == "OnSetClothing" && vl->items.size() >= 5) {
                                        ClothingSet cs;
                                        extract_clothing_from_vl(*vl, cs);
                                        if (gp.net_id == session.local_net_id) {
                                            session.real_clothes = cs;
                                            session.original_skin = cs.skin_color;
                                            session.has_original_skin = true;
                                            if (session.visual_clothes_mode && downstream_peer) {
                                                send_enet_bytes(downstream_peer, chan,
                                                    proto::build_on_set_clothing(
                                                        gp.net_id, session.visual_clothes.slots, session.visual_clothes.skin_color),
                                                    flags);
                                                forwarded = true;
                                            }
                                        } else {
                                            session.remote_clothes[gp.net_id] = cs;
                                            if (session.hide_clothes || session.fps_boost) {
                                                vl->items[1] = proto::Variant::make_vec3(0.0f, 0.0f, 0.0f);
                                                vl->items[2] = proto::Variant::make_vec3(0.0f, 0.0f, 0.0f);
                                                vl->items[3] = proto::Variant::make_vec3(0.0f, 0.0f, 0.0f);
                                                auto mod = proto::build_call_function_packet(gp.net_id, gp.value, *vl);
                                                if (downstream_peer) {
                                                    send_enet_bytes(downstream_peer, chan, mod, flags);
                                                }
                                                forwarded = true;
                                            }
                                        }
                                    } else if (fn == "OnSetPos") {
                                        if (session.warp_waiting_menu) {
                                            forwarded = true;
                                        }
                                    } else if (fn == "OnClearItemTransforms") {
                                        if (session.warp_suppress_menu) {
                                            forwarded = true;
                                        }
                                    } else if ((fn == "OnFlagMay2019" || fn == "OnAction") && session.fps_boost) {
                                        forwarded = true;
                                    } else if (fn == "OnSetCurrentWeather" && session.fps_boost && vl->items.size() >= 2) {
                                        vl->items[1] = proto::Variant::make_unsigned(0u);
                                        auto mod = proto::build_call_function_packet(gp.net_id, gp.value, *vl);
                                        if (downstream_peer) {
                                            send_enet_bytes(downstream_peer, chan, mod, flags);
                                        }
                                        forwarded = true;
                                    } else if (fn == "OnTalkBubble" && vl->items.size() >= 2) {
                                        if (session.fps_hide_bubbles &&
                                            vl->items[1].as_int().value_or(-1) != session.local_net_id) {
                                            forwarded = true;
                                        } else if (session.evan_branding && vl->items.size() >= 3 && downstream_peer) {
                                            const std::string btxt = vl->items[2].as_string();
                                            if (!btxt.empty() && btxt.find("EvanProxy") == std::string::npos) {
                                                vl->items[2].value = "`9[`#EvanProxy`9]`o " + btxt;
                                                auto mod = proto::build_call_function_packet(gp.net_id, gp.value, *vl);
                                                send_enet_bytes(downstream_peer, chan, mod, flags);
                                                forwarded = true;
                                            }
                                        }
                                    } else if (fn == "OnFailedToEnterWorld") {
                                        if (session.warp_suppress_menu) {
                                            session.warp_active = false;
                                            session.warp_waiting_menu = false;
                                            session.warp_suppress_menu = false;
                                            if (!session.suppressed_world_menu_pkt.empty() && downstream_peer) {
                                                send_enet_bytes(downstream_peer, chan, session.suppressed_world_menu_pkt, flags);
                                                session.suppressed_world_menu_pkt.clear();
                                            }
                                        }
                                    } else if (fn == "OnRequestWorldSelectMenu") {
                                        session.on_leave_world();
                                        if (session.warp_suppress_menu) {
                                            session.suppressed_world_menu_pkt.assign(raw, raw + len);
                                            forwarded = true;
                                            if (session.warp_active && session.warp_waiting_menu) {
                                                session.warp_waiting_menu = false;
                                                queue_to_upstream(0, proto::encode_text_packet(
                                                    proto::MessageType::GameMessage,
                                                    build_join_request_str(session.warp_world, session.warp_door)),
                                                    ENET_PACKET_FLAG_RELIABLE);
                                                enet_host_flush(client_host);
                                            }
                                        }
                                    } else if (fn == "OnDialogRequest" && vl->items.size() >= 2) {
                                        const std::string markup = vl->items[1].as_string();
                                        const bool is_gazette =
                                            (markup.find("interface/large/news_banner.rttex") != std::string::npos ||
                                             markup.find("The Growtopia Gazette") != std::string::npos ||
                                             markup.find("end_dialog|gazette|") != std::string::npos);
                                        if (is_gazette) {
                                            session.last_news_markup = markup;
                                        }
                                        const auto now_dlg = std::chrono::steady_clock::now();
                                        if (session.auto_bgl_stage != AutoBglStage::Idle &&
                                            now_dlg >= session.auto_bgl_deadline) {
                                            session.auto_bgl_stage = AutoBglStage::Idle;
                                        }

                                        bool handled_dlg = false;
                                        if (session.auto_bgl &&
                                            markup.find("end_dialog|phonecall|") != std::string::npos) {
                                            auto tx_s = extract_embed_str(markup, "tilex");
                                            auto ty_s = extract_embed_str(markup, "tiley");
                                            auto num_s = extract_embed_str(markup, "num");

                                            if (markup.find("|3898|") != std::string::npos &&
                                                session.auto_bgl_stage == AutoBglStage::Idle) {
                                                if (!session.inventory.empty() && session.dl_count() < 100) {
                                                    if (downstream_peer) {
                                                        send_enet_bytes(downstream_peer, 0,
                                                            proto::build_on_console_message(
                                                                "`9[`#EvanProxy`9]`4 Auto-BGL:`` Butuh minimal `9100 Diamond Lock`` (punya " +
                                                                std::to_string(session.dl_count()) + " DL). Membuka Telephone normal."),
                                                            ENET_PACKET_FLAG_RELIABLE);
                                                    }
                                                } else {
                                                    const std::string tx = tx_s.value_or(std::to_string(session.tile_x));
                                                    const std::string ty = ty_s.value_or(std::to_string(session.tile_y));
                                                    try {
                                                        session.auto_bgl_tile_x = std::stoi(tx);
                                                        session.auto_bgl_tile_y = std::stoi(ty);
                                                    } catch (...) {
                                                    }
                                                    session.auto_bgl_stage = AutoBglStage::Dialled;
                                                    session.auto_bgl_deadline = now_dlg + std::chrono::seconds(5);
                                                    std::ostringstream dr;
                                                    dr << "action|dialog_return\ndialog_name|phonecall\ntilex|" << tx
                                                       << "|\ntiley|" << ty << "|\nnum|" << num_s.value_or("-2")
                                                       << "|\ndial|53785\n";
                                                    queue_to_upstream(0, proto::encode_text_packet(
                                                        proto::MessageType::GenericText, dr.str()),
                                                        ENET_PACKET_FLAG_RELIABLE);
                                                    enet_host_flush(client_host);
                                                    handled_dlg = true;
                                                    forwarded = true;
                                                }
                                            } else if (session.auto_bgl_stage == AutoBglStage::Dialled &&
                                                       markup.find("|4358|") != std::string::npos) {
                                                const std::string tx = tx_s.value_or(std::to_string(session.auto_bgl_tile_x));
                                                const std::string ty = ty_s.value_or(std::to_string(session.auto_bgl_tile_y));
                                                session.auto_bgl_stage = AutoBglStage::Buying;
                                                session.auto_bgl_deadline = now_dlg + std::chrono::seconds(5);
                                                std::ostringstream dr;
                                                dr << "action|dialog_return\ndialog_name|phonecall\ntilex|" << tx
                                                   << "|\ntiley|" << ty << "|\nnum|" << num_s.value_or("53785")
                                                   << "|\nbuttonClicked|chc5\n";
                                                queue_to_upstream(0, proto::encode_text_packet(
                                                    proto::MessageType::GenericText, dr.str()),
                                                    ENET_PACKET_FLAG_RELIABLE);
                                                enet_host_flush(client_host);
                                                handled_dlg = true;
                                                forwarded = true;
                                            } else if (session.auto_bgl_stage == AutoBglStage::Buying &&
                                                       markup.find("|7188|") != std::string::npos) {
                                                if (markup.find("add_button|chc0|") != std::string::npos) {
                                                    const std::string tx = tx_s.value_or(std::to_string(session.auto_bgl_tile_x));
                                                    const std::string ty = ty_s.value_or(std::to_string(session.auto_bgl_tile_y));
                                                    session.auto_bgl_stage = AutoBglStage::Confirming;
                                                    session.auto_bgl_deadline = now_dlg + std::chrono::seconds(5);
                                                    std::ostringstream dr;
                                                    dr << "action|dialog_return\ndialog_name|phonecall\ntilex|" << tx
                                                       << "|\ntiley|" << ty << "|\nnum|" << num_s.value_or("-34")
                                                       << "|\nbuttonClicked|chc0\n";
                                                    queue_to_upstream(0, proto::encode_text_packet(
                                                        proto::MessageType::GenericText, dr.str()),
                                                        ENET_PACKET_FLAG_RELIABLE);
                                                    enet_host_flush(client_host);
                                                } else if (markup.find("100 Diamond Lock") != std::string::npos) {
                                                    session.auto_bgl_stage = AutoBglStage::Idle;
                                                    if (downstream_peer) {
                                                        send_enet_bytes(downstream_peer, 0,
                                                            proto::build_on_console_message(
                                                                "`9[`#EvanProxy`9]`4 Auto-BGL:`` Butuh minimal `9100 Diamond Lock`` untuk tukar 1 BGL!"),
                                                            ENET_PACKET_FLAG_RELIABLE);
                                                        if (session.local_net_id >= 0) {
                                                            send_enet_bytes(downstream_peer, 0,
                                                                proto::build_on_talk_bubble(
                                                                    session.local_net_id, "`9[`#EvanProxy`9]`4 DL kurang (butuh 100 DL)!"),
                                                                ENET_PACKET_FLAG_RELIABLE);
                                                        }
                                                        send_enet_bytes(downstream_peer, 0,
                                                            proto::build_play_sfx("audio/bleep_fail.wav", 0),
                                                            ENET_PACKET_FLAG_RELIABLE);
                                                    }
                                                } else {
                                                    session.auto_bgl_stage = AutoBglStage::Idle;
                                                    if (downstream_peer) {
                                                        send_enet_bytes(downstream_peer, 0,
                                                            proto::build_on_console_message(
                                                                "`9[`#EvanProxy`9]`2 Auto-BGL Berhasil! `w100 DL -> 1 Blue Gem Lock``!"),
                                                            ENET_PACKET_FLAG_RELIABLE);
                                                        if (session.local_net_id >= 0) {
                                                            send_enet_bytes(downstream_peer, 0,
                                                                proto::build_on_talk_bubble(
                                                                    session.local_net_id, "`9[`#EvanProxy`9]`2 +1 Blue Gem Lock!"),
                                                                ENET_PACKET_FLAG_RELIABLE);
                                                        }
                                                        send_enet_bytes(downstream_peer, 0,
                                                            proto::build_play_sfx("audio/dialog_confirm.wav", 0),
                                                            ENET_PACKET_FLAG_RELIABLE);
                                                    }
                                                }
                                                handled_dlg = true;
                                                forwarded = true;
                                            } else if (session.auto_bgl_stage == AutoBglStage::Confirming) {
                                                session.auto_bgl_stage = AutoBglStage::Idle;
                                                if (downstream_peer) {
                                                    send_enet_bytes(downstream_peer, 0,
                                                        proto::build_on_console_message(
                                                            "`9[`#EvanProxy`9]`2 Auto-BGL Berhasil! `w100 DL -> 1 Blue Gem Lock``!"),
                                                        ENET_PACKET_FLAG_RELIABLE);
                                                    if (session.local_net_id >= 0) {
                                                        send_enet_bytes(downstream_peer, 0,
                                                            proto::build_on_talk_bubble(
                                                                session.local_net_id, "`9[`#EvanProxy`9]`2 +1 Blue Gem Lock!"),
                                                            ENET_PACKET_FLAG_RELIABLE);
                                                    }
                                                    send_enet_bytes(downstream_peer, 0,
                                                        proto::build_play_sfx("audio/dialog_confirm.wav", 0),
                                                        ENET_PACKET_FLAG_RELIABLE);
                                                }
                                                handled_dlg = true;
                                                forwarded = true;
                                            }
                                        }

                                        if (markup.find("end_dialog|drop_item|") != std::string::npos) {
                                            auto sync_id = extract_embed_item_id(markup);
                                            auto sync_avail = extract_drop_count(markup);
                                            if (sync_id && *sync_id > 0 && *sync_id <= 65535 &&
                                                sync_avail && *sync_avail >= 0) {
                                                session.inventory[static_cast<uint16_t>(*sync_id)] =
                                                    static_cast<uint32_t>(*sync_avail);
                                            }
                                        }

                                        if (!handled_dlg && session.active_planned_drop &&
                                            markup.find("end_dialog|drop_item|") != std::string::npos) {
                                            auto item_id = extract_embed_item_id(markup);
                                            const uint32_t target_id = session.active_planned_drop->item_id;
                                            if (!item_id || static_cast<uint32_t>(*item_id) == target_id) {
                                                uint32_t count = session.active_planned_drop->count;
                                                if (auto avail = extract_drop_count(markup); avail && *avail > 0 &&
                                                    static_cast<uint32_t>(*avail) < count) {
                                                    count = static_cast<uint32_t>(*avail);
                                                }
                                                std::ostringstream dr;
                                                dr << "action|dialog_return\ndialog_name|drop_item\nitemID|"
                                                   << target_id << "|\ncount|" << count << "\n";
                                                queue_to_upstream(0, proto::encode_text_packet(
                                                    proto::MessageType::GenericText, dr.str()),
                                                    ENET_PACKET_FLAG_RELIABLE);
                                                session.active_planned_drop.reset();
                                                session.planned_drop_next_at = now_dlg + std::chrono::milliseconds(400);
                                                if (downstream_peer) {
                                                    send_enet_bytes(downstream_peer, 0,
                                                        proto::build_on_console_message(
                                                            "`9[`#EvanProxy`9]`2 Dropped `w" + std::to_string(count) +
                                                            "x `w" + items_db.name_or_fallback(target_id)),
                                                        ENET_PACKET_FLAG_RELIABLE);
                                                }
                                                handled_dlg = true;
                                                forwarded = true;
                                            }
                                        }

                                        if (!handled_dlg) {
                                            if (auto offer = parse_vending_dialog(markup)) {
                                                session.vend.item_id = offer->item_id;
                                                session.vend.price = offer->price;
                                                session.vend.stock_before = offer->stock;
                                                session.vend.wl_before = offer->wl_have;
                                                session.vend.tilex = offer->tilex;
                                                session.vend.tiley = offer->tiley;

                                                if (session.fast_buy == 2) {
                                                    const int64_t max_b = vending_max_buy(*offer);
                                                    int64_t want = 0;
                                                    if (max_b > 0) {
                                                        if (session.fast_buy_qty <= 0) {
                                                            want = max_b;
                                                        } else if (offer->price < 0) {
                                                            const int64_t per_lock = -offer->price;
                                                            if (session.fast_buy_qty < per_lock) {
                                                                want = std::min<int64_t>(per_lock, max_b);
                                                            } else {
                                                                want = std::min<int64_t>((session.fast_buy_qty / per_lock) * per_lock, max_b);
                                                            }
                                                        } else {
                                                            want = std::min<int64_t>(session.fast_buy_qty, max_b);
                                                        }
                                                    }
                                                    if (want > 0) {
                                                        int64_t est_items = 0, est_cost = 0;
                                                        if (vending_cost(*offer, want, est_items, est_cost)) {
                                                            session.vend.active = true;
                                                            session.vend.items = est_items;
                                                            session.vend.cost = est_cost;
                                                            session.vend.deadline = now_dlg + std::chrono::seconds(4);
                                                        }
                                                        std::ostringstream vr;
                                                        vr << "action|dialog_return\ndialog_name|vending\ntilex|" << offer->tilex
                                                           << "|\ntiley|" << offer->tiley << "|\nexpectprice|" << offer->price
                                                           << "|\nexpectitem|" << offer->item_id << "|\nbuycount|" << want << "\n";
                                                        queue_to_upstream(0, proto::encode_text_packet(
                                                            proto::MessageType::GenericText, vr.str()),
                                                            ENET_PACKET_FLAG_RELIABLE);
                                                        enet_host_flush(client_host);
                                                        handled_dlg = true;
                                                        forwarded = true;
                                                    } else if (downstream_peer) {
                                                        send_enet_bytes(downstream_peer, 0,
                                                            proto::build_on_console_message(
                                                                "`9[`#EvanProxy`9]`4 FastBuy Auto: `oStok habis atau WL tidak cukup (Stok: " +
                                                                std::to_string(offer->stock) + ", WL: " + std::to_string(offer->wl_have) + ")."),
                                                            ENET_PACKET_FLAG_RELIABLE);
                                                    }
                                                } else if (session.fast_buy == 1) {
                                                    const int64_t max_b = vending_max_buy(*offer);
                                                    int64_t prefill = (session.fast_buy_qty > 0)
                                                        ? std::min<int64_t>(session.fast_buy_qty, max_b)
                                                        : (max_b > 0 ? (offer->price < 0 ? std::min<int64_t>(-offer->price, max_b) : 1) : 0);
                                                    const std::string info_line =
                                                        "`9[FastBuy Quick] `oStok: `w" + std::to_string(offer->stock) +
                                                        " `o- Maks beli: `2" + std::to_string(max_b) +
                                                        " `o- Konfirmasi otomatis dilewati";
                                                    std::string mod_mk = build_vending_buy_markup(markup, prefill, info_line);
                                                    if (session.style_all_dialogs && session.ui_theme != "classic") {
                                                        mod_mk = ui::apply_theme_to_dialog(mod_mk, session.ui_theme);
                                                    }
                                                    vl->items[1].value = mod_mk;
                                                    auto mod = proto::build_call_function_packet(gp.net_id, gp.value, *vl);
                                                    if (downstream_peer) {
                                                        send_enet_bytes(downstream_peer, chan, mod, flags);
                                                    }
                                                    handled_dlg = true;
                                                    forwarded = true;
                                                }
                                            } else if (session.fast_buy >= 1 &&
                                                       markup.find("end_dialog|vending|") != std::string::npos &&
                                                       markup.find("embed_data|verify|1") != std::string::npos) {
                                                auto tx_s = extract_embed_str(markup, "tilex");
                                                auto ty_s = extract_embed_str(markup, "tiley");
                                                auto bc_s = extract_embed_str(markup, "buycount");
                                                auto ep_s = extract_embed_str(markup, "expectprice");
                                                auto ei_s = extract_embed_str(markup, "expectitem");
                                                if (bc_s && ep_s && ei_s) {
                                                    try {
                                                        const int64_t bc = std::stoll(*bc_s);
                                                        const int64_t ep = std::stoll(*ep_s);
                                                        VendingOffer tmp;
                                                        tmp.price = ep;
                                                        int64_t items = 0, cost = 0;
                                                        if (vending_cost(tmp, bc, items, cost)) {
                                                            session.vend.active = true;
                                                            session.vend.items = items;
                                                            session.vend.cost = cost;
                                                            session.vend.deadline = now_dlg + std::chrono::seconds(4);
                                                        }
                                                    } catch (...) {
                                                    }
                                                    std::ostringstream vr;
                                                    vr << "action|dialog_return\ndialog_name|vending\ntilex|"
                                                       << tx_s.value_or(std::to_string(session.vend.tilex))
                                                       << "|\ntiley|" << ty_s.value_or(std::to_string(session.vend.tiley))
                                                       << "|\nverify|1|\nbuycount|" << *bc_s
                                                       << "|\nexpectprice|" << *ep_s
                                                       << "|\nexpectitem|" << *ei_s << "|\n";
                                                    queue_to_upstream(0, proto::encode_text_packet(
                                                        proto::MessageType::GenericText, vr.str()),
                                                        ENET_PACKET_FLAG_RELIABLE);
                                                    enet_host_flush(client_host);
                                                    handled_dlg = true;
                                                    forwarded = true;
                                                }
                                            }
                                        }

                                        if (!handled_dlg && session.fast_drop && markup.find("end_dialog|drop_item|") != std::string::npos) {
                                            auto item_id = extract_embed_item_id(markup);
                                            if (!item_id && session.pending_drop_item_id > 0) {
                                                item_id = session.pending_drop_item_id;
                                            }
                                            auto count = extract_drop_count(markup);
                                            if (item_id && count && *count > 0) {
                                                std::ostringstream dr;
                                                dr << "action|dialog_return\ndialog_name|drop_item\nitemID|"
                                                   << *item_id << "|\ncount|" << *count;
                                                queue_to_upstream(0, proto::encode_text_packet(
                                                    proto::MessageType::GenericText, dr.str()),
                                                    ENET_PACKET_FLAG_RELIABLE);
                                                if (downstream_peer) {
                                                    send_enet_bytes(downstream_peer, 0,
                                                        proto::build_on_console_message(
                                                            "`2[FastDrop] Dropped `w" + std::to_string(*count) +
                                                            "x `oitem #" + std::to_string(*item_id)),
                                                        ENET_PACKET_FLAG_RELIABLE);
                                                }
                                                forwarded = true;
                                            }
                                        } else if (!handled_dlg && session.fast_trash && markup.find("end_dialog|trash_item|") != std::string::npos) {
                                            auto item_id = extract_embed_item_id(markup);
                                            if (!item_id && session.pending_trash_item_id > 0) {
                                                item_id = session.pending_trash_item_id;
                                            }
                                            auto count = extract_trash_owned_count(markup);
                                            if (item_id && count && *count > 0) {
                                                std::ostringstream dr;
                                                dr << "action|dialog_return\ndialog_name|trash_item\nitemID|"
                                                   << *item_id << "|\ncount|" << *count;
                                                queue_to_upstream(0, proto::encode_text_packet(
                                                    proto::MessageType::GenericText, dr.str()),
                                                    ENET_PACKET_FLAG_RELIABLE);
                                                if (downstream_peer) {
                                                    send_enet_bytes(downstream_peer, 0,
                                                        proto::build_on_console_message(
                                                            "`2[FastTrash] Trashed `w" + std::to_string(*count) +
                                                            "x `oitem #" + std::to_string(*item_id)),
                                                        ENET_PACKET_FLAG_RELIABLE);
                                                }
                                                forwarded = true;
                                            }
                                        } else if (!handled_dlg && session.custom_banner && is_gazette) {
                                            vl->items[1].value = ui::build_changelog_dialog(session);
                                            auto mod = proto::build_call_function_packet(gp.net_id, gp.value, *vl);
                                            if (downstream_peer) {
                                                send_enet_bytes(downstream_peer, chan, mod, flags);
                                            }
                                            forwarded = true;
                                        } else if (!handled_dlg && session.style_all_dialogs && session.ui_theme != "classic") {
                                            vl->items[1].value = ui::apply_theme_to_dialog(markup, session.ui_theme);
                                            auto mod = proto::build_call_function_packet(gp.net_id, gp.value, *vl);
                                            if (downstream_peer) {
                                                send_enet_bytes(downstream_peer, chan, mod, flags);
                                            }
                                            forwarded = true;
                                        }
                                    } else if (fn == "OnSendToServer") {
                                        if (auto redir = proto::try_rewrite_on_send_to_server(
                                                raw, len, cfg_.local_ip, cfg_.enet_port)) {
                                            session.warp_active = false;
                                            session.warp_waiting_menu = false;
                                            session.warp_suppress_menu = false;
                                            session.suppressed_world_menu_pkt.clear();
                                            shared_.set_pending_upstream(redir->real_ip, redir->real_port);
                                            log_both("[Redirect] Sub-server -> " + redir->real_ip + ":" +
                                                     std::to_string(redir->real_port) + " (rewritten ke " +
                                                     cfg_.local_ip + ":" + std::to_string(cfg_.enet_port) + ")");
                                            if (downstream_peer) {
                                                send_enet_bytes(downstream_peer, chan, redir->packet, flags);
                                                enet_host_flush(server_host);
                                            }
                                            forwarded = true;
                                        }
                                    }
                                }
                            }
                        }

                        if (!forwarded && downstream_peer) {
                            std::vector<uint8_t> buf(raw, raw + len);
                            send_enet_bytes(downstream_peer, chan, buf, flags);
                            queued_s2c_now = true;
                        } else if (forwarded && downstream_peer) {
                            queued_s2c_now = true;
                        }

                        const auto pkt_t1 = std::chrono::steady_clock::now();
                        const double pkt_us = std::chrono::duration<double, std::micro>(pkt_t1 - pkt_t0).count();
                        ovh_ema_us = (ovh_ema_us <= 0.0) ? pkt_us : (ovh_ema_us * 0.85 + pkt_us * 0.15);
                        session.proxy_overhead_us = static_cast<int>(ovh_ema_us + 0.5);

                        enet_packet_destroy(event.packet);
                        break;
                    }

                    case ENET_EVENT_TYPE_DISCONNECT: {
                        event.peer->nonce = 0;
                        if (event.peer == upstream_peer) {
                            log_both("[ENet] Server Growtopia memutus koneksi.");
                            upstream_peer = nullptr;
                            pending_c2s.clear();
                            session.live_ping_ms = 0;
                            session.ping_min_ms = 0;
                            session.ping_max_ms = 0;
                            session.ping_jitter_ms = 0;
                            if (downstream_peer) {
                                enet_peer_disconnect_later(downstream_peer, 0);
                                enet_host_flush(server_host);
                            }
                        }
                        break;
                    }

                    default:
                        break;
                }
            }
            if (queued_s2c_now && downstream_peer) {
                enet_host_flush(server_host);
            }
        }

        // Check warp fallback, periodic FPS/ping badge update, & countdown timer
        const auto now = std::chrono::steady_clock::now();
        if (session.warp_active && session.warp_waiting_menu && now >= session.warp_deadline) {
            session.warp_waiting_menu = false;
            queue_to_upstream(0, proto::encode_text_packet(
                proto::MessageType::GameMessage,
                build_join_request_str(session.warp_world, session.warp_door)),
                ENET_PACKET_FLAG_RELIABLE);
        }
        if (session.warp_suppress_menu && now >= session.warp_suppress_deadline) {
            session.warp_suppress_menu = false;
            session.warp_active = false;
            if (!session.suppressed_world_menu_pkt.empty() && downstream_peer) {
                send_enet_bytes(downstream_peer, 0, session.suppressed_world_menu_pkt, ENET_PACKET_FLAG_RELIABLE);
                session.suppressed_world_menu_pkt.clear();
            }
        }
        if (session.active_planned_drop && now >= session.active_drop_deadline) {
            session.active_planned_drop.reset();
        }
        if (!session.active_planned_drop && !session.planned_drops.empty() &&
            now >= session.planned_drop_next_at &&
            upstream_peer && upstream_peer->state == ENET_PEER_STATE_CONNECTED) {
            PlannedDrop next = session.planned_drops.front();
            session.planned_drops.pop_front();
            if (next.activate) {
                proto::GameUpdatePacket gp{};
                gp.type = static_cast<uint8_t>(proto::GamePacketType::ItemActivateRequest);
                gp.value = static_cast<int32_t>(next.item_id);
                queue_to_upstream(0, proto::encode_game_packet(gp), ENET_PACKET_FLAG_RELIABLE);
                enet_host_flush(client_host);
                session.planned_drop_next_at = now + std::chrono::milliseconds(450);
            } else {
                session.active_planned_drop = next;
                session.active_drop_deadline = now + std::chrono::seconds(3);
                queue_to_upstream(0, build_drop_request_packet(next.item_id), ENET_PACKET_FLAG_RELIABLE);
                enet_host_flush(client_host);
            }
        }

        if (now - last_hotkey_tick >= std::chrono::milliseconds(25)) {
            last_hotkey_tick = now;
            if (session.hk_capture_slot >= 0) {
                if (now >= session.hk_capture_deadline) {
                    session.hk_capture_slot = -1;
                    cap_initialized = false;
                    cap_pending_mod_vk = 0;
                    cap_mod_combo_used = false;
                    if (downstream_peer) {
                        send_enet_bytes(downstream_peer, 0,
                            proto::build_on_console_message("`9[`#EvanProxy`9]`4 Rekam tombol dibatalkan (timeout)."),
                            ENET_PACKET_FLAG_RELIABLE);
                    }
                } else if (downstream_peer && is_growtopia_foreground()) {
                    const auto& cap_vks = hotkey_capture_vks();
                    if (!cap_initialized) {
                        prev_cap_down.fill(false);
                        prev_cap_down[VK_ESCAPE] = (GetAsyncKeyState(VK_ESCAPE) & 0x8000) != 0;
                        for (int mvk : {VK_CONTROL, VK_MENU, VK_SHIFT}) {
                            prev_cap_down[static_cast<size_t>(mvk)] = (GetAsyncKeyState(mvk) & 0x8000) != 0;
                        }
                        for (int vk : cap_vks) {
                            if (vk >= 0 && vk < 256) {
                                prev_cap_down[static_cast<size_t>(vk)] = (GetAsyncKeyState(vk) & 0x8000) != 0;
                            }
                        }
                        cap_pending_mod_vk = 0;
                        cap_mod_combo_used = false;
                        cap_initialized = true;
                    } else {
                        const bool esc_down = (GetAsyncKeyState(VK_ESCAPE) & 0x8000) != 0;
                        if (esc_down && !prev_cap_down[VK_ESCAPE]) {
                            const int slot = session.hk_capture_slot;
                            session.hk_capture_slot = -1;
                            cap_initialized = false;
                            cap_pending_mod_vk = 0;
                            cap_mod_combo_used = false;
                            send_enet_bytes(downstream_peer, 0,
                                proto::build_on_dialog_request(ui::build_hotkey_edit_dialog(session, slot)),
                                ENET_PACKET_FLAG_RELIABLE);
                        } else {
                            prev_cap_down[VK_ESCAPE] = esc_down;
                            bool recorded_now = false;
                            for (int vk : cap_vks) {
                                if (vk < 0 || vk >= 256) continue;
                                const bool down = (GetAsyncKeyState(vk) & 0x8000) != 0;
                                if (down && !prev_cap_down[static_cast<size_t>(vk)]) {
                                    HotkeySpec spec;
                                    spec.vk = vk;
                                    spec.ctrl = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
                                    spec.alt = (GetAsyncKeyState(VK_MENU) & 0x8000) != 0;
                                    spec.shift = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
                                    ui::UiEffects cap_eff;
                                    ui::hotkey_capture_finish(session, format_hotkey(spec), cap_eff);
                                    apply_ui_effects(cap_eff);
                                    cap_initialized = false;
                                    cap_pending_mod_vk = 0;
                                    cap_mod_combo_used = false;
                                    prev_hk_down.fill(false);
                                    hk_mod_dirty.fill(false);
                                    recorded_now = true;
                                    break;
                                }
                                prev_cap_down[static_cast<size_t>(vk)] = down;
                            }
                            if (!recorded_now) {
                                for (int mvk : {VK_CONTROL, VK_MENU, VK_SHIFT}) {
                                    const bool mdown = (GetAsyncKeyState(mvk) & 0x8000) != 0;
                                    if (mdown && !prev_cap_down[static_cast<size_t>(mvk)]) {
                                        if (cap_pending_mod_vk == 0) {
                                            cap_pending_mod_vk = mvk;
                                            cap_mod_combo_used = false;
                                        } else {
                                            cap_mod_combo_used = true;
                                        }
                                    } else if (!mdown && prev_cap_down[static_cast<size_t>(mvk)] &&
                                               cap_pending_mod_vk == mvk) {
                                        if (!cap_mod_combo_used) {
                                            HotkeySpec spec;
                                            spec.vk = mvk;
                                            ui::UiEffects cap_eff;
                                            ui::hotkey_capture_finish(session, format_hotkey(spec), cap_eff);
                                            apply_ui_effects(cap_eff);
                                            cap_initialized = false;
                                            prev_hk_down.fill(false);
                                            hk_mod_dirty.fill(false);
                                            cap_pending_mod_vk = 0;
                                            break;
                                        }
                                        cap_pending_mod_vk = 0;
                                        cap_mod_combo_used = false;
                                    }
                                    prev_cap_down[static_cast<size_t>(mvk)] = mdown;
                                }
                            }
                        }
                    }
                }
            } else {
                cap_initialized = false;
                cap_pending_mod_vk = 0;
                cap_mod_combo_used = false;
                if (session.hotkeys_enabled && downstream_peer && session.in_world && is_growtopia_foreground()) {
                    const bool ctrl_now = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
                    const bool alt_now = (GetAsyncKeyState(VK_MENU) & 0x8000) != 0;
                    const bool shift_now = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;

                    bool has_ctrl_combo = false;
                    bool has_alt_combo = false;
                    bool has_shift_combo = false;
                    std::array<std::optional<HotkeySpec>, kHotkeySlots> parsed_hk;
                    for (size_t i = 0; i < session.hotkeys.size() && i < kHotkeySlots; ++i) {
                        if (session.hotkeys[i].command.empty()) continue;
                        parsed_hk[i] = parse_hotkey(session.hotkeys[i].key);
                        if (parsed_hk[i] && !is_modifier_vk(parsed_hk[i]->vk)) {
                            if (parsed_hk[i]->ctrl) has_ctrl_combo = true;
                            if (parsed_hk[i]->alt) has_alt_combo = true;
                            if (parsed_hk[i]->shift) has_shift_combo = true;
                        }
                    }

                    bool any_other_key_down = false;
                    if (has_ctrl_combo || has_alt_combo || has_shift_combo) {
                        for (int vk : hotkey_capture_vks()) {
                            if ((GetAsyncKeyState(vk) & 0x8000) != 0) {
                                any_other_key_down = true;
                                break;
                            }
                        }
                    }

                    for (size_t i = 0; i < session.hotkeys.size() && i < kHotkeySlots; ++i) {
                        const auto& spec = parsed_hk[i];
                        if (!spec) {
                            prev_hk_down[i] = false;
                            hk_mod_dirty[i] = false;
                            continue;
                        }
                        if (is_modifier_vk(spec->vk)) {
                            const int canon = canonical_modifier_vk(spec->vk);
                            const bool is_ctrl_key = (canon == 0x11);
                            const bool is_alt_key = (canon == 0x12);
                            const bool is_shift_key = (canon == 0x10);
                            const bool self_down = (GetAsyncKeyState(spec->vk) & 0x8000) != 0;
                            const bool other_mods_ok =
                                (is_ctrl_key || ctrl_now == spec->ctrl) &&
                                (is_alt_key || alt_now == spec->alt) &&
                                (is_shift_key || shift_now == spec->shift);
                            const bool held_ok = self_down && other_mods_ok;
                            const bool shares_combo =
                                (is_ctrl_key && has_ctrl_combo) ||
                                (is_alt_key && has_alt_combo) ||
                                (is_shift_key && has_shift_combo);

                            if (shares_combo) {
                                if (held_ok) {
                                    if (!prev_hk_down[i]) hk_mod_dirty[i] = any_other_key_down;
                                    else if (any_other_key_down) hk_mod_dirty[i] = true;
                                } else if (prev_hk_down[i] && !hk_mod_dirty[i] && session.client_icon_state == 0) {
                                    ui::UiEffects hk_eff;
                                    ui::run_hotkey_command(session.hotkeys[i].command, session, shared_, hk_eff);
                                    apply_ui_effects(hk_eff);
                                    shared_.notify_hotkey_toast(session.hotkeys[i].key, session.hotkeys[i].command);
                                    shared_.push_console_line(LogTag::Action, "HOTKEY",
                                                              session.hotkeys[i].key + " ran " + session.hotkeys[i].command);
                                    hk_mod_dirty[i] = false;
                                } else if (!held_ok) {
                                    hk_mod_dirty[i] = false;
                                }
                            } else {
                                if (held_ok && !prev_hk_down[i] && session.client_icon_state == 0) {
                                    ui::UiEffects hk_eff;
                                    ui::run_hotkey_command(session.hotkeys[i].command, session, shared_, hk_eff);
                                    apply_ui_effects(hk_eff);
                                    shared_.notify_hotkey_toast(session.hotkeys[i].key, session.hotkeys[i].command);
                                    shared_.push_console_line(LogTag::Action, "HOTKEY",
                                                              session.hotkeys[i].key + " ran " + session.hotkeys[i].command);
                                }
                            }
                            prev_hk_down[i] = held_ok;
                        } else {
                            const bool is_bare_typing_key =
                                !spec->ctrl && !spec->alt && !(spec->vk >= 0x70 && spec->vk <= 0x7B);
                            const bool key_down =
                                (GetAsyncKeyState(spec->vk) & 0x8000) != 0 &&
                                ctrl_now == spec->ctrl &&
                                alt_now == spec->alt &&
                                shift_now == spec->shift;
                            if (key_down && !prev_hk_down[i]) {
                                if (!(is_bare_typing_key && session.client_icon_state != 0)) {
                                    ui::UiEffects hk_eff;
                                    ui::run_hotkey_command(session.hotkeys[i].command, session, shared_, hk_eff);
                                    apply_ui_effects(hk_eff);
                                    shared_.notify_hotkey_toast(session.hotkeys[i].key, session.hotkeys[i].command);
                                    shared_.push_console_line(LogTag::Action, "HOTKEY",
                                                              session.hotkeys[i].key + " ran " + session.hotkeys[i].command);
                                }
                            }
                            prev_hk_down[i] = key_down;
                        }
                    }
                } else {
                    prev_hk_down.fill(false);
                    hk_mod_dirty.fill(false);
                }
            }
        }

        if (now - last_ping_tick >= std::chrono::milliseconds(250)) {
            last_ping_tick = now;
            if (upstream_peer && upstream_peer->state == ENET_PEER_STATE_CONNECTED) {
                const uint32_t rtt_ewma = upstream_peer->roundTripTime;
                const uint32_t rtt_recent = upstream_peer->lastRoundTripTime;
                const uint32_t cli_rtt =
                    (downstream_peer &&
                     downstream_peer->state == ENET_PEER_STATE_CONNECTED &&
                     downstream_peer->lastRoundTripTime < 50u)
                        ? downstream_peer->lastRoundTripTime
                        : 0u;
                const uint32_t base_rtt =
                    (rtt_recent > 0 && rtt_recent < 5000 && rtt_recent != ENET_PEER_DEFAULT_ROUND_TRIP_TIME)
                    ? rtt_recent
                    : rtt_ewma;
                const int live = static_cast<int>(base_rtt) + static_cast<int>(cli_rtt);
                session.live_ping_ms = live;
                session.ping_jitter_ms = static_cast<int>(upstream_peer->roundTripTimeVariance);
                if (live > 0) {
                    if (session.ping_min_ms == 0 || live < session.ping_min_ms) session.ping_min_ms = live;
                    if (live > session.ping_max_ms) session.ping_max_ms = live;
                }
            } else {
                session.live_ping_ms = 0;
                session.ping_jitter_ms = 0;
            }
        }

        const bool anim_due = (now - last_anim_tick >= std::chrono::milliseconds(700));
        if (anim_due) {
            last_anim_tick = now;
            if (session.needs_animated_name()) {
                ++session.rainbow_step;
            }
        }
        if ((session.fps_show_name || session.needs_animated_name()) &&
            session.in_world && session.local_net_id >= 0 && downstream_peer) {
            const std::string composed = session.compose_display_name();
            if (composed != session.last_sent_display_name &&
                (anim_due || now - last_ping_name_push >= std::chrono::milliseconds(350))) {
                last_ping_name_push = now;
                send_enet_bytes(
                    downstream_peer,
                    0,
                    proto::build_on_name_changed(session.local_net_id, composed, session.server_name_extra_json),
                    ENET_PACKET_FLAG_RELIABLE
                );
                enet_host_flush(server_host);
                session.last_sent_display_name = composed;
            }
        }
        if (session.timer_active && now >= session.timer_end) {
            session.timer_active = false;
            if (downstream_peer) {
                send_enet_bytes(downstream_peer, 0,
                                proto::build_on_text_overlay("`9[`#EvanProxy`9]`2 Timer selesai (" + session.timer_label + ")!"),
                                ENET_PACKET_FLAG_RELIABLE);
                send_enet_bytes(downstream_peer, 0,
                                proto::build_on_console_message("`9[`#EvanProxy`9]`2 Pengingat " + session.timer_label + " selesai!"),
                                ENET_PACKET_FLAG_RELIABLE);
                send_enet_bytes(downstream_peer, 0,
                                proto::build_play_sfx("audio/door_open.wav", 0),
                                ENET_PACKET_FLAG_RELIABLE);
            }
        }
        if (now - last_fps_tick >= std::chrono::milliseconds(500)) {
            last_fps_tick = now;
            session.live_fps = fps_sampler.sample_fps();
        }
        if (now - last_snapshot_tick >= std::chrono::milliseconds(100)) {
            last_snapshot_tick = now;
            publish_live_snapshot();
        }

        enet_host_flush(server_host);
        if (upstream_peer) {
            enet_host_flush(client_host);
        }
        if (!any_event) {
            fd_set rfds;
            FD_ZERO(&rfds);
            bool has_sock = false;
            if (server_host->socket != ENET_SOCKET_NULL) {
                FD_SET(static_cast<SOCKET>(server_host->socket), &rfds);
                has_sock = true;
            }
            if (upstream_peer && client_host->socket != ENET_SOCKET_NULL) {
                FD_SET(static_cast<SOCKET>(client_host->socket), &rfds);
                has_sock = true;
            }
            if (has_sock) {
                timeval tv{0, 1000};
                select(0, &rfds, nullptr, nullptr, &tv);
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
    }

    teardown_upstream_now();
    if (downstream_peer) {
        downstream_peer->nonce = 0;
        enet_peer_disconnect_now(downstream_peer, 0);
        enet_host_flush(server_host);
    }

    enet_host_destroy(client_host);
    enet_host_destroy(server_host);
    return true;
}

} // namespace evan
