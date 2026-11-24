#include "proxy_controller.hpp"

#include "banner.hpp"
#include "session.hpp"
#include "ui_menu.hpp"

#include <chrono>
#include <iostream>

namespace evan {

namespace {

bool is_offline_state_command(const std::string& raw) {
    if (raw.empty() || raw[0] != '/') return false;
    std::string cmd = raw;
    size_t sp = cmd.find(' ');
    if (sp != std::string::npos) cmd = cmd.substr(0, sp);
    for (char& c : cmd) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return cmd == "/evantag" || cmd == "/branding" || cmd == "/evanchat" ||
           cmd == "/fps" || cmd == "/fpsboost" || cmd == "/vendinfo" ||
           cmd == "/autobgl" || cmd == "/change" || cmd == "/gems" ||
           cmd == "/hotkey" || cmd == "/hotkeys" ||
           cmd == "/fastdrop" || cmd == "/fasttrash" || cmd == "/rainbow" ||
           cmd == "/weather" || cmd == "/hideclothes" || cmd == "/title" || cmd == "/tittle" ||
           cmd == "/banner" || cmd == "/hud" || cmd == "/zoom" ||
           cmd == "/fastbuy" || cmd == "/fb" ||
           cmd == "/paction" || cmd == "/pmove" || cmd == "/plog" || cmd == "/phex";
}

} // namespace

ProxyController::ProxyController(Options opts)
    : opts_(std::move(opts)) {
    if (!opts_.config_path.empty()) {
        cfg_ = load_or_create_config(opts_.config_path);
    }
    if (opts_.no_hosts_override) {
        cfg_.manage_hosts = false;
    }

    if (!opts_.skip_os_hosts_and_ca && !opts_.exe_dir.empty()) {
        const auto br = banner::sync_banners_to_growtopia(opts_.exe_dir);
        if (br.installed_count > 0) {
            shared_.push_console_line(
                LogTag::Ok,
                "OK",
                "Banner assets ready (" + std::to_string(br.installed_count) + " files)");
        }
    }

    if (!opts_.cert_dir.empty()) {
        certs_ready_ = cert::ensure_certs(opts_.cert_dir, cfg_.server_data_hosts, certs_, cert_init_err_);
    }

    if (!opts_.skip_os_hosts_and_ca) {
        ca_installed_ = cert::is_ca_trusted_in_user_root();
    } else {
        ca_installed_ = certs_ready_;
    }

    if (items_db_.load_default_cache()) {
        shared_.push_console_line(
            LogTag::Ok,
            "OK",
            "Loaded " + std::to_string(items_db_.size()) + " items from items.dat");
    }

    shared_.push_console_line(LogTag::Info, "INFO", "Proxy is stopped. Press Start to begin.");
}

ProxyController::~ProxyController() {
    stop();
}

bool ProxyController::start(std::string& err, bool& out_port_conflict, bool& out_needs_admin) {
    out_port_conflict = false;
    out_needs_admin = false;
    err.clear();

    if (running_.load(std::memory_order_acquire)) {
        return true;
    }

    std::unique_lock<std::mutex> lk(mu_);
    if (!opts_.config_path.empty()) {
        cfg_ = load_or_create_config(opts_.config_path);
        if (opts_.no_hosts_override) {
            cfg_.manage_hosts = false;
        }
    }

    if (!certs_ready_ && !opts_.cert_dir.empty()) {
        certs_ready_ = cert::ensure_certs(opts_.cert_dir, cfg_.server_data_hosts, certs_, cert_init_err_);
    }
    if (!certs_ready_) {
        err = cert_init_err_.empty() ? "Failed to prepare TLS certificates" : cert_init_err_;
        last_error_ = err;
        port_conflict_.store(false);
        shared_.push_console_line(LogTag::Error, "ERROR", err);
        return false;
    }

    if (!opts_.skip_os_hosts_and_ca) {
        ca_installed_ = cert::is_ca_trusted_in_user_root();
        if (cfg_.manage_hosts && !hosts::is_admin()) {
            out_needs_admin = true;
            err = "Administrator privileges are required to edit the Windows hosts file.";
            last_error_ = err;
            shared_.push_console_line(LogTag::Warn, "WARN", err);
            return false;
        }
    }

    last_error_.clear();
    port_conflict_.store(false);
    shared_.reset_for_start();

    if (!opts_.skip_os_hosts_and_ca && cfg_.manage_hosts) {
        std::string hosts_err;
        if (!hosts::install_hosts(cfg_.local_ip, hosts_err)) {
            err = hosts_err;
            last_error_ = err;
            shared_.push_console_line(LogTag::Error, "ERROR", "Hosts error: " + err);
            return false;
        }
        hosts_guard_.set_active(true);
        hosts_active_ = true;
        shared_.push_console_line(LogTag::Ok, "OK", "Hosts file backed up and updated");
    } else {
        hosts_active_ = false;
        shared_.push_console_line(LogTag::Ok, "OK", "Hosts file left untouched (--no-hosts)");
    }

    if (ca_installed_) {
        shared_.push_console_line(LogTag::Ok, "OK", "Local root CA loaded");
    } else {
        shared_.push_console_line(LogTag::Warn, "WARN", "Local root CA missing, HTTPS bridge may fail");
    }

    active_run_cfg_ = cfg_;
    auto bridge = std::make_unique<HttpBridge>(active_run_cfg_, shared_, certs_);
    std::string http_err;
    if (!bridge->start(http_err)) {
        const bool is_conflict = bridge->last_start_port_in_use();
        out_port_conflict = is_conflict;
        port_conflict_.store(is_conflict);
        err = http_err;
        last_error_ = err;
        hosts_guard_.release();
        hosts_active_ = false;

        if (is_conflict) {
            shared_.push_console_line(
                LogTag::Error,
                "ERROR",
                "Could not listen on :" + std::to_string(active_run_cfg_.http_port) + ", port is already in use");
            shared_.push_console_line(
                LogTag::Info,
                "INFO",
                "Proxy is stopped. Free the port, then press Start.");
        } else {
            shared_.push_console_line(LogTag::Error, "ERROR", err);
        }
        return false;
    }

    const uint16_t bound_http = bridge->bound_port();
    http_bridge_ = std::move(bridge);
    http_running_ = true;
    shared_.push_console_line(LogTag::Ok, "OK", "HTTPS bridge listening on :" + std::to_string(bound_http));

    auto enet_ready = std::make_shared<std::atomic<int>>(0); // 0=starting, 1=running, -1=failed
    auto enet_err_ptr = std::make_shared<std::string>();
    const auto log_dir = opts_.log_dir;
    const auto cfg_path = opts_.config_path;
    const auto worlds_path = opts_.worlds_path;

    enet_thread_ = std::thread([this, enet_ready, enet_err_ptr, log_dir, cfg_path, worlds_path]() {
        EnetProxy enet_proxy(active_run_cfg_, shared_, log_dir, cfg_path, worlds_path);
        std::string run_err;
        // Wait for ENetProxy::run to either succeed or fail on early bind; publish_live_snapshot runs once bound.
        const bool ok = enet_proxy.run(run_err);
        if (!ok && enet_ready->load() == 0) {
            *enet_err_ptr = run_err;
            enet_ready->store(-1);
        } else if (!ok) {
            shared_.push_console_line(LogTag::Error, "ERROR", "ENet stopped: " + run_err);
        }
    });

    // Wait briefly (up to 600ms) for ENet UDP host creation or failure
    for (int i = 0; i < 60; ++i) {
        if (enet_ready->load() < 0) {
            break;
        }
        if (shared_.get_snapshot().enet_running) {
            enet_ready->store(1);
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    if (enet_ready->load() < 0) {
        err = enet_err_ptr->empty() ? "ENet UDP bridge failed to start" : *enet_err_ptr;
        last_error_ = err;
        shared_.stop_requested.store(true);
        auto t = std::move(enet_thread_);
        auto b = std::move(http_bridge_);
        http_running_ = false;
        enet_running_ = false;
        hosts_guard_.release();
        hosts_active_ = false;
        lk.unlock();
        if (t.joinable()) t.join();
        if (b) b->stop();
        shared_.push_console_line(LogTag::Error, "ERROR", err);
        return false;
    }

    enet_running_ = true;
    running_.store(true, std::memory_order_release);
    shared_.push_console_line(
        LogTag::Ok,
        "OK",
        "ENet UDP bridge listening on :" + std::to_string(active_run_cfg_.enet_port));
    shared_.push_console_line(LogTag::Info, "INFO", "Waiting for Growtopia to connect...");
    return true;
}

void ProxyController::stop() {
    std::unique_ptr<HttpBridge> bridge_to_stop;
    std::thread thread_to_join;
    bool was_running = false;

    {
        std::lock_guard<std::mutex> lk(mu_);
        was_running = running_.exchange(false, std::memory_order_release) ||
                      http_bridge_ != nullptr ||
                      enet_thread_.joinable();
        shared_.stop_requested.store(true);
        bridge_to_stop = std::move(http_bridge_);
        thread_to_join = std::move(enet_thread_);
        http_running_ = false;
        enet_running_ = false;
    }

    if (thread_to_join.joinable()) {
        thread_to_join.join();
    }
    if (bridge_to_stop) {
        bridge_to_stop->stop();
    }

    std::lock_guard<std::mutex> lk(mu_);
    hosts_guard_.release();
    hosts_active_ = false;
    sync_stopped_config_locked();
    if (was_running) {
        shared_.push_console_line(LogTag::Info, "INFO", "Proxy is stopped. Press Start to begin.");
    }
}

bool ProxyController::is_ca_installed() const {
    if (opts_.skip_os_hosts_and_ca) {
        return ca_installed_;
    }
    return cert::is_ca_trusted_in_user_root();
}

bool ProxyController::install_ca(std::string& err) {
    std::lock_guard<std::mutex> lk(mu_);
    if (!certs_ready_ && !opts_.cert_dir.empty()) {
        certs_ready_ = cert::ensure_certs(opts_.cert_dir, cfg_.server_data_hosts, certs_, cert_init_err_);
    }
    if (!certs_ready_) {
        err = cert_init_err_.empty() ? "Certificates not initialized" : cert_init_err_;
        shared_.push_console_line(LogTag::Error, "ERROR", err);
        return false;
    }
    if (opts_.skip_os_hosts_and_ca) {
        ca_installed_ = true;
        return true;
    }
    if (!cert::install_ca_user_root(certs_.ca_cert, err)) {
        shared_.push_console_line(LogTag::Error, "ERROR", "Install CA failed: " + err);
        return false;
    }
    ca_installed_ = cert::is_ca_trusted_in_user_root();
    shared_.push_console_line(LogTag::Ok, "OK", "Root CA installed in CurrentUser store");
    return true;
}

bool ProxyController::uninstall_ca(std::string& err) {
    std::lock_guard<std::mutex> lk(mu_);
    if (opts_.skip_os_hosts_and_ca) {
        ca_installed_ = false;
        return true;
    }
    if (!cert::uninstall_ca_user_root(err)) {
        shared_.push_console_line(LogTag::Error, "ERROR", "Uninstall CA failed: " + err);
        return false;
    }
    ca_installed_ = cert::is_ca_trusted_in_user_root();
    shared_.push_console_line(LogTag::Info, "INFO", "Root CA uninstalled from CurrentUser store");
    return true;
}

bool ProxyController::set_manage_hosts(bool enabled) {
    std::lock_guard<std::mutex> lk(mu_);
    opts_.no_hosts_override = false;
    cfg_.manage_hosts = enabled;
    active_run_cfg_.manage_hosts = enabled;
    if (!opts_.config_path.empty()) {
        save_config(opts_.config_path, cfg_);
    }
    shared_.push_console_line(
        LogTag::Info,
        "INFO",
        enabled ? "Hosts file editing enabled (Default)" : "Hosts file editing disabled (--no-hosts)");
    return true;
}

bool ProxyController::clean_leftover_hosts(std::string& err, bool& out_needs_admin) {
    out_needs_admin = false;
    if (opts_.skip_os_hosts_and_ca) {
        return true;
    }
    if (!hosts::is_admin()) {
        out_needs_admin = true;
        err = "Administrator privileges required to clean Windows hosts file.";
        shared_.push_console_line(LogTag::Warn, "WARN", err);
        return false;
    }
    if (!hosts::uninstall_hosts(err)) {
        shared_.push_console_line(LogTag::Error, "ERROR", "Clean hosts failed: " + err);
        return false;
    }
    std::lock_guard<std::mutex> lk(mu_);
    hosts_guard_.set_active(false);
    hosts_active_ = false;
    shared_.push_console_line(LogTag::Ok, "OK", "Cleaned leftover EvanProxy hosts entries");
    return true;
}

void ProxyController::dispatch_ui_command(const UiCommand& cmd) {
    if (cmd.kind == UiCommand::Kind::ClearConsole) {
        shared_.clear_console_lines();
        shared_.clear_packet_lines();
        if (running_.load(std::memory_order_acquire)) {
            shared_.enqueue_ui_command(cmd);
        }
        return;
    }

    if (running_.load(std::memory_order_acquire)) {
        shared_.enqueue_ui_command(cmd);
        return;
    }

    std::lock_guard<std::mutex> lk(mu_);
    if (cmd.kind == UiCommand::Kind::RunChatCommand) {
        if (!is_offline_state_command(cmd.value)) {
            std::string trimmed = cmd.value;
            if (trimmed.rfind("/cd ", 0) == 0) {
                try {
                    const long long n = std::stoll(trimmed.substr(4));
                    shared_.push_console_line(
                        LogTag::Info,
                        "CALC",
                        "/cd " + std::to_string(n) + " = " + format_cd_breakdown(n) +
                            " (start proxy & log in to drop)");
                    return;
                } catch (...) {
                }
            }
            shared_.push_console_line(
                LogTag::Info,
                "INFO",
                "Start proxy & log into Growtopia to run: " + cmd.value);
            return;
        }
    } else if (cmd.kind == UiCommand::Kind::WardrobeAddItem) {
        auto matches = search_items_preview(cmd.value, 1);
        if (matches.empty()) {
            shared_.push_console_line(LogTag::Warn, "WARN", "No item matched: " + cmd.value);
        } else {
            shared_.push_console_line(
                LogTag::Info,
                "INFO",
                "Found " + matches[0] + " (start proxy & enter world to equip to visual backpack)");
        }
        return;
    }

    Session temp;
    temp.apply_config(cfg_);
    temp.items_db = &items_db_;
    ui::UiEffects eff;
    if (ui::apply_ui_command(cmd, temp, shared_, eff)) {
        temp.export_to_config(cfg_);
        if (eff.save_config && !opts_.config_path.empty()) {
            save_config(opts_.config_path, cfg_);
        }
    }
}

void ProxyController::sync_stopped_config_locked() {
    if (!opts_.config_path.empty() && std::filesystem::exists(opts_.config_path)) {
        cfg_ = load_or_create_config(opts_.config_path);
        if (opts_.no_hosts_override) {
            cfg_.manage_hosts = false;
        }
    }
}

UiSnapshot ProxyController::build_stopped_snapshot_locked() const {
    UiSnapshot s;
    s.proxy_running = false;
    s.http_running = false;
    s.enet_running = false;
    s.port_conflict = port_conflict_.load(std::memory_order_acquire);
    s.last_error = last_error_;
    s.http_port = cfg_.http_port;
    s.enet_port = cfg_.enet_port;
    s.ca_installed = ca_installed_;
    s.manage_hosts = cfg_.manage_hosts;
    s.hosts_active = hosts_active_;

    s.evan_branding = cfg_.evan_branding;
    s.outgoing_evan_prefix = cfg_.outgoing_evan_prefix;
    s.fps_boost = cfg_.fps_boost;
    s.fps_show_name = cfg_.fps_show_name;
    s.fps_hide_bubbles = cfg_.fps_hide_bubbles;
    s.vending_info = cfg_.vending_info;
    s.auto_bgl = cfg_.auto_bgl;
    s.gems_tracker = cfg_.gems_tracker;
    s.hotkeys_enabled = cfg_.hotkeys_enabled;
    s.fast_drop = cfg_.fast_drop;
    s.fast_trash = cfg_.fast_trash;
    s.rainbow_name = cfg_.rainbow_name;
    s.unlimited_zoom = cfg_.unlimited_zoom;
    s.weather_override = cfg_.weather_override;
    s.hide_clothes = cfg_.hide_clothes;
    s.visual_clothes_mode = false;
    s.custom_banner = cfg_.custom_banner;
    s.hud_overlay = cfg_.hud_overlay;
    s.log_actions = cfg_.log_actions;
    s.log_raw_movement = cfg_.log_raw_movement;
    s.verbose_log = shared_.verbose_log.load(std::memory_order_relaxed);
    s.hex_log = shared_.hex_log.load(std::memory_order_relaxed);

    s.zoom_percent = cfg_.zoom_percent;
    s.weather_id = cfg_.weather_id;
    s.fast_buy = cfg_.fast_buy;
    s.fast_buy_qty = cfg_.fast_buy_qty;

    Session tmp;
    tmp.apply_config(cfg_);
    s.active_titles_summary = tmp.active_titles_summary();
    s.title_maxlevel = cfg_.title_maxlevel;
    s.title_doctor = cfg_.title_doctor;
    s.title_legendary = cfg_.title_legendary;
    s.title_g4g = cfg_.title_g4g;
    s.title_master = cfg_.title_master;
    s.title_mentor = cfg_.title_mentor;
    s.title_anniversary = cfg_.title_anniversary;
    s.title_award = cfg_.title_award;
    s.title_party = cfg_.title_party;
    s.title_royalwinter = cfg_.title_royalwinter;
    s.title_immortal = cfg_.title_immortal;
    s.title_thanksgiving = cfg_.title_thanksgiving;
    s.title_cc_badge = cfg_.title_cc_badge;
    s.title_tt_badge = cfg_.title_tt_badge;
    s.title_moderator = cfg_.title_moderator;
    s.title_developer = cfg_.title_developer;
    s.title_growroyal_tier = cfg_.title_growroyal_tier;
    s.title_pbl_role = cfg_.title_pbl_role;
    s.hotkeys = cfg_.hotkeys;
    if (s.hotkeys.size() < kHotkeySlots) s.hotkeys.resize(kHotkeySlots);
    return s;
}

UiSnapshot ProxyController::get_live_snapshot() const {
    if (running_.load(std::memory_order_acquire)) {
        UiSnapshot s = shared_.get_snapshot();
        std::lock_guard<std::mutex> lk(mu_);
        s.proxy_running = true;
        s.http_running = http_running_;
        s.enet_running = enet_running_;
        s.port_conflict = port_conflict_.load(std::memory_order_acquire);
        s.last_error = last_error_;
        s.ca_installed = ca_installed_;
        s.manage_hosts = cfg_.manage_hosts;
        s.hosts_active = hosts_active_;
        return s;
    }

    std::lock_guard<std::mutex> lk(mu_);
    return build_stopped_snapshot_locked();
}

std::vector<std::string> ProxyController::search_items_preview(const std::string& query, size_t max_results) const {
    std::vector<std::string> out;
    if (items_db_.size() == 0 || query.empty()) return out;
    auto hits = items_db_.search(query, true, max_results);
    if (hits.empty()) {
        hits = items_db_.search(query, false, max_results);
    }
    for (const ItemEntry* item : hits) {
        out.push_back(item->name + " (#" + std::to_string(item->id) + ")");
    }
    return out;
}

} // namespace evan
