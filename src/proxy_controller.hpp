#pragma once

#include "cert.hpp"
#include "config.hpp"
#include "enet_proxy.hpp"
#include "hosts.hpp"
#include "http_bridge.hpp"
#include "items_db.hpp"
#include "ui_bridge.hpp"

#include <atomic>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace evan {

class ProxyController {
public:
    struct Options {
        std::filesystem::path exe_dir;
        std::filesystem::path config_path;
        std::filesystem::path cert_dir;
        std::filesystem::path log_dir;
        std::filesystem::path worlds_path;
        bool skip_os_hosts_and_ca = false; // for isolated unit/integration tests
        bool no_hosts_override = false;    // CLI --no-hosts
    };

    explicit ProxyController(Options opts);
    ~ProxyController();

    ProxyController(const ProxyController&) = delete;
    ProxyController& operator=(const ProxyController&) = delete;

    bool start(std::string& err, bool& out_port_conflict, bool& out_needs_admin);
    void stop();

    bool is_running() const { return running_.load(std::memory_order_acquire); }
    bool has_port_conflict() const { return port_conflict_.load(std::memory_order_acquire); }

    bool is_ca_installed() const;
    bool install_ca(std::string& err);
    bool uninstall_ca(std::string& err);

    bool set_manage_hosts(bool enabled);
    bool clean_leftover_hosts(std::string& err, bool& out_needs_admin);

    void dispatch_ui_command(const UiCommand& cmd);
    UiSnapshot get_live_snapshot() const;

    std::vector<ConsoleLine> get_console_lines() const { return shared_.get_console_lines(); }
    std::vector<ConsoleLine> get_packet_lines() const { return shared_.get_packet_lines(); }
    void clear_console() { shared_.clear_console_lines(); }
    void clear_packet_console() { shared_.clear_packet_lines(); }

    size_t items_db_size() const { return items_db_.size(); }
    std::vector<std::string> search_items_preview(const std::string& query, size_t max_results = 6) const;

    const Options& options() const { return opts_; }
    SharedState& shared() { return shared_; }

private:
    UiSnapshot build_stopped_snapshot_locked() const;
    void sync_stopped_config_locked();

    Options opts_;
    ProxyConfig cfg_;
    cert::CertPaths certs_;
    bool certs_ready_ = false;
    std::string cert_init_err_;

    ItemDatabase items_db_;
    mutable SharedState shared_;

    mutable std::mutex mu_;
    std::atomic<bool> running_{false};
    std::atomic<bool> port_conflict_{false};
    bool http_running_ = false;
    bool enet_running_ = false;
    bool ca_installed_ = false;
    bool hosts_active_ = false;
    std::string last_error_;

    hosts::HostsGuard hosts_guard_;
    std::unique_ptr<HttpBridge> http_bridge_;
    std::thread enet_thread_;
    ProxyConfig active_run_cfg_;
};

} // namespace evan
