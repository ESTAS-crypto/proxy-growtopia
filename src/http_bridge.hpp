#pragma once

#include "cert.hpp"
#include "config.hpp"

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>

namespace evan {

class SharedState {
public:
    std::atomic<bool> stop_requested{false};
    std::atomic<bool> verbose_log{false};
    std::atomic<bool> hex_log{false};
    std::atomic<uint64_t> c2s_packets{0};
    std::atomic<uint64_t> s2c_packets{0};

    void set_pending_upstream(const std::string& ip, uint16_t port);
    std::optional<std::pair<std::string, uint16_t>> take_or_reuse_upstream();

    void set_current_upstream(const std::string& ip, uint16_t port);
    std::optional<std::pair<std::string, uint16_t>> get_current_upstream() const;

    void set_local_net_id(int32_t net_id);
    int32_t get_local_net_id() const;

    void set_log_file_path(const std::string& path);
    std::string get_log_file_path() const;

private:
    mutable std::mutex mutex_;
    std::string pending_ip_;
    uint16_t pending_port_ = 0;
    bool has_pending_ = false;

    std::string last_ip_;
    uint16_t last_port_ = 0;

    std::string current_ip_;
    uint16_t current_port_ = 0;

    int32_t local_net_id_ = -1;
    std::string log_file_path_;
};

class HttpBridge {
public:
    struct Options {
        std::string bind_ip = "0.0.0.0";
        uint16_t bind_port = 443;
        uint16_t upstream_https_port = 443;
        std::filesystem::path upstream_ca_override;
    };

    HttpBridge(const ProxyConfig& cfg, SharedState& shared, const cert::CertPaths& certs);
    HttpBridge(const ProxyConfig& cfg, SharedState& shared, const cert::CertPaths& certs, Options opts);
    ~HttpBridge();

    HttpBridge(const HttpBridge&) = delete;
    HttpBridge& operator=(const HttpBridge&) = delete;

    bool start(std::string& err);
    void stop();
    uint16_t bound_port() const { return bound_port_; }

    static bool probe_upstream(
        const ProxyConfig& cfg,
        std::string& out_real_ip,
        uint16_t& out_real_port,
        std::string& out_rewritten,
        std::string& err
    );

private:
    void accept_loop();
    void handle_client(uintptr_t client_sock);
    bool forward_server_data(
        const std::string& user_agent,
        const std::string& body,
        std::string& out_rewritten,
        std::string& out_real_ip,
        uint16_t& out_real_port,
        std::string& err
    );

    const ProxyConfig& cfg_;
    SharedState& shared_;
    cert::CertPaths certs_;
    Options opts_;

    uintptr_t listen_sock_ = static_cast<uintptr_t>(~0ULL);
    uint16_t bound_port_ = 0;
    std::atomic<bool> running_{false};
    std::thread worker_;
};

} // namespace evan
