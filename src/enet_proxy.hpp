#pragma once

#include "config.hpp"
#include "http_bridge.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace evan {

class EnetProxy {
public:
    EnetProxy(
        const ProxyConfig& cfg,
        SharedState& shared,
        std::filesystem::path log_dir = {},
        std::filesystem::path config_path = {},
        std::filesystem::path worlds_path = {}
    );

    bool run(std::string& err);

private:
    struct PendingPacket {
        std::vector<uint8_t> data;
        uint8_t channel = 0;
        uint32_t flags = 0;
    };

    const ProxyConfig& cfg_;
    SharedState& shared_;
    std::filesystem::path log_dir_;
    std::filesystem::path config_path_;
    std::filesystem::path worlds_path_;
};

} // namespace evan
