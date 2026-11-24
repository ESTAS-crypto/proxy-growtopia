#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace evan::dns {

// Pure helpers (also exercised by unit tests)
std::vector<uint8_t> build_dns_a_query(uint16_t id, const std::string& domain);
std::optional<std::string> parse_dns_a_response(const uint8_t* data, size_t len, uint16_t expected_id);

// Sends a direct UDP A-record query to `dns_server` (bypassing Windows hosts file).
std::optional<std::string> resolve_ipv4_direct(
    const std::string& host,
    const std::string& dns_server,
    std::string& err
);

} // namespace evan::dns
