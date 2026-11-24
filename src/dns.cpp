#include "dns.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <array>
#include <sstream>

namespace evan::dns {

namespace {

uint16_t read_u16_be(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

bool skip_dns_name(const uint8_t* data, size_t len, size_t& pos) {
    size_t jumps = 0;
    while (pos < len) {
        uint8_t label_len = data[pos];
        if (label_len == 0) {
            ++pos;
            return true;
        }
        if ((label_len & 0xC0) == 0xC0) {
            if (pos + 2 > len) return false;
            pos += 2;
            return true;
        }
        if ((label_len & 0xC0) != 0) {
            return false;
        }
        pos += 1 + static_cast<size_t>(label_len);
        if (++jumps > 128) return false;
    }
    return false;
}

std::optional<std::string> query_single_server(
    const std::string& domain,
    const std::string& server_ip,
    uint16_t query_id,
    std::string& err
) {
    sockaddr_in srv{};
    srv.sin_family = AF_INET;
    srv.sin_port = htons(53);
    if (inet_pton(AF_INET, server_ip.c_str(), &srv.sin_addr) != 1) {
        err = "DNS server IP tidak valid: " + server_ip;
        return std::nullopt;
    }

    auto query = build_dns_a_query(query_id, domain);
    if (query.empty()) {
        err = "Nama domain tidak valid: " + domain;
        return std::nullopt;
    }

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        err = "Gagal membuat UDP socket untuk DNS";
        return std::nullopt;
    }

    DWORD timeout_ms = 2000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));

    std::array<uint8_t, 1500> buf{};
    for (int attempt = 0; attempt < 3; ++attempt) {
        int sent = sendto(sock, reinterpret_cast<const char*>(query.data()), static_cast<int>(query.size()), 0,
                          reinterpret_cast<const sockaddr*>(&srv), sizeof(srv));
        if (sent == SOCKET_ERROR) {
            continue;
        }

        sockaddr_in from{};
        int from_len = sizeof(from);
        int n = recvfrom(sock, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0,
                         reinterpret_cast<sockaddr*>(&from), &from_len);
        if (n <= 0) {
            continue;
        }
        if (from.sin_addr.s_addr != srv.sin_addr.s_addr || from.sin_port != srv.sin_port) {
            continue;
        }
        if (auto ip = parse_dns_a_response(buf.data(), static_cast<size_t>(n), query_id)) {
            closesocket(sock);
            return ip;
        }
    }

    closesocket(sock);
    err = "Timeout atau tidak ada record A untuk " + domain + " dari DNS " + server_ip;
    return std::nullopt;
}

} // namespace

std::vector<uint8_t> build_dns_a_query(uint16_t id, const std::string& domain) {
    std::vector<uint8_t> q;
    q.reserve(32 + domain.size());
    q.push_back(static_cast<uint8_t>(id >> 8));
    q.push_back(static_cast<uint8_t>(id & 0xFF));
    // Flags: RD = 1
    q.push_back(0x01);
    q.push_back(0x00);
    // QDCOUNT = 1, ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
    q.insert(q.end(), {0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});

    std::string trimmed = domain;
    while (!trimmed.empty() && trimmed.back() == '.') {
        trimmed.pop_back();
    }
    if (trimmed.empty()) {
        return {};
    }

    std::stringstream ss(trimmed);
    std::string label;
    while (std::getline(ss, label, '.')) {
        if (label.empty() || label.size() > 63) {
            return {};
        }
        q.push_back(static_cast<uint8_t>(label.size()));
        q.insert(q.end(), label.begin(), label.end());
    }
    q.push_back(0x00);
    // QTYPE = A (1), QCLASS = IN (1)
    q.insert(q.end(), {0x00, 0x01, 0x00, 0x01});
    return q;
}

std::optional<std::string> parse_dns_a_response(const uint8_t* data, size_t len, uint16_t expected_id) {
    if (!data || len < 12) {
        return std::nullopt;
    }
    if (read_u16_be(data) != expected_id) {
        return std::nullopt;
    }
    // RCODE (low 4 bits of byte 3) must be 0 (NoError)
    if ((data[3] & 0x0F) != 0) {
        return std::nullopt;
    }
    uint16_t qdcount = read_u16_be(data + 4);
    uint16_t ancount = read_u16_be(data + 6);
    size_t pos = 12;

    for (uint16_t i = 0; i < qdcount; ++i) {
        if (!skip_dns_name(data, len, pos)) return std::nullopt;
        if (pos + 4 > len) return std::nullopt;
        pos += 4;
    }

    for (uint16_t i = 0; i < ancount; ++i) {
        if (!skip_dns_name(data, len, pos)) return std::nullopt;
        if (pos + 10 > len) return std::nullopt;
        uint16_t rtype = read_u16_be(data + pos);
        uint16_t rclass = read_u16_be(data + pos + 2);
        uint16_t rdlen = read_u16_be(data + pos + 8);
        pos += 10;
        if (pos + rdlen > len) return std::nullopt;

        if (rtype == 1 && rclass == 1 && rdlen == 4) {
            char ip_buf[INET_ADDRSTRLEN] = {};
            in_addr addr{};
            addr.s_addr = (static_cast<uint32_t>(data[pos])) |
                          (static_cast<uint32_t>(data[pos + 1]) << 8) |
                          (static_cast<uint32_t>(data[pos + 2]) << 16) |
                          (static_cast<uint32_t>(data[pos + 3]) << 24);
            if (inet_ntop(AF_INET, &addr, ip_buf, sizeof(ip_buf))) {
                return std::string(ip_buf);
            }
        }
        pos += rdlen;
    }
    return std::nullopt;
}

std::optional<std::string> resolve_ipv4_direct(
    const std::string& host,
    const std::string& dns_server,
    std::string& err
) {
    in_addr addr{};
    if (inet_pton(AF_INET, host.c_str(), &addr) == 1) {
        return host;
    }
    if (host == "localhost") {
        return std::string("127.0.0.1");
    }

    const uint16_t qid = static_cast<uint16_t>((GetCurrentProcessId() & 0xFFFF) ^ 0x5A5A);
    if (auto ip = query_single_server(host, dns_server, qid, err)) {
        return ip;
    }

    if (dns_server != "8.8.8.8") {
        std::string fallback_err;
        if (auto ip = query_single_server(host, "8.8.8.8", static_cast<uint16_t>(qid ^ 0x1234), fallback_err)) {
            return ip;
        }
        err += " | Fallback 8.8.8.8: " + fallback_err;
    }
    return std::nullopt;
}

} // namespace evan::dns
