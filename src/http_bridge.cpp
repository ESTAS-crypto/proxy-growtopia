#include "http_bridge.hpp"

#include "dns.hpp"
#include "protocol.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <iostream>
#include <sstream>
#include <vector>

namespace evan {

void SharedState::set_pending_upstream(const std::string& ip, uint16_t port) {
    std::lock_guard<std::mutex> lock(mutex_);
    pending_ip_ = ip;
    pending_port_ = port;
    has_pending_ = true;
    last_ip_ = ip;
    last_port_ = port;
}

std::optional<std::pair<std::string, uint16_t>> SharedState::take_or_reuse_upstream() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (has_pending_ && !pending_ip_.empty() && pending_port_ != 0) {
        has_pending_ = false;
        return std::make_pair(pending_ip_, pending_port_);
    }
    if (!last_ip_.empty() && last_port_ != 0) {
        return std::make_pair(last_ip_, last_port_);
    }
    return std::nullopt;
}

void SharedState::set_current_upstream(const std::string& ip, uint16_t port) {
    std::lock_guard<std::mutex> lock(mutex_);
    current_ip_ = ip;
    current_port_ = port;
}

std::optional<std::pair<std::string, uint16_t>> SharedState::get_current_upstream() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!current_ip_.empty() && current_port_ != 0) {
        return std::make_pair(current_ip_, current_port_);
    }
    return std::nullopt;
}

void SharedState::set_local_net_id(int32_t net_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    local_net_id_ = net_id;
}

int32_t SharedState::get_local_net_id() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return local_net_id_;
}

void SharedState::set_log_file_path(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    log_file_path_ = path;
}

std::string SharedState::get_log_file_path() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return log_file_path_;
}

namespace {

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

std::string trim(const std::string& s) {
    size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

int win_ssl_send(void* ctx, const unsigned char* buf, size_t len) {
    SOCKET s = *reinterpret_cast<SOCKET*>(ctx);
    int ret = send(s, reinterpret_cast<const char*>(buf), static_cast<int>(len), 0);
    if (ret == SOCKET_ERROR) {
        int e = WSAGetLastError();
        if (e == WSAEWOULDBLOCK) return MBEDTLS_ERR_SSL_WANT_WRITE;
        if (e == WSAETIMEDOUT) return MBEDTLS_ERR_SSL_TIMEOUT;
        return -0x004E; // Net send failed
    }
    return ret;
}

int win_ssl_recv(void* ctx, unsigned char* buf, size_t len) {
    SOCKET s = *reinterpret_cast<SOCKET*>(ctx);
    int ret = recv(s, reinterpret_cast<char*>(buf), static_cast<int>(len), 0);
    if (ret == 0) {
        return MBEDTLS_ERR_SSL_CONN_EOF;
    }
    if (ret == SOCKET_ERROR) {
        int e = WSAGetLastError();
        if (e == WSAEWOULDBLOCK) return MBEDTLS_ERR_SSL_WANT_READ;
        if (e == WSAETIMEDOUT) return MBEDTLS_ERR_SSL_TIMEOUT;
        return -0x004C; // Net recv failed
    }
    return ret;
}

bool ssl_write_all(mbedtls_ssl_context* ssl, const std::string& data) {
    size_t sent = 0;
    while (sent < data.size()) {
        int r = mbedtls_ssl_write(
            ssl,
            reinterpret_cast<const unsigned char*>(data.data() + sent),
            data.size() - sent
        );
        if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        if (r <= 0) {
            return false;
        }
        sent += static_cast<size_t>(r);
    }
    return true;
}

struct HttpMessage {
    std::string start_line;
    std::string method;
    std::string path;
    int status_code = 0;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;

    std::string get_header(const std::string& name_lower) const {
        for (const auto& [k, v] : headers) {
            if (to_lower(k) == name_lower) return v;
        }
        return {};
    }
};

bool decode_chunked(const std::string& raw, std::string& out) {
    out.clear();
    size_t pos = 0;
    while (pos < raw.size()) {
        size_t crlf = raw.find("\r\n", pos);
        if (crlf == std::string::npos) return false;
        std::string size_str = raw.substr(pos, crlf - pos);
        size_t semi = size_str.find(';');
        if (semi != std::string::npos) size_str.resize(semi);
        size_t chunk_len = 0;
        try {
            chunk_len = std::stoul(trim(size_str), nullptr, 16);
        } catch (...) {
            return false;
        }
        pos = crlf + 2;
        if (chunk_len == 0) {
            return true;
        }
        if (pos + chunk_len + 2 > raw.size()) return false;
        out.append(raw, pos, chunk_len);
        pos += chunk_len + 2;
    }
    return false;
}

bool read_http_message(mbedtls_ssl_context* ssl, bool is_response, HttpMessage& msg) {
    std::string buf;
    buf.reserve(4096);
    unsigned char chunk[4096];
    size_t header_end = std::string::npos;

    while (header_end == std::string::npos) {
        int r = mbedtls_ssl_read(ssl, chunk, sizeof(chunk));
        if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        if (r <= 0) {
            break;
        }
        buf.append(reinterpret_cast<const char*>(chunk), static_cast<size_t>(r));
        if (buf.size() > 1024 * 1024) return false;
        header_end = buf.find("\r\n\r\n");
    }

    if (header_end == std::string::npos) {
        return false;
    }

    const std::string header_part = buf.substr(0, header_end);
    std::string body_part = buf.substr(header_end + 4);

    std::istringstream iss(header_part);
    if (!std::getline(iss, msg.start_line)) return false;
    if (!msg.start_line.empty() && msg.start_line.back() == '\r') msg.start_line.pop_back();

    if (is_response) {
        std::istringstream sl(msg.start_line);
        std::string ver;
        sl >> ver >> msg.status_code;
    } else {
        std::istringstream sl(msg.start_line);
        std::string uri;
        sl >> msg.method >> uri;
        size_t q = uri.find('?');
        msg.path = (q == std::string::npos) ? uri : uri.substr(0, q);
    }

    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            msg.headers.emplace_back(trim(line.substr(0, colon)), trim(line.substr(colon + 1)));
        }
    }

    const std::string te = to_lower(msg.get_header("transfer-encoding"));
    const std::string cl = msg.get_header("content-length");

    if (te.find("chunked") != std::string::npos) {
        std::string decoded;
        while (!decode_chunked(body_part, decoded)) {
            int r = mbedtls_ssl_read(ssl, chunk, sizeof(chunk));
            if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
            if (r <= 0) return false;
            body_part.append(reinterpret_cast<const char*>(chunk), static_cast<size_t>(r));
            if (body_part.size() > 2 * 1024 * 1024) return false;
        }
        msg.body = std::move(decoded);
        return true;
    }

    if (!cl.empty()) {
        size_t expected = 0;
        try {
            expected = std::stoull(cl);
        } catch (...) {
            return false;
        }
        while (body_part.size() < expected) {
            int r = mbedtls_ssl_read(ssl, chunk, sizeof(chunk));
            if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
            if (r <= 0) break;
            body_part.append(reinterpret_cast<const char*>(chunk), static_cast<size_t>(r));
        }
        if (body_part.size() < expected) return false;
        msg.body = body_part.substr(0, expected);
        return true;
    }

    if (is_response) {
        // Close-delimited HTTP response
        while (true) {
            int r = mbedtls_ssl_read(ssl, chunk, sizeof(chunk));
            if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
            if (r <= 0) break;
            body_part.append(reinterpret_cast<const char*>(chunk), static_cast<size_t>(r));
            if (body_part.size() > 2 * 1024 * 1024) break;
        }
    }
    msg.body = std::move(body_part);
    return true;
}

std::string build_http_response(int status, const std::string& status_text, const std::string& body) {
    std::ostringstream oss;
    oss << "HTTP/1.1 " << status << " " << status_text << "\r\n"
        << "Content-Type: text/html\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Connection: close\r\n"
        << "\r\n"
        << body;
    return oss.str();
}

} // namespace

HttpBridge::HttpBridge(const ProxyConfig& cfg, SharedState& shared, const cert::CertPaths& certs)
    : HttpBridge(cfg, shared, certs, Options{ "0.0.0.0", cfg.http_port, 443, {} }) {}

HttpBridge::HttpBridge(const ProxyConfig& cfg, SharedState& shared, const cert::CertPaths& certs, Options opts)
    : cfg_(cfg), shared_(shared), certs_(certs), opts_(std::move(opts)) {}

HttpBridge::~HttpBridge() {
    stop();
}

bool HttpBridge::start(std::string& err) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        err = "Gagal membuat socket HTTPS";
        return false;
    }

    BOOL reuse = TRUE;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(opts_.bind_port);
    if (inet_pton(AF_INET, opts_.bind_ip.c_str(), &addr.sin_addr) != 1) {
        closesocket(s);
        err = "Bind IP tidak valid: " + opts_.bind_ip;
        return false;
    }

    if (bind(s, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        int wsa_err = WSAGetLastError();
        closesocket(s);
        if (wsa_err == WSAEADDRINUSE) {
            err = "Port " + std::to_string(opts_.bind_port) +
                  " sedang dipakai aplikasi lain (misalnya Laragon/Apache/Nginx/IIS). Matikan sementara layanan tersebut lalu coba lagi.";
        } else {
            err = "Gagal bind HTTPS di " + opts_.bind_ip + ":" + std::to_string(opts_.bind_port) +
                  " (WSA error " + std::to_string(wsa_err) + ")";
        }
        return false;
    }

    if (listen(s, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(s);
        err = "Gagal listen pada port " + std::to_string(opts_.bind_port);
        return false;
    }

    sockaddr_in bound{};
    int bound_len = sizeof(bound);
    if (getsockname(s, reinterpret_cast<sockaddr*>(&bound), &bound_len) == 0) {
        bound_port_ = ntohs(bound.sin_port);
    } else {
        bound_port_ = opts_.bind_port;
    }

    listen_sock_ = static_cast<uintptr_t>(s);
    running_ = true;
    worker_ = std::thread(&HttpBridge::accept_loop, this);
    return true;
}

void HttpBridge::stop() {
    bool expected = true;
    if (!running_.compare_exchange_strong(expected, false)) {
        return;
    }
    SOCKET s = static_cast<SOCKET>(listen_sock_);
    if (s != INVALID_SOCKET) {
        closesocket(s);
        listen_sock_ = static_cast<uintptr_t>(INVALID_SOCKET);
    }
    if (worker_.joinable()) {
        worker_.join();
    }
}

void HttpBridge::accept_loop() {
    while (running_ && !shared_.stop_requested.load()) {
        SOCKET ls = static_cast<SOCKET>(listen_sock_);
        if (ls == INVALID_SOCKET) break;

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(ls, &rfds);
        timeval tv{0, 100000}; // 100ms
        int sel = select(0, &rfds, nullptr, nullptr, &tv);
        if (sel <= 0) {
            continue;
        }

        SOCKET client = accept(ls, nullptr, nullptr);
        if (client == INVALID_SOCKET) {
            continue;
        }
        std::thread(&HttpBridge::handle_client, this, static_cast<uintptr_t>(client)).detach();
    }
}

void HttpBridge::handle_client(uintptr_t client_sock_raw) {
    SOCKET client_sock = static_cast<SOCKET>(client_sock_raw);
    DWORD timeout_ms = 10000;
    setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
    setsockopt(client_sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&pkey);

    auto cleanup = [&]() {
        mbedtls_ssl_close_notify(&ssl);
        mbedtls_pk_free(&pkey);
        mbedtls_x509_crt_free(&srvcert);
        mbedtls_ssl_config_free(&conf);
        mbedtls_ssl_free(&ssl);
        mbedtls_ctr_drbg_free(&drbg);
        mbedtls_entropy_free(&entropy);
        closesocket(client_sock);
    };

    const char* pers = "EvanProxyHttpSrv";
    if (mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
                              reinterpret_cast<const unsigned char*>(pers), std::strlen(pers)) != 0 ||
        mbedtls_x509_crt_parse_file(&srvcert, certs_.server_cert.string().c_str()) != 0 ||
        mbedtls_pk_parse_keyfile(&pkey, certs_.server_key.string().c_str(), nullptr,
                                 mbedtls_ctr_drbg_random, &drbg) != 0 ||
        mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        std::cerr << "[!] Gagal memuat sertifikat TLS dari " << certs_.server_cert.string() << "\n";
        cleanup();
        return;
    }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);
    static const char* kAlpnProtocols[] = {"http/1.1", nullptr};
    mbedtls_ssl_conf_alpn_protocols(&conf, kAlpnProtocols);
    mbedtls_ssl_conf_ca_chain(&conf, srvcert.next, nullptr);
    if (mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey) != 0 ||
        mbedtls_ssl_setup(&ssl, &conf) != 0) {
        cleanup();
        return;
    }

    mbedtls_ssl_set_bio(&ssl, &client_sock, win_ssl_send, win_ssl_recv, nullptr);

    int hs = 0;
    while ((hs = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (hs != MBEDTLS_ERR_SSL_WANT_READ && hs != MBEDTLS_ERR_SSL_WANT_WRITE) {
            char err_buf[128] = {};
            mbedtls_strerror(hs, err_buf, sizeof(err_buf));
            std::cerr << "[!] TLS handshake dari Growtopia gagal (" << err_buf
                      << "). Pastikan CA sudah di-install: jalankan 'EvanProxy.exe --install-cert'\n";
            cleanup();
            return;
        }
    }

    HttpMessage req;
    if (!read_http_message(&ssl, false, req)) {
        cleanup();
        return;
    }

    std::cout << "[HTTP] " << req.method << " " << req.path << "\n";

    const std::string method_low = to_lower(req.method);
    if ((method_low != "post" && method_low != "get") || req.path != "/growtopia/server_data.php") {
        ssl_write_all(&ssl, build_http_response(404, "Not Found", "Not Found"));
        cleanup();
        return;
    }

    std::string ua = req.get_header("user-agent");
    if (ua.empty()) {
        ua = "UbiServices_SDK_2022.Release.9_PC64_ansi_static";
    }

    std::string rewritten;
    std::string real_ip;
    uint16_t real_port = 0;
    std::string err;
    if (!forward_server_data(ua, req.body, rewritten, real_ip, real_port, err)) {
        std::cerr << "[!] Gagal menghubungi server_data.php asli: " << err << "\n";
        ssl_write_all(&ssl, build_http_response(502, "Bad Gateway", "EvanProxy could not reach Growtopia"));
        cleanup();
        return;
    }

    shared_.set_pending_upstream(real_ip, real_port);
    std::cout << "[HTTP] Server asli: " << real_ip << ":" << real_port
              << " -> klien diarahkan ke " << cfg_.local_ip << ":" << cfg_.enet_port << "\n";

    ssl_write_all(&ssl, build_http_response(200, "OK", rewritten));
    cleanup();
}

bool HttpBridge::forward_server_data(
    const std::string& user_agent,
    const std::string& body,
    std::string& out_rewritten,
    std::string& out_real_ip,
    uint16_t& out_real_port,
    std::string& err
) {
    std::string last_err = "Tidak ada server_data_hosts";

    for (const auto& host : cfg_.server_data_hosts) {
        std::string dns_err;
        auto ip_opt = dns::resolve_ipv4_direct(host, cfg_.dns_server, dns_err);
        if (!ip_opt) {
            last_err = host + ": " + dns_err;
            continue;
        }
        const std::string& target_ip = *ip_opt;

        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            last_err = "Gagal membuat socket upstream";
            continue;
        }

        DWORD timeout_ms = 10000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(opts_.upstream_https_port);
        inet_pton(AF_INET, target_ip.c_str(), &addr.sin_addr);

        if (connect(sock, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
            closesocket(sock);
            last_err = "Gagal TCP connect ke " + target_ip + ":" + std::to_string(opts_.upstream_https_port);
            continue;
        }

        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context drbg;
        mbedtls_ssl_context ssl;
        mbedtls_ssl_config conf;
        mbedtls_x509_crt cacert;

        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&drbg);
        mbedtls_ssl_init(&ssl);
        mbedtls_ssl_config_init(&conf);
        mbedtls_x509_crt_init(&cacert);

        auto cleanup_up = [&]() {
            mbedtls_ssl_close_notify(&ssl);
            mbedtls_x509_crt_free(&cacert);
            mbedtls_ssl_config_free(&conf);
            mbedtls_ssl_free(&ssl);
            mbedtls_ctr_drbg_free(&drbg);
            mbedtls_entropy_free(&entropy);
            closesocket(sock);
        };

        const char* pers = "EvanProxyHttpCli";
        if (mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
                                  reinterpret_cast<const unsigned char*>(pers), std::strlen(pers)) != 0 ||
            mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                        MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
            cleanup_up();
            last_err = "Gagal inisialisasi TLS client";
            continue;
        }

        mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);
        static const char* kAlpnProtocols[] = {"http/1.1", nullptr};
        mbedtls_ssl_conf_alpn_protocols(&conf, kAlpnProtocols);
        if (!opts_.upstream_ca_override.empty()) {
            mbedtls_x509_crt_parse_file(&cacert, opts_.upstream_ca_override.string().c_str());
            mbedtls_ssl_conf_ca_chain(&conf, &cacert, nullptr);
            mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        } else if (cfg_.verify_upstream_tls) {
            cert::load_windows_root_cas(&cacert);
            mbedtls_ssl_conf_ca_chain(&conf, &cacert, nullptr);
            mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        } else {
            mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
        }

        if (mbedtls_ssl_setup(&ssl, &conf) != 0 ||
            mbedtls_ssl_set_hostname(&ssl, host.c_str()) != 0) {
            cleanup_up();
            last_err = "Gagal setup TLS client untuk " + host;
            continue;
        }

        mbedtls_ssl_set_bio(&ssl, &sock, win_ssl_send, win_ssl_recv, nullptr);

        int hs = 0;
        while ((hs = mbedtls_ssl_handshake(&ssl)) != 0) {
            if (hs != MBEDTLS_ERR_SSL_WANT_READ && hs != MBEDTLS_ERR_SSL_WANT_WRITE) break;
        }
        if (hs != 0) {
            char eb[128] = {};
            mbedtls_strerror(hs, eb, sizeof(eb));
            cleanup_up();
            last_err = "TLS handshake upstream (" + host + ") gagal: " + std::string(eb);
            continue;
        }

        const std::string effective_body = body.empty() ? "version=5.61&protocol=227&platform=0" : body;
        std::ostringstream req_ss;
        req_ss << "POST /growtopia/server_data.php HTTP/1.1\r\n"
               << "Host: " << host << "\r\n"
               << "User-Agent: " << user_agent << "\r\n"
               << "Content-Type: application/x-www-form-urlencoded\r\n"
               << "Accept: */*\r\n"
               << "Content-Length: " << effective_body.size() << "\r\n"
               << "Connection: close\r\n\r\n"
               << effective_body;

        if (!ssl_write_all(&ssl, req_ss.str())) {
            cleanup_up();
            last_err = "Gagal mengirim POST server_data.php ke " + host;
            continue;
        }

        HttpMessage resp;
        if (!read_http_message(&ssl, true, resp)) {
            cleanup_up();
            last_err = "Gagal membaca response server_data.php dari " + host;
            continue;
        }
        cleanup_up();

        if (resp.status_code != 200 || resp.body.empty()) {
            last_err = host + " membalas HTTP " + std::to_string(resp.status_code);
            continue;
        }

        proto::TextParse tp(resp.body);
        if (tp.has("maint")) {
            std::cout << "[!] Server melaporkan maintenance: " << tp.get("maint") << "\n";
        }
        const std::string srv = tp.get("server");
        const std::string port_str = tp.get("port");
        if (srv.empty() || port_str.empty()) {
            last_err = "Response server_data.php tidak memiliki field server/port";
            continue;
        }

        int parsed_port = 0;
        try {
            parsed_port = std::stoi(port_str);
        } catch (...) {
            parsed_port = 0;
        }
        if (parsed_port <= 0 || parsed_port > 65535) {
            last_err = "Port tidak valid di server_data.php: " + port_str;
            continue;
        }

        auto resolved_srv = dns::resolve_ipv4_direct(srv, cfg_.dns_server, dns_err);
        if (!resolved_srv) {
            last_err = "Gagal resolve game server " + srv + ": " + dns_err;
            continue;
        }

        out_real_ip = *resolved_srv;
        out_real_port = static_cast<uint16_t>(parsed_port);

        tp.set("server", cfg_.local_ip);
        tp.set("port", std::to_string(cfg_.enet_port));
        out_rewritten = tp.render();
        return true;
    }

    err = last_err;
    return false;
}

bool HttpBridge::probe_upstream(
    const ProxyConfig& cfg,
    std::string& out_real_ip,
    uint16_t& out_real_port,
    std::string& out_rewritten,
    std::string& err
) {
    SharedState dummy_shared;
    cert::CertPaths dummy_certs;
    HttpBridge probe(cfg, dummy_shared, dummy_certs);
    return probe.forward_server_data(
        "UbiServices_SDK_2022.Release.9_PC64_ansi_static",
        "version=5.61&protocol=227&platform=0",
        out_rewritten,
        out_real_ip,
        out_real_port,
        err
    );
}

} // namespace evan
