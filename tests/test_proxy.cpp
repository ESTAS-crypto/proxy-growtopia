#include "cert.hpp"
#include "config.hpp"
#include "dns.hpp"
#include "enet_proxy.hpp"
#include "hosts.hpp"
#include "http_bridge.hpp"
#include "items_db.hpp"
#include "protocol.hpp"
#include "session.hpp"
#include "ui_menu.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <enet/enet.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

void require(bool cond, const std::string& msg) {
    if (!cond) {
        throw std::runtime_error(msg);
    }
}

uint16_t get_bound_udp_port(ENetHost* host) {
    sockaddr_in addr{};
    int len = sizeof(addr);
    if (getsockname(host->socket, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
        return 0;
    }
    return ntohs(addr.sin_port);
}

int win_ssl_send(void* ctx, const unsigned char* buf, size_t len) {
    SOCKET s = *reinterpret_cast<SOCKET*>(ctx);
    int r = send(s, reinterpret_cast<const char*>(buf), static_cast<int>(len), 0);
    if (r == SOCKET_ERROR) {
        int e = WSAGetLastError();
        if (e == WSAEWOULDBLOCK) return MBEDTLS_ERR_SSL_WANT_WRITE;
        if (e == WSAETIMEDOUT) return MBEDTLS_ERR_SSL_TIMEOUT;
        return -0x004E;
    }
    return r;
}

int win_ssl_recv(void* ctx, unsigned char* buf, size_t len) {
    SOCKET s = *reinterpret_cast<SOCKET*>(ctx);
    int r = recv(s, reinterpret_cast<char*>(buf), static_cast<int>(len), 0);
    if (r == 0) return MBEDTLS_ERR_SSL_CONN_EOF;
    if (r == SOCKET_ERROR) {
        int e = WSAGetLastError();
        if (e == WSAEWOULDBLOCK) return MBEDTLS_ERR_SSL_WANT_READ;
        if (e == WSAETIMEDOUT) return MBEDTLS_ERR_SSL_TIMEOUT;
        return -0x004C;
    }
    return r;
}

void test_dns_query_and_parse() {
    auto q = evan::dns::build_dns_a_query(0x1234, "www.growtopia1.com");
    require(q.size() > 12, "DNS query too short");

    // Simulate CNAME + A answer
    std::vector<uint8_t> resp = q;
    resp[2] = 0x81;
    resp[3] = 0x80;
    resp[7] = 2; // ANCOUNT = 2
    // CNAME record
    resp.insert(resp.end(), {0xC0, 0x0C, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x02, 0xC0, 0x0C});
    // A record -> 1.2.3.4
    resp.insert(resp.end(), {0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 1, 2, 3, 4});

    auto parsed = evan::dns::parse_dns_a_response(resp.data(), resp.size(), 0x1234);
    require(parsed.has_value() && *parsed == "1.2.3.4", "DNS A record parse mismatch");
    require(!evan::dns::parse_dns_a_response(resp.data(), resp.size(), 0x9999).has_value(),
            "DNS wrong ID should be rejected");
}

void test_hosts_marker_preservation() {
    const std::string original =
        "127.0.0.1 localhost\r\n"
        "127.0.0.1 midtrans-php-master.test #laragon magic!\r\n";

    const std::string with_block = evan::hosts::build_hosts_with_block(original, "127.0.0.1");
    require(with_block.find("midtrans-php-master.test #laragon magic!") != std::string::npos,
            "User hosts line missing after install");
    require(with_block.find("127.0.0.1 www.growtopia1.com\r\n") != std::string::npos,
            "Growtopia entry or CRLF missing");

    const std::string restored = evan::hosts::strip_hosts_block(with_block);
    require(restored == original, "Hosts strip did not restore exact original content");

    const std::string legacy_hosts =
        original +
        "127.0.0.1 growtopia1.com\r\n"
        "127.0.0.1\tgrowtopia2.com\r\n"
        "127.0.0.1 growtopia3.com\r\n"
        "127.0.0.1 www.growtopia1.com\r\n"
        "127.0.0.1 www.growtopia2.com\r\n"
        "127.0.0.1 www.growtopia3.com\r\n";
    require(evan::hosts::strip_hosts_block(legacy_hosts) == original,
            "Legacy unmarked Growtopia hosts lines were not cleaned cleanly");
}

void test_protocol_text_and_variants() {
    const std::string raw_sd =
        "server|54.1.2.3\n"
        "port|17099\n"
        "type|2\n"
        "#maint|Maintenance mode\n"
        "meta|abc123\n"
        "RTENDMARKERBS1001\n";
    evan::proto::TextParse tp(raw_sd);
    require(tp.get("server") == "54.1.2.3", "TextParse server mismatch");
    require(!tp.has("maint"), "Commented #maint must not trigger active maint");
    tp.set("server", "127.0.0.1");
    tp.set("port", "17091");
    const std::string rendered = tp.render();
    require(rendered.find("#maint|Maintenance mode") != std::string::npos, "#maint lost");
    require(rendered.find("RTENDMARKERBS1001") != std::string::npos, "RTENDMARKERBS1001 lost");

    // Trailing garbage byte removal
    std::vector<uint8_t> txt_pkt = evan::proto::encode_text_packet(
        evan::proto::MessageType::GenericText, "action|input\n|text|/proxy");
    txt_pkt.back() = 0x2A; // '*' garbage byte
    require(evan::proto::decode_text_payload(txt_pkt.data(), txt_pkt.size()) == "action|input\n|text|/proxy",
            "Trailing garbage byte was not stripped cleanly");

    // VariantList round-trip & OnSendToServer rewrite
    evan::proto::VariantList vl;
    vl.items = {
        evan::proto::Variant::make_string("OnSendToServer"),
        evan::proto::Variant::make_signed(17095),
        evan::proto::Variant::make_signed(4242),
        evan::proto::Variant::make_signed(9999),
        evan::proto::Variant::make_string("52.200.10.5|0|UUID123"),
        evan::proto::Variant::make_unsigned(1)
    };
    auto raw_pkt = evan::proto::build_call_function_packet(-1, 0, vl);
    auto rw = evan::proto::try_rewrite_on_send_to_server(raw_pkt.data(), raw_pkt.size(), "127.0.0.1", 17091);
    require(rw.has_value(), "OnSendToServer rewrite failed");
    require(rw->real_ip == "52.200.10.5" && rw->real_port == 17095, "Extracted real endpoint mismatch");

    auto parsed_rw = evan::proto::VariantList::parse(
        rw->packet.data() + 4 + sizeof(evan::proto::GameUpdatePacket),
        rw->packet.size() - 4 - sizeof(evan::proto::GameUpdatePacket));
    require(parsed_rw.has_value(), "Rewritten VariantList failed to parse");
    require(parsed_rw->items[1].type == evan::proto::Variant::Type::Signed &&
            *parsed_rw->items[1].as_int() == 17091, "Rewritten port type/value mismatch");
    require(parsed_rw->items[4].as_string() == "127.0.0.1|0|UUID123",
            "Rewritten destination did not preserve |doorID|UUIDToken");
}

void test_https_server_data_bridge() {
    const auto temp_dir = std::filesystem::temp_directory_path() / "evanproxy_test_certs";
    std::error_code ec;
    std::filesystem::remove_all(temp_dir, ec);

    evan::cert::CertPaths certs;
    std::string err;
    require(evan::cert::ensure_certs(temp_dir, {"www.growtopia1.com", "localhost"}, certs, err),
            "ensure_certs failed: " + err);

    // Spin up mock upstream HTTPS server on 127.0.0.1:18444
    SOCKET up_listen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    require(up_listen != INVALID_SOCKET, "mock upstream socket failed");
    BOOL reuse = TRUE;
    setsockopt(up_listen, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
    sockaddr_in up_addr{};
    up_addr.sin_family = AF_INET;
    up_addr.sin_port = htons(18444);
    inet_pton(AF_INET, "127.0.0.1", &up_addr.sin_addr);
    require(bind(up_listen, reinterpret_cast<sockaddr*>(&up_addr), sizeof(up_addr)) == 0,
            "mock upstream bind 18444 failed");
    require(listen(up_listen, 4) == 0, "mock upstream listen failed");

    std::atomic<bool> stop_mock{false};
    std::thread mock_thread([&]() {
        while (!stop_mock.load()) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(up_listen, &rfds);
            timeval tv{0, 50000};
            if (select(0, &rfds, nullptr, nullptr, &tv) <= 0) continue;

            SOCKET cli = accept(up_listen, nullptr, nullptr);
            if (cli == INVALID_SOCKET) continue;

            mbedtls_entropy_context ent;
            mbedtls_ctr_drbg_context drbg;
            mbedtls_ssl_context ssl;
            mbedtls_ssl_config conf;
            mbedtls_x509_crt srvcert;
            mbedtls_pk_context pkey;
            mbedtls_entropy_init(&ent);
            mbedtls_ctr_drbg_init(&drbg);
            mbedtls_ssl_init(&ssl);
            mbedtls_ssl_config_init(&conf);
            mbedtls_x509_crt_init(&srvcert);
            mbedtls_pk_init(&pkey);

            const char* pers = "MockUp";
            mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &ent,
                                  reinterpret_cast<const unsigned char*>(pers), std::strlen(pers));
            mbedtls_x509_crt_parse_file(&srvcert, certs.server_cert.string().c_str());
            mbedtls_pk_parse_keyfile(&pkey, certs.server_key.string().c_str(), nullptr,
                                     mbedtls_ctr_drbg_random, &drbg);
            mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
                                        MBEDTLS_SSL_PRESET_DEFAULT);
            mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);
            mbedtls_ssl_conf_ca_chain(&conf, srvcert.next, nullptr);
            mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey);
            mbedtls_ssl_setup(&ssl, &conf);
            mbedtls_ssl_set_bio(&ssl, &cli, win_ssl_send, win_ssl_recv, nullptr);

            if (mbedtls_ssl_handshake(&ssl) == 0) {
                unsigned char req_buf[2048];
                mbedtls_ssl_read(&ssl, req_buf, sizeof(req_buf));
                const std::string body =
                    "server|127.0.0.1\n"
                    "port|17099\n"
                    "type|2\n"
                    "#maint|Maintenance\n"
                    "meta|testmeta123\n"
                    "RTENDMARKERBS1001\n";
                std::ostringstream resp;
                resp << "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: "
                     << body.size() << "\r\nConnection: close\r\n\r\n" << body;
                const std::string rstr = resp.str();
                mbedtls_ssl_write(&ssl, reinterpret_cast<const unsigned char*>(rstr.data()), rstr.size());
                mbedtls_ssl_close_notify(&ssl);
            }

            mbedtls_pk_free(&pkey);
            mbedtls_x509_crt_free(&srvcert);
            mbedtls_ssl_config_free(&conf);
            mbedtls_ssl_free(&ssl);
            mbedtls_ctr_drbg_free(&drbg);
            mbedtls_entropy_free(&ent);
            closesocket(cli);
        }
    });
    struct MockCleanup {
        std::atomic<bool>& stop;
        SOCKET& sock;
        std::thread& t;
        ~MockCleanup() {
            stop.store(true);
            if (sock != INVALID_SOCKET) {
                closesocket(sock);
                sock = INVALID_SOCKET;
            }
            if (t.joinable()) t.join();
        }
    } mock_guard{stop_mock, up_listen, mock_thread};

    evan::ProxyConfig cfg;
    cfg.local_ip = "127.0.0.1";
    cfg.http_port = 18443;
    cfg.enet_port = 17191;
    cfg.server_data_hosts = {"localhost"};
    cfg.verify_upstream_tls = true;

    evan::SharedState shared;
    evan::HttpBridge bridge(cfg, shared, certs,
                            evan::HttpBridge::Options{"127.0.0.1", 18443, 18444, certs.ca_cert});
    require(bridge.start(err), "HttpBridge start failed: " + err);

    // Client connects to HttpBridge on 18443 with STRICT CA verification for www.growtopia1.com
    SOCKET cli = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in b_addr{};
    b_addr.sin_family = AF_INET;
    b_addr.sin_port = htons(18443);
    inet_pton(AF_INET, "127.0.0.1", &b_addr.sin_addr);
    require(connect(cli, reinterpret_cast<sockaddr*>(&b_addr), sizeof(b_addr)) == 0,
            "Client failed to connect to HttpBridge");

    mbedtls_entropy_context ent;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mbedtls_entropy_init(&ent);
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cacert);

    const char* pers = "TestCli";
    require(mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &ent,
                                  reinterpret_cast<const unsigned char*>(pers), std::strlen(pers)) == 0,
            "drbg seed failed");
    require(mbedtls_x509_crt_parse_file(&cacert, certs.ca_cert.string().c_str()) == 0,
            "parse ca.pem failed");
    require(mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                        MBEDTLS_SSL_PRESET_DEFAULT) == 0,
            "ssl defaults failed");
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, nullptr);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    require(mbedtls_ssl_setup(&ssl, &conf) == 0, "ssl setup failed");
    require(mbedtls_ssl_set_hostname(&ssl, "www.growtopia1.com") == 0, "ssl set hostname failed");
    mbedtls_ssl_set_bio(&ssl, &cli, win_ssl_send, win_ssl_recv, nullptr);

    int hs = mbedtls_ssl_handshake(&ssl);
    require(hs == 0, "Strict TLS handshake with generated CA+SAN failed");

    const std::string post_body = "version=5.61&protocol=227&platform=0";
    std::ostringstream req;
    req << "POST /growtopia/server_data.php HTTP/1.1\r\n"
        << "Host: www.growtopia1.com\r\n"
        << "Content-Length: " << post_body.size() << "\r\n"
        << "Connection: close\r\n\r\n"
        << post_body;
    const std::string req_str = req.str();
    require(mbedtls_ssl_write(&ssl, reinterpret_cast<const unsigned char*>(req_str.data()), req_str.size()) > 0,
            "ssl write failed");

    std::string resp_raw;
    unsigned char buf[2048];
    while (true) {
        int r = mbedtls_ssl_read(&ssl, buf, sizeof(buf));
        if (r <= 0) break;
        resp_raw.append(reinterpret_cast<const char*>(buf), static_cast<size_t>(r));
    }

    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ssl_free(&ssl);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&ent);
    closesocket(cli);

    bridge.stop();
    stop_mock.store(true);
    closesocket(up_listen);
    up_listen = INVALID_SOCKET;
    if (mock_thread.joinable()) mock_thread.join();
    std::filesystem::remove_all(temp_dir, ec);

    require(resp_raw.find("200 OK") != std::string::npos, "HttpBridge did not return 200 OK: " + resp_raw);
    require(resp_raw.find("server|127.0.0.1") != std::string::npos, "Rewritten server missing");
    require(resp_raw.find("port|17191") != std::string::npos, "Rewritten port missing");
    require(resp_raw.find("meta|testmeta123") != std::string::npos, "meta field lost");
    require(resp_raw.find("RTENDMARKERBS1001") != std::string::npos, "RTENDMARKERBS1001 lost");

    auto up = shared.take_or_reuse_upstream();
    require(up.has_value() && up->first == "127.0.0.1" && up->second == 17099,
            "SharedState did not record real upstream IP:port");
}

void test_enet_bridge_and_subserver_redirect() {
    require(enet_initialize() == 0, "enet_initialize failed");

    auto make_host = [](bool is_server) -> ENetHost* {
        ENetAddress addr{};
        if (is_server) {
            enet_address_set_host(&addr, ENET_ADDRESS_TYPE_IPV4, "127.0.0.1");
            addr.port = 0;
        }
        ENetHost* h = enet_host_create(ENET_ADDRESS_TYPE_IPV4, is_server ? &addr : nullptr, 2, 2, 0, 0);
        require(h != nullptr, "enet_host_create failed");
        require(enet_host_compress_with_range_coder(h) == 0, "range coder failed");
        h->checksum = enet_crc32;
        if (is_server) h->usingNewPacketForServer = 1;
        else h->usingNewPacket = 1;
        return h;
    };

    ENetHost* main_srv = make_host(true);
    ENetHost* sub_srv = make_host(true);
    ENetHost* client = make_host(false);
    ENetHost* client2 = make_host(false);

    const uint16_t main_port = get_bound_udp_port(main_srv);
    const uint16_t sub_port = get_bound_udp_port(sub_srv);
    require(main_port != 0 && sub_port != 0, "Failed to read bound UDP ports");
    main_srv->address.port = main_port;
    sub_srv->address.port = sub_port;

    const auto log_dir = std::filesystem::temp_directory_path() / "evanproxy_test_logs";
    std::error_code log_ec;
    std::filesystem::remove_all(log_dir, log_ec);

    evan::ProxyConfig cfg;
    cfg.local_ip = "127.0.0.1";
    cfg.enet_port = 17191;
    cfg.using_new_packet = true;
    cfg.log_text_packets = false;
    cfg.log_variants = false;
    cfg.log_to_file = true;

    evan::SharedState shared;
    shared.set_pending_upstream("127.0.0.1", main_port);

    evan::EnetProxy proxy(cfg, shared, log_dir);
    std::string proxy_err;
    bool proxy_ok = true;
    std::thread proxy_thread([&]() {
        proxy_ok = proxy.run(proxy_err);
    });
    struct ProxyThreadGuard {
        evan::SharedState& s;
        std::thread& t;
        ~ProxyThreadGuard() {
            s.stop_requested.store(true);
            if (t.joinable()) t.join();
        }
    } proxy_guard{shared, proxy_thread};

    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    ENetAddress proxy_addr{};
    enet_address_set_host(&proxy_addr, ENET_ADDRESS_TYPE_IPV4, "127.0.0.1");
    proxy_addr.port = cfg.enet_port;

    ENetPeer* cli_peer = enet_host_connect(client, &proxy_addr, 2, 0);
    require(cli_peer != nullptr, "client enet_host_connect failed");
    ENetPeer* cli2_peer = nullptr;

    ENetPeer* main_peer = nullptr;
    ENetPeer* sub_peer = nullptr;
    bool got_hello = false;
    bool got_dialog = false;
    bool main_got_chat = false;
    bool main_saw_proxy_cmd = false;
    bool got_redirect = false;
    bool sub_got_connect = false;
    bool sub_got_msg = false;

    auto pump = [&](int ms) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
        while (std::chrono::steady_clock::now() < deadline) {
            ENetEvent ev{};
            while (enet_host_service(client, &ev, 1) > 0) {
                if (ev.type == ENET_EVENT_TYPE_CONNECT) {
                    cli_peer = ev.peer;
                } else if (ev.type == ENET_EVENT_TYPE_RECEIVE) {
                    auto mt = evan::proto::read_message_type(ev.packet->data, ev.packet->dataLength);
                    if (mt && *mt == evan::proto::MessageType::ServerHello) {
                        got_hello = true;
                    } else if (mt && *mt == evan::proto::MessageType::GamePacket &&
                               ev.packet->dataLength >= 4 + sizeof(evan::proto::GameUpdatePacket)) {
                        evan::proto::GameUpdatePacket gp{};
                        std::memcpy(&gp, ev.packet->data + 4, sizeof(gp));
                        if (gp.extra_data_size > 0 &&
                            4 + sizeof(gp) + gp.extra_data_size <= ev.packet->dataLength) {
                            auto vl = evan::proto::VariantList::parse(
                                ev.packet->data + 4 + sizeof(gp), gp.extra_data_size);
                            if (vl && vl->function_name() == "OnDialogRequest") {
                                got_dialog = true;
                            } else if (vl && vl->function_name() == "OnSendToServer") {
                                if (*vl->items[1].as_int() == cfg.enet_port &&
                                    vl->items[4].as_string() == "127.0.0.1|0|UUID") {
                                    got_redirect = true;
                                }
                            }
                        }
                    }
                    enet_packet_destroy(ev.packet);
                }
            }

            while (enet_host_service(client2, &ev, 1) > 0) {
                if (ev.type == ENET_EVENT_TYPE_CONNECT) {
                    cli2_peer = ev.peer;
                } else if (ev.type == ENET_EVENT_TYPE_RECEIVE) {
                    enet_packet_destroy(ev.packet);
                }
            }

            while (enet_host_service(main_srv, &ev, 1) > 0) {
                if (ev.type == ENET_EVENT_TYPE_CONNECT) {
                    main_peer = ev.peer;
                } else if (ev.type == ENET_EVENT_TYPE_RECEIVE) {
                    std::string txt = evan::proto::decode_text_payload(ev.packet->data, ev.packet->dataLength);
                    if (txt.find("/proxy") != std::string::npos) main_saw_proxy_cmd = true;
                    if (txt == "action|input\n|text|hello") main_got_chat = true;
                    enet_packet_destroy(ev.packet);
                }
            }

            while (enet_host_service(sub_srv, &ev, 1) > 0) {
                if (ev.type == ENET_EVENT_TYPE_CONNECT) {
                    sub_peer = ev.peer;
                    sub_got_connect = true;
                } else if (ev.type == ENET_EVENT_TYPE_RECEIVE) {
                    std::string txt = evan::proto::decode_text_payload(ev.packet->data, ev.packet->dataLength);
                    if (txt == "action|input\n|text|in_subserver") sub_got_msg = true;
                    enet_packet_destroy(ev.packet);
                }
            }
        }
    };

    // Wait for client & main_srv handshake
    for (int i = 0; i < 40 && (!main_peer || cli_peer->state != ENET_PEER_STATE_CONNECTED); ++i) {
        pump(50);
    }
    require(main_peer != nullptr && cli_peer->state == ENET_PEER_STATE_CONNECTED,
            "Initial ENet bridge handshake failed (main_peer=" +
            std::string(main_peer ? "set" : "null") +
            ", cli_state=" + std::to_string(static_cast<int>(cli_peer->state)) + ")");

    // 1. ServerHello
    auto hello = evan::proto::encode_server_hello();
    ENetPacket* p_hello = enet_packet_create(hello.data(), hello.size(), ENET_PACKET_FLAG_RELIABLE);
    enet_peer_send(main_peer, 0, p_hello);
    for (int i = 0; i < 20 && !got_hello; ++i) pump(25);
    require(got_hello, "Client did not receive ServerHello");

    // 2. Local /proxy command swallowed + normal chat forwarded
    auto cmd = evan::proto::encode_text_packet(evan::proto::MessageType::GenericText, "action|input\n|text|/proxy");
    auto chat = evan::proto::encode_text_packet(evan::proto::MessageType::GenericText, "action|input\n|text|hello");
    enet_peer_send(cli_peer, 0, enet_packet_create(cmd.data(), cmd.size(), ENET_PACKET_FLAG_RELIABLE));
    enet_peer_send(cli_peer, 0, enet_packet_create(chat.data(), chat.size(), ENET_PACKET_FLAG_RELIABLE));
    for (int i = 0; i < 30 && (!got_dialog || !main_got_chat); ++i) pump(25);
    require(got_dialog, "Client did not receive OnDialogRequest for /proxy");
    require(main_got_chat, "Main server did not receive normal chat");
    require(!main_saw_proxy_cmd, "/proxy command leaked to main server");

    // 3. OnSendToServer rewrite
    evan::proto::VariantList redir_vl;
    redir_vl.items = {
        evan::proto::Variant::make_string("OnSendToServer"),
        evan::proto::Variant::make_signed(sub_port),
        evan::proto::Variant::make_signed(1234),
        evan::proto::Variant::make_signed(5678),
        evan::proto::Variant::make_string("127.0.0.1|0|UUID"),
        evan::proto::Variant::make_signed(1)
    };
    auto redir_pkt = evan::proto::build_call_function_packet(-1, 0, redir_vl);
    enet_peer_send(main_peer, 0, enet_packet_create(redir_pkt.data(), redir_pkt.size(), ENET_PACKET_FLAG_RELIABLE));
    for (int i = 0; i < 30 && !got_redirect; ++i) pump(25);
    require(got_redirect, "Client did not receive rewritten OnSendToServer");

    // 4. Overlapping reconnect: client2 connects BEFORE client disconnects
    cli2_peer = enet_host_connect(client2, &proxy_addr, 2, 0);
    require(cli2_peer != nullptr, "Client2 overlapping connect failed");
    for (int i = 0; i < 60 && (!sub_got_connect || cli2_peer->state != ENET_PEER_STATE_CONNECTED); ++i) {
        pump(40);
    }
    require(sub_got_connect && cli2_peer->state == ENET_PEER_STATE_CONNECTED,
            "Sub-server did not receive overlapping client2 connection");

    auto sub_msg = evan::proto::encode_text_packet(
        evan::proto::MessageType::GenericText, "action|input\n|text|in_subserver");
    enet_peer_send(cli2_peer, 0, enet_packet_create(sub_msg.data(), sub_msg.size(), ENET_PACKET_FLAG_RELIABLE));
    for (int i = 0; i < 30 && !sub_got_msg; ++i) pump(25);
    require(sub_got_msg, "Sub-server did not receive message from client2");

    shared.stop_requested.store(true);
    proxy_thread.join();
    require(proxy_ok, "EnetProxy returned error: " + proxy_err);

    // Verify detailed packet log file was written
    std::string log_contents;
    for (const auto& entry : std::filesystem::directory_iterator(log_dir)) {
        if (entry.is_regular_file() && entry.path().filename().string().rfind("packets_", 0) == 0) {
            std::ifstream lf(entry.path());
            log_contents.assign((std::istreambuf_iterator<char>(lf)), std::istreambuf_iterator<char>());
            break;
        }
    }
    std::filesystem::remove_all(log_dir, log_ec);
    require(!log_contents.empty(), "Packet log file was not created");
    require(log_contents.find("ServerHello") != std::string::npos, "Packet log missing ServerHello");
    require(log_contents.find("CallFunction") != std::string::npos, "Packet log missing CallFunction");
    require(log_contents.find("OnSendToServer") != std::string::npos, "Packet log missing OnSendToServer");
    require(log_contents.find("in_subserver") != std::string::npos, "Packet log missing sub-server message");

    enet_host_destroy(client2);
    enet_host_destroy(client);
    enet_host_destroy(sub_srv);
    enet_host_destroy(main_srv);
    enet_deinitialize();
}

void test_calculator_and_session() {
    std::string err;
    auto r1 = evan::evaluate_calc("(250 * 4) + 50 / 2 - 5", err);
    require(r1.has_value() && std::abs(*r1 - 1020.0) < 1e-6, "Calc mismatch: " + err);
    require(!evan::evaluate_calc("10 / 0", err).has_value(), "Division by zero should fail");

    require(evan::proto::strip_growtopia_colors("`2clo0x`` `5World``") == "clo0x World",
            "strip_growtopia_colors failed");
    require(evan::formalize_chat_text("halo semua") == "Halo semua.", "formalize_chat_text failed");
    require(evan::formalize_chat_text("/warp START") == "/warp START", "formalize should ignore slash cmds");

    // Build fake SendInventoryState: u8 ver, u32 slots=20, u16 count=3 -> WL(242,50), DL(1796,2), BGL(7188,1)
    std::vector<uint8_t> inv_extra;
    auto push_u8 = [&](uint8_t v) { inv_extra.push_back(v); };
    auto push_u16 = [&](uint16_t v) {
        inv_extra.push_back(static_cast<uint8_t>(v & 0xFF));
        inv_extra.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    };
    auto push_u32 = [&](uint32_t v) {
        for (int i = 0; i < 4; ++i) inv_extra.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
    };
    push_u8(1);
    push_u32(20);
    push_u16(3);
    push_u16(242); push_u8(50); push_u8(0);
    push_u16(1796); push_u8(2); push_u8(0);
    push_u16(7188); push_u8(1); push_u8(0);

    evan::Session sess;
    sess.on_server_inventory(inv_extra.data(), inv_extra.size());
    require(sess.wl_count() == 50 && sess.dl_count() == 2 && sess.bgl_count() == 1,
            "Inventory WL/DL/BGL count mismatch");

    bool is_local = false;
    sess.on_server_spawn("spawn|avatar\nnetID|7\nuserID|42\nname|`2clo0x``\ncountry|id|0\ntype|local\n", is_local);
    require(is_local && sess.local_net_id == 7 && sess.player_name == "clo0x", "Local OnSpawn tracking failed");

    bool is_local_other = true;
    sess.on_server_spawn("spawn|avatar\nnetID|9\nuserID|100\nname|`wGuest``\nposXY|320|640\n", is_local_other);
    require(!is_local_other && sess.players.size() == 1 && sess.players[9].name == "Guest",
            "Remote OnSpawn tracking failed");

    sess.on_server_console_message("World `wEVILAX `0[```2NOPUNCH```0]`` entered.");
    sess.on_server_console_message("`5[```wEVILAX`` `$World Locked`` by clo0x (`2ACCESS GRANTED``)`5]``");
    require(sess.in_world && sess.current_world == "EVILAX" && sess.world_owner == "clo0x",
            "World/owner parsing failed");
}

void test_action_decoding_and_ui_dialogs() {
    evan::Session sess;
    sess.local_net_id = 1;
    sess.player_name = "clo0x";
    sess.in_world = true;
    sess.current_world = "EVILAX";

    // Walk
    evan::proto::GameUpdatePacket walk_gp{};
    walk_gp.type = static_cast<uint8_t>(evan::proto::GamePacketType::State);
    walk_gp.vec_x = 320.0f;
    walk_gp.vec_y = 640.0f;
    walk_gp.flags = 0x01; // WALK
    auto d_walk = sess.describe_client_game_packet(walk_gp, false);
    require(d_walk.has_value() && d_walk->find("Walk ke tile") != std::string::npos, "Walk action decode failed");

    // Jump
    evan::proto::GameUpdatePacket jump_gp = walk_gp;
    jump_gp.flags = 0x80; // JUMP
    auto d_jump = sess.describe_client_game_packet(jump_gp, false);
    require(d_jump.has_value() && d_jump->find("Jump di tile") != std::string::npos, "Jump action decode failed");

    // Punch empty tile via State PUNCH
    evan::proto::GameUpdatePacket punch_gp = walk_gp;
    punch_gp.flags = 0x200; // PUNCH
    punch_gp.int_x = 12;
    punch_gp.int_y = 20;
    auto d_punch = sess.describe_client_game_packet(punch_gp, false);
    require(d_punch.has_value() && d_punch->find("Punch/Click tile (12,20)") != std::string::npos,
            "State punch action decode failed");

    // TileChangeRequest punch & place
    evan::proto::GameUpdatePacket tcr_punch{};
    tcr_punch.type = static_cast<uint8_t>(evan::proto::GamePacketType::TileChangeRequest);
    tcr_punch.value = 18;
    tcr_punch.int_x = 15;
    tcr_punch.int_y = 21;
    auto d_tcr = sess.describe_client_game_packet(tcr_punch, false);
    require(d_tcr.has_value() && d_tcr->find("Punch blok di tile (15,21)") != std::string::npos,
            "TCR punch decode failed");

    evan::proto::GameUpdatePacket tcr_place = tcr_punch;
    tcr_place.value = 2; // Dirt
    auto d_place = sess.describe_client_game_packet(tcr_place, false);
    require(d_place.has_value() && d_place->find("Place/Click item #2") != std::string::npos,
            "TCR place decode failed");

    // Pickup
    evan::proto::GameUpdatePacket pickup{};
    pickup.type = static_cast<uint8_t>(evan::proto::GamePacketType::ItemActivateObjectRequest);
    pickup.value = 77;
    auto d_pick = sess.describe_client_game_packet(pickup, false);
    require(d_pick.has_value() && d_pick->find("Pickup drop uid=77") != std::string::npos,
            "Pickup decode failed");

    // /proxy -> themed multi-tab dialog
    evan::SharedState shared;
    evan::ui::UiEffects eff;
    require(evan::ui::handle_chat_command("/proxy", sess, shared, eff), "/proxy should be handled");
    require(eff.to_client.size() == 1, "/proxy should emit 1 dialog");

    auto extract_dialog_markup = [](const std::vector<uint8_t>& pkt) -> std::string {
        auto vl = evan::proto::VariantList::parse(
            pkt.data() + 4 + sizeof(evan::proto::GameUpdatePacket),
            pkt.size() - 4 - sizeof(evan::proto::GameUpdatePacket));
        return (vl && vl->items.size() >= 2) ? vl->items[1].as_string() : std::string{};
    };
    const std::string home_markup = extract_dialog_markup(eff.to_client[0]);
    require(home_markup.find("set_bg_color|11,25,44,235|") != std::string::npos, "Home theme bg missing");
    require(home_markup.find("add_button_with_icon|nav_go_nav|") != std::string::npos, "Home icon grid missing");
    require(home_markup.find("END_LIST") != std::string::npos, "Home END_LIST missing");
    require(home_markup.find("end_dialog|evanproxy_home|") != std::string::npos, "Home dialog name missing");

    // Test navigation to every sub-page + theme switching
    for (const auto& [btn, expected_end] : std::vector<std::pair<std::string, std::string>>{
             {"nav_go_nav", "end_dialog|evanproxy_nav|"},
             {"nav_go_packets", "end_dialog|evanproxy_packets|"},
             {"nav_go_visual", "end_dialog|evanproxy_visual|"},
             {"nav_go_tools", "end_dialog|evanproxy_tools|"},
             {"nav_go_commands", "end_dialog|evanproxy_commands|"}}) {
        evan::ui::UiEffects nav_eff;
        evan::proto::TextParse tp("action|dialog_return\ndialog_name|evanproxy_home\nbuttonClicked|" + btn);
        require(evan::ui::handle_dialog_return(tp, sess, shared, nav_eff), "Dialog return failed for " + btn);
        require(!nav_eff.to_client.empty(), "No dialog emitted for " + btn);
        require(extract_dialog_markup(nav_eff.to_client[0]).find(expected_end) != std::string::npos,
                "Unexpected dialog markup for " + btn);
    }

    evan::ui::UiEffects theme_eff;
    evan::proto::TextParse theme_tp("action|dialog_return\ndialog_name|evanproxy_visual\nbuttonClicked|theme_violet");
    require(evan::ui::handle_dialog_return(theme_tp, sess, shared, theme_eff), "Theme switch failed");
    require(sess.ui_theme == "violet" && theme_eff.save_config, "Theme state/save flag mismatch");
    require(extract_dialog_markup(theme_eff.to_client[0]).find("set_bg_color|20,14,42,235|") != std::string::npos,
            "Violet theme color not applied");

    // Test /warp trigger
    evan::ui::UiEffects warp_eff;
    require(evan::ui::handle_chat_command("/warp start:42", sess, shared, warp_eff), "/warp not handled");
    require(warp_eff.trigger_warp.has_value() &&
            warp_eff.trigger_warp->first == "START" &&
            warp_eff.trigger_warp->second == "42",
            "/warp parsed world/door mismatch");
}

void test_titles_fps_and_portal_warp() {
    auto extract_dialog_markup = [](const std::vector<uint8_t>& pkt) -> std::string {
        auto vl = evan::proto::VariantList::parse(
            pkt.data() + 4 + sizeof(evan::proto::GameUpdatePacket),
            pkt.size() - 4 - sizeof(evan::proto::GameUpdatePacket));
        return (vl && vl->items.size() >= 2) ? vl->items[1].as_string() : std::string{};
    };

    // 1. Clean [ACTION] filter (noisy internal packets suppressed, Walk/Jump kept)
    evan::Session sess;
    sess.local_net_id = 1;
    sess.raw_player_name = "`2clo0x``";
    sess.player_name = "clo0x";
    sess.on_server_country_state("us|showGuild");

    for (auto pt : {evan::proto::GamePacketType::SetIconState,
                    evan::proto::GamePacketType::AppCheckResponse,
                    evan::proto::GamePacketType::AppIntegrityFail,
                    evan::proto::GamePacketType::Disconnect}) {
        evan::proto::GameUpdatePacket gp{};
        gp.type = static_cast<uint8_t>(pt);
        require(!sess.describe_client_game_packet(gp, false).has_value(),
                "Noisy internal packet should not produce [ACTION]");
    }

    // 2. Visual Titles (/title) & /fps name badge + boost
    evan::SharedState shared;
    {
        evan::ui::UiEffects eff;
        require(evan::ui::handle_chat_command("/title", sess, shared, eff), "/title dialog not handled");
        require(eff.to_client.size() == 1, "/title should emit 1 dialog");
        const std::string dlg = extract_dialog_markup(eff.to_client[0]);
        require(dlg.find("end_dialog|evanproxy_title|") != std::string::npos, "Title dialog name mismatch");
        require(dlg.find("Max Level") != std::string::npos &&
                dlg.find("Doctor") != std::string::npos &&
                dlg.find("Legendary") != std::string::npos &&
                dlg.find("Grow4Good") != std::string::npos &&
                dlg.find("Master") != std::string::npos,
                "Title dialog missing expected options");
    }

    for (const char* btn : {"title_tog_maxlevel", "title_tog_doctor", "title_tog_legendary", "title_tog_g4g", "title_tog_master"}) {
        evan::ui::UiEffects eff;
        evan::proto::TextParse tp(std::string("action|dialog_return\ndialog_name|evanproxy_title\nbuttonClicked|") + btn);
        require(evan::ui::handle_dialog_return(tp, sess, shared, eff), "Title toggle failed");
        require(eff.save_config, "Title toggle should request save_config");
    }
    const std::string cstate = sess.compose_country_state();
    require(cstate == "lg|showGuild|maxLevel|doctor|donor|g4g|master|legend",
            "Composed country state mismatch: " + cstate);

    sess.live_fps = 60;
    sess.live_ping_ms = 42;
    {
        evan::ui::UiEffects eff;
        require(evan::ui::handle_chat_command("/fps", sess, shared, eff), "/fps dialog not handled");
        require(eff.to_client.size() == 1 &&
                extract_dialog_markup(eff.to_client[0]).find("end_dialog|evanproxy_fps|") != std::string::npos,
                "FPS dialog mismatch");
    }
    {
        evan::ui::UiEffects eff;
        require(evan::ui::handle_chat_command("/fps on", sess, shared, eff), "/fps on not handled");
        require(sess.fps_show_name && eff.save_config, "/fps on did not enable flag");
    }
    const std::string raw_dname = sess.compose_display_name();
    const std::string dname = evan::proto::strip_growtopia_colors(raw_dname);
    require(dname.find("Dr.clo0x") != std::string::npos &&
            dname.find("of Legend") != std::string::npos &&
            dname.find("[42ms]") != std::string::npos &&
            dname.find("FPS") == std::string::npos,
            "Composed display name mismatch: " + dname);
    require(raw_dname.size() >= 12 &&
            raw_dname.substr(raw_dname.size() - 12) == " of Legend``",
            "Legendary suffix must be clean at end of string: " + raw_dname);

    {
        evan::ui::UiEffects eff;
        require(evan::ui::handle_chat_command("/title reset", sess, shared, eff), "/title reset failed");
        require(!sess.has_any_title(), "Titles not cleared on /title reset");
        require(sess.compose_country_state() == "us|showGuild", "Country state not restored on /title reset");
    }
    {
        evan::ui::UiEffects eff;
        require(evan::ui::handle_chat_command("/fps boost", sess, shared, eff), "/fps boost failed");
        require(sess.fps_boost && eff.save_config && eff.to_client.size() >= 1,
                "/fps boost should enable boost and force weather 0");
    }

    // 3. Config persistence round-trip for new [features] keys
    {
        const auto cfg_path = std::filesystem::temp_directory_path() / "evanproxy_test_cfg.ini";
        std::error_code ec;
        std::filesystem::remove(cfg_path, ec);

        evan::ProxyConfig wcfg;
        wcfg.title_maxlevel = true;
        wcfg.title_doctor = true;
        wcfg.title_legendary = true;
        wcfg.title_g4g = true;
        wcfg.title_master = true;
        wcfg.fps_show_name = true;
        wcfg.fps_boost = true;
        wcfg.fps_hide_bubbles = true;
        require(evan::save_config(cfg_path, wcfg), "save_config failed");

        evan::ProxyConfig rcfg = evan::load_or_create_config(cfg_path);
        std::filesystem::remove(cfg_path, ec);
        require(rcfg.title_maxlevel && rcfg.title_doctor && rcfg.title_legendary &&
                rcfg.title_g4g && rcfg.title_master &&
                rcfg.fps_show_name && rcfg.fps_boost && rcfg.fps_hide_bubbles,
                "Config round-trip lost new [features] flags");
    }

    // 4. Live portal-style /warp + FPS boost packet drop test over ENet
    require(enet_initialize() == 0, "enet_initialize failed");
    ENetAddress srv_addr{};
    enet_address_set_host(&srv_addr, ENET_ADDRESS_TYPE_IPV4, "127.0.0.1");
    srv_addr.port = 0;
    ENetHost* mock_srv = enet_host_create(ENET_ADDRESS_TYPE_IPV4, &srv_addr, 2, 2, 0, 0);
    ENetHost* client = enet_host_create(ENET_ADDRESS_TYPE_IPV4, nullptr, 2, 2, 0, 0);
    require(mock_srv && client, "Failed creating ENet hosts for portal warp test");
    require(enet_host_compress_with_range_coder(mock_srv) == 0 &&
            enet_host_compress_with_range_coder(client) == 0, "range coder failed");
    mock_srv->checksum = enet_crc32;
    mock_srv->usingNewPacketForServer = 1;
    client->checksum = enet_crc32;
    client->usingNewPacket = 1;

    const uint16_t srv_port = get_bound_udp_port(mock_srv);
    require(srv_port != 0, "mock_srv bound port 0");
    mock_srv->address.port = srv_port;

    evan::ProxyConfig pcfg;
    pcfg.local_ip = "127.0.0.1";
    pcfg.enet_port = 17192;
    pcfg.using_new_packet = true;
    pcfg.log_text_packets = false;
    pcfg.log_variants = false;
    pcfg.log_to_file = false;

    evan::SharedState pshared;
    pshared.set_pending_upstream("127.0.0.1", srv_port);

    evan::EnetProxy pproxy(pcfg, pshared);
    std::string p_err;
    bool p_ok = true;
    std::thread p_thread([&]() { p_ok = pproxy.run(p_err); });
    struct PGuard {
        evan::SharedState& s;
        std::thread& t;
        ~PGuard() {
            s.stop_requested.store(true);
            if (t.joinable()) t.join();
        }
    } pguard{pshared, p_thread};

    std::this_thread::sleep_for(std::chrono::milliseconds(120));

    ENetAddress px_addr{};
    enet_address_set_host(&px_addr, ENET_ADDRESS_TYPE_IPV4, "127.0.0.1");
    px_addr.port = pcfg.enet_port;
    ENetPeer* cli_peer = enet_host_connect(client, &px_addr, 2, 0);
    require(cli_peer != nullptr, "cli connect failed");

    ENetPeer* srv_peer = nullptr;
    bool cli_got_world_menu = false;
    bool cli_got_map_data = false;
    bool cli_got_particle = false;
    bool srv_got_quit_to_exit = false;
    bool srv_got_join_target = false;

    auto pump = [&](int ms) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
        while (std::chrono::steady_clock::now() < deadline) {
            ENetEvent ev{};
            while (enet_host_service(client, &ev, 1) > 0) {
                if (ev.type == ENET_EVENT_TYPE_RECEIVE) {
                    auto mt = evan::proto::read_message_type(ev.packet->data, ev.packet->dataLength);
                    if (mt && *mt == evan::proto::MessageType::GamePacket &&
                        ev.packet->dataLength >= 4 + sizeof(evan::proto::GameUpdatePacket)) {
                        evan::proto::GameUpdatePacket gp{};
                        std::memcpy(&gp, ev.packet->data + 4, sizeof(gp));
                        if (gp.type == static_cast<uint8_t>(evan::proto::GamePacketType::SendMapData)) {
                            cli_got_map_data = true;
                        } else if (gp.type == static_cast<uint8_t>(evan::proto::GamePacketType::SendParticleEffect)) {
                            cli_got_particle = true;
                        } else if (gp.type == static_cast<uint8_t>(evan::proto::GamePacketType::CallFunction) &&
                                   gp.extra_data_size > 0 &&
                                   4 + sizeof(gp) + gp.extra_data_size <= ev.packet->dataLength) {
                            auto vl = evan::proto::VariantList::parse(
                                ev.packet->data + 4 + sizeof(gp), gp.extra_data_size);
                            if (vl && vl->function_name() == "OnRequestWorldSelectMenu") {
                                cli_got_world_menu = true;
                            }
                        }
                    }
                    enet_packet_destroy(ev.packet);
                }
            }
            while (enet_host_service(mock_srv, &ev, 1) > 0) {
                if (ev.type == ENET_EVENT_TYPE_CONNECT) {
                    srv_peer = ev.peer;
                } else if (ev.type == ENET_EVENT_TYPE_RECEIVE) {
                    std::string txt = evan::proto::decode_text_payload(ev.packet->data, ev.packet->dataLength);
                    if (txt.find("action|quit_to_exit") != std::string::npos) srv_got_quit_to_exit = true;
                    if (txt.find("action|join_request\nname|TARGET|door1\ninvitedWorld|0") != std::string::npos) {
                        srv_got_join_target = true;
                    }
                    enet_packet_destroy(ev.packet);
                }
            }
        }
    };

    for (int i = 0; i < 40 && (!srv_peer || cli_peer->state != ENET_PEER_STATE_CONNECTED); ++i) pump(40);
    require(srv_peer && cli_peer->state == ENET_PEER_STATE_CONNECTED, "Portal warp test handshake failed");

    // Simulate player inside START world
    evan::proto::VariantList spawn_vl;
    spawn_vl.items = {
        evan::proto::Variant::make_string("OnSpawn"),
        evan::proto::Variant::make_string("spawn|avatar\nnetID|1\nuserID|42\nname|`2clo0x``\ncountry|us|showGuild\ntype|local\n")
    };
    auto sp_pkt = evan::proto::build_call_function_packet(-1, 0, spawn_vl);
    auto world_msg = evan::proto::build_on_console_message("World `wSTART `0[```2NOPUNCH```0]`` entered.");
    enet_peer_send(srv_peer, 0, enet_packet_create(sp_pkt.data(), sp_pkt.size(), ENET_PACKET_FLAG_RELIABLE));
    enet_peer_send(srv_peer, 0, enet_packet_create(world_msg.data(), world_msg.size(), ENET_PACKET_FLAG_RELIABLE));
    pump(120);

    // Turn on /fps boost, send particle effect -> verify suppressed
    auto boost_cmd = evan::proto::encode_text_packet(evan::proto::MessageType::GenericText, "action|input\n|text|/fps boost");
    enet_peer_send(cli_peer, 0, enet_packet_create(boost_cmd.data(), boost_cmd.size(), ENET_PACKET_FLAG_RELIABLE));
    pump(80);
    std::vector<uint8_t> part_pkt(4 + sizeof(evan::proto::GameUpdatePacket), 0);
    uint32_t pt_type = static_cast<uint32_t>(evan::proto::MessageType::GamePacket);
    evan::proto::GameUpdatePacket pgp{};
    pgp.type = static_cast<uint8_t>(evan::proto::GamePacketType::SendParticleEffect);
    std::memcpy(part_pkt.data(), &pt_type, 4);
    std::memcpy(part_pkt.data() + 4, &pgp, sizeof(pgp));
    enet_peer_send(srv_peer, 0, enet_packet_create(part_pkt.data(), part_pkt.size(), ENET_PACKET_FLAG_RELIABLE));
    pump(80);
    require(!cli_got_particle, "SendParticleEffect should be dropped when fps_boost is ON");

    // Client executes /warp target:door1
    auto wcmd = evan::proto::encode_text_packet(evan::proto::MessageType::GenericText, "action|input\n|text|/warp target:door1");
    enet_peer_send(cli_peer, 0, enet_packet_create(wcmd.data(), wcmd.size(), ENET_PACKET_FLAG_RELIABLE));
    for (int i = 0; i < 20 && !srv_got_quit_to_exit; ++i) pump(25);
    require(srv_got_quit_to_exit, "/warp should send quit_to_exit to server");

    // Server answers with OnRequestWorldSelectMenu -> proxy suppresses it from client and emits join_request TARGET|door1
    evan::proto::VariantList menu_vl;
    menu_vl.items = {
        evan::proto::Variant::make_string("OnRequestWorldSelectMenu"),
        evan::proto::Variant::make_string("add_filter|\n")
    };
    auto menu_pkt = evan::proto::build_call_function_packet(-1, 0, menu_vl);
    enet_peer_send(srv_peer, 0, enet_packet_create(menu_pkt.data(), menu_pkt.size(), ENET_PACKET_FLAG_RELIABLE));
    for (int i = 0; i < 20 && !srv_got_join_target; ++i) pump(25);
    require(!cli_got_world_menu, "OnRequestWorldSelectMenu must be suppressed from client during portal-style /warp");
    require(srv_got_join_target, "Proxy did not dispatch join_request TARGET|door1 upon OnRequestWorldSelectMenu");

    // Server sends SendMapData -> client receives map directly
    std::vector<uint8_t> map_pkt(4 + sizeof(evan::proto::GameUpdatePacket), 0);
    evan::proto::GameUpdatePacket mgp{};
    mgp.type = static_cast<uint8_t>(evan::proto::GamePacketType::SendMapData);
    std::memcpy(map_pkt.data(), &pt_type, 4);
    std::memcpy(map_pkt.data() + 4, &mgp, sizeof(mgp));
    enet_peer_send(srv_peer, 0, enet_packet_create(map_pkt.data(), map_pkt.size(), ENET_PACKET_FLAG_RELIABLE));
    for (int i = 0; i < 20 && !cli_got_map_data; ++i) pump(25);
    require(cli_got_map_data, "Client did not receive SendMapData after portal-style /warp");
    require(!cli_got_world_menu, "World select menu leaked to client during /warp");

    pshared.stop_requested.store(true);
    p_thread.join();
    require(p_ok, "Portal warp EnetProxy returned error: " + p_err);

    enet_host_destroy(client);
    enet_host_destroy(mock_srv);
    enet_deinitialize();
}

std::vector<uint8_t> build_synth_item_record(
    uint32_t id,
    uint8_t action_type,
    uint8_t clothing_type,
    const std::string& name,
    const std::string& tex
) {
    static constexpr const char* kKey = "PBG892FXX982ABC*";
    std::vector<uint8_t> r;
    auto push_u16 = [&](uint16_t v) {
        r.push_back(static_cast<uint8_t>(v & 0xFF));
        r.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    };
    auto push_u32 = [&](uint32_t v) {
        for (int i = 0; i < 4; ++i) r.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
    };
    push_u32(id);
    push_u16(0); // flags
    r.push_back(action_type);
    r.push_back(0); // hitSoundType
    push_u16(static_cast<uint16_t>(name.size()));
    for (size_t i = 0; i < name.size(); ++i) {
        r.push_back(static_cast<uint8_t>(name[i]) ^ static_cast<uint8_t>(kKey[(id + i) % 16]));
    }
    push_u16(static_cast<uint16_t>(tex.size()));
    r.insert(r.end(), tex.begin(), tex.end());
    // 22 tail bytes after texture name (offset +19 is clothing_type, +20..21 rarity)
    std::vector<uint8_t> tail(22, 0);
    tail[19] = clothing_type;
    tail[20] = 50;
    r.insert(r.end(), tail.begin(), tail.end());
    return r;
}

void test_visual_clothes_items_and_branding() {
    // 1. Ping-only name + Fixed Legendary + New Titles + /tittle alias
    {
        evan::Session s;
        s.local_net_id = 1;
        s.raw_player_name = "`2clo0x``";
        s.player_name = "clo0x";
        s.on_server_country_state("us|showGuild");
        s.live_ping_ms = 55;

        evan::SharedState sh;
        evan::ui::UiEffects eff;
        require(evan::ui::handle_chat_command("/tittle legendary", s, sh, eff), "/tittle alias failed");
        require(s.title_legendary, "/tittle legendary did not enable title_legendary");
        require(s.compose_display_name() == "`2clo0x of Legend``",
                "Legendary name mismatch: " + s.compose_display_name());

        eff = {};
        require(evan::ui::handle_chat_command("/fps on", s, sh, eff), "/fps on failed");
        const std::string with_ping = s.compose_display_name();
        require(with_ping.find("[`255ms`w]``") != std::string::npos &&
                with_ping.find("FPS") == std::string::npos &&
                with_ping.size() >= 12 &&
                with_ping.substr(with_ping.size() - 12) == " of Legend``",
                "Ping + Legendary name mismatch: " + with_ping);

        eff = {};
        require(evan::ui::handle_chat_command("/title dev", s, sh, eff), "/title dev failed");
        require(s.compose_country_state().rfind("rt|", 0) == 0,
                "Developer badge should set rt country prefix: " + s.compose_country_state());
        eff = {};
        require(evan::ui::handle_chat_command("/title royal", s, sh, eff), "/title royal failed");
        require(s.title_growroyal_tier == 1, "/title royal toggle failed");
        eff = {};
        require(evan::ui::handle_chat_command("/title reset", s, sh, eff), "/title reset failed");
        require(!s.has_any_title(), "/title reset should clear all 12 titles");
    }

    // 2. [EvanProxy] branding preserving CP: channel routing prefix
    {
        const std::string plain = evan::proto::apply_evan_brand_to_console_msg("Welcome back!");
        require(plain == "`9[`#EvanProxy`9]`o Welcome back!", "Plain brand mismatch: " + plain);

        const std::string sb = "CP:0_PL:0_OID:_CT:[SB]_ `5** from player **";
        const std::string branded_sb = evan::proto::apply_evan_brand_to_console_msg(sb);
        require(branded_sb == "CP:0_PL:0_OID:_CT:[SB]_ `9[`#EvanProxy`9]`o `5** from player **",
                "CP channel-routed brand mismatch: " + branded_sb);
        require(evan::proto::apply_evan_brand_to_console_msg(branded_sb) == branded_sb,
                "Should not double-brand message already containing EvanProxy");
    }

    // 3. ItemDatabase synthetic v27 parsing & real cache check if installed
    std::vector<uint8_t> synth = {27, 0, 5, 0, 0, 0};
    auto append_rec = [&](std::vector<uint8_t> rec) {
        synth.insert(synth.end(), rec.begin(), rec.end());
    };
    append_rec(build_synth_item_record(0, 0, 0, "Blank", "tiles_page1.rttex"));
    append_rec(build_synth_item_record(1, 17, 0, "Dirt", "tiles_page1.rttex"));
    append_rec(build_synth_item_record(2, 20, 5, "Pickaxe", "player_hand.rttex"));
    append_rec(build_synth_item_record(3, 20, 6, "Angel Wings", "player_back.rttex"));
    append_rec(build_synth_item_record(4, 107, 5, "Ancestral Tesseract", "player_ances.rttex"));

    evan::ItemDatabase db;
    require(db.parse_bytes(synth.data(), synth.size()), "Synthetic items.dat parse failed");
    require(db.size() == 5, "Synthetic item count mismatch");
    require(db.get_clothing_slot(2) == 5, "Pickaxe slot mismatch");
    require(db.get_clothing_slot(3) == 6, "Angel Wings slot mismatch");
    require(db.get_clothing_slot(4) == 9, "Ancestral Tesseract slot mismatch");
    require(db.get_clothing_slot(1) == -1, "Dirt should not be wearable");
    auto sh_res = db.search("angel", true);
    require(sh_res.size() == 1 && sh_res[0]->id == 3, "ItemDatabase search mismatch");

    evan::ItemDatabase real_db;
    if (real_db.load_default_cache()) {
        require(real_db.size() > 10000, "Real Growtopia items.dat should load >10000 items");
        require(real_db.get_clothing_slot(5480) == 5 &&
                real_db.name_or_fallback(5480).find("Rayman") != std::string::npos,
                "Real items.dat missing Rayman's Fist #5480");
        require(real_db.get_clothing_slot(5080) == 9, "Real items.dat #5080 should map to Ances slot 9");
    }

    // 4. Config round-trip for new branding, rainbow, and title keys
    {
        const auto cfg_path = std::filesystem::temp_directory_path() / "evanproxy_test_cfg2.ini";
        std::error_code ec;
        std::filesystem::remove(cfg_path, ec);
        evan::ProxyConfig wcfg;
        wcfg.title_mentor = true;
        wcfg.title_growroyal_tier = 1;
        wcfg.title_royalwinter = true;
        wcfg.title_thanksgiving = true;
        wcfg.title_anniversary = true;
        wcfg.title_moderator = true;
        wcfg.title_developer = true;
        wcfg.evan_branding = false;
        wcfg.outgoing_evan_prefix = true;
        wcfg.rainbow_name = true;
        require(evan::save_config(cfg_path, wcfg), "save_config failed");
        evan::ProxyConfig rcfg = evan::load_or_create_config(cfg_path);
        std::filesystem::remove(cfg_path, ec);
        require(rcfg.title_mentor && rcfg.title_growroyal_tier == 1 && rcfg.title_royalwinter &&
                rcfg.title_thanksgiving && rcfg.title_anniversary &&
                rcfg.title_moderator && rcfg.title_developer &&
                !rcfg.evan_branding && rcfg.outgoing_evan_prefix && rcfg.rainbow_name,
                "Config round-trip lost new branding/title keys");
    }

    // 5. Visual /clothes + /search BP pick + ItemActivateRequest toggle + /clothes off restore
    {
        evan::Session s;
        s.local_net_id = 1;
        s.player_name = "clo0x";
        s.raw_player_name = "`2clo0x``";
        s.real_clothes.slots[6] = 2390; // Teeny Angel Wings
        s.real_clothes.valid = true;
        s.items_db = &db;
        evan::SharedState sh;

        evan::ui::UiEffects search_eff;
        require(evan::ui::handle_chat_command("/search angel", s, sh, search_eff), "/search not handled");
        require(search_eff.to_client.size() == 1, "/search should open 1 dialog");
        auto s_vl = evan::proto::VariantList::parse(
            search_eff.to_client[0].data() + 4 + sizeof(evan::proto::GameUpdatePacket),
            search_eff.to_client[0].size() - 4 - sizeof(evan::proto::GameUpdatePacket));
        require(s_vl && s_vl->items.size() >= 2 &&
                s_vl->items[1].as_string().find("vpick_3|") != std::string::npos,
                "/search dialog missing vpick_3");

        evan::ui::UiEffects pick_eff;
        evan::proto::TextParse pick_tp("action|dialog_return\ndialog_name|evanproxy_search\nbuttonClicked|vpick_3");
        require(evan::ui::handle_dialog_return(pick_tp, s, sh, pick_eff), "vpick_3 failed");
        require(s.visual_clothes_mode && s.visual_clothes.slots[6] == 3 && s.visual_bp_items.count(3) == 1,
                "Visual clothes equip failed on vpick_3");
        require(pick_eff.to_client.size() >= 3, "vpick_3 should send ModifyItemInventory(+1), OnSetClothing, SFX, msg, dialog");

        evan::ui::UiEffects off_eff;
        require(evan::ui::handle_chat_command("/clothes off", s, sh, off_eff), "/clothes off failed");
        require(!s.visual_clothes_mode && s.visual_bp_items.empty(), "/clothes off did not clean visual BP state");
        require(off_eff.to_client.size() >= 2, "/clothes off should remove BP item & restore OnSetClothing");
    }

    // 6. Live ENet test: Visual BP ItemActivateRequest equip/unequip is swallowed (never leaks to server)
    {
        require(enet_initialize() == 0, "enet_initialize failed");
        ENetAddress srv_addr{};
        enet_address_set_host(&srv_addr, ENET_ADDRESS_TYPE_IPV4, "127.0.0.1");
        srv_addr.port = 0;
        ENetHost* mock_srv = enet_host_create(ENET_ADDRESS_TYPE_IPV4, &srv_addr, 2, 2, 0, 0);
        ENetHost* client = enet_host_create(ENET_ADDRESS_TYPE_IPV4, nullptr, 2, 2, 0, 0);
        require(mock_srv && client, "Failed ENet hosts for visual clothes test");
        require(enet_host_compress_with_range_coder(mock_srv) == 0 &&
                enet_host_compress_with_range_coder(client) == 0, "range coder failed");
        mock_srv->checksum = enet_crc32;
        mock_srv->usingNewPacketForServer = 1;
        client->checksum = enet_crc32;
        client->usingNewPacket = 1;

        const uint16_t srv_port = get_bound_udp_port(mock_srv);
        require(srv_port != 0, "mock_srv port 0");
        mock_srv->address.port = srv_port;

        evan::ProxyConfig pcfg;
        pcfg.local_ip = "127.0.0.1";
        pcfg.enet_port = 17193;
        pcfg.using_new_packet = true;
        pcfg.log_text_packets = false;
        pcfg.log_variants = false;
        pcfg.log_to_file = false;

        evan::SharedState pshared;
        pshared.set_pending_upstream("127.0.0.1", srv_port);

        evan::EnetProxy pproxy(pcfg, pshared);
        std::string p_err;
        bool p_ok = true;
        std::thread p_thread([&]() { p_ok = pproxy.run(p_err); });
        struct PGuard {
            evan::SharedState& s;
            std::thread& t;
            ~PGuard() {
                s.stop_requested.store(true);
                if (t.joinable()) t.join();
            }
        } pguard{pshared, p_thread};

        std::this_thread::sleep_for(std::chrono::milliseconds(120));
        ENetAddress px_addr{};
        enet_address_set_host(&px_addr, ENET_ADDRESS_TYPE_IPV4, "127.0.0.1");
        px_addr.port = pcfg.enet_port;
        ENetPeer* cli_peer = enet_host_connect(client, &px_addr, 2, 0);
        require(cli_peer != nullptr, "cli connect failed");

        ENetPeer* srv_peer = nullptr;
        int srv_item_activate_count = 0;
        int cli_set_clothing_count = 0;
        bool cli_saw_unequipped_zero = false;
        bool cli_saw_equipped_5480 = false;

        auto pump = [&](int ms) {
            auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
            while (std::chrono::steady_clock::now() < deadline) {
                ENetEvent ev{};
                while (enet_host_service(client, &ev, 1) > 0) {
                    if (ev.type == ENET_EVENT_TYPE_RECEIVE) {
                        auto mt = evan::proto::read_message_type(ev.packet->data, ev.packet->dataLength);
                        if (mt && *mt == evan::proto::MessageType::GamePacket &&
                            ev.packet->dataLength >= 4 + sizeof(evan::proto::GameUpdatePacket)) {
                            evan::proto::GameUpdatePacket gp{};
                            std::memcpy(&gp, ev.packet->data + 4, sizeof(gp));
                            if (gp.type == static_cast<uint8_t>(evan::proto::GamePacketType::CallFunction) &&
                                gp.extra_data_size > 0 &&
                                4 + sizeof(gp) + gp.extra_data_size <= ev.packet->dataLength) {
                                auto vl = evan::proto::VariantList::parse(
                                    ev.packet->data + 4 + sizeof(gp), gp.extra_data_size);
                                if (vl && vl->function_name() == "OnSetClothing" && vl->items.size() >= 3) {
                                    ++cli_set_clothing_count;
                                    const auto& p2 = std::get<evan::proto::Vec3>(vl->items[2].value);
                                    if (static_cast<int>(p2.z + 0.5f) == 0) cli_saw_unequipped_zero = true;
                                    if (static_cast<int>(p2.z + 0.5f) == 5480) cli_saw_equipped_5480 = true;
                                }
                            }
                        }
                        enet_packet_destroy(ev.packet);
                    }
                }
                while (enet_host_service(mock_srv, &ev, 1) > 0) {
                    if (ev.type == ENET_EVENT_TYPE_CONNECT) {
                        srv_peer = ev.peer;
                    } else if (ev.type == ENET_EVENT_TYPE_RECEIVE) {
                        auto mt = evan::proto::read_message_type(ev.packet->data, ev.packet->dataLength);
                        if (mt && *mt == evan::proto::MessageType::GamePacket &&
                            ev.packet->dataLength >= 4 + sizeof(evan::proto::GameUpdatePacket)) {
                            evan::proto::GameUpdatePacket gp{};
                            std::memcpy(&gp, ev.packet->data + 4, sizeof(gp));
                            if (gp.type == static_cast<uint8_t>(evan::proto::GamePacketType::ItemActivateRequest)) {
                                ++srv_item_activate_count;
                            }
                        }
                        enet_packet_destroy(ev.packet);
                    }
                }
            }
        };

        for (int i = 0; i < 40 && (!srv_peer || cli_peer->state != ENET_PEER_STATE_CONNECTED); ++i) pump(40);
        require(srv_peer && cli_peer->state == ENET_PEER_STATE_CONNECTED, "Visual clothes ENet handshake failed");

        evan::proto::VariantList spawn_vl;
        spawn_vl.items = {
            evan::proto::Variant::make_string("OnSpawn"),
            evan::proto::Variant::make_string("spawn|avatar\nnetID|1\nuserID|42\nname|`2clo0x``\ncountry|us\ntype|local\n")
        };
        auto sp_pkt = evan::proto::build_call_function_packet(-1, 0, spawn_vl);
        enet_peer_send(srv_peer, 0, enet_packet_create(sp_pkt.data(), sp_pkt.size(), ENET_PACKET_FLAG_RELIABLE));
        pump(100);

        // Apply Rayman preset -> puts 5480 (Hand, slot 5) into visual BP & equips it
        auto preset_cmd = evan::proto::encode_text_packet(
            evan::proto::MessageType::GenericText, "action|input\n|text|/clothes preset rayman");
        enet_peer_send(cli_peer, 0, enet_packet_create(preset_cmd.data(), preset_cmd.size(), ENET_PACKET_FLAG_RELIABLE));
        for (int i = 0; i < 20 && !cli_saw_equipped_5480; ++i) pump(25);
        require(cli_saw_equipped_5480, "Client did not receive OnSetClothing equipping Rayman's Fist #5480");

        // Now simulate player clicking #5480 in BP (ItemActivateRequest) -> must unequip locally & NEVER reach server
        cli_saw_unequipped_zero = false;
        evan::proto::GameUpdatePacket act_gp{};
        act_gp.type = static_cast<uint8_t>(evan::proto::GamePacketType::ItemActivateRequest);
        act_gp.value = 5480;
        auto act_pkt = evan::proto::encode_game_packet(act_gp);
        enet_peer_send(cli_peer, 0, enet_packet_create(act_pkt.data(), act_pkt.size(), ENET_PACKET_FLAG_RELIABLE));
        for (int i = 0; i < 20 && !cli_saw_unequipped_zero; ++i) pump(25);
        require(cli_saw_unequipped_zero, "ItemActivateRequest in Visual Clothes Mode did not unequip #5480");
        require(srv_item_activate_count == 0, "Fake ItemActivateRequest leaked to server!");

        // Click #5480 again -> re-equips #5480 locally
        cli_saw_equipped_5480 = false;
        enet_peer_send(cli_peer, 0, enet_packet_create(act_pkt.data(), act_pkt.size(), ENET_PACKET_FLAG_RELIABLE));
        for (int i = 0; i < 20 && !cli_saw_equipped_5480; ++i) pump(25);
        require(cli_saw_equipped_5480 && srv_item_activate_count == 0,
                "Second ItemActivateRequest failed to re-equip #5480 locally");

        pshared.stop_requested.store(true);
        p_thread.join();
        require(p_ok, "Visual clothes EnetProxy error: " + p_err);
        enet_host_destroy(client);
        enet_host_destroy(mock_srv);
        enet_deinitialize();
    }
}

void test_autobgl_new_titles_hotkeys_and_locks() {
    auto extract_dialog_markup = [](const std::vector<uint8_t>& pkt) -> std::string {
        auto vl = evan::proto::VariantList::parse(
            pkt.data() + 4 + sizeof(evan::proto::GameUpdatePacket),
            pkt.size() - 4 - sizeof(evan::proto::GameUpdatePacket));
        return (vl && vl->items.size() >= 2) ? vl->items[1].as_string() : std::string{};
    };

    // 1. All new & fixed Growtopia 5.62 titles
    {
        evan::Session s;
        s.local_net_id = 1;
        s.raw_player_name = "`2clo0x``";
        s.player_name = "clo0x";
        s.country = "us";
        evan::SharedState sh;

        evan::ui::UiEffects eff;
        require(evan::ui::handle_chat_command("/title 10y", s, sh, eff), "/title 10y failed");
        require(s.title_anniversary && s.compose_display_name().find("\xC4\xA8") != std::string::npos,
                "10-Year Anniversary should use Party Popper UTF-8 glyph");

        eff = {};
        require(evan::ui::handle_chat_command("/title reset", s, sh, eff), "/title reset failed");
        require(evan::ui::handle_chat_command("/title award", s, sh, eff), "/title award failed");
        require(s.title_award && s.compose_display_name().find("\xC5\x84") != std::string::npos,
                "Award-Winning should use Trophy glyph");

        eff = {};
        require(evan::ui::handle_chat_command("/title reset", s, sh, eff), "/title reset failed");
        require(evan::ui::handle_chat_command("/title party", s, sh, eff), "/title party failed");
        const std::string party_dn = s.compose_display_name();
        require(s.title_party && party_dn.find("`5c`9l`2o`50`9x") != std::string::npos,
                "Party Animal per-letter rainbow mismatch: " + party_dn);

        eff = {};
        require(evan::ui::handle_chat_command("/title reset", s, sh, eff), "/title reset failed");
        require(evan::ui::handle_chat_command("/title winter", s, sh, eff), "/title winter failed");
        require(s.title_royalwinter && s.needs_animated_name() &&
                s.compose_display_name().find("\xC4\xA6") != std::string::npos,
                "Royal Winter should use animated Fireworks/Shooting Star glyph");

        eff = {};
        require(evan::ui::handle_chat_command("/title reset", s, sh, eff), "/title reset failed");
        require(evan::ui::handle_chat_command("/title silverroyal", s, sh, eff), "/title silverroyal failed");
        require(s.title_growroyal_tier == 2 && s.compose_display_name().find("`w//") != std::string::npos,
                "Silver Grow Royal mismatch");
        require(evan::ui::handle_chat_command("/title bronzeroyal", s, sh, eff), "/title bronzeroyal failed");
        require(s.title_growroyal_tier == 3 && s.compose_display_name().find("`4//") != std::string::npos,
                "Bronze Grow Royal mismatch");
        require(evan::ui::handle_chat_command("/title goldroyal", s, sh, eff), "/title goldroyal failed");
        require(s.title_growroyal_tier == 1 && s.compose_display_name().find("\xC4\xAE//") != std::string::npos,
                "Gold Grow Royal mismatch");

        eff = {};
        require(evan::ui::handle_chat_command("/title cc", s, sh, eff), "/title cc failed");
        require(s.title_cc_badge && s.compose_country_state().rfind("ccBadge", 0) == 0,
                "Content Creator badge flag mismatch: " + s.compose_country_state());
        require(evan::ui::handle_chat_command("/title tiktok", s, sh, eff), "/title tiktok failed");
        require(s.title_tt_badge && !s.title_cc_badge &&
                s.compose_country_state().rfind("ttBadge", 0) == 0,
                "TikTok badge flag mismatch: " + s.compose_country_state());

        eff = {};
        require(evan::ui::handle_chat_command("/title pblorg", s, sh, eff), "/title pblorg failed");
        require(s.title_pbl_role == 1 && s.compose_display_name().find("[PBL Organizer]") != std::string::npos,
                "PBL Organizer mismatch");
        require(evan::ui::handle_chat_command("/title pblmod", s, sh, eff), "/title pblmod failed");
        require(s.title_pbl_role == 2 && s.compose_display_name().find("[PBL Mod]") != std::string::npos,
                "PBL Mod mismatch");

        eff = {};
        require(evan::ui::handle_chat_command("/title reset", s, sh, eff), "/title reset failed");
        require(evan::ui::handle_chat_command("/title imortal", s, sh, eff), "/title imortal alias failed");
        const std::string imm_cs = s.compose_country_state();
        require(s.title_immortal && imm_cs == "lg|maxLevel" &&
                (s.effective_aura_bits() & 32768u) != 0 &&
                s.compose_display_name().find("\xC4\xBE") != std::string::npos,
                "Immortal title mismatch: cs=" + imm_cs);
    }

    // 2. Redesigned dialogs, unified top nav bar, /hotkey, /autobgl, /change, /convert, & lock planner
    {
        evan::Session s;
        s.local_net_id = 1;
        s.player_name = "clo0x";
        s.inventory[242] = 150;
        s.inventory[1796] = 5;
        s.inventory[7188] = 1;
        evan::SharedState sh;

        const std::string home_dlg = evan::ui::build_home_dialog(s, sh);
        require(home_dlg.find("nav_go_nav") != std::string::npos &&
                home_dlg.find("nav_go_hotkeys") != std::string::npos &&
                home_dlg.find("END_LIST") != std::string::npos,
                "Home dialog missing 5-icon Quick Bar");
        for (const std::string& dlg : {
                 evan::ui::build_title_dialog(s),
                 evan::ui::build_hotkeys_dialog(s),
                 evan::ui::build_tools_dialog(s),
                 evan::ui::build_visual_dialog(s),
                 evan::ui::build_clothes_dialog(s)}) {
            require(dlg.find("nav_go_home") != std::string::npos &&
                    dlg.find("end_dialog|") != std::string::npos,
                    "Sub-page dialog missing back-to-dashboard control");
        }

        evan::ui::UiEffects hk_eff;
        require(evan::ui::handle_chat_command("/hotkey", s, sh, hk_eff) &&
                hk_eff.to_client.size() == 1 &&
                extract_dialog_markup(hk_eff.to_client[0]).find("end_dialog|evanproxy_hotkeys|") != std::string::npos,
                "/hotkey dialog mismatch");

        evan::ui::UiEffects ab_eff;
        require(evan::ui::handle_chat_command("/autobgl", s, sh, ab_eff) && s.auto_bgl && ab_eff.save_config,
                "/autobgl toggle failed");
        ab_eff = {};
        require(evan::ui::handle_chat_command("/change", s, sh, ab_eff) && !s.auto_bgl && ab_eff.save_config,
                "/change alias toggle failed");

        evan::ui::UiEffects cv_eff;
        require(evan::ui::handle_chat_command("/convert", s, sh, cv_eff) && !cv_eff.to_server.empty(),
                "/convert should send ItemActivateRequest");
        require(cv_eff.to_server[0].size() >= 4 + sizeof(evan::proto::GameUpdatePacket), "Convert packet too short");
        evan::proto::GameUpdatePacket cgp{};
        std::memcpy(&cgp, cv_eff.to_server[0].data() + 4, sizeof(cgp));
        require(cgp.type == static_cast<uint8_t>(evan::proto::GamePacketType::ItemActivateRequest) &&
                cgp.value == 242, "/convert must activate WL #242");

        std::vector<evan::PlannedDrop> plan;
        std::string perr;
        require(evan::plan_lock_drops(10250, 150, 5, 1, plan, perr), "plan_lock_drops failed: " + perr);
        require(plan.size() == 3 &&
                !plan[0].activate && plan[0].item_id == 7188 && plan[0].count == 1 &&
                !plan[1].activate && plan[1].item_id == 1796 && plan[1].count == 2 &&
                !plan[2].activate && plan[2].item_id == 242 && plan[2].count == 50,
                "plan_lock_drops breakdown mismatch");
        std::vector<evan::PlannedDrop> shatter_plan;
        require(evan::plan_lock_drops(10250, 10, 5, 1, shatter_plan, perr),
                "plan_lock_drops should succeed by breaking 1 DL into 100 WL");
        bool has_dl_activate = false;
        for (const auto& step : shatter_plan) {
            if (step.activate && step.item_id == 1796) {
                has_dl_activate = true;
            }
        }
        require(has_dl_activate, "plan_lock_drops missing DL activate step when WL change is short");
        require(!evan::plan_lock_drops(20000, 10, 5, 1, plan, perr),
                "plan_lock_drops should fail when total wealth is insufficient");

        // Config round-trip + legacy title_growroyal=true migration
        const auto cfg_path = std::filesystem::temp_directory_path() / "evanproxy_test_cfg3.ini";
        std::error_code ec;
        std::filesystem::remove(cfg_path, ec);
        evan::ProxyConfig wcfg;
        wcfg.auto_bgl = true;
        wcfg.hotkeys_enabled = false;
        wcfg.title_award = true;
        wcfg.title_party = true;
        wcfg.title_growroyal_tier = 2;
        wcfg.title_cc_badge = true;
        wcfg.title_pbl_role = 1;
        wcfg.title_immortal = true;
        require(evan::save_config(cfg_path, wcfg), "save_config v3 failed");
        evan::ProxyConfig rcfg = evan::load_or_create_config(cfg_path);
        require(rcfg.auto_bgl && !rcfg.hotkeys_enabled && rcfg.title_award &&
                rcfg.title_party && rcfg.title_growroyal_tier == 2 &&
                rcfg.title_cc_badge && rcfg.title_pbl_role == 1 && rcfg.title_immortal,
                "Config v3 round-trip mismatch");

        {
            std::ofstream leg(cfg_path, std::ios::trunc);
            leg << "[features]\ntitle_growroyal=true\n";
        }
        evan::ProxyConfig lcfg = evan::load_or_create_config(cfg_path);
        std::filesystem::remove(cfg_path, ec);
        require(lcfg.title_growroyal_tier == 1, "Legacy title_growroyal=true migration failed");
    }

    // 3. Live ENet test: Auto-BGL 3-step Telephone exchange, insufficient DL handling, & exact /wl drop
    {
        require(enet_initialize() == 0, "enet_initialize failed");
        ENetAddress srv_addr{};
        enet_address_set_host(&srv_addr, ENET_ADDRESS_TYPE_IPV4, "127.0.0.1");
        srv_addr.port = 0;
        ENetHost* mock_srv = enet_host_create(ENET_ADDRESS_TYPE_IPV4, &srv_addr, 2, 2, 0, 0);
        ENetHost* client = enet_host_create(ENET_ADDRESS_TYPE_IPV4, nullptr, 2, 2, 0, 0);
        require(mock_srv && client, "Failed creating ENet hosts for auto-BGL test");
        require(enet_host_compress_with_range_coder(mock_srv) == 0 &&
                enet_host_compress_with_range_coder(client) == 0, "range coder failed");
        mock_srv->checksum = enet_crc32;
        mock_srv->usingNewPacketForServer = 1;
        client->checksum = enet_crc32;
        client->usingNewPacket = 1;

        const uint16_t srv_port = get_bound_udp_port(mock_srv);
        require(srv_port != 0, "mock_srv bound port 0");
        mock_srv->address.port = srv_port;

        evan::ProxyConfig pcfg;
        pcfg.local_ip = "127.0.0.1";
        pcfg.enet_port = 17194;
        pcfg.using_new_packet = true;
        pcfg.log_text_packets = false;
        pcfg.log_variants = false;
        pcfg.log_to_file = false;
        pcfg.auto_bgl = true;

        evan::SharedState pshared;
        pshared.set_pending_upstream("127.0.0.1", srv_port);

        evan::EnetProxy pproxy(pcfg, pshared);
        std::string p_err;
        bool p_ok = true;
        std::thread p_thread([&]() { p_ok = pproxy.run(p_err); });
        struct PGuard {
            evan::SharedState& s;
            std::thread& t;
            ~PGuard() {
                s.stop_requested.store(true);
                if (t.joinable()) t.join();
            }
        } pguard{pshared, p_thread};

        std::this_thread::sleep_for(std::chrono::milliseconds(120));
        ENetAddress px_addr{};
        enet_address_set_host(&px_addr, ENET_ADDRESS_TYPE_IPV4, "127.0.0.1");
        px_addr.port = pcfg.enet_port;
        ENetPeer* cli_peer = enet_host_connect(client, &px_addr, 2, 0);
        require(cli_peer != nullptr, "cli connect failed");

        ENetPeer* srv_peer = nullptr;
        int cli_phone_dialog_leaks = 0;
        bool cli_got_bgl_success = false;
        bool cli_got_bgl_fail = false;
        bool srv_got_dial_53785 = false;
        bool srv_got_chc5 = false;
        bool srv_got_chc0 = false;
        bool srv_got_drop_req_242 = false;
        bool srv_got_drop_return_25 = false;

        auto pump = [&](int ms) {
            auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
            while (std::chrono::steady_clock::now() < deadline) {
                ENetEvent ev{};
                while (enet_host_service(client, &ev, 1) > 0) {
                    if (ev.type == ENET_EVENT_TYPE_RECEIVE) {
                        auto mt = evan::proto::read_message_type(ev.packet->data, ev.packet->dataLength);
                        if (mt && *mt == evan::proto::MessageType::GamePacket &&
                            ev.packet->dataLength >= 4 + sizeof(evan::proto::GameUpdatePacket)) {
                            evan::proto::GameUpdatePacket gp{};
                            std::memcpy(&gp, ev.packet->data + 4, sizeof(gp));
                            if (gp.type == static_cast<uint8_t>(evan::proto::GamePacketType::CallFunction) &&
                                gp.extra_data_size > 0 &&
                                4 + sizeof(gp) + gp.extra_data_size <= ev.packet->dataLength) {
                                auto vl = evan::proto::VariantList::parse(
                                    ev.packet->data + 4 + sizeof(gp), gp.extra_data_size);
                                if (vl && vl->function_name() == "OnDialogRequest" && vl->items.size() >= 2) {
                                    const std::string mk = vl->items[1].as_string();
                                    if (mk.find("phonecall") != std::string::npos ||
                                        mk.find("drop_item") != std::string::npos) {
                                        ++cli_phone_dialog_leaks;
                                    }
                                } else if (vl && vl->function_name() == "OnConsoleMessage" && vl->items.size() >= 2) {
                                    const std::string cm = vl->items[1].as_string();
                                    if (cm.find("Auto-BGL Berhasil") != std::string::npos) cli_got_bgl_success = true;
                                    if (cm.find("Butuh minimal") != std::string::npos) cli_got_bgl_fail = true;
                                }
                            }
                        }
                        enet_packet_destroy(ev.packet);
                    }
                }
                while (enet_host_service(mock_srv, &ev, 1) > 0) {
                    if (ev.type == ENET_EVENT_TYPE_CONNECT) {
                        srv_peer = ev.peer;
                    } else if (ev.type == ENET_EVENT_TYPE_RECEIVE) {
                        std::string txt = evan::proto::decode_text_payload(ev.packet->data, ev.packet->dataLength);
                        if (txt.find("dialog_name|phonecall") != std::string::npos &&
                            txt.find("dial|53785") != std::string::npos) {
                            srv_got_dial_53785 = true;
                        }
                        if (txt.find("dialog_name|phonecall") != std::string::npos &&
                            txt.find("buttonClicked|chc5") != std::string::npos) {
                            srv_got_chc5 = true;
                        }
                        if (txt.find("dialog_name|phonecall") != std::string::npos &&
                            txt.find("buttonClicked|chc0") != std::string::npos) {
                            srv_got_chc0 = true;
                        }
                        if (txt.find("action|drop") != std::string::npos &&
                            txt.find("itemID|242") != std::string::npos) {
                            srv_got_drop_req_242 = true;
                        }
                        if (txt.find("dialog_name|drop_item") != std::string::npos &&
                            txt.find("itemID|242") != std::string::npos &&
                            txt.find("count|25") != std::string::npos) {
                            srv_got_drop_return_25 = true;
                        }
                        enet_packet_destroy(ev.packet);
                    }
                }
            }
        };

        for (int i = 0; i < 40 && (!srv_peer || cli_peer->state != ENET_PEER_STATE_CONNECTED); ++i) pump(40);
        require(srv_peer && cli_peer->state == ENET_PEER_STATE_CONNECTED, "Auto-BGL ENet handshake failed");

        auto sp_pkt = evan::proto::build_call_function_packet(-1, 0, evan::proto::VariantList{
            {evan::proto::Variant::make_string("OnSpawn"),
             evan::proto::Variant::make_string("spawn|avatar\nnetID|1\nuserID|42\nname|`2clo0x``\ncountry|us\ntype|local\n")}
        });
        enet_peer_send(srv_peer, 0, enet_packet_create(sp_pkt.data(), sp_pkt.size(), ENET_PACKET_FLAG_RELIABLE));
        pump(80);

        // Full 3-step Auto-BGL exchange
        auto phone1 = evan::proto::build_on_dialog_request(
            "set_default_color|`o\nadd_label_with_icon|big|`wTelephone``|left|3898|\n"
            "embed_data|tilex|49\nembed_data|tiley|48\nembed_data|num|-2\n"
            "add_text_input|dial|Phone #||5|\nend_dialog|phonecall|Hang Up|Dial|\n");
        enet_peer_send(srv_peer, 0, enet_packet_create(phone1.data(), phone1.size(), ENET_PACKET_FLAG_RELIABLE));
        for (int i = 0; i < 20 && !srv_got_dial_53785; ++i) pump(25);
        require(srv_got_dial_53785, "Auto-BGL did not dial 53785");

        auto phone2 = evan::proto::build_on_dialog_request(
            "set_default_color|`o\nadd_label_with_icon|big|`wSales-Man``|left|4358|\n"
            "embed_data|tilex|49\nembed_data|tiley|48\nembed_data|num|53785\n"
            "add_button|chc5|Blue Gem Lock|noflags|0|0|0\nend_dialog|phonecall|Hang Up||\n");
        enet_peer_send(srv_peer, 0, enet_packet_create(phone2.data(), phone2.size(), ENET_PACKET_FLAG_RELIABLE));
        for (int i = 0; i < 20 && !srv_got_chc5; ++i) pump(25);
        require(srv_got_chc5, "Auto-BGL did not click chc5");

        auto phone3 = evan::proto::build_on_dialog_request(
            "set_default_color|`o\nadd_label_with_icon|big|`wBlue Gem Lock``|left|7188|\n"
            "embed_data|tilex|49\nembed_data|tiley|48\nembed_data|num|-34\n"
            "add_button|chc0|Trade 100 Diamond Lock|noflags|0|0|0\nend_dialog|phonecall|Hang Up||\n");
        enet_peer_send(srv_peer, 0, enet_packet_create(phone3.data(), phone3.size(), ENET_PACKET_FLAG_RELIABLE));
        for (int i = 0; i < 20 && !srv_got_chc0; ++i) pump(25);
        require(srv_got_chc0, "Auto-BGL did not click chc0");

        auto phone4 = evan::proto::build_on_dialog_request(
            "set_default_color|`o\nadd_label_with_icon|big|`wBlue Gem Lock``|left|7188|\n"
            "add_textbox|Thanks!|\nend_dialog|phonecall|Hang Up||\n");
        enet_peer_send(srv_peer, 0, enet_packet_create(phone4.data(), phone4.size(), ENET_PACKET_FLAG_RELIABLE));
        for (int i = 0; i < 20 && !cli_got_bgl_success; ++i) pump(25);
        require(cli_got_bgl_success, "Client did not receive Auto-BGL success console toast");

        // Insufficient DL path on next phone click
        srv_got_dial_53785 = false;
        srv_got_chc5 = false;
        enet_peer_send(srv_peer, 0, enet_packet_create(phone1.data(), phone1.size(), ENET_PACKET_FLAG_RELIABLE));
        for (int i = 0; i < 20 && !srv_got_dial_53785; ++i) pump(25);
        enet_peer_send(srv_peer, 0, enet_packet_create(phone2.data(), phone2.size(), ENET_PACKET_FLAG_RELIABLE));
        for (int i = 0; i < 20 && !srv_got_chc5; ++i) pump(25);
        auto phone3_no_dl = evan::proto::build_on_dialog_request(
            "set_default_color|`o\nadd_label_with_icon|big|`wBlue Gem Lock``|left|7188|\n"
            "embed_data|tilex|49\nembed_data|tiley|48\nembed_data|num|-34\n"
            "add_textbox|Excellent! I'm happy to sell you a Blue Gem Lock in exchange for 100 Diamond Lock..|left|\n"
            "add_button|chc1|Back|noflags|0|0|0\nend_dialog|phonecall|Hang Up||\n");
        enet_peer_send(srv_peer, 0, enet_packet_create(phone3_no_dl.data(), phone3_no_dl.size(), ENET_PACKET_FLAG_RELIABLE));
        for (int i = 0; i < 20 && !cli_got_bgl_fail; ++i) pump(25);
        require(cli_got_bgl_fail, "Client did not receive Auto-BGL insufficient DL notification");

        // Planned /wl 25 drop flow
        auto wl_cmd = evan::proto::encode_text_packet(
            evan::proto::MessageType::GenericText, "action|input\n|text|/wl 25");
        enet_peer_send(cli_peer, 0, enet_packet_create(wl_cmd.data(), wl_cmd.size(), ENET_PACKET_FLAG_RELIABLE));
        for (int i = 0; i < 25 && !srv_got_drop_req_242; ++i) pump(25);
        require(srv_got_drop_req_242, "/wl 25 did not emit action|drop|242");

        auto drop_dlg = evan::proto::build_on_dialog_request(
            "set_default_color|`o\nadd_label_with_icon|big|`wDrop World Lock``|left|242|\n"
            "embed_data|itemID|242\nadd_text_input|count||100|5|\nend_dialog|drop_item|Cancel|OK|\n");
        enet_peer_send(srv_peer, 0, enet_packet_create(drop_dlg.data(), drop_dlg.size(), ENET_PACKET_FLAG_RELIABLE));
        for (int i = 0; i < 25 && !srv_got_drop_return_25; ++i) pump(25);
        require(srv_got_drop_return_25, "Proxy did not reply with exact count|25 for /wl 25");
        require(cli_phone_dialog_leaks == 0, "Automated phonecall or drop_item dialog leaked to client!");

        pshared.stop_requested.store(true);
        p_thread.join();
        require(p_ok, "Auto-BGL EnetProxy error: " + p_err);
        enet_host_destroy(client);
        enet_host_destroy(mock_srv);
        enet_deinitialize();
    }
}

void test_custom_hotkeys_smart_cd_and_fastbuy() {
    // 1. Smart /cd lock breakdown across WL, DL, and BGL conversions
    {
        std::vector<evan::PlannedDrop> plan;
        std::string err;

        // 102 WL from (28 WL, 1 DL, 0 BGL) -> direct 1 DL + 2 WL
        require(evan::plan_lock_drops(102, 28, 1, 0, plan, err), "cd 102 direct failed: " + err);
        require(plan.size() == 2 &&
                !plan[0].activate && plan[0].item_id == 1796 && plan[0].count == 1 &&
                !plan[1].activate && plan[1].item_id == 242 && plan[1].count == 2,
                "cd 102 direct mismatch");

        // 102 WL from (128 WL, 0 DL, 0 BGL) -> convert 100 WL -> 1 DL, drop 1 DL + 2 WL
        require(evan::plan_lock_drops(102, 128, 0, 0, plan, err), "cd 102 wl->dl failed: " + err);
        require(plan.size() == 3 &&
                plan[0].activate && plan[0].item_id == 242 &&
                !plan[1].activate && plan[1].item_id == 1796 && plan[1].count == 1 &&
                !plan[2].activate && plan[2].item_id == 242 && plan[2].count == 2,
                "cd 102 wl->dl plan mismatch");

        // 102 WL from (0 WL, 2 DL, 0 BGL) -> break 1 DL -> 100 WL, drop 1 DL + 2 WL
        require(evan::plan_lock_drops(102, 0, 2, 0, plan, err), "cd 102 dl->wl failed: " + err);
        require(plan.size() == 3 &&
                plan[0].activate && plan[0].item_id == 1796 &&
                !plan[1].activate && plan[1].item_id == 1796 && plan[1].count == 1 &&
                !plan[2].activate && plan[2].item_id == 242 && plan[2].count == 2,
                "cd 102 dl->wl plan mismatch");

        // 50 WL from (0 WL, 1 DL, 0 BGL) -> break 1 DL -> 100 WL, drop 50 WL
        require(evan::plan_lock_drops(50, 0, 1, 0, plan, err), "cd 50 dl->wl failed: " + err);
        require(plan.size() == 2 &&
                plan[0].activate && plan[0].item_id == 1796 &&
                !plan[1].activate && plan[1].item_id == 242 && plan[1].count == 50,
                "cd 50 dl->wl plan mismatch");

        // 102 WL from (0 WL, 0 DL, 1 BGL) -> break 1 BGL -> 100 DL, break 1 DL -> 100 WL, drop 1 DL + 2 WL
        require(evan::plan_lock_drops(102, 0, 0, 1, plan, err), "cd 102 bgl->dl->wl failed: " + err);
        require(plan.size() == 4 &&
                plan[0].activate && plan[0].item_id == 7188 &&
                plan[1].activate && plan[1].item_id == 1796 &&
                !plan[2].activate && plan[2].item_id == 1796 && plan[2].count == 1 &&
                !plan[3].activate && plan[3].item_id == 242 && plan[3].count == 2,
                "cd 102 bgl->dl->wl plan mismatch");
    }

    // 2. Custom /hotkey parsing, editor UI flow, capture, execution, and INI persistence
    {
        auto hk_a = evan::parse_hotkey("a");
        require(hk_a && !hk_a->ctrl && !hk_a->alt && hk_a->vk == 'A' && evan::format_hotkey(*hk_a) == "A",
                "parse_hotkey('a') failed");
        auto hk_ca = evan::parse_hotkey("ctrl + a");
        require(hk_ca && hk_ca->ctrl && hk_ca->vk == 'A' && evan::format_hotkey(*hk_ca) == "CTRL+A",
                "parse_hotkey('ctrl + a') failed");
        auto hk_f1 = evan::parse_hotkey("F1");
        require(hk_f1 && hk_f1->vk == VK_F1 && evan::format_hotkey(*hk_f1) == "F1",
                "parse_hotkey('F1') failed");

        evan::Session s;
        evan::SharedState sh;
        evan::ui::UiEffects fx;
        require(s.hotkeys.size() == evan::kHotkeySlots && evan::kHotkeySlots == 12,
                "Default hotkey slots should be 12");

        require(evan::ui::handle_dialog_return(
                    evan::proto::TextParse("action|dialog_return\ndialog_name|evanproxy_hotkeys\nbuttonClicked|hk_edit_0\n"),
                    s, sh, fx),
                "hk_edit_0 should be handled");
        require(!fx.to_client.empty() && s.hk_edit_slot == 0, "hk_edit_0 should open slot 0 editor");

        fx = {};
        require(evan::ui::handle_dialog_return(
                    evan::proto::TextParse("action|dialog_return\ndialog_name|evanproxy_hk_edit\nhk_slot|0\nhk_key_input|A\nhk_cmd_input|/warp clunxz\n"),
                    s, sh, fx),
                "evanproxy_hk_edit submit should succeed");
        require(s.hotkeys[0].key == "A" && s.hotkeys[0].command == "/warp clunxz",
                "Slot 0 hotkey should save key A -> /warp clunxz");

        s.hk_capture_slot = 0;
        fx = {};
        evan::ui::hotkey_capture_finish(s, "CTRL+A", fx);
        require(s.hotkeys[0].key == "CTRL+A" && fx.save_config, "hotkey_capture_finish failed");

        fx = {};
        evan::ui::run_hotkey_command(s.hotkeys[0].command, s, sh, fx);
        require(fx.trigger_warp.has_value() && fx.trigger_warp->first == "CLUNXZ",
                "run_hotkey_command('/warp clunxz') did not trigger warp");

        // Config round-trip
        evan::ProxyConfig cfg;
        s.fast_buy = 2;
        s.fast_buy_qty = 2;
        s.vending_info = false;
        s.export_to_config(cfg);
        const std::filesystem::path cfg_path =
            std::filesystem::temp_directory_path() / "evanproxy_test_hk_fb.ini";
        require(evan::save_config(cfg_path, cfg), "Save hotkey config failed");
        evan::ProxyConfig loaded = evan::load_or_create_config(cfg_path);
        std::error_code ec;
        std::filesystem::remove(cfg_path, ec);
        require(loaded.fast_buy == 2 && loaded.fast_buy_qty == 2 && !loaded.vending_info &&
                loaded.hotkeys.size() == evan::kHotkeySlots &&
                loaded.hotkeys[0].key == "CTRL+A" && loaded.hotkeys[0].command == "/warp clunxz",
                "Hotkey/FastBuy config round-trip mismatch");

        // UI truncation guard: no accidental inner '|' in add_smalltext / add_textbox / add_checkbox texts
        for (const std::string& dlg : {
                 evan::ui::build_home_dialog(s, sh),
                 evan::ui::build_hotkeys_dialog(s),
                 evan::ui::build_hotkey_edit_dialog(s, 0),
                 evan::ui::build_tools_dialog(s),
                 evan::ui::build_title_dialog(s),
                 evan::ui::build_visual_dialog(s),
                 evan::ui::build_clothes_dialog(s)}) {
            std::istringstream iss(dlg);
            std::string line;
            while (std::getline(iss, line)) {
                size_t pipe_count = static_cast<size_t>(std::count(line.begin(), line.end(), '|'));
                if (line.rfind("add_smalltext|", 0) == 0 || line.rfind("add_textbox|", 0) == 0) {
                    require(pipe_count == 3, "Inner pipe found in text dialog line: " + line);
                } else if (line.rfind("add_checkbox|", 0) == 0) {
                    require(pipe_count == 4, "Inner pipe found in checkbox dialog line: " + line);
                }
            }
        }
    }

    // 3. Vending parser unit check
    {
        const std::string vend_markup =
            "set_default_color|`o\n"
            "add_label_with_icon|big|`wDigiVend Machine``|left|9268|\n"
            "embed_data|tilex|14\n"
            "embed_data|tiley|22\n"
            "add_label_with_icon|sml|The machine contains a total of 324 `2Fairy Dress``.|left|2924|\n"
            "add_textbox|You have 128 World Locks.|left|\n"
            "add_text_input|buycount|`wBuy how many? (3 WL each)|0|3|\n"
            "embed_data|expectprice|3\n"
            "embed_data|expectitem|2924\n"
            "end_dialog|vending|Close|Buy|\n";
        auto offer = evan::parse_vending_dialog(vend_markup);
        require(offer && offer->tilex == 14 && offer->tiley == 22 &&
                offer->item_id == 2924 && offer->price == 3 &&
                offer->stock == 324 && offer->wl_have == 128 &&
                evan::vending_max_buy(*offer) == 42,
                "parse_vending_dialog / max_buy mismatch");
    }

    // 4. Live ENet test: smart /cd 102 DL shatter + Fast Buy Auto + Private Local Stock/WL Notice
    {
        require(enet_initialize() == 0, "enet_initialize failed");
        ENetAddress srv_addr{};
        enet_address_set_host(&srv_addr, ENET_ADDRESS_TYPE_IPV4, "127.0.0.1");
        srv_addr.port = 0;
        ENetHost* mock_srv = enet_host_create(ENET_ADDRESS_TYPE_IPV4, &srv_addr, 2, 2, 0, 0);
        ENetHost* client = enet_host_create(ENET_ADDRESS_TYPE_IPV4, nullptr, 2, 2, 0, 0);
        require(mock_srv && client, "Failed creating ENet hosts for fastbuy test");
        require(enet_host_compress_with_range_coder(mock_srv) == 0 &&
                enet_host_compress_with_range_coder(client) == 0, "range coder failed");
        mock_srv->checksum = enet_crc32;
        mock_srv->usingNewPacketForServer = 1;
        client->checksum = enet_crc32;
        client->usingNewPacket = 1;

        const uint16_t srv_port = get_bound_udp_port(mock_srv);
        require(srv_port != 0, "mock_srv bound port 0");
        mock_srv->address.port = srv_port;

        evan::ProxyConfig pcfg;
        pcfg.local_ip = "127.0.0.1";
        pcfg.enet_port = 17195;
        pcfg.using_new_packet = true;
        pcfg.log_text_packets = false;
        pcfg.log_variants = false;
        pcfg.log_to_file = false;
        pcfg.fast_buy = 2;
        pcfg.fast_buy_qty = 2;
        pcfg.vending_info = true;

        evan::SharedState pshared;
        pshared.set_pending_upstream("127.0.0.1", srv_port);

        evan::EnetProxy pproxy(pcfg, pshared);
        std::string p_err;
        bool p_ok = true;
        std::thread p_thread([&]() { p_ok = pproxy.run(p_err); });
        struct PGuard {
            evan::SharedState& s;
            std::thread& t;
            ~PGuard() {
                s.stop_requested.store(true);
                if (t.joinable()) t.join();
            }
        } pguard{pshared, p_thread};

        std::this_thread::sleep_for(std::chrono::milliseconds(120));
        ENetAddress px_addr{};
        enet_address_set_host(&px_addr, ENET_ADDRESS_TYPE_IPV4, "127.0.0.1");
        px_addr.port = pcfg.enet_port;
        ENetPeer* cli_peer = enet_host_connect(client, &px_addr, 2, 0);
        require(cli_peer != nullptr, "cli connect failed");

        auto make_inv_packet = [](uint8_t wl, uint8_t dl) {
            std::vector<uint8_t> extra;
            auto pu8 = [&](uint8_t v) { extra.push_back(v); };
            auto pu16 = [&](uint16_t v) {
                extra.push_back(static_cast<uint8_t>(v & 0xFF));
                extra.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
            };
            auto pu32 = [&](uint32_t v) {
                for (int i = 0; i < 4; ++i) extra.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
            };
            pu8(1);
            pu32(20);
            pu16(2);
            pu16(242); pu8(wl); pu8(0);
            pu16(1796); pu8(dl); pu8(0);

            evan::proto::GameUpdatePacket gp{};
            gp.type = static_cast<uint8_t>(evan::proto::GamePacketType::SendInventoryState);
            gp.flags = evan::proto::PACKET_FLAG_EXTENDED;
            gp.extra_data_size = static_cast<uint32_t>(extra.size());

            std::vector<uint8_t> pkt(4 + sizeof(gp) + extra.size(), 0);
            const uint32_t mt = static_cast<uint32_t>(evan::proto::MessageType::GamePacket);
            std::memcpy(pkt.data(), &mt, 4);
            std::memcpy(pkt.data() + 4, &gp, sizeof(gp));
            std::memcpy(pkt.data() + 4 + sizeof(gp), extra.data(), extra.size());
            return pkt;
        };

        ENetPeer* srv_peer = nullptr;
        int cli_vend_dialog_leaks = 0;
        bool cli_got_private_vend_info = false;
        bool srv_got_dl_activate = false;
        bool srv_got_drop_req_1796 = false;
        bool srv_got_drop_dl = false;
        bool srv_got_drop_req_242 = false;
        bool srv_got_drop_wl = false;
        bool srv_got_vend_buycount = false;
        bool srv_got_vend_verify = false;

        auto pump = [&](int ms) {
            auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
            while (std::chrono::steady_clock::now() < deadline) {
                ENetEvent ev{};
                while (enet_host_service(client, &ev, 1) > 0) {
                    if (ev.type == ENET_EVENT_TYPE_RECEIVE) {
                        auto mt = evan::proto::read_message_type(ev.packet->data, ev.packet->dataLength);
                        if (mt && *mt == evan::proto::MessageType::GamePacket &&
                            ev.packet->dataLength >= 4 + sizeof(evan::proto::GameUpdatePacket)) {
                            evan::proto::GameUpdatePacket gp{};
                            std::memcpy(&gp, ev.packet->data + 4, sizeof(gp));
                            if (gp.type == static_cast<uint8_t>(evan::proto::GamePacketType::CallFunction) &&
                                gp.extra_data_size > 0 &&
                                4 + sizeof(gp) + gp.extra_data_size <= ev.packet->dataLength) {
                                auto vl = evan::proto::VariantList::parse(
                                    ev.packet->data + 4 + sizeof(gp), gp.extra_data_size);
                                if (vl && vl->function_name() == "OnDialogRequest" && vl->items.size() >= 2) {
                                    const std::string mk = vl->items[1].as_string();
                                    if (mk.find("end_dialog|vending|") != std::string::npos) {
                                        ++cli_vend_dialog_leaks;
                                    }
                                } else if (vl && vl->function_name() == "OnConsoleMessage" && vl->items.size() >= 2) {
                                    const std::string cm = vl->items[1].as_string();
                                    if (cm.find("[Vending Privat]") != std::string::npos &&
                                        cm.find("322") != std::string::npos &&
                                        cm.find("122 WL") != std::string::npos) {
                                        cli_got_private_vend_info = true;
                                    }
                                }
                            }
                        }
                        enet_packet_destroy(ev.packet);
                    }
                }
                while (enet_host_service(mock_srv, &ev, 1) > 0) {
                    if (ev.type == ENET_EVENT_TYPE_CONNECT) {
                        srv_peer = ev.peer;
                    } else if (ev.type == ENET_EVENT_TYPE_RECEIVE) {
                        auto mt = evan::proto::read_message_type(ev.packet->data, ev.packet->dataLength);
                        if (mt && *mt == evan::proto::MessageType::GamePacket &&
                            ev.packet->dataLength >= 4 + sizeof(evan::proto::GameUpdatePacket)) {
                            evan::proto::GameUpdatePacket gp{};
                            std::memcpy(&gp, ev.packet->data + 4, sizeof(gp));
                            if (gp.type == static_cast<uint8_t>(evan::proto::GamePacketType::ItemActivateRequest) &&
                                gp.value == 1796) {
                                srv_got_dl_activate = true;
                            }
                        } else {
                            std::string txt = evan::proto::decode_text_payload(ev.packet->data, ev.packet->dataLength);
                            if (txt.find("action|drop") != std::string::npos &&
                                txt.find("itemID|1796") != std::string::npos) {
                                srv_got_drop_req_1796 = true;
                            }
                            if (txt.find("action|drop") != std::string::npos &&
                                txt.find("itemID|242") != std::string::npos) {
                                srv_got_drop_req_242 = true;
                            }
                            if (txt.find("dialog_name|drop_item") != std::string::npos &&
                                txt.find("itemID|1796") != std::string::npos &&
                                txt.find("count|1") != std::string::npos) {
                                srv_got_drop_dl = true;
                            }
                            if (txt.find("dialog_name|drop_item") != std::string::npos &&
                                txt.find("itemID|242") != std::string::npos &&
                                txt.find("count|2") != std::string::npos) {
                                srv_got_drop_wl = true;
                            }
                            if (txt.find("dialog_name|vending") != std::string::npos &&
                                txt.find("buycount|2") != std::string::npos &&
                                txt.find("verify|1") == std::string::npos) {
                                srv_got_vend_buycount = true;
                            }
                            if (txt.find("dialog_name|vending") != std::string::npos &&
                                txt.find("buycount|2") != std::string::npos &&
                                txt.find("verify|1") != std::string::npos) {
                                srv_got_vend_verify = true;
                            }
                        }
                        enet_packet_destroy(ev.packet);
                    }
                }
            }
        };

        for (int i = 0; i < 40 && (!srv_peer || cli_peer->state != ENET_PEER_STATE_CONNECTED); ++i) pump(40);
        require(srv_peer && cli_peer->state == ENET_PEER_STATE_CONNECTED, "FastBuy ENet handshake failed");

        auto sp_pkt = evan::proto::build_call_function_packet(-1, 0, evan::proto::VariantList{
            {evan::proto::Variant::make_string("OnSpawn"),
             evan::proto::Variant::make_string("spawn|avatar\nnetID|1\nuserID|42\nname|`2clo0x``\ncountry|us\ntype|local\n")}
        });
        enet_peer_send(srv_peer, 0, enet_packet_create(sp_pkt.data(), sp_pkt.size(), ENET_PACKET_FLAG_RELIABLE));
        auto inv1 = make_inv_packet(0, 2);
        enet_peer_send(srv_peer, 0, enet_packet_create(inv1.data(), inv1.size(), ENET_PACKET_FLAG_RELIABLE));
        pump(80);

        // Test /cd 102 with 0 WL + 2 DL -> shatter 1 DL, drop 1 DL + 2 WL
        auto cd_cmd = evan::proto::encode_text_packet(
            evan::proto::MessageType::GenericText, "action|input\n|text|/cd 102");
        enet_peer_send(cli_peer, 0, enet_packet_create(cd_cmd.data(), cd_cmd.size(), ENET_PACKET_FLAG_RELIABLE));
        for (int i = 0; i < 25 && !srv_got_dl_activate; ++i) pump(25);
        require(srv_got_dl_activate, "/cd 102 did not activate DL #1796 to shatter into WL");

        // Server reflects shattered inventory (100 WL, 1 DL) and responds after each action|drop request
        auto inv2 = make_inv_packet(100, 1);
        enet_peer_send(srv_peer, 0, enet_packet_create(inv2.data(), inv2.size(), ENET_PACKET_FLAG_RELIABLE));
        for (int i = 0; i < 40 && !srv_got_drop_req_1796; ++i) pump(25);
        require(srv_got_drop_req_1796, "/cd 102 did not request action|drop for DL #1796");

        auto drop_dl_dlg = evan::proto::build_on_dialog_request(
            "set_default_color|`o\nembed_data|itemID|1796\nadd_text_input|count||1|5|\nend_dialog|drop_item|Cancel|OK|\n");
        enet_peer_send(srv_peer, 0, enet_packet_create(drop_dl_dlg.data(), drop_dl_dlg.size(), ENET_PACKET_FLAG_RELIABLE));
        for (int i = 0; i < 40 && !srv_got_drop_dl; ++i) pump(25);
        require(srv_got_drop_dl, "/cd 102 did not drop 1 DL after DL shatter");

        for (int i = 0; i < 40 && !srv_got_drop_req_242; ++i) pump(25);
        require(srv_got_drop_req_242, "/cd 102 did not request action|drop for WL #242");

        auto drop_wl_dlg = evan::proto::build_on_dialog_request(
            "set_default_color|`o\nembed_data|itemID|242\nadd_text_input|count||100|5|\nend_dialog|drop_item|Cancel|OK|\n");
        enet_peer_send(srv_peer, 0, enet_packet_create(drop_wl_dlg.data(), drop_wl_dlg.size(), ENET_PACKET_FLAG_RELIABLE));
        for (int i = 0; i < 40 && !srv_got_drop_wl; ++i) pump(25);
        require(srv_got_drop_wl, "/cd 102 did not drop 2 WL after DL shatter");

        // Test Vending Fast Buy Auto (mode=2, qty=2) + Private Stock/WL Notice
        auto vend_step1 = evan::proto::build_on_dialog_request(
            "set_default_color|`o\n"
            "add_label_with_icon|big|`wDigiVend Machine``|left|9268|\n"
            "embed_data|tilex|14\n"
            "embed_data|tiley|22\n"
            "add_label_with_icon|sml|The machine contains a total of 324 `2Fairy Dress``.|left|2924|\n"
            "add_textbox|You have 128 World Locks.|left|\n"
            "add_text_input|buycount|`wBuy how many? (3 WL each)|0|3|\n"
            "embed_data|expectprice|3\n"
            "embed_data|expectitem|2924\n"
            "end_dialog|vending|Close|Buy|\n");
        enet_peer_send(srv_peer, 0, enet_packet_create(vend_step1.data(), vend_step1.size(), ENET_PACKET_FLAG_RELIABLE));
        for (int i = 0; i < 25 && !srv_got_vend_buycount; ++i) pump(25);
        require(srv_got_vend_buycount, "Fast Buy Auto did not submit buycount|2");

        auto vend_step2 = evan::proto::build_on_dialog_request(
            "set_default_color|`o\n"
            "add_label_with_icon|big|`wVerify Purchase``|left|9268|\n"
            "embed_data|tilex|14\n"
            "embed_data|tiley|22\n"
            "embed_data|verify|1\n"
            "embed_data|buycount|2\n"
            "embed_data|expectprice|3\n"
            "embed_data|expectitem|2924\n"
            "end_dialog|vending|Cancel|OK|\n");
        enet_peer_send(srv_peer, 0, enet_packet_create(vend_step2.data(), vend_step2.size(), ENET_PACKET_FLAG_RELIABLE));
        for (int i = 0; i < 25 && !srv_got_vend_verify; ++i) pump(25);
        require(srv_got_vend_verify, "Fast Buy did not auto-confirm verify|1");

        auto vend_ok_msg = evan::proto::build_on_console_message(
            "`2clo0x bought 2 Fairy Dress for 6 World Locks.");
        enet_peer_send(srv_peer, 0, enet_packet_create(vend_ok_msg.data(), vend_ok_msg.size(), ENET_PACKET_FLAG_RELIABLE));
        for (int i = 0; i < 25 && !cli_got_private_vend_info; ++i) pump(25);
        require(cli_got_private_vend_info, "Client did not receive private [Vending Privat] remaining stock/WL message");
        require(cli_vend_dialog_leaks == 0, "Fast Buy Auto leaked vending dialog to client");

        pshared.stop_requested.store(true);
        p_thread.join();
        require(p_ok, "FastBuy EnetProxy error: " + p_err);
        enet_host_destroy(client);
        enet_host_destroy(mock_srv);
        enet_deinitialize();
    }
}

} // namespace

int main() {
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }

    struct TestCase {
        const char* name;
        void (*fn)();
    };

    const TestCase cases[] = {
        {"test_dns_query_and_parse", test_dns_query_and_parse},
        {"test_hosts_marker_preservation", test_hosts_marker_preservation},
        {"test_protocol_text_and_variants", test_protocol_text_and_variants},
        {"test_https_server_data_bridge", test_https_server_data_bridge},
        {"test_enet_bridge_and_subserver_redirect", test_enet_bridge_and_subserver_redirect},
        {"test_calculator_and_session", test_calculator_and_session},
        {"test_action_decoding_and_ui_dialogs", test_action_decoding_and_ui_dialogs},
        {"test_titles_fps_and_portal_warp", test_titles_fps_and_portal_warp},
        {"test_visual_clothes_items_and_branding", test_visual_clothes_items_and_branding},
        {"test_autobgl_new_titles_hotkeys_and_locks", test_autobgl_new_titles_hotkeys_and_locks},
        {"test_custom_hotkeys_smart_cd_and_fastbuy", test_custom_hotkeys_smart_cd_and_fastbuy}
    };

    int passed = 0;
    const int total = static_cast<int>(sizeof(cases) / sizeof(cases[0]));

    for (const auto& tc : cases) {
        try {
            tc.fn();
            std::cout << "[PASS] " << tc.name << std::endl;
            ++passed;
        } catch (const std::exception& ex) {
            std::cerr << "[FAIL] " << tc.name << ": " << ex.what() << std::endl;
        }
    }

    WSACleanup();
    std::cout << "\nSummary: " << passed << "/" << total << " tests passed.\n";
    return (passed == total) ? 0 : 1;
}
