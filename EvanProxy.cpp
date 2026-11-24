#include "banner.hpp"
#include "cert.hpp"
#include "config.hpp"
#include "desktop_gui.hpp"
#include "enet_proxy.hpp"
#include "hosts.hpp"
#include "http_bridge.hpp"
#include "proxy_controller.hpp"

#include <winsock2.h>
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <iostream>
#include <string>

namespace {

evan::SharedState* g_shared_state = nullptr;
evan::ProxyController* g_controller = nullptr;
std::atomic<bool> g_manage_hosts_active{false};

BOOL WINAPI console_ctrl_handler(DWORD ctrl_type) {
    switch (ctrl_type) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            std::cout << "\n[*] Menghentikan EvanProxy dan membersihkan hosts...\n";
            if (g_controller) {
                g_controller->stop();
            }
            if (g_shared_state) {
                g_shared_state->stop_requested.store(true);
            }
            if (g_manage_hosts_active.exchange(false)) {
                std::string err;
                evan::hosts::uninstall_hosts(err);
            }
            return TRUE;
        default:
            return FALSE;
    }
}

void print_help() {
    std::cout << "EvanProxy - Growtopia Local Proxy (C++20 / HTTPS + ENet)\n\n"
              << "Penggunaan:\n"
              << "  EvanProxy.exe                  Buka Desktop Launcher & Dashboard UI/UX + HUD Overlay\n"
              << "  EvanProxy.exe --autostart      Buka UI Desktop dan langsung Start proxy\n"
              << "  EvanProxy.exe --cli            Jalankan mode konsol klasik (tanpa UI Desktop)\n"
              << "  EvanProxy.exe --install-cert   Buat & install Root CA lokal ke Windows CurrentUser Store\n"
              << "  EvanProxy.exe --uninstall-cert Hapus Root CA lokal dari Windows CurrentUser Store\n"
              << "  EvanProxy.exe --clean-hosts    Hapus blok EvanProxy dari file hosts Windows\n"
              << "  EvanProxy.exe --no-hosts       Jalankan proxy tanpa mengubah file hosts\n"
              << "  EvanProxy.exe --test-upstream  Uji koneksi langsung ke server_data.php Growtopia\n"
              << "  EvanProxy.exe --help           Tampilkan bantuan ini\n";
}

void pause_before_exit() {
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    if (hIn != INVALID_HANDLE_VALUE && GetFileType(hIn) == FILE_TYPE_CHAR) {
        std::cout << "\nTekan Enter untuk menutup...";
        std::string dummy;
        std::getline(std::cin, dummy);
    }
}

std::string join_args(int argc, char* argv[]) {
    std::string out;
    for (int i = 1; i < argc; ++i) {
        if (i > 1) out.push_back(' ');
        out.append(argv[i]);
    }
    return out;
}

} // namespace

int main(int argc, char* argv[]) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleTitleA("EvanProxy - Growtopia Proxy (C++20)");

    bool opt_install_cert = false;
    bool opt_uninstall_cert = false;
    bool opt_clean_hosts = false;
    bool opt_no_hosts = false;
    bool opt_test_upstream = false;
    bool opt_cli = false;
    bool opt_autostart = false;
    bool opt_help = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--install-cert") opt_install_cert = true;
        else if (arg == "--uninstall-cert") opt_uninstall_cert = true;
        else if (arg == "--clean-hosts") opt_clean_hosts = true;
        else if (arg == "--no-hosts") opt_no_hosts = true;
        else if (arg == "--test-upstream") opt_test_upstream = true;
        else if (arg == "--cli") opt_cli = true;
        else if (arg == "--autostart") opt_autostart = true;
        else if (arg == "--help" || arg == "-h") opt_help = true;
        else {
            std::cerr << "[!] Argumen tidak dikenal: " << arg << "\n\n";
            print_help();
            return 1;
        }
    }

    if (opt_help) {
        print_help();
        return 0;
    }

    const auto exe_dir = evan::get_exe_dir();
    const auto cfg_path = exe_dir / "config.ini";
    const auto cert_dir = exe_dir / "certs";

    evan::ProxyConfig cfg = evan::load_or_create_config(cfg_path);
    if (opt_no_hosts) {
        cfg.manage_hosts = false;
    }

    if (opt_test_upstream) {
        WSADATA wsa{};
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            std::cerr << "[!] Gagal inisialisasi Winsock2.\n";
            return 1;
        }
        std::string real_ip;
        uint16_t real_port = 0;
        std::string rewritten;
        std::string err;
        bool ok = evan::HttpBridge::probe_upstream(cfg, real_ip, real_port, rewritten, err);
        WSACleanup();
        if (!ok) {
            std::cerr << "[!] Uji upstream server_data.php gagal: " << err << "\n";
            return 1;
        }
        std::cout << "[+] Uji upstream berhasil!\n"
                  << "    Server asli : " << real_ip << ":" << real_port << "\n"
                  << "    Rewritten   :\n" << rewritten << "\n";
        return 0;
    }

    if (opt_uninstall_cert) {
        std::string err;
        if (evan::cert::uninstall_ca_user_root(err)) {
            std::cout << "[+] Root CA '" << evan::cert::CA_COMMON_NAME << "' berhasil dihapus dari store.\n";
            return 0;
        }
        std::cerr << "[!] Gagal menghapus Root CA: " << err << "\n";
        return 1;
    }

    if (opt_clean_hosts) {
        if (!evan::hosts::is_admin()) {
            std::cout << "[!] Meminta hak Administrator untuk membersihkan hosts...\n";
            if (!evan::hosts::relaunch_as_admin("--clean-hosts")) {
                std::cerr << "[!] Gagal meminta elevasi Administrator.\n";
                return 1;
            }
            return 0;
        }
        std::string err;
        if (evan::hosts::uninstall_hosts(err)) {
            std::cout << "[+] Blok EvanProxy di file hosts berhasil dibersihkan.\n";
            return 0;
        }
        std::cerr << "[!] Gagal membersihkan hosts: " << err << "\n";
        return 1;
    }

    if (opt_install_cert) {
        evan::cert::CertPaths certs;
        std::string cert_err;
        if (!evan::cert::ensure_certs(cert_dir, cfg.server_data_hosts, certs, cert_err)) {
            std::cerr << "[!] Gagal menyiapkan sertifikat TLS: " << cert_err << "\n";
            pause_before_exit();
            return 1;
        }
        std::string err;
        if (evan::cert::install_ca_user_root(certs.ca_cert, err)) {
            std::cout << "[+] Root CA berhasil di-install ke Windows CurrentUser Root Store.\n";
            return 0;
        }
        std::cerr << "[!] Gagal install Root CA: " << err << "\n";
        return 1;
    }

    // Default GUI mode (Launcher + Dashboard + In-Game HUD Overlay)
    if (!opt_cli) {
        WSADATA wsa{};
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            std::cerr << "[!] Gagal inisialisasi Winsock2.\n";
            return 1;
        }
        struct WsaGuard {
            ~WsaGuard() { WSACleanup(); }
        } wsa_guard;

        // Hide the standalone console window only when launched by double-click (no parent terminal)
        DWORD pid_list[4] = {};
        if (GetConsoleProcessList(pid_list, 4) <= 1) {
            if (HWND cw = GetConsoleWindow()) {
                ShowWindow(cw, SW_HIDE);
            }
        }

        evan::ProxyController::Options opts;
        opts.exe_dir = exe_dir;
        opts.config_path = cfg_path;
        opts.cert_dir = cert_dir;
        opts.log_dir = exe_dir / "logs";
        opts.worlds_path = exe_dir / "worlds.ini";
        opts.no_hosts_override = opt_no_hosts;

        evan::ProxyController controller(opts);
        g_controller = &controller;
        SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

        const int rc = evan::DesktopGui::run(controller, opt_autostart);
        g_controller = nullptr;
        return rc;
    }

    // Classic headless console mode (--cli)
    evan::cert::CertPaths certs;
    std::string cert_err;
    if (!evan::cert::ensure_certs(cert_dir, cfg.server_data_hosts, certs, cert_err)) {
        std::cerr << "[!] Gagal menyiapkan sertifikat TLS: " << cert_err << "\n";
        pause_before_exit();
        return 1;
    }

    std::cout << "========================================\n";
    std::cout << "   EvanProxy (Growtopia HTTPS + ENet)\n";
    std::cout << "========================================\n";
    std::cout << "[*] Config : " << cfg_path.string() << "\n";
    std::cout << "[*] Certs  : " << cert_dir.string() << "\n";
    {
        const auto br = evan::banner::sync_banners_to_growtopia(exe_dir);
        if (br.installed_count > 0) {
            std::cout << "[Banner] " << br.installed_count
                      << " aset banner EvanProxy siap di: " << br.cache_dir.string() << "\n";
        }
    }

    if (!evan::cert::is_ca_trusted_in_user_root()) {
        std::cout << "\n[!] Root CA lokal ('" << evan::cert::CA_COMMON_NAME
                  << "') belum terpasang di Windows CurrentUser Root Store.\n"
                  << "    Tanpa ini, Growtopia akan menolak koneksi HTTPS (port 443).\n"
                  << "    Anda juga bisa memasangnya kapan saja dengan: EvanProxy.exe --install-cert\n"
                  << "    Pasang sertifikat sekarang? [Y/n]: ";
        std::string ans;
        std::getline(std::cin, ans);
        if (ans.empty() || ans[0] == 'y' || ans[0] == 'Y') {
            std::string err;
            if (evan::cert::install_ca_user_root(certs.ca_cert, err)) {
                std::cout << "[+] Root CA berhasil dipasang.\n";
            } else {
                std::cerr << "[!] Gagal memasang Root CA: " << err << "\n";
            }
        }
    }

    if (cfg.manage_hosts && !evan::hosts::is_admin()) {
        std::cout << "[*] Meminta hak Administrator untuk mengelola file hosts...\n";
        if (!evan::hosts::relaunch_as_admin(join_args(argc, argv))) {
            std::cerr << "[!] Gagal meminta hak Administrator. Jalankan ulang sebagai Administrator atau pakai --no-hosts.\n";
            pause_before_exit();
            return 1;
        }
        return 0;
    }

    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "[!] Gagal inisialisasi Winsock2.\n";
        pause_before_exit();
        return 1;
    }
    struct WsaGuard {
        ~WsaGuard() { WSACleanup(); }
    } wsa_guard;

    evan::SharedState shared;
    g_shared_state = &shared;
    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

    evan::hosts::HostsGuard hosts_guard;
    if (cfg.manage_hosts) {
        std::string hosts_err;
        if (!evan::hosts::install_hosts(cfg.local_ip, hosts_err)) {
            std::cerr << "[!] Gagal menulis hosts: " << hosts_err << "\n";
            pause_before_exit();
            return 1;
        }
        hosts_guard.set_active(true);
        g_manage_hosts_active.store(true);
        std::cout << "[+] Entri hosts Growtopia diarahkan ke " << cfg.local_ip << "\n";
    } else {
        std::cout << "[*] Mode --no-hosts aktif (file hosts tidak diubah).\n";
    }

    evan::HttpBridge http_bridge(cfg, shared, certs);
    std::string http_err;
    if (!http_bridge.start(http_err)) {
        std::cerr << "[!] Gagal memulai HTTPS bridge: " << http_err << "\n";
        g_manage_hosts_active.store(false);
        hosts_guard.release();
        pause_before_exit();
        return 1;
    }
    std::cout << "[HTTP] HTTPS bridge aktif di 0.0.0.0:" << http_bridge.bound_port()
              << " (server_data.php)\n";

    std::cout << "[*] Siap! Silakan buka Growtopia sekarang.\n";
    std::cout << "[*] Di dalam game ketik /proxy untuk membuka Dashboard UI/UX.\n";
    std::cout << "[*] Tekan Ctrl+C untuk berhenti & mengembalikan file hosts.\n\n";

    evan::EnetProxy enet_proxy(cfg, shared, exe_dir / "logs", cfg_path, exe_dir / "worlds.ini");
    std::string enet_err;
    if (!enet_proxy.run(enet_err)) {
        std::cerr << "[!] ENet proxy berhenti dengan error: " << enet_err << "\n";
        http_bridge.stop();
        g_manage_hosts_active.store(false);
        hosts_guard.release();
        pause_before_exit();
        return 1;
    }

    http_bridge.stop();
    g_manage_hosts_active.store(false);
    hosts_guard.release();
    std::cout << "[+] EvanProxy berhenti dengan bersih.\n";
    return 0;
}
