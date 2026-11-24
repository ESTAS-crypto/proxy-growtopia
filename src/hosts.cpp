#include "hosts.hpp"

#include <winsock2.h>
#include <windows.h>
#include <shellapi.h>

#include <cstdlib>
#include <fstream>
#include <sstream>

namespace evan::hosts {

namespace {

std::string detect_line_ending(const std::string& s) {
    return (s.find("\r\n") != std::string::npos) ? "\r\n" : "\n";
}

std::string trim_line_end(const std::string& s) {
    size_t end = s.size();
    while (end > 0 && (s[end - 1] == '\r' || s[end - 1] == '\n')) {
        --end;
    }
    return s.substr(0, end);
}

bool is_legacy_gt_hosts_line(const std::string& trimmed) {
    std::istringstream iss(trimmed);
    std::string ip;
    std::string domain;
    if (!(iss >> ip >> domain)) {
        return false;
    }
    if (ip != "127.0.0.1") {
        return false;
    }
    std::string extra;
    if (iss >> extra) {
        if (extra.empty() || extra[0] != '#') {
            return false;
        }
    }
    static const char* kLegacyDomains[] = {
        "growtopia1.com",
        "growtopia2.com",
        "growtopia3.com",
        "www.growtopia1.com",
        "www.growtopia2.com",
        "www.growtopia3.com"
    };
    for (const char* d : kLegacyDomains) {
        if (domain == d) {
            return true;
        }
    }
    return false;
}

void flush_dns() {
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};
    char cmd[] = "ipconfig.exe /flushdns";
    if (CreateProcessA(nullptr, cmd, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 3000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

bool read_file_bytes(const std::filesystem::path& p, std::string& out, std::string& err) {
    std::ifstream in(p, std::ios::binary);
    if (!in) {
        err = "Tidak dapat membaca file: " + p.string();
        return false;
    }
    out.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return true;
}

bool write_file_bytes(const std::filesystem::path& p, const std::string& data, std::string& err) {
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    if (!out) {
        err = "Tidak dapat menulis file: " + p.string() + " (pastikan dijalankan sebagai Administrator)";
        return false;
    }
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
    if (!out.good()) {
        err = "Gagal menulis lengkap ke file: " + p.string();
        return false;
    }
    return true;
}

} // namespace

const std::vector<std::string>& managed_domains() {
    static const std::vector<std::string> kDomains = {
        "www.growtopia1.com",
        "www.growtopia2.com",
        "growtopia1.com",
        "growtopia2.com"
    };
    return kDomains;
}

std::string strip_hosts_block(const std::string& content) {
    std::string out;
    out.reserve(content.size());
    bool inside = false;
    size_t pos = 0;

    while (pos < content.size()) {
        size_t nl = content.find('\n', pos);
        size_t next = (nl == std::string::npos) ? content.size() : (nl + 1);
        std::string line = content.substr(pos, next - pos);
        std::string trimmed = trim_line_end(line);
        pos = next;

        if (trimmed == BEGIN_MARKER) {
            inside = true;
            continue;
        }
        if (inside) {
            if (trimmed == END_MARKER) {
                inside = false;
            }
            continue;
        }
        if (is_legacy_gt_hosts_line(trimmed)) {
            continue;
        }
        out.append(line);
    }
    return out;
}

std::string build_hosts_with_block(const std::string& original, const std::string& ip) {
    const std::string nl = detect_line_ending(original);
    std::string out = strip_hosts_block(original);
    if (!out.empty() && out.back() != '\n') {
        out.append(nl);
    }
    out.append(BEGIN_MARKER);
    out.append(nl);
    for (const auto& domain : managed_domains()) {
        out.append(ip);
        out.push_back(' ');
        out.append(domain);
        out.append(nl);
    }
    out.append(END_MARKER);
    out.append(nl);
    return out;
}

std::filesystem::path hosts_file_path() {
    char root[MAX_PATH] = {};
    UINT len = GetSystemWindowsDirectoryA(root, MAX_PATH);
    std::filesystem::path base = (len > 0 && len < MAX_PATH)
        ? std::filesystem::path(root)
        : std::filesystem::path("C:\\Windows");
    return base / "System32" / "drivers" / "etc" / "hosts";
}

bool install_hosts(const std::string& ip, std::string& err) {
    const auto path = hosts_file_path();
    std::string original;
    if (!read_file_bytes(path, original, err)) {
        return false;
    }

    std::error_code ec;
    const auto backup = path.parent_path() / "hosts.evanproxy.bak";
    if (!std::filesystem::exists(backup, ec)) {
        std::string backup_err;
        write_file_bytes(backup, original, backup_err);
    }

    const std::string updated = build_hosts_with_block(original, ip);
    if (!write_file_bytes(path, updated, err)) {
        return false;
    }
    flush_dns();
    return true;
}

bool uninstall_hosts(std::string& err) {
    const auto path = hosts_file_path();
    std::string original;
    if (!read_file_bytes(path, original, err)) {
        return false;
    }

    const std::string stripped = strip_hosts_block(original);
    if (stripped == original) {
        return true;
    }
    if (!write_file_bytes(path, stripped, err)) {
        return false;
    }
    flush_dns();
    return true;
}

bool is_admin() {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID adminGroup = nullptr;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
}

bool relaunch_as_admin(const std::string& args) {
    char exePath[MAX_PATH] = {};
    if (GetModuleFileNameA(nullptr, exePath, MAX_PATH) == 0) {
        return false;
    }
    HINSTANCE res = ShellExecuteA(
        nullptr,
        "runas",
        exePath,
        args.empty() ? nullptr : args.c_str(),
        nullptr,
        SW_SHOWNORMAL
    );
    return reinterpret_cast<intptr_t>(res) > 32;
}

HostsGuard::~HostsGuard() {
    release();
}

void HostsGuard::release() {
    if (!active_) {
        return;
    }
    active_ = false;
    std::string err;
    uninstall_hosts(err);
}

} // namespace evan::hosts
