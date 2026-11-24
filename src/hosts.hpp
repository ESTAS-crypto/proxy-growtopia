#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace evan::hosts {

inline constexpr const char* BEGIN_MARKER = "# >>> EvanProxy (auto, removed on exit)";
inline constexpr const char* END_MARKER = "# <<< EvanProxy";

const std::vector<std::string>& managed_domains();

// Pure helpers (also exercised by unit tests)
std::string strip_hosts_block(const std::string& content);
std::string build_hosts_with_block(const std::string& original, const std::string& ip);

// OS operations
std::filesystem::path hosts_file_path();
bool install_hosts(const std::string& ip, std::string& err);
bool uninstall_hosts(std::string& err);

bool is_admin();
bool relaunch_as_admin(const std::string& args);

class HostsGuard {
public:
    HostsGuard() = default;
    explicit HostsGuard(bool active) : active_(active) {}
    HostsGuard(const HostsGuard&) = delete;
    HostsGuard& operator=(const HostsGuard&) = delete;
    HostsGuard(HostsGuard&& other) noexcept : active_(other.active_) { other.active_ = false; }
    HostsGuard& operator=(HostsGuard&& other) noexcept {
        if (this != &other) {
            release();
            active_ = other.active_;
            other.active_ = false;
        }
        return *this;
    }
    ~HostsGuard();

    void set_active(bool active) { active_ = active; }
    void release();

private:
    bool active_ = false;
};

} // namespace evan::hosts
