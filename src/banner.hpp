#pragma once

#include <filesystem>

namespace evan::banner {

struct InstallResult {
    int installed_count = 0;
    std::filesystem::path cache_dir;
};

// Synchronizes custom EvanProxy RTTEX banner assets from <exe_dir>/assets/
// into Growtopia's local interface/large cache folders without overwriting
// Growtopia's original assets (e.g. news_banner.rttex).
InstallResult sync_banners_to_growtopia(const std::filesystem::path& exe_dir);

// Returns true if evanproxy_banner.rttex is present in Growtopia's local cache.
bool is_banner_ready();

} // namespace evan::banner
