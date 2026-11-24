#include "banner.hpp"

#include <cstdlib>
#include <vector>

namespace evan::banner {

namespace {

constexpr const char* kBannerFiles[] = {
    "evanproxy_banner.rttex",
    "evanproxy_card1.rttex",
    "evanproxy_card2.rttex",
    "evanproxy_card3.rttex",
};

std::filesystem::path get_growtopia_root() {
    char* local_app = nullptr;
    size_t len = 0;
    if (_dupenv_s(&local_app, &len, "LOCALAPPDATA") == 0 && local_app != nullptr) {
        std::filesystem::path p(local_app);
        free(local_app);
        return p / "Growtopia";
    }
    return {};
}

bool needs_copy(const std::filesystem::path& src, const std::filesystem::path& dst) {
    std::error_code ec;
    if (!std::filesystem::exists(dst, ec)) {
        return true;
    }
    const auto s_sz = std::filesystem::file_size(src, ec);
    if (ec) return false;
    const auto d_sz = std::filesystem::file_size(dst, ec);
    if (ec || s_sz != d_sz) {
        return true;
    }
    const auto s_tm = std::filesystem::last_write_time(src, ec);
    if (ec) return false;
    const auto d_tm = std::filesystem::last_write_time(dst, ec);
    if (ec || s_tm > d_tm) {
        return true;
    }
    return false;
}

} // namespace

InstallResult sync_banners_to_growtopia(const std::filesystem::path& exe_dir) {
    InstallResult res;
    std::error_code ec;
    const std::filesystem::path assets_dir = exe_dir / "assets";
    if (!std::filesystem::is_directory(assets_dir, ec)) {
        return res;
    }

    const std::filesystem::path gt_root = get_growtopia_root();
    if (gt_root.empty() || !std::filesystem::is_directory(gt_root, ec)) {
        return res;
    }

    std::vector<std::filesystem::path> targets;
    const std::filesystem::path cache_large = gt_root / "cache" / "interface" / "large";
    std::filesystem::create_directories(cache_large, ec);
    if (!ec && std::filesystem::is_directory(cache_large, ec)) {
        res.cache_dir = cache_large;
        targets.push_back(cache_large);
    }

    const std::filesystem::path direct_large = gt_root / "interface" / "large";
    if (std::filesystem::is_directory(direct_large, ec)) {
        targets.push_back(direct_large);
        if (res.cache_dir.empty()) {
            res.cache_dir = direct_large;
        }
    }

    for (const char* name : kBannerFiles) {
        const std::filesystem::path src = assets_dir / name;
        if (!std::filesystem::is_regular_file(src, ec)) {
            continue;
        }
        bool updated_any = false;
        for (const auto& dir : targets) {
            const std::filesystem::path dst = dir / name;
            if (needs_copy(src, dst)) {
                std::filesystem::copy_file(src, dst, std::filesystem::copy_options::overwrite_existing, ec);
                if (!ec) {
                    updated_any = true;
                }
            }
        }
        if (updated_any) {
            ++res.installed_count;
        }
    }
    return res;
}

bool is_banner_ready() {
    std::error_code ec;
    const std::filesystem::path gt_root = get_growtopia_root();
    if (gt_root.empty()) {
        return false;
    }
    return std::filesystem::is_regular_file(gt_root / "cache" / "interface" / "large" / "evanproxy_banner.rttex", ec) ||
           std::filesystem::is_regular_file(gt_root / "interface" / "large" / "evanproxy_banner.rttex", ec);
}

} // namespace evan::banner
