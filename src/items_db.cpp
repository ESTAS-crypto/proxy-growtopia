#include "items_db.hpp"

#include "config.hpp"

#include <winsock2.h>
#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>

namespace evan {

namespace {

constexpr const char kXorKey[] = "PBG892FXX982ABC*";
constexpr size_t kXorKeyLen = 16;

std::string to_lower_ascii(std::string s) {
    for (char& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

bool is_all_digits(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s) {
        if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

uint16_t read_u16_le(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

uint32_t read_u32_le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

bool ends_with_rttex(const uint8_t* p, size_t len) {
    if (len < 6) return false;
    return std::memcmp(p + len - 6, ".rttex", 6) == 0;
}

bool try_parse_record_at(
    const uint8_t* data,
    size_t len,
    size_t off,
    uint32_t id,
    ItemEntry& out_entry,
    size_t& out_next_pos
) {
    if (off + 12 > len) return false;
    const uint16_t name_len = read_u16_le(data + off + 8);
    if (name_len == 0 || name_len > 128) return false;
    if (off + 10 + name_len + 2 > len) return false;

    std::string name(name_len, '\0');
    for (size_t i = 0; i < name_len; ++i) {
        const uint8_t dec = static_cast<uint8_t>(data[off + 10 + i] ^ static_cast<uint8_t>(kXorKey[(id + i) % kXorKeyLen]));
        if (dec < 0x20 || dec > 0x7E) {
            return false;
        }
        name[i] = static_cast<char>(dec);
    }

    const size_t tp = off + 10 + name_len;
    const uint16_t tex_len = read_u16_le(data + tp);
    if (tex_len < 6 || tex_len > 128 || tp + 2 + tex_len > len) {
        return false;
    }
    if (!ends_with_rttex(data + tp + 2, tex_len)) {
        return false;
    }

    const size_t next = tp + 2 + tex_len;
    out_entry.id = id;
    out_entry.action_type = data[off + 6];
    out_entry.clothing_type = (next + 19 < len) ? data[next + 19] : 0;
    out_entry.rarity = (next + 21 < len) ? read_u16_le(data + next + 20) : 0;
    out_entry.name_lower = to_lower_ascii(name);
    out_entry.name = std::move(name);
    out_next_pos = next;
    return true;
}

} // namespace

bool ItemDatabase::load_default_cache() {
    char env_buf[MAX_PATH] = {};
    DWORD env_len = GetEnvironmentVariableA("LOCALAPPDATA", env_buf, MAX_PATH);
    if (env_len > 0 && env_len < MAX_PATH) {
        std::filesystem::path gt_cache = std::filesystem::path(env_buf) / "Growtopia" / "cache" / "items.dat";
        if (std::filesystem::exists(gt_cache) && load_from_file(gt_cache)) {
            return true;
        }
        std::filesystem::path gt_root = std::filesystem::path(env_buf) / "Growtopia" / "items.dat";
        if (std::filesystem::exists(gt_root) && load_from_file(gt_root)) {
            return true;
        }
    }

    std::filesystem::path exe_local = get_exe_dir() / "items.dat";
    if (std::filesystem::exists(exe_local) && load_from_file(exe_local)) {
        return true;
    }
    return false;
}

bool ItemDatabase::load_from_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) return false;
    const std::streamsize sz = in.tellg();
    if (sz <= 6 || sz > 64 * 1024 * 1024) return false;
    in.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf(static_cast<size_t>(sz));
    if (!in.read(reinterpret_cast<char*>(buf.data()), sz)) {
        return false;
    }
    if (!parse_bytes(buf.data(), buf.size())) {
        return false;
    }
    loaded_path_ = path;
    return !items_.empty();
}

bool ItemDatabase::parse_bytes(const uint8_t* data, size_t len) {
    items_.clear();
    items_by_id_.clear();
    items_by_name_lower_.clear();
    if (!data || len < 6) {
        return false;
    }

    const uint32_t count = read_u32_le(data + 2);
    if (count == 0 || count > 200000) {
        return false;
    }
    items_.reserve(count);
    items_by_id_.reserve(count);
    items_by_name_lower_.reserve(count);

    size_t pos = 6;
    for (uint32_t id = 0; id < count && pos + 12 <= len; ++id) {
        const uint8_t b0 = static_cast<uint8_t>(id & 0xFFu);
        const uint8_t b1 = static_cast<uint8_t>((id >> 8) & 0xFFu);
        const uint8_t b2 = static_cast<uint8_t>((id >> 16) & 0xFFu);
        const uint8_t b3 = static_cast<uint8_t>((id >> 24) & 0xFFu);

        const size_t window_end = std::min(len - 12, pos + 65536);
        for (size_t off = pos; off <= window_end; ++off) {
            if (data[off] == b0 && data[off + 1] == b1 && data[off + 2] == b2 && data[off + 3] == b3) {
                ItemEntry entry;
                size_t next_pos = pos;
                if (try_parse_record_at(data, len, off, id, entry, next_pos)) {
                    const size_t idx = items_.size();
                    items_by_id_[id] = idx;
                    if (!entry.name_lower.empty()) {
                        items_by_name_lower_[entry.name_lower] = idx;
                    }
                    items_.push_back(std::move(entry));
                    pos = next_pos;
                    break;
                }
            }
        }
    }

    return !items_.empty();
}

const ItemEntry* ItemDatabase::find_by_id(uint32_t id) const {
    auto it = items_by_id_.find(id);
    if (it == items_by_id_.end()) return nullptr;
    return &items_[it->second];
}

const ItemEntry* ItemDatabase::find_by_name(const std::string& name) const {
    if (name.empty()) return nullptr;
    const std::string low = to_lower_ascii(name);
    if (auto it = items_by_name_lower_.find(low); it != items_by_name_lower_.end()) {
        return &items_[it->second];
    }
    if (low.size() > 1 && low.back() == 's') {
        if (auto it = items_by_name_lower_.find(low.substr(0, low.size() - 1)); it != items_by_name_lower_.end()) {
            return &items_[it->second];
        }
    }
    return nullptr;
}

std::string ItemDatabase::name_or_fallback(uint32_t id) const {
    if (const ItemEntry* e = find_by_id(id)) {
        return e->name;
    }
    return "item #" + std::to_string(id);
}

int ItemDatabase::get_clothing_slot(uint32_t id) const {
    const ItemEntry* e = find_by_id(id);
    if (!e) return -1;
    if (e->action_type == 107) {
        return 9; // Ancestral / Artifact
    }
    if (e->action_type == 20 && e->clothing_type <= 9) {
        return static_cast<int>(e->clothing_type);
    }
    return -1;
}

const char* ItemDatabase::slot_name(int slot) {
    switch (slot) {
        case 0: return "Hat";
        case 1: return "Shirt";
        case 2: return "Pants";
        case 3: return "Shoes";
        case 4: return "Face";
        case 5: return "Hand";
        case 6: return "Back";
        case 7: return "Hair";
        case 8: return "Neck";
        case 9: return "Ances";
        default: return "Item";
    }
}

std::vector<const ItemEntry*> ItemDatabase::search(
    const std::string& query,
    bool clothes_only,
    size_t max_results
) const {
    std::vector<const ItemEntry*> matches;
    const std::string q = to_lower_ascii(query);

    if (is_all_digits(q)) {
        try {
            uint32_t exact_id = static_cast<uint32_t>(std::stoul(q));
            if (const ItemEntry* exact = find_by_id(exact_id)) {
                matches.push_back(exact);
            }
        } catch (...) {
        }
    }

    for (const auto& item : items_) {
        if (!matches.empty() && item.id == matches[0]->id) {
            continue;
        }
        const bool wearable = (item.action_type == 20 || item.action_type == 107);
        if (clothes_only) {
            if (!wearable) continue;
        } else if (item.action_type == 19) {
            // Skip seeds unless query explicitly mentions seed
            if (!q.empty() && q.find("seed") == std::string::npos) continue;
        }
        if (q.empty() || item.name_lower.find(q) != std::string::npos) {
            matches.push_back(&item);
        }
    }

    auto start_sort = (!matches.empty() && is_all_digits(q)) ? (matches.begin() + 1) : matches.begin();
    std::sort(start_sort, matches.end(), [](const ItemEntry* a, const ItemEntry* b) {
        const bool wa = (a->action_type == 20 || a->action_type == 107);
        const bool wb = (b->action_type == 20 || b->action_type == 107);
        if (wa != wb) return wa > wb;
        if (a->name.size() != b->name.size()) return a->name.size() < b->name.size();
        return a->id < b->id;
    });

    if (matches.size() > max_results) {
        matches.resize(max_results);
    }
    return matches;
}

} // namespace evan
