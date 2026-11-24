#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <vector>

namespace evan {

struct ItemEntry {
    uint32_t id = 0;
    std::string name;
    std::string name_lower;
    uint8_t action_type = 0;
    uint8_t clothing_type = 0;
    uint16_t rarity = 0;
};

class ItemDatabase {
public:
    bool load_default_cache();
    bool load_from_file(const std::filesystem::path& path);
    bool parse_bytes(const uint8_t* data, size_t len);

    size_t size() const { return items_by_id_.size(); }
    const std::filesystem::path& loaded_path() const { return loaded_path_; }

    const ItemEntry* find_by_id(uint32_t id) const;
    std::string name_or_fallback(uint32_t id) const;

    // Returns 0..9 clothing slot index, or -1 if item is not wearable
    int get_clothing_slot(uint32_t id) const;
    static const char* slot_name(int slot);

    std::vector<const ItemEntry*> search(
        const std::string& query,
        bool clothes_only,
        size_t max_results = 24
    ) const;

private:
    std::vector<ItemEntry> items_;
    std::unordered_map<uint32_t, size_t> items_by_id_;
    std::filesystem::path loaded_path_;
};

} // namespace evan
