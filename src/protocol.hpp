#pragma once

#include <cmath>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace evan::proto {

enum class MessageType : uint32_t {
    ServerHello = 1,
    GenericText = 2,
    GameMessage = 3,
    GamePacket = 4,
    Error = 5,
    Track = 6,
    ClientLogRequest = 7,
    ClientLogResponse = 8
};

// Growtopia TankPacket / GameUpdatePacket types
enum class GamePacketType : uint8_t {
    State = 0,
    CallFunction = 1,
    UpdateStatus = 2,
    TileChangeRequest = 3,
    SendMapData = 4,
    SendTileUpdateData = 5,
    SendTileUpdateDataMultiple = 6,
    TileActivateRequest = 7,
    TileApplyDamage = 8,
    SendInventoryState = 9,
    ItemActivateRequest = 10,
    ItemActivateObjectRequest = 11,
    SendTileTreeState = 12,
    ModifyItemInventory = 13,
    ItemChangeObject = 14,
    SendLock = 15,
    SendItemDatabaseData = 16,
    SendParticleEffect = 17,
    SetIconState = 18,
    ItemEffect = 19,
    SetCharacterState = 20,
    PingReply = 21,
    PingRequest = 22,
    GotPunched = 23,
    AppCheckResponse = 24,
    AppIntegrityFail = 25,
    Disconnect = 26,
    BattleJoin = 27,
    BattleEvent = 28,
    UseDoor = 29,
    SendParental = 30,
    GoneFishin = 31,
    Steam = 32,
    PetBattle = 33,
    Npc = 34,
    Special = 35,
    SendParticleEffectV2 = 36,
    ActiveArrowToItem = 37,
    SelectTileIndex = 38,
    SendPlayerTributeData = 39,
    FtueSetItemToQuickInventory = 40,
    PveNpc = 41,
    PvpCardBattle = 42,
    PveApplyPlayerDamage = 43,
    PveNpcPositionUpdate = 44,
    SetExtraMods = 45,
    OnStepOnTileMod = 46
};

constexpr uint32_t PACKET_FLAG_EXTENDED = 0x08;

#pragma pack(push, 1)
struct GameUpdatePacket {
    uint8_t type = 0;
    uint8_t object_type = 0;
    uint8_t jump_count = 0;
    uint8_t animation_type = 0;
    int32_t net_id = 0;
    int32_t target_net_id = 0;
    uint32_t flags = 0;
    float float_var = 0.0f;
    int32_t value = 0;
    float vec_x = 0.0f;
    float vec_y = 0.0f;
    float vec_x2 = 0.0f;
    float vec_y2 = 0.0f;
    float particle_rotation = 0.0f;
    int32_t int_x = 0;
    int32_t int_y = 0;
    uint32_t extra_data_size = 0;
};
#pragma pack(pop)
static_assert(sizeof(GameUpdatePacket) == 56, "GameUpdatePacket must be 56 bytes on the wire");

class TextParse {
public:
    TextParse() = default;
    explicit TextParse(const std::string& raw);

    void parse(const std::string& raw);
    bool empty() const { return lines_.empty(); }
    bool has(const std::string& key) const;
    std::string get(const std::string& key, size_t value_index = 0) const;
    std::string get_joined(const std::string& key) const;
    void set(const std::string& key, const std::string& value);
    std::string render() const;

private:
    struct Line {
        bool is_kv = false;
        bool leading_pipe = false;
        std::string raw_line;
        std::string key;
        std::vector<std::string> values;
    };

    std::vector<Line> lines_;
    std::string line_ending_ = "\n";
    bool trailing_newline_ = false;
};

struct Vec2 {
    float x = 0.0f;
    float y = 0.0f;
};

struct Vec3 {
    float x = 0.0f;
    float y = 0.0f;
    float z = 0.0f;
};

struct Variant {
    enum class Type : uint8_t {
        Float = 1,
        String = 2,
        Vec2 = 3,
        Vec3 = 4,
        Unsigned = 5,
        Signed = 9,
        Int64 = 10,
        Uint64 = 11
    };

    Type type = Type::String;
    std::variant<float, std::string, Vec2, Vec3, uint32_t, int32_t, int64_t, uint64_t> value;

    static Variant make_float(float v) { return Variant{Type::Float, v}; }
    static Variant make_string(std::string v) { return Variant{Type::String, std::move(v)}; }
    static Variant make_vec2(float x, float y) { return Variant{Type::Vec2, Vec2{x, y}}; }
    static Variant make_vec3(float x, float y, float z) { return Variant{Type::Vec3, Vec3{x, y, z}}; }
    static Variant make_unsigned(uint32_t v) { return Variant{Type::Unsigned, v}; }
    static Variant make_signed(int32_t v) { return Variant{Type::Signed, v}; }
    static Variant make_int64(int64_t v) { return Variant{Type::Int64, v}; }
    static Variant make_uint64(uint64_t v) { return Variant{Type::Uint64, v}; }

    std::string as_string() const;
    std::optional<int64_t> as_int() const;
};

class VariantList {
public:
    std::vector<Variant> items;

    static std::optional<VariantList> parse(const uint8_t* data, size_t len);
    std::vector<uint8_t> serialize() const;

    std::string function_name() const;
    std::string summary() const;
    std::string detailed_dump(bool truncate_strings = false) const;
};

// Diagnostic / logging helpers
const char* message_type_name(MessageType t);
const char* game_packet_type_name(uint8_t type);
std::string format_packet_flags(uint32_t flags);
std::string hex_dump(const uint8_t* data, size_t len, size_t max_bytes = 512);

// Message framing helpers
std::optional<MessageType> read_message_type(const uint8_t* data, size_t len);
std::string decode_text_payload(const uint8_t* data, size_t len);
std::vector<uint8_t> encode_text_packet(MessageType type, const std::string& text);
std::vector<uint8_t> encode_server_hello();

struct RedirectRewriteResult {
    std::vector<uint8_t> packet;
    std::string real_ip;
    uint16_t real_port = 0;
};

std::optional<RedirectRewriteResult> try_rewrite_on_send_to_server(
    const uint8_t* raw,
    size_t len,
    const std::string& local_ip,
    uint16_t local_port
);

std::vector<uint8_t> build_call_function_packet(int32_t net_id, int32_t delay_ms, const VariantList& vl);
std::vector<uint8_t> build_on_console_message(const std::string& msg);
std::vector<uint8_t> build_on_dialog_request(const std::string& dialog_markup);
std::vector<uint8_t> build_on_name_changed(
    int32_t net_id,
    const std::string& name,
    const std::string& extra_json = ""
);
std::vector<uint8_t> build_on_text_overlay(const std::string& text);
std::vector<uint8_t> build_on_talk_bubble(int32_t net_id, const std::string& text);
std::vector<uint8_t> build_on_change_skin(int32_t net_id, uint32_t skin_color);
std::vector<uint8_t> build_on_country_state(int32_t net_id, const std::string& country);
std::vector<uint8_t> build_on_set_current_weather(uint32_t weather_id);
std::vector<uint8_t> build_on_set_clothing(int32_t net_id, const uint32_t slots[10], uint32_t skin_color);
std::vector<uint8_t> build_modify_item_inventory(uint32_t item_id, int8_t delta);
std::vector<uint8_t> encode_game_packet(const GameUpdatePacket& gp);
std::vector<uint8_t> build_play_sfx(const std::string& file, int32_t delay_ms = 0);

std::string strip_growtopia_colors(const std::string& text);
std::string apply_evan_brand_to_console_msg(const std::string& msg);
bool parse_inventory_state(
    const uint8_t* extra,
    size_t len,
    std::vector<std::pair<uint16_t, uint8_t>>& out_items,
    uint32_t& out_slots
);

inline std::pair<int, int> pixel_to_tile(float x, float y) {
    return {
        static_cast<int>(std::floor((x + 10.0f) / 32.0f)),
        static_cast<int>(std::floor((y + 15.0f) / 32.0f))
    };
}

} // namespace evan::proto
