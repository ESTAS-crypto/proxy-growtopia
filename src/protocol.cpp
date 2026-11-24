#include "protocol.hpp"

#include <cstring>
#include <sstream>

namespace evan::proto {

namespace {

template <typename T>
void append_le(std::vector<uint8_t>& out, const T& v) {
    const auto* p = reinterpret_cast<const uint8_t*>(&v);
    out.insert(out.end(), p, p + sizeof(T));
}

template <typename T>
bool read_le(const uint8_t* data, size_t len, size_t& pos, T& out) {
    if (pos + sizeof(T) > len) return false;
    std::memcpy(&out, data + pos, sizeof(T));
    pos += sizeof(T);
    return true;
}

std::vector<std::string> split_pipe(const std::string& s) {
    std::vector<std::string> parts;
    size_t start = 0;
    while (true) {
        size_t p = s.find('|', start);
        if (p == std::string::npos) {
            parts.push_back(s.substr(start));
            break;
        }
        parts.push_back(s.substr(start, p - start));
        start = p + 1;
    }
    return parts;
}

} // namespace

TextParse::TextParse(const std::string& raw) {
    parse(raw);
}

void TextParse::parse(const std::string& raw) {
    lines_.clear();
    line_ending_ = (raw.find("\r\n") != std::string::npos) ? "\r\n" : "\n";
    trailing_newline_ = (!raw.empty() && raw.back() == '\n');

    size_t pos = 0;
    while (pos < raw.size()) {
        size_t nl = raw.find('\n', pos);
        size_t next = (nl == std::string::npos) ? raw.size() : (nl + 1);
        std::string line = raw.substr(pos, (nl == std::string::npos ? raw.size() : nl) - pos);
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        pos = next;

        Line entry;
        entry.raw_line = line;

        if (!line.empty() && line[0] != '#') {
            size_t pipe = line.find('|');
            if (pipe != std::string::npos) {
                if (pipe == 0) {
                    // Handle Growtopia leading pipe like `|text|/proxy`
                    std::string rest = line.substr(1);
                    auto parts = split_pipe(rest);
                    if (!parts.empty() && !parts[0].empty()) {
                        entry.is_kv = true;
                        entry.leading_pipe = true;
                        entry.key = parts[0];
                        for (size_t i = 1; i < parts.size(); ++i) {
                            entry.values.push_back(parts[i]);
                        }
                    }
                } else {
                    auto parts = split_pipe(line);
                    if (!parts.empty()) {
                        entry.is_kv = true;
                        entry.key = parts[0];
                        for (size_t i = 1; i < parts.size(); ++i) {
                            entry.values.push_back(parts[i]);
                        }
                    }
                }
            }
        }
        lines_.push_back(std::move(entry));
    }
}

bool TextParse::has(const std::string& key) const {
    for (const auto& l : lines_) {
        if (l.is_kv && l.key == key) {
            return true;
        }
    }
    return false;
}

std::string TextParse::get(const std::string& key, size_t value_index) const {
    for (const auto& l : lines_) {
        if (l.is_kv && l.key == key) {
            if (value_index < l.values.size()) {
                return l.values[value_index];
            }
            return {};
        }
    }
    return {};
}

std::string TextParse::get_joined(const std::string& key) const {
    for (const auto& l : lines_) {
        if (l.is_kv && l.key == key) {
            std::string out;
            for (size_t i = 0; i < l.values.size(); ++i) {
                if (i > 0) out.push_back('|');
                out.append(l.values[i]);
            }
            return out;
        }
    }
    return {};
}

void TextParse::set(const std::string& key, const std::string& value) {
    for (auto& l : lines_) {
        if (l.is_kv && l.key == key) {
            l.values.clear();
            l.values.push_back(value);
            return;
        }
    }
    Line entry;
    entry.is_kv = true;
    entry.key = key;
    entry.values.push_back(value);
    lines_.push_back(std::move(entry));
}

std::string TextParse::render() const {
    std::string out;
    for (size_t i = 0; i < lines_.size(); ++i) {
        const auto& l = lines_[i];
        if (!l.is_kv) {
            out.append(l.raw_line);
        } else {
            if (l.leading_pipe) {
                out.push_back('|');
            }
            out.append(l.key);
            for (const auto& v : l.values) {
                out.push_back('|');
                out.append(v);
            }
        }
        if (i + 1 < lines_.size() || trailing_newline_) {
            out.append(line_ending_);
        }
    }
    return out;
}

std::string Variant::as_string() const {
    if (type == Type::String && std::holds_alternative<std::string>(value)) {
        return std::get<std::string>(value);
    }
    return {};
}

std::optional<int64_t> Variant::as_int() const {
    if (type == Type::Signed && std::holds_alternative<int32_t>(value)) {
        return static_cast<int64_t>(std::get<int32_t>(value));
    }
    if (type == Type::Unsigned && std::holds_alternative<uint32_t>(value)) {
        return static_cast<int64_t>(std::get<uint32_t>(value));
    }
    if (type == Type::Int64 && std::holds_alternative<int64_t>(value)) {
        return std::get<int64_t>(value);
    }
    if (type == Type::Uint64 && std::holds_alternative<uint64_t>(value)) {
        return static_cast<int64_t>(std::get<uint64_t>(value));
    }
    return std::nullopt;
}

std::optional<VariantList> VariantList::parse(const uint8_t* data, size_t len) {
    if (!data || len < 1) {
        return std::nullopt;
    }

    size_t pos = 0;
    uint8_t count = data[pos++];
    VariantList vl;
    vl.items.resize(count);

    for (uint8_t i = 0; i < count; ++i) {
        uint8_t index = 0;
        uint8_t type_raw = 0;
        if (!read_le(data, len, pos, index) || !read_le(data, len, pos, type_raw)) {
            return std::nullopt;
        }
        if (index >= count) {
            return std::nullopt;
        }

        auto type = static_cast<Variant::Type>(type_raw);
        Variant var;
        var.type = type;

        switch (type) {
            case Variant::Type::Float: {
                float f = 0.0f;
                if (!read_le(data, len, pos, f)) return std::nullopt;
                var.value = f;
                break;
            }
            case Variant::Type::String: {
                uint32_t slen = 0;
                if (!read_le(data, len, pos, slen)) return std::nullopt;
                if (pos + slen > len) return std::nullopt;
                std::string s(reinterpret_cast<const char*>(data + pos), slen);
                pos += slen;
                var.value = std::move(s);
                break;
            }
            case Variant::Type::Vec2: {
                Vec2 v{};
                if (!read_le(data, len, pos, v.x) || !read_le(data, len, pos, v.y)) return std::nullopt;
                var.value = v;
                break;
            }
            case Variant::Type::Vec3: {
                Vec3 v{};
                if (!read_le(data, len, pos, v.x) || !read_le(data, len, pos, v.y) || !read_le(data, len, pos, v.z)) {
                    return std::nullopt;
                }
                var.value = v;
                break;
            }
            case Variant::Type::Unsigned: {
                uint32_t u = 0;
                if (!read_le(data, len, pos, u)) return std::nullopt;
                var.value = u;
                break;
            }
            case Variant::Type::Signed: {
                int32_t s = 0;
                if (!read_le(data, len, pos, s)) return std::nullopt;
                var.value = s;
                break;
            }
            case Variant::Type::Int64: {
                int64_t v = 0;
                if (!read_le(data, len, pos, v)) return std::nullopt;
                var.value = v;
                break;
            }
            case Variant::Type::Uint64: {
                uint64_t v = 0;
                if (!read_le(data, len, pos, v)) return std::nullopt;
                var.value = v;
                break;
            }
            default:
                return std::nullopt;
        }

        vl.items[index] = std::move(var);
    }

    return vl;
}

std::vector<uint8_t> VariantList::serialize() const {
    std::vector<uint8_t> out;
    const uint8_t count = static_cast<uint8_t>(items.size() > 255 ? 255 : items.size());
    out.push_back(count);

    for (uint8_t i = 0; i < count; ++i) {
        const auto& var = items[i];
        out.push_back(i);
        out.push_back(static_cast<uint8_t>(var.type));

        switch (var.type) {
            case Variant::Type::Float:
                append_le(out, std::get<float>(var.value));
                break;
            case Variant::Type::String: {
                const auto& s = std::get<std::string>(var.value);
                uint32_t slen = static_cast<uint32_t>(s.size());
                append_le(out, slen);
                out.insert(out.end(), s.begin(), s.end());
                break;
            }
            case Variant::Type::Vec2: {
                const auto& v = std::get<Vec2>(var.value);
                append_le(out, v.x);
                append_le(out, v.y);
                break;
            }
            case Variant::Type::Vec3: {
                const auto& v = std::get<Vec3>(var.value);
                append_le(out, v.x);
                append_le(out, v.y);
                append_le(out, v.z);
                break;
            }
            case Variant::Type::Unsigned:
                append_le(out, std::get<uint32_t>(var.value));
                break;
            case Variant::Type::Signed:
                append_le(out, std::get<int32_t>(var.value));
                break;
            case Variant::Type::Int64:
                append_le(out, std::get<int64_t>(var.value));
                break;
            case Variant::Type::Uint64:
                append_le(out, std::get<uint64_t>(var.value));
                break;
        }
    }
    return out;
}

std::string VariantList::function_name() const {
    if (items.empty()) return {};
    return items[0].as_string();
}

std::string VariantList::summary() const {
    std::ostringstream oss;
    oss << function_name();
    for (size_t i = 1; i < items.size(); ++i) {
        oss << " [" << i << "]=";
        const auto& v = items[i];
        switch (v.type) {
            case Variant::Type::Float:
                oss << std::get<float>(v.value);
                break;
            case Variant::Type::String: {
                const auto& s = std::get<std::string>(v.value);
                if (s.size() > 80) {
                    oss << '"' << s.substr(0, 77) << "...\"";
                } else {
                    oss << '"' << s << '"';
                }
                break;
            }
            case Variant::Type::Vec2: {
                const auto& p = std::get<Vec2>(v.value);
                oss << "(" << p.x << "," << p.y << ")";
                break;
            }
            case Variant::Type::Vec3: {
                const auto& p = std::get<Vec3>(v.value);
                oss << "(" << p.x << "," << p.y << "," << p.z << ")";
                break;
            }
            case Variant::Type::Unsigned:
                oss << std::get<uint32_t>(v.value) << "u";
                break;
            case Variant::Type::Signed:
                oss << std::get<int32_t>(v.value);
                break;
            case Variant::Type::Int64:
                oss << std::get<int64_t>(v.value);
                break;
            case Variant::Type::Uint64:
                oss << std::get<uint64_t>(v.value) << "u";
                break;
        }
    }
    return oss.str();
}

std::string VariantList::detailed_dump(bool truncate_strings) const {
    std::ostringstream oss;
    for (size_t i = 0; i < items.size(); ++i) {
        if (i > 0) oss << ", ";
        const auto& v = items[i];
        oss << "[" << i << "]";
        switch (v.type) {
            case Variant::Type::Float:
                oss << "(f)=" << std::get<float>(v.value);
                break;
            case Variant::Type::String: {
                const auto& s = std::get<std::string>(v.value);
                if (truncate_strings && s.size() > 160) {
                    oss << "(s)=\"" << s.substr(0, 157) << "...\"(" << s.size() << "B)";
                } else {
                    oss << "(s)=\"" << s << "\"";
                }
                break;
            }
            case Variant::Type::Vec2: {
                const auto& p = std::get<Vec2>(v.value);
                oss << "(v2)=(" << p.x << "," << p.y << ")";
                break;
            }
            case Variant::Type::Vec3: {
                const auto& p = std::get<Vec3>(v.value);
                oss << "(v3)=(" << p.x << "," << p.y << "," << p.z << ")";
                break;
            }
            case Variant::Type::Unsigned:
                oss << "(u)=" << std::get<uint32_t>(v.value);
                break;
            case Variant::Type::Signed:
                oss << "(i)=" << std::get<int32_t>(v.value);
                break;
            case Variant::Type::Int64:
                oss << "(i64)=" << std::get<int64_t>(v.value);
                break;
            case Variant::Type::Uint64:
                oss << "(u64)=" << std::get<uint64_t>(v.value);
                break;
        }
    }
    return oss.str();
}

const char* message_type_name(MessageType t) {
    switch (t) {
        case MessageType::ServerHello: return "ServerHello";
        case MessageType::GenericText: return "GenericText";
        case MessageType::GameMessage: return "GameMessage";
        case MessageType::GamePacket: return "GamePacket";
        case MessageType::Error: return "Error";
        case MessageType::Track: return "Track";
        case MessageType::ClientLogRequest: return "ClientLogRequest";
        case MessageType::ClientLogResponse: return "ClientLogResponse";
        default: return "Unknown";
    }
}

const char* game_packet_type_name(uint8_t type) {
    static constexpr const char* kNames[] = {
        "State",                      // 0
        "CallFunction",               // 1
        "UpdateStatus",               // 2
        "TileChangeRequest",          // 3
        "SendMapData",                // 4
        "SendTileUpdateData",         // 5
        "SendTileUpdateDataMultiple", // 6
        "TileActivateRequest",        // 7
        "TileApplyDamage",            // 8
        "SendInventoryState",         // 9
        "ItemActivateRequest",        // 10
        "ItemActivateObjectRequest",  // 11
        "SendTileTreeState",          // 12
        "ModifyItemInventory",        // 13
        "ItemChangeObject",           // 14
        "SendLock",                   // 15
        "SendItemDatabaseData",       // 16
        "SendParticleEffect",         // 17
        "SetIconState",               // 18
        "ItemEffect",                 // 19
        "SetCharacterState",          // 20
        "PingReply",                  // 21
        "PingRequest",                // 22
        "GotPunched",                 // 23
        "AppCheckResponse",           // 24
        "AppIntegrityFail",           // 25
        "Disconnect",                 // 26
        "BattleJoin",                 // 27
        "BattleEvent",                // 28
        "UseDoor",                    // 29
        "SendParental",               // 30
        "GoneFishin",                 // 31
        "Steam",                      // 32
        "PetBattle",                  // 33
        "Npc",                        // 34
        "Special",                    // 35
        "SendParticleEffectV2",       // 36
        "ActiveArrowToItem",          // 37
        "SelectTileIndex",            // 38
        "SendPlayerTributeData",      // 39
        "FtueSetItemToQuickInventory",// 40
        "PveNpc",                     // 41
        "PvpCardBattle",              // 42
        "PveApplyPlayerDamage",       // 43
        "PveNpcPositionUpdate",       // 44
        "SetExtraMods",               // 45
        "OnStepOnTileMod"             // 46
    };
    if (type < sizeof(kNames) / sizeof(kNames[0])) {
        return kNames[type];
    }
    return "Unknown";
}

std::string format_packet_flags(uint32_t flags) {
    if (flags == 0) return "NONE";
    struct FlagBit {
        uint32_t bit;
        const char* name;
    };
    static constexpr FlagBit kBits[] = {
        {0x00000001u, "WALK"},
        {0x00000004u, "SPAWN_RELATED"},
        {0x00000008u, "EXTENDED"},
        {0x00000010u, "FACING_LEFT"},
        {0x00000020u, "STANDING"},
        {0x00000040u, "FIRE_DAMAGE"},
        {0x00000080u, "JUMP"},
        {0x00000100u, "GOT_KILLED"},
        {0x00000200u, "PUNCH"},
        {0x00000400u, "PLACE"},
        {0x00000800u, "TILE_CHANGE"},
        {0x00001000u, "GOT_PUNCHED"},
        {0x00002000u, "RESPAWN"},
        {0x00004000u, "OBJECT_COLLECT"},
        {0x00008000u, "TRAMPOLINE"},
        {0x00010000u, "DAMAGE"},
        {0x00020000u, "SLIDE"},
        {0x00040000u, "PARASOL"},
        {0x00100000u, "SWIM"},
        {0x00200000u, "WALL_HANG"},
        {0x10000000u, "ACID_DAMAGE"}
    };
    std::ostringstream oss;
    bool first = true;
    uint32_t remaining = flags;
    for (const auto& fb : kBits) {
        if ((flags & fb.bit) != 0) {
            if (!first) oss << '|';
            oss << fb.name;
            first = false;
            remaining &= ~fb.bit;
        }
    }
    if (remaining != 0) {
        if (!first) oss << '|';
        oss << "0x" << std::hex << remaining;
    }
    return oss.str();
}

std::string hex_dump(const uint8_t* data, size_t len, size_t max_bytes) {
    if (!data || len == 0) return {};
    static constexpr char kHex[] = "0123456789ABCDEF";
    const size_t shown = (len > max_bytes) ? max_bytes : len;
    std::string out;
    out.reserve(shown * 3 + 32);
    for (size_t i = 0; i < shown; ++i) {
        if (i > 0) out.push_back(' ');
        out.push_back(kHex[(data[i] >> 4) & 0x0F]);
        out.push_back(kHex[data[i] & 0x0F]);
    }
    if (len > max_bytes) {
        out.append(" ...(+");
        out.append(std::to_string(len - max_bytes));
        out.append("B)");
    }
    return out;
}

std::optional<MessageType> read_message_type(const uint8_t* data, size_t len) {
    if (!data || len < 4) return std::nullopt;
    uint32_t raw = 0;
    std::memcpy(&raw, data, sizeof(raw));
    return static_cast<MessageType>(raw);
}

std::string decode_text_payload(const uint8_t* data, size_t len) {
    if (!data || len <= 4) return {};
    // Drop the trailing terminator byte (Growtopia leaves uninitialized garbage in the last byte)
    size_t body_len = len - 4;
    if (body_len > 0) {
        --body_len;
    }
    const char* start = reinterpret_cast<const char*>(data + 4);
    size_t nul_pos = 0;
    while (nul_pos < body_len && start[nul_pos] != '\0') {
        ++nul_pos;
    }
    return std::string(start, nul_pos);
}

std::vector<uint8_t> encode_text_packet(MessageType type, const std::string& text) {
    std::vector<uint8_t> out;
    out.reserve(4 + text.size() + 1);
    uint32_t raw_type = static_cast<uint32_t>(type);
    append_le(out, raw_type);
    out.insert(out.end(), text.begin(), text.end());
    out.push_back(0x00);
    return out;
}

std::vector<uint8_t> encode_server_hello() {
    std::vector<uint8_t> out;
    uint32_t raw_type = static_cast<uint32_t>(MessageType::ServerHello);
    append_le(out, raw_type);
    return out;
}

std::optional<RedirectRewriteResult> try_rewrite_on_send_to_server(
    const uint8_t* raw,
    size_t len,
    const std::string& local_ip,
    uint16_t local_port
) {
    if (!raw || len < 4 + sizeof(GameUpdatePacket)) {
        return std::nullopt;
    }
    auto msg_type = read_message_type(raw, len);
    if (!msg_type || *msg_type != MessageType::GamePacket) {
        return std::nullopt;
    }

    GameUpdatePacket pkt{};
    std::memcpy(&pkt, raw + 4, sizeof(GameUpdatePacket));
    if (pkt.type != static_cast<uint8_t>(GamePacketType::CallFunction) ||
        (pkt.flags & PACKET_FLAG_EXTENDED) == 0) {
        return std::nullopt;
    }

    const size_t extra_offset = 4 + sizeof(GameUpdatePacket);
    const size_t extra_avail = len - extra_offset;
    if (pkt.extra_data_size == 0 || pkt.extra_data_size > extra_avail) {
        return std::nullopt;
    }

    auto vl = VariantList::parse(raw + extra_offset, pkt.extra_data_size);
    if (!vl || vl->items.size() < 5 || vl->function_name() != "OnSendToServer") {
        return std::nullopt;
    }

    auto port_opt = vl->items[1].as_int();
    if (!port_opt || *port_opt <= 0 || *port_opt > 65535) {
        return std::nullopt;
    }
    if (vl->items[4].type != Variant::Type::String) {
        return std::nullopt;
    }

    const std::string orig_dest = vl->items[4].as_string();
    const size_t pipe_pos = orig_dest.find('|');
    const std::string real_ip = (pipe_pos == std::string::npos) ? orig_dest : orig_dest.substr(0, pipe_pos);
    const std::string suffix = (pipe_pos == std::string::npos) ? std::string{} : orig_dest.substr(pipe_pos);
    if (real_ip.empty()) {
        return std::nullopt;
    }

    RedirectRewriteResult res;
    res.real_ip = real_ip;
    res.real_port = static_cast<uint16_t>(*port_opt);

    // Rewrite [1] port keeping exact Signed/Unsigned type
    if (vl->items[1].type == Variant::Type::Unsigned) {
        vl->items[1].value = static_cast<uint32_t>(local_port);
    } else {
        vl->items[1].value = static_cast<int32_t>(local_port);
    }

    // Rewrite [4] IP keeping |doorID|UUIDToken intact
    vl->items[4].value = local_ip + suffix;

    const auto new_extra = vl->serialize();
    pkt.extra_data_size = static_cast<uint32_t>(new_extra.size());

    res.packet.reserve(4 + sizeof(GameUpdatePacket) + new_extra.size());
    append_le(res.packet, static_cast<uint32_t>(MessageType::GamePacket));
    append_le(res.packet, pkt);
    res.packet.insert(res.packet.end(), new_extra.begin(), new_extra.end());
    return res;
}

std::vector<uint8_t> build_call_function_packet(int32_t net_id, int32_t delay_ms, const VariantList& vl) {
    const auto extra = vl.serialize();
    GameUpdatePacket pkt{};
    pkt.type = static_cast<uint8_t>(GamePacketType::CallFunction);
    pkt.net_id = net_id;
    pkt.flags = PACKET_FLAG_EXTENDED;
    pkt.value = delay_ms;
    pkt.extra_data_size = static_cast<uint32_t>(extra.size());

    std::vector<uint8_t> out;
    out.reserve(4 + sizeof(GameUpdatePacket) + extra.size());
    append_le(out, static_cast<uint32_t>(MessageType::GamePacket));
    append_le(out, pkt);
    out.insert(out.end(), extra.begin(), extra.end());
    return out;
}

std::vector<uint8_t> build_on_console_message(const std::string& msg) {
    VariantList vl;
    vl.items.push_back(Variant::make_string("OnConsoleMessage"));
    vl.items.push_back(Variant::make_string(msg));
    return build_call_function_packet(-1, 0, vl);
}

std::vector<uint8_t> build_on_dialog_request(const std::string& dialog_markup) {
    VariantList vl;
    vl.items.push_back(Variant::make_string("OnDialogRequest"));
    vl.items.push_back(Variant::make_string(dialog_markup));
    return build_call_function_packet(-1, 0, vl);
}

std::vector<uint8_t> build_on_name_changed(
    int32_t net_id,
    const std::string& name,
    const std::string& extra_json
) {
    VariantList vl;
    vl.items.push_back(Variant::make_string("OnNameChanged"));
    vl.items.push_back(Variant::make_string(name));
    if (!extra_json.empty()) {
        vl.items.push_back(Variant::make_string(extra_json));
    }
    return build_call_function_packet(net_id, 0, vl);
}

std::vector<uint8_t> build_on_text_overlay(const std::string& text) {
    VariantList vl;
    vl.items.push_back(Variant::make_string("OnTextOverlay"));
    vl.items.push_back(Variant::make_string(text));
    return build_call_function_packet(-1, 0, vl);
}

std::vector<uint8_t> build_on_talk_bubble(int32_t net_id, const std::string& text) {
    VariantList vl;
    vl.items.push_back(Variant::make_string("OnTalkBubble"));
    vl.items.push_back(Variant::make_signed(net_id));
    vl.items.push_back(Variant::make_string(text));
    vl.items.push_back(Variant::make_unsigned(0));
    return build_call_function_packet(-1, 0, vl);
}

std::vector<uint8_t> build_on_change_skin(int32_t net_id, uint32_t skin_color) {
    VariantList vl;
    vl.items.push_back(Variant::make_string("OnChangeSkin"));
    vl.items.push_back(Variant::make_unsigned(skin_color));
    return build_call_function_packet(net_id, 0, vl);
}

std::vector<uint8_t> build_on_country_state(int32_t net_id, const std::string& country) {
    VariantList vl;
    vl.items.push_back(Variant::make_string("OnCountryState"));
    vl.items.push_back(Variant::make_string(country));
    return build_call_function_packet(net_id, 0, vl);
}

std::vector<uint8_t> build_on_set_current_weather(uint32_t weather_id) {
    VariantList vl;
    vl.items.push_back(Variant::make_string("OnSetCurrentWeather"));
    vl.items.push_back(Variant::make_unsigned(weather_id));
    return build_call_function_packet(-1, 0, vl);
}

std::vector<uint8_t> build_on_set_clothing(int32_t net_id, const uint32_t slots[10], uint32_t skin_color) {
    VariantList vl;
    vl.items.push_back(Variant::make_string("OnSetClothing"));
    vl.items.push_back(Variant::make_vec3(
        static_cast<float>(slots[0]), static_cast<float>(slots[1]), static_cast<float>(slots[2])));
    vl.items.push_back(Variant::make_vec3(
        static_cast<float>(slots[3]), static_cast<float>(slots[4]), static_cast<float>(slots[5])));
    vl.items.push_back(Variant::make_vec3(
        static_cast<float>(slots[6]), static_cast<float>(slots[7]), static_cast<float>(slots[8])));
    vl.items.push_back(Variant::make_unsigned(skin_color));
    vl.items.push_back(Variant::make_vec3(static_cast<float>(slots[9]), 0.0f, 0.0f));
    return build_call_function_packet(net_id, 0, vl);
}

std::vector<uint8_t> encode_game_packet(const GameUpdatePacket& gp) {
    std::vector<uint8_t> out;
    out.reserve(4 + sizeof(GameUpdatePacket));
    append_le(out, static_cast<uint32_t>(MessageType::GamePacket));
    append_le(out, gp);
    return out;
}

std::vector<uint8_t> build_modify_item_inventory(uint32_t item_id, int8_t delta) {
    GameUpdatePacket gp{};
    gp.type = static_cast<uint8_t>(GamePacketType::ModifyItemInventory);
    gp.value = static_cast<int32_t>(item_id);
    if (delta < 0) {
        gp.jump_count = static_cast<uint8_t>(-delta);
    } else if (delta > 0) {
        gp.animation_type = static_cast<uint8_t>(delta);
    }
    return encode_game_packet(gp);
}

std::vector<uint8_t> build_play_sfx(const std::string& file, int32_t delay_ms) {
    return encode_text_packet(
        MessageType::GameMessage,
        "action|play_sfx\nfile|" + file + "\ndelayMS|" + std::to_string(delay_ms)
    );
}

std::string strip_growtopia_colors(const std::string& text) {
    std::string out;
    out.reserve(text.size());
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '`') {
            if (i + 1 < text.size()) {
                ++i;
            }
            continue;
        }
        out.push_back(text[i]);
    }
    return out;
}

std::string apply_evan_brand_to_console_msg(const std::string& msg) {
    if (msg.empty() || msg.find("EvanProxy") != std::string::npos) {
        return msg;
    }
    static constexpr const char* kTag = "`9[`#EvanProxy`9]`o ";
    if (msg.rfind("CP:", 0) == 0) {
        size_t sep = msg.find("_ ");
        if (sep != std::string::npos) {
            const size_t insert_pos = sep + 2;
            return msg.substr(0, insert_pos) + kTag + msg.substr(insert_pos);
        }
    }
    return std::string(kTag) + msg;
}

bool parse_inventory_state(
    const uint8_t* extra,
    size_t len,
    std::vector<std::pair<uint16_t, uint8_t>>& out_items,
    uint32_t& out_slots
) {
    out_items.clear();
    out_slots = 0;
    if (!extra || len < 7) {
        return false;
    }
    size_t pos = 1; // skip u8 version
    if (!read_le(extra, len, pos, out_slots)) return false;
    uint16_t count = 0;
    if (!read_le(extra, len, pos, count)) return false;
    if (pos + static_cast<size_t>(count) * 4 > len) {
        return false;
    }
    out_items.reserve(count);
    for (uint16_t i = 0; i < count; ++i) {
        uint16_t id = 0;
        uint8_t amount = 0;
        uint8_t flags = 0;
        if (!read_le(extra, len, pos, id) ||
            !read_le(extra, len, pos, amount) ||
            !read_le(extra, len, pos, flags)) {
            return false;
        }
        out_items.emplace_back(id, amount);
    }
    return true;
}

} // namespace evan::proto
