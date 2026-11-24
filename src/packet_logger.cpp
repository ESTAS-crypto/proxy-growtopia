#include "packet_logger.hpp"

#include "protocol.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <iostream>
#include <sstream>

namespace evan {

namespace {

std::string timestamp_hms_ms() {
    using namespace std::chrono;
    const auto now = system_clock::now();
    const auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    const std::time_t tt = system_clock::to_time_t(now);
    std::tm tm_local{};
    localtime_s(&tm_local, &tt);
    char buf[32] = {};
    std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d.%03lld",
                  tm_local.tm_hour, tm_local.tm_min, tm_local.tm_sec,
                  static_cast<long long>(ms.count()));
    return std::string(buf);
}

std::string timestamp_filename() {
    const std::time_t tt = std::time(nullptr);
    std::tm tm_local{};
    localtime_s(&tm_local, &tt);
    char buf[48] = {};
    std::snprintf(buf, sizeof(buf), "packets_%04d%02d%02d_%02d%02d%02d.log",
                  tm_local.tm_year + 1900, tm_local.tm_mon + 1, tm_local.tm_mday,
                  tm_local.tm_hour, tm_local.tm_min, tm_local.tm_sec);
    return std::string(buf);
}

std::string sanitize_single_line(std::string s) {
    for (char& c : s) {
        if (c == '\r') c = ' ';
        else if (c == '\n') c = '|';
    }
    return s;
}

} // namespace

PacketLogger::PacketLogger(const std::filesystem::path& log_dir, bool enabled) {
    if (!enabled || log_dir.empty()) {
        return;
    }
    std::error_code ec;
    std::filesystem::create_directories(log_dir, ec);
    if (ec) {
        return;
    }
    log_path_ = log_dir / timestamp_filename();
    file_.open(log_path_, std::ios::out | std::ios::trunc);
    if (file_.is_open()) {
        file_ << "=== EvanProxy Packet Session (" << timestamp_hms_ms() << ") ===\n";
        file_.flush();
        last_flush_ = std::chrono::steady_clock::now();
    }
}

PacketLogger::~PacketLogger() {
    maybe_flush(true);
}

void PacketLogger::maybe_flush(bool force) {
    if (!file_.is_open()) return;
    const auto now = std::chrono::steady_clock::now();
    if (force || pending_writes_ >= 64 || (now - last_flush_) >= std::chrono::milliseconds(1000)) {
        file_.flush();
        pending_writes_ = 0;
        last_flush_ = now;
    }
}

void PacketLogger::log_event(const std::string& line) {
    if (file_.is_open()) {
        file_ << "[" << timestamp_hms_ms() << "] " << line << "\n";
        ++pending_writes_;
        maybe_flush(true);
    }
}

void PacketLogger::log_action(const std::string& line, bool to_console) {
    if (file_.is_open()) {
        file_ << "[" << timestamp_hms_ms() << "] [ACTION] " << line << "\n";
        ++pending_writes_;
        maybe_flush(false);
    }
    if (to_console) {
        std::cout << "[ACTION] " << line << "\n";
    }
}

void PacketLogger::log_packet(
    uint64_t seq,
    const char* dir,
    uint8_t channel,
    uint32_t enet_flags,
    const uint8_t* raw,
    size_t len,
    bool console_text,
    bool console_variants,
    bool console_game,
    bool include_hex,
    bool quiet_console
) {
    if (!raw || len == 0) return;

    const char* rel_tag = (enet_flags & 1u) ? "REL" : "UNREL";
    auto mt_opt = proto::read_message_type(raw, len);
    const uint32_t raw_mt = mt_opt ? static_cast<uint32_t>(*mt_opt) : 0;
    const char* mt_name = mt_opt ? proto::message_type_name(*mt_opt) : "Malformed";

    std::ostringstream hdr;
    hdr << "[" << timestamp_hms_ms() << "] #" << seq << " " << dir
        << " ch=" << static_cast<int>(channel)
        << " len=" << len
        << " " << rel_tag
        << " " << mt_name << "(" << raw_mt << ")";

    std::ostringstream file_entry;
    file_entry << hdr.str();

    std::string console_line;
    bool print_console = false;

    if (!mt_opt) {
        file_entry << " raw=" << proto::hex_dump(raw, len, 512);
        if (console_game) {
            console_line = hdr.str() + " raw=" + proto::hex_dump(raw, len, 64);
            print_console = true;
        }
    } else if (*mt_opt == proto::MessageType::ServerHello) {
        if (console_text || console_game) {
            console_line = std::string("[") + dir + " Hello]";
            print_console = true;
        }
    } else if (*mt_opt == proto::MessageType::GenericText ||
               *mt_opt == proto::MessageType::GameMessage ||
               *mt_opt == proto::MessageType::Track ||
               *mt_opt == proto::MessageType::Error ||
               *mt_opt == proto::MessageType::ClientLogRequest ||
               *mt_opt == proto::MessageType::ClientLogResponse) {
        std::string txt = proto::decode_text_payload(raw, len);
        file_entry << "\n  " << txt;
        if (console_text) {
            console_line = std::string("[") + dir + " " + mt_name + "] " + sanitize_single_line(txt);
            print_console = true;
        }
    } else if (*mt_opt == proto::MessageType::GamePacket &&
               len >= 4 + sizeof(proto::GameUpdatePacket)) {
        proto::GameUpdatePacket gp{};
        std::memcpy(&gp, raw + 4, sizeof(gp));
        const char* gp_name = proto::game_packet_type_name(gp.type);
        const std::string flags_str = proto::format_packet_flags(gp.flags);

        file_entry << " -> " << gp_name << "(" << static_cast<int>(gp.type) << ")"
                   << " obj=" << static_cast<int>(gp.object_type)
                   << " jump=" << static_cast<int>(gp.jump_count)
                   << " anim=" << static_cast<int>(gp.animation_type)
                   << " net=" << gp.net_id
                   << " target=" << gp.target_net_id
                   << " flags=" << flags_str
                   << " float=" << gp.float_var
                   << " val=" << gp.value
                   << " vec=(" << gp.vec_x << "," << gp.vec_y << ")"
                   << " vec2=(" << gp.vec_x2 << "," << gp.vec_y2 << ")"
                   << " rot=" << gp.particle_rotation
                   << " tile=(" << gp.int_x << "," << gp.int_y << ")"
                   << " extra=" << gp.extra_data_size;

        const bool has_extra = ((gp.flags & proto::PACKET_FLAG_EXTENDED) != 0) &&
                               gp.extra_data_size > 0 &&
                               (4 + sizeof(gp) + gp.extra_data_size <= len);

        if (gp.type == static_cast<uint8_t>(proto::GamePacketType::CallFunction) && has_extra) {
            auto vl = proto::VariantList::parse(raw + 4 + sizeof(gp), gp.extra_data_size);
            if (vl) {
                file_entry << "\n  Variant: " << vl->detailed_dump(false);
                if (console_variants) {
                    const std::string fn = vl->function_name();
                    const bool noisy_variant =
                        !console_game &&
                        (fn == "OnUpdateRespawnTimeout" ||
                         fn == "OnFlagMay2019" ||
                         fn == "OnClearItemTransforms" ||
                         fn == "OnAction" ||
                         fn == "OnEmoticonDataChanged" ||
                         fn == "OnEventButtonDataSet");
                    if (!noisy_variant) {
                        console_line = std::string("[") + dir + " Variant] " + vl->summary();
                        print_console = true;
                    }
                }
            } else {
                file_entry << "\n  Variant(unparsed)=" << proto::hex_dump(raw + 4 + sizeof(gp), gp.extra_data_size, 256);
                if (console_game) {
                    console_line = std::string("[") + dir + " CallFunction] unparsed extra=" +
                                   std::to_string(gp.extra_data_size);
                    print_console = true;
                }
            }
        } else {
            if (has_extra) {
                file_entry << "\n  ExtraHex: " << proto::hex_dump(raw + 4 + sizeof(gp), gp.extra_data_size, 256);
            }
            if (console_game) {
                std::ostringstream cs;
                cs << "[" << dir << " " << gp_name << "] net=" << gp.net_id
                   << " val=" << gp.value << " tile=(" << gp.int_x << "," << gp.int_y << ")"
                   << " flags=" << flags_str;
                if (gp.extra_data_size > 0) cs << " extra=" << gp.extra_data_size;
                console_line = cs.str();
                print_console = true;
            }
        }
    } else {
        file_entry << " raw=" << proto::hex_dump(raw, len, 512);
        if (console_game) {
            console_line = hdr.str() + " raw=" + proto::hex_dump(raw, len, 64);
            print_console = true;
        }
    }

    if (include_hex) {
        std::string hx = proto::hex_dump(raw, len, 512);
        file_entry << "\n  Hex: " << hx;
        if (print_console || console_game || console_variants || console_text) {
            if (!print_console) {
                console_line = hdr.str();
                print_console = true;
            }
            console_line += "\n  [Hex] " + proto::hex_dump(raw, len, 128);
        }
    }

    if (quiet_console) {
        print_console = false;
    }

    if (file_.is_open()) {
        file_ << file_entry.str() << "\n";
        ++pending_writes_;
        maybe_flush(false);
    }
    if (print_console) {
        std::cout << console_line << "\n";
    }
}

} // namespace evan
