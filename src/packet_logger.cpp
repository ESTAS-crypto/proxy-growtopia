#include "packet_logger.hpp"

#include "protocol.hpp"

#include <windows.h>

#include <cstdio>
#include <cstring>
#include <ctime>
#include <iostream>
#include <sstream>

namespace evan {

namespace {

std::string timestamp_hms_ms(std::chrono::system_clock::time_point tp) {
    using namespace std::chrono;
    const auto ms = duration_cast<milliseconds>(tp.time_since_epoch()) % 1000;
    const std::time_t tt = system_clock::to_time_t(tp);
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

PacketLogger::PacketLogger(const std::filesystem::path& log_dir, bool enabled, UiLogSink ui_sink)
    : ui_sink_(std::move(ui_sink)) {
    if (enabled && !log_dir.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(log_dir, ec);
        if (!ec) {
            log_path_ = log_dir / timestamp_filename();
            file_.open(log_path_, std::ios::out | std::ios::trunc);
            if (file_.is_open()) {
                file_open_ = true;
                file_ << "=== EvanProxy Packet Session ("
                      << timestamp_hms_ms(std::chrono::system_clock::now()) << ") ===\n";
                file_.flush();
            }
        }
    }
    worker_ = std::thread(&PacketLogger::worker_loop, this);
}

PacketLogger::~PacketLogger() {
    {
        std::lock_guard<std::mutex> lk(mu_);
        stop_ = true;
    }
    cv_.notify_all();
    if (worker_.joinable()) {
        worker_.join();
    }
    if (file_open_) {
        file_.flush();
        file_.close();
        file_open_ = false;
    }
}

void PacketLogger::enqueue(LogTask&& task) {
    constexpr size_t kMaxQueue = 4096;
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (stop_) return;
        if (queue_.size() >= kMaxQueue) {
            // Keep ENet thread zero-block by dropping oldest noisy entry when saturated
            queue_.pop_front();
        }
        queue_.push_back(std::move(task));
    }
    cv_.notify_one();
}

void PacketLogger::log_event(const std::string& line) {
    if (!file_open_) return;
    LogTask task;
    task.kind = LogTask::Kind::Event;
    task.sys_time = std::chrono::system_clock::now();
    task.text = line;
    task.force_flush = true;
    enqueue(std::move(task));
}

void PacketLogger::log_action(const std::string& line, bool to_console) {
    if (!file_open_ && !to_console) return;
    LogTask task;
    task.kind = LogTask::Kind::Action;
    task.sys_time = std::chrono::system_clock::now();
    task.text = line;
    task.console_text = to_console;
    enqueue(std::move(task));
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
    const bool any_console = !quiet_console && (console_text || console_variants || console_game || include_hex);
    if (!file_open_ && !any_console) return;

    // Under heavy load drop State(0) movement telemetry first so important packets aren't evicted
    if (len >= 4 + sizeof(proto::GameUpdatePacket)) {
        const auto mt = proto::read_message_type(raw, len);
        if (mt && *mt == proto::MessageType::GamePacket &&
            raw[4] == static_cast<uint8_t>(proto::GamePacketType::State)) {
            std::lock_guard<std::mutex> lk(mu_);
            if (queue_.size() >= 2048) return;
        }
    }

    LogTask task;
    task.kind = LogTask::Kind::Packet;
    task.sys_time = std::chrono::system_clock::now();
    task.seq = seq;
    task.dir = dir;
    task.channel = channel;
    task.enet_flags = enet_flags;
    task.console_text = console_text;
    task.console_variants = console_variants;
    task.console_game = console_game;
    task.include_hex = include_hex;
    task.quiet_console = quiet_console;
    task.raw.assign(raw, raw + len);
    enqueue(std::move(task));
}

void PacketLogger::process_task(
    const LogTask& task,
    uint32_t& pending_writes,
    std::chrono::steady_clock::time_point& last_flush
) {
    auto maybe_flush = [&](bool force) {
        if (!file_open_) return;
        const auto now = std::chrono::steady_clock::now();
        if (force || pending_writes >= 64 || (now - last_flush) >= std::chrono::milliseconds(1000)) {
            file_.flush();
            pending_writes = 0;
            last_flush = now;
        }
    };

    if (task.kind == LogTask::Kind::Event) {
        if (file_open_) {
            file_ << "[" << timestamp_hms_ms(task.sys_time) << "] " << task.text << "\n";
            ++pending_writes;
            maybe_flush(task.force_flush);
        }
        return;
    }

    if (task.kind == LogTask::Kind::Action) {
        if (file_open_) {
            file_ << "[" << timestamp_hms_ms(task.sys_time) << "] [ACTION] " << task.text << "\n";
            ++pending_writes;
            maybe_flush(false);
        }
        if (task.console_text) {
            std::cout << "[ACTION] " << task.text << "\n";
            if (ui_sink_) {
                ui_sink_(LogTag::Action, "ACT", task.text);
            }
        }
        return;
    }

    // Kind::Packet
    const uint8_t* raw = task.raw.data();
    const size_t len = task.raw.size();
    const char* dir = task.dir;
    const char* rel_tag = (task.enet_flags & 1u) ? "REL" : "UNREL";
    auto mt_opt = proto::read_message_type(raw, len);
    const uint32_t raw_mt = mt_opt ? static_cast<uint32_t>(*mt_opt) : 0;
    const char* mt_name = mt_opt ? proto::message_type_name(*mt_opt) : "Malformed";

    std::ostringstream hdr;
    hdr << "[" << timestamp_hms_ms(task.sys_time) << "] #" << task.seq << " " << dir
        << " ch=" << static_cast<int>(task.channel)
        << " len=" << len
        << " " << rel_tag
        << " " << mt_name << "(" << raw_mt << ")";

    std::ostringstream file_entry;
    file_entry << hdr.str();

    std::string console_line;
    bool print_console = false;

    if (!mt_opt) {
        file_entry << " raw=" << proto::hex_dump(raw, len, 512);
        if (task.console_game) {
            console_line = hdr.str() + " raw=" + proto::hex_dump(raw, len, 64);
            print_console = true;
        }
    } else if (*mt_opt == proto::MessageType::ServerHello) {
        if (task.console_text || task.console_game) {
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
        if (task.console_text) {
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
                if (task.console_variants) {
                    const std::string fn = vl->function_name();
                    const bool noisy_variant =
                        !task.console_game &&
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
                if (task.console_game) {
                    console_line = std::string("[") + dir + " CallFunction] unparsed extra=" +
                                   std::to_string(gp.extra_data_size);
                    print_console = true;
                }
            }
        } else {
            if (has_extra) {
                file_entry << "\n  ExtraHex: " << proto::hex_dump(raw + 4 + sizeof(gp), gp.extra_data_size, 256);
            }
            if (task.console_game) {
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
        if (task.console_game) {
            console_line = hdr.str() + " raw=" + proto::hex_dump(raw, len, 64);
            print_console = true;
        }
    }

    if (task.include_hex) {
        std::string hx = proto::hex_dump(raw, len, 512);
        file_entry << "\n  Hex: " << hx;
        if (print_console || task.console_game || task.console_variants || task.console_text) {
            if (!print_console) {
                console_line = hdr.str();
                print_console = true;
            }
            console_line += "\n  [Hex] " + proto::hex_dump(raw, len, 128);
        }
    }

    if (task.quiet_console) {
        print_console = false;
    }

    if (file_open_) {
        file_ << file_entry.str() << "\n";
        ++pending_writes;
        maybe_flush(false);
    }
    if (print_console) {
        std::cout << console_line << "\n";
        if (ui_sink_) {
            ui_sink_(LogTag::Packet, dir ? dir : "PKT", console_line);
        }
    }
}

void PacketLogger::worker_loop() {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    uint32_t pending_writes = 0;
    auto last_flush = std::chrono::steady_clock::now();

    while (true) {
        std::deque<LogTask> batch;
        {
            std::unique_lock<std::mutex> lk(mu_);
            cv_.wait(lk, [&] { return stop_ || !queue_.empty(); });
            if (queue_.empty() && stop_) {
                break;
            }
            batch.swap(queue_);
        }
        for (const auto& task : batch) {
            process_task(task, pending_writes, last_flush);
        }
    }
}

} // namespace evan
