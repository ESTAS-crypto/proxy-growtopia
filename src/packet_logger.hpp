#pragma once

#include "ui_bridge.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace evan {

class PacketLogger {
public:
    using UiLogSink = std::function<void(LogTag, const std::string&, const std::string&)>;

    PacketLogger() = default;
    PacketLogger(const std::filesystem::path& log_dir, bool enabled, UiLogSink ui_sink = {});
    ~PacketLogger();

    PacketLogger(const PacketLogger&) = delete;
    PacketLogger& operator=(const PacketLogger&) = delete;

    bool is_file_open() const { return file_open_; }
    const std::filesystem::path& log_file_path() const { return log_path_; }

    void log_event(const std::string& line);
    void log_action(const std::string& line, bool to_console);
    void log_packet(
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
        bool quiet_console = false
    );

private:
    struct LogTask {
        enum class Kind : uint8_t { Event, Action, Packet };
        Kind kind = Kind::Event;
        std::chrono::system_clock::time_point sys_time{};
        uint64_t seq = 0;
        const char* dir = "";
        uint8_t channel = 0;
        uint32_t enet_flags = 0;
        bool console_text = false;
        bool console_variants = false;
        bool console_game = false;
        bool include_hex = false;
        bool quiet_console = false;
        bool force_flush = false;
        std::string text;
        std::vector<uint8_t> raw;
    };

    void enqueue(LogTask&& task);
    void worker_loop();
    void process_task(const LogTask& task, uint32_t& pending_writes,
                      std::chrono::steady_clock::time_point& last_flush);

    std::filesystem::path log_path_;
    std::ofstream file_;
    bool file_open_ = false;
    UiLogSink ui_sink_;
    std::mutex mu_;
    std::condition_variable cv_;
    std::deque<LogTask> queue_;
    bool stop_ = false;
    std::thread worker_;
};

} // namespace evan
