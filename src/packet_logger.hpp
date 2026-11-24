#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>

namespace evan {

class PacketLogger {
public:
    PacketLogger() = default;
    PacketLogger(const std::filesystem::path& log_dir, bool enabled);
    ~PacketLogger();

    bool is_file_open() const { return file_.is_open(); }
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
    void maybe_flush(bool force = false);

    std::filesystem::path log_path_;
    std::ofstream file_;
    uint32_t pending_writes_ = 0;
    std::chrono::steady_clock::time_point last_flush_{};
};

} // namespace evan
