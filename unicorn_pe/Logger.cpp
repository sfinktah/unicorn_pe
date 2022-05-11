#include <exception>
#include <time.h>
#include "Logger.hpp"
#include "Filesystem.hpp"
#include <fmt/format.h>

Logger g_Logger;
clock_t g_startTime;

void Logger::Init() {
    g_startTime = clock();
    try {
        m_File.open(GetDllFolder() / "Latest.log", std::ios_base::out | std::ios_base::trunc);
    } catch (const std::exception& err) {
        Log("Failed to create log file: {}", err.what());
    }
}

void Logger::Uninit() {
    m_File.close();
}

#ifdef SFINK
#include "date_howard.h"
std::string GetTimeFormatted() {
    using namespace date;
    auto now   = std::chrono::system_clock::now();
    auto today = date::floor<days>(now);

    std::ostringstream ss;
    ss << today << ' ' << make_time(now - today) << " UTC" << ' ' << (clock() - g_startTime);

    return ss.str();
}

#endif

void Logger::LogImpl(std::string_view message) {
#ifdef SFINK
    auto output = fmt::format("[unicorn_pe] {:6} [{}] [Debug] {}\n", GetCurrentThreadId(), GetTimeFormatted(), message);
#else
    time_t time;
    tm local_time;

    ::time(&time);
    ::localtime_s(&local_time, &time);

    auto output = fmt::format("[{:0>2}:{:0>2}:{:0>2}] {}\n", local_time.tm_hour, local_time.tm_min,
                              local_time.tm_sec, message);
#endif

    std::lock_guard lock(m_Mutex);

    if (m_File.is_open())
        m_File << output << std::flush;
}
