#pragma once
#include <mutex>
#include <ostream>
#include <fstream>
#include <fmt/format.h>
#include <fmt/printf.h>

class Logger
{
   public:
    void Init();
    void Uninit();

    void Log(std::string_view message)
    {
        LogImpl(message);
    }

    void Logf(std::string_view message)
    {
        LogImpl(message);
    }

    template <typename... Args>
    void Log(std::string_view format, const Args&... args)
    {
        LogImpl(fmt::format(format, args...));
    }

    template <typename... Args>
    void Logf(std::string_view format, const Args&... args)
    {
        LogImpl(fmt::sprintf(format, args...));
    }

   private:
    void LogImpl(std::string_view message);

    std::mutex m_Mutex;
    std::ofstream m_File;

};

extern Logger g_Logger;


#define LOG_IMPL(format, ...) ::g_Logger.Log(format, __VA_ARGS__)
#define LOGF_IMPL(format, ...) ::g_Logger.Logf(format, __VA_ARGS__)
#define LOG(format, ...) LOG_IMPL(format, __VA_ARGS__)
#define LOGF(format, ...) LOGF_IMPL(format, __VA_ARGS__)

#define LOG_DEV(format, ...) __noop
