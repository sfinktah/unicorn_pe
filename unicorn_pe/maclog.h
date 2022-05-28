#pragma once

#define LOG_NOOP(...) (0)
#define LOG_TRACE LOG
#define LOG_INFO LOG
#define LOG_DEBUG LOG
#define LOG_WARN LOG
#define LOG_FUNC LOG
#define LOG_ERROR LOG
#define LOG_TRACE_UNIQ LOG_NOOP
#define LOG_TRACE_UNIQ_KEYED LOG_NOOP

