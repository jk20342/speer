#include "log.h"

#include <stdarg.h>
#include <stdio.h>

#include <string.h>

#ifndef SPEER_LOG_LEVEL
#define SPEER_LOG_LEVEL SPEER_LOG_DEBUG
#endif

static speer_log_fn_t g_log_fn = NULL;
static void *g_log_user = NULL;
static speer_log_level_t g_log_level = SPEER_LOG_LEVEL;

static const char *level_str(speer_log_level_t level) {
    switch (level) {
    case SPEER_LOG_TRACE:
        return "TRACE";
    case SPEER_LOG_DEBUG:
        return "DEBUG";
    case SPEER_LOG_INFO:
        return "INFO";
    case SPEER_LOG_WARN:
        return "WARN";
    case SPEER_LOG_ERROR:
        return "ERROR";
    case SPEER_LOG_FATAL:
        return "FATAL";
    default:
        return "UNKNOWN";
    }
}

void speer_log_set_callback(speer_log_fn_t fn, void *user) {
    g_log_fn = fn;
    g_log_user = user;
}

void speer_log_set_level(speer_log_level_t level) {
    g_log_level = level;
}

void speer_log(speer_log_level_t level, const char *module, const char *file, const char *func,
               int line, const char *fmt, ...) {
    if (level < g_log_level) return;

    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    buf[sizeof(buf) - 1] = '\0';

    if (g_log_fn) {
        speer_log_entry_t entry = {
            .level = level,
            .file = file,
            .func = func,
            .line = line,
            .timestamp_ms = 0,
            .module = module,
            .msg = buf,
        };
        g_log_fn(&entry, g_log_user);
    } else {
        const char *lvl = level_str(level);
        const char *fname = strrchr(file, '/');
        if (!fname) fname = strrchr(file, '\\');
        if (!fname)
            fname = file;
        else
            fname++;
        fprintf(stderr, "[%s] %s:%d (%s) %s: %s\n", lvl, fname, line, func, module, buf);
    }
}

void speer_log_str(speer_log_level_t level, const char *module, const char *file, const char *func,
                   int line, const char *msg) {
    speer_log(level, module, file, func, line, "%s", msg ? msg : "(null)");
}
