#ifndef SPEER_LOG_H
#define SPEER_LOG_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    SPEER_LOG_TRACE = 0,
    SPEER_LOG_DEBUG = 1,
    SPEER_LOG_INFO = 2,
    SPEER_LOG_WARN = 3,
    SPEER_LOG_ERROR = 4,
    SPEER_LOG_FATAL = 5,
} speer_log_level_t;

typedef struct {
    speer_log_level_t level;
    const char *file;
    const char *func;
    int line;
    uint64_t timestamp_ms;
    const char *module;
    const char *msg;
} speer_log_entry_t;

typedef void (*speer_log_fn_t)(const speer_log_entry_t *entry, void *user);

void speer_log_set_callback(speer_log_fn_t fn, void *user);
void speer_log_set_level(speer_log_level_t level);

void speer_log(speer_log_level_t level, const char *module, const char *file, const char *func,
               int line, const char *fmt, ...);

#define SPEER_LOG(level, module, fmt, ...) \
    speer_log(level, module, __FILE__, __func__, __LINE__, fmt, ##__VA_ARGS__)

#define SPEER_LOG_TRACE(module, fmt, ...) SPEER_LOG(SPEER_LOG_TRACE, module, fmt, ##__VA_ARGS__)

#define SPEER_LOG_DEBUG(module, fmt, ...) SPEER_LOG(SPEER_LOG_DEBUG, module, fmt, ##__VA_ARGS__)

#define SPEER_LOG_INFO(module, fmt, ...)  SPEER_LOG(SPEER_LOG_INFO, module, fmt, ##__VA_ARGS__)

#define SPEER_LOG_WARN(module, fmt, ...)  SPEER_LOG(SPEER_LOG_WARN, module, fmt, ##__VA_ARGS__)

#define SPEER_LOG_ERROR(module, fmt, ...) SPEER_LOG(SPEER_LOG_ERROR, module, fmt, ##__VA_ARGS__)

#define SPEER_LOG_FATAL(module, fmt, ...) SPEER_LOG(SPEER_LOG_FATAL, module, fmt, ##__VA_ARGS__)

#endif
