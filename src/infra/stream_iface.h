#ifndef SPEER_STREAM_IFACE_H
#define SPEER_STREAM_IFACE_H

#include <stdint.h>
#include <stddef.h>

typedef struct speer_stream_obj_s speer_stream_obj_t;

typedef struct {
    const char* name;
    int (*read)(speer_stream_obj_t* s, uint8_t* buf, size_t cap, size_t* out_n);
    int (*write)(speer_stream_obj_t* s, const uint8_t* data, size_t len, size_t* out_n);
    int (*close)(speer_stream_obj_t* s);
    int (*reset)(speer_stream_obj_t* s, uint64_t code);
    uint64_t (*id)(speer_stream_obj_t* s);
    int (*is_open)(speer_stream_obj_t* s);
} speer_stream_ops_t;

#endif
