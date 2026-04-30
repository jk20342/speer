#ifndef SPEER_PROTOBUF_H
#define SPEER_PROTOBUF_H

#include <stddef.h>
#include <stdint.h>

#define PB_WIRE_VARINT 0
#define PB_WIRE_64BIT  1
#define PB_WIRE_LEN    2
#define PB_WIRE_32BIT  5

typedef struct {
    const uint8_t *buf;
    size_t len;
    size_t pos;
    int err;
} speer_pb_reader_t;

typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t pos;
    int err;
} speer_pb_writer_t;

void speer_pb_reader_init(speer_pb_reader_t *r, const uint8_t *buf, size_t len);
int speer_pb_read_tag(speer_pb_reader_t *r, uint32_t *field, uint32_t *wire);
int speer_pb_read_varint(speer_pb_reader_t *r, uint64_t *v);
int speer_pb_read_int32(speer_pb_reader_t *r, int32_t *v);
int speer_pb_read_int64(speer_pb_reader_t *r, int64_t *v);
int speer_pb_read_bool(speer_pb_reader_t *r, int *v);
int speer_pb_read_bytes(speer_pb_reader_t *r, const uint8_t **data, size_t *len);
int speer_pb_read_string(speer_pb_reader_t *r, const char **s, size_t *len);
int speer_pb_skip(speer_pb_reader_t *r, uint32_t wire);

void speer_pb_writer_init(speer_pb_writer_t *w, uint8_t *buf, size_t cap);
int speer_pb_write_tag(speer_pb_writer_t *w, uint32_t field, uint32_t wire);
int speer_pb_write_varint(speer_pb_writer_t *w, uint64_t v);
int speer_pb_write_int32_field(speer_pb_writer_t *w, uint32_t field, int32_t v);
int speer_pb_write_int64_field(speer_pb_writer_t *w, uint32_t field, int64_t v);
int speer_pb_write_bool_field(speer_pb_writer_t *w, uint32_t field, int v);
int speer_pb_write_bytes_field(speer_pb_writer_t *w, uint32_t field, const uint8_t *data,
                               size_t len);
int speer_pb_write_string_field(speer_pb_writer_t *w, uint32_t field, const char *s);

#endif
