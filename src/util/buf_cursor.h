#ifndef SPEER_BUF_CURSOR_H
#define SPEER_BUF_CURSOR_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

typedef struct {
    const uint8_t* buf;
    size_t len;
    size_t pos;
    int err;
} speer_rcur_t;

typedef struct {
    uint8_t* buf;
    size_t cap;
    size_t pos;
    int err;
} speer_wcur_t;

static inline void speer_rcur_init(speer_rcur_t* c, const uint8_t* buf, size_t len) {
    c->buf = buf; c->len = len; c->pos = 0; c->err = 0;
}

static inline void speer_wcur_init(speer_wcur_t* c, uint8_t* buf, size_t cap) {
    c->buf = buf; c->cap = cap; c->pos = 0; c->err = 0;
}

static inline size_t speer_rcur_remaining(const speer_rcur_t* c) {
    return c->len - c->pos;
}

static inline size_t speer_wcur_remaining(const speer_wcur_t* c) {
    return c->cap - c->pos;
}

static inline int speer_rcur_eof(const speer_rcur_t* c) {
    return c->pos >= c->len;
}

static inline uint8_t speer_rcur_u8(speer_rcur_t* c) {
    if (c->pos + 1 > c->len) { c->err = 1; return 0; }
    return c->buf[c->pos++];
}

static inline uint16_t speer_rcur_u16be(speer_rcur_t* c) {
    if (c->pos + 2 > c->len) { c->err = 1; return 0; }
    uint16_t v = ((uint16_t)c->buf[c->pos] << 8) | c->buf[c->pos+1];
    c->pos += 2;
    return v;
}

static inline uint32_t speer_rcur_u24be(speer_rcur_t* c) {
    if (c->pos + 3 > c->len) { c->err = 1; return 0; }
    uint32_t v = ((uint32_t)c->buf[c->pos] << 16) |
                 ((uint32_t)c->buf[c->pos+1] << 8) |
                 (uint32_t)c->buf[c->pos+2];
    c->pos += 3;
    return v;
}

static inline uint32_t speer_rcur_u32be(speer_rcur_t* c) {
    if (c->pos + 4 > c->len) { c->err = 1; return 0; }
    uint32_t v = ((uint32_t)c->buf[c->pos] << 24) |
                 ((uint32_t)c->buf[c->pos+1] << 16) |
                 ((uint32_t)c->buf[c->pos+2] << 8) |
                 (uint32_t)c->buf[c->pos+3];
    c->pos += 4;
    return v;
}

static inline uint64_t speer_rcur_u64be(speer_rcur_t* c) {
    if (c->pos + 8 > c->len) { c->err = 1; return 0; }
    uint64_t v = ((uint64_t)c->buf[c->pos] << 56) |
                 ((uint64_t)c->buf[c->pos+1] << 48) |
                 ((uint64_t)c->buf[c->pos+2] << 40) |
                 ((uint64_t)c->buf[c->pos+3] << 32) |
                 ((uint64_t)c->buf[c->pos+4] << 24) |
                 ((uint64_t)c->buf[c->pos+5] << 16) |
                 ((uint64_t)c->buf[c->pos+6] << 8) |
                 (uint64_t)c->buf[c->pos+7];
    c->pos += 8;
    return v;
}

static inline const uint8_t* speer_rcur_bytes(speer_rcur_t* c, size_t n) {
    if (c->pos + n > c->len) { c->err = 1; return NULL; }
    const uint8_t* p = c->buf + c->pos;
    c->pos += n;
    return p;
}

static inline int speer_rcur_skip(speer_rcur_t* c, size_t n) {
    if (c->pos + n > c->len) { c->err = 1; return -1; }
    c->pos += n;
    return 0;
}

static inline int speer_rcur_copy(speer_rcur_t* c, void* dst, size_t n) {
    if (c->pos + n > c->len) { c->err = 1; return -1; }
    memcpy(dst, c->buf + c->pos, n);
    c->pos += n;
    return 0;
}

static inline int speer_wcur_u8(speer_wcur_t* c, uint8_t v) {
    if (c->pos + 1 > c->cap) { c->err = 1; return -1; }
    c->buf[c->pos++] = v;
    return 0;
}

static inline int speer_wcur_u16be(speer_wcur_t* c, uint16_t v) {
    if (c->pos + 2 > c->cap) { c->err = 1; return -1; }
    c->buf[c->pos] = (uint8_t)(v >> 8);
    c->buf[c->pos+1] = (uint8_t)v;
    c->pos += 2;
    return 0;
}

static inline int speer_wcur_u24be(speer_wcur_t* c, uint32_t v) {
    if (c->pos + 3 > c->cap) { c->err = 1; return -1; }
    c->buf[c->pos] = (uint8_t)(v >> 16);
    c->buf[c->pos+1] = (uint8_t)(v >> 8);
    c->buf[c->pos+2] = (uint8_t)v;
    c->pos += 3;
    return 0;
}

static inline int speer_wcur_u32be(speer_wcur_t* c, uint32_t v) {
    if (c->pos + 4 > c->cap) { c->err = 1; return -1; }
    c->buf[c->pos] = (uint8_t)(v >> 24);
    c->buf[c->pos+1] = (uint8_t)(v >> 16);
    c->buf[c->pos+2] = (uint8_t)(v >> 8);
    c->buf[c->pos+3] = (uint8_t)v;
    c->pos += 4;
    return 0;
}

static inline int speer_wcur_u64be(speer_wcur_t* c, uint64_t v) {
    if (c->pos + 8 > c->cap) { c->err = 1; return -1; }
    for (int i = 0; i < 8; i++) c->buf[c->pos + i] = (uint8_t)(v >> ((7 - i) * 8));
    c->pos += 8;
    return 0;
}

static inline int speer_wcur_bytes(speer_wcur_t* c, const void* src, size_t n) {
    if (c->pos + n > c->cap) { c->err = 1; return -1; }
    memcpy(c->buf + c->pos, src, n);
    c->pos += n;
    return 0;
}

static inline uint8_t* speer_wcur_reserve(speer_wcur_t* c, size_t n) {
    if (c->pos + n > c->cap) { c->err = 1; return NULL; }
    uint8_t* p = c->buf + c->pos;
    c->pos += n;
    return p;
}

#endif
