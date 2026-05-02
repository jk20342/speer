#include <stdio.h>

#include <string.h>

#include "speer_libp2p_tcp.h"

#define FAIL(...)                     \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        return 1;                     \
    } while (0)

typedef struct {
    uint8_t data[256];
    size_t len;
    size_t off;
} memio_t;

static int mem_send(void *user, const uint8_t *data, size_t len) {
    memio_t *m = (memio_t *)user;
    if (m->len + len > sizeof(m->data)) return -1;
    memcpy(m->data + m->len, data, len);
    m->len += len;
    return 0;
}

static int mem_recv_partial(void *user, uint8_t *buf, size_t cap, size_t *out_n) {
    memio_t *m = (memio_t *)user;
    if (m->off >= m->len) return -1;
    size_t rem = m->len - m->off;
    size_t take = rem < cap ? rem : cap;
    if (take > 3) take = 3;
    memcpy(buf, m->data + m->off, take);
    m->off += take;
    if (out_n) *out_n = take;
    return 0;
}

static int test_uvar_frame_roundtrip(void) {
    memio_t io = {0};
    const uint8_t payload[] = "hello framed world";
    if (speer_libp2p_uvar_frame_send(&io, mem_send, payload, sizeof(payload) - 1) != 0)
        FAIL("send frame failed\n");

    uint8_t out[64];
    size_t out_len = 0;
    if (speer_libp2p_uvar_frame_recv(&io, mem_recv_partial, out, sizeof(out), &out_len) != 0)
        FAIL("recv frame failed\n");
    if (out_len != sizeof(payload) - 1) FAIL("unexpected out_len\n");
    if (memcmp(out, payload, out_len) != 0) FAIL("payload mismatch\n");
    return 0;
}

static int test_uvar_frame_rejects_oversize(void) {
    memio_t io = {0};
    io.data[0] = 0x2a;
    io.len = 1;
    io.off = 0;
    uint8_t out[8];
    size_t out_len = 0;
    if (speer_libp2p_uvar_frame_recv(&io, mem_recv_partial, out, sizeof(out), &out_len) == 0)
        FAIL("expected oversize failure\n");
    return 0;
}

static int test_uvar_frame_rejects_bad_varint(void) {
    memio_t io = {0};
    memset(io.data, 0x80, 10);
    io.len = 10;
    io.off = 0;
    uint8_t out[32];
    size_t out_len = 0;
    if (speer_libp2p_uvar_frame_recv(&io, mem_recv_partial, out, sizeof(out), &out_len) == 0)
        FAIL("expected malformed varint failure\n");
    return 0;
}

int main(void) {
    if (test_uvar_frame_roundtrip() != 0) return 1;
    if (test_uvar_frame_rejects_oversize() != 0) return 1;
    if (test_uvar_frame_rejects_bad_varint() != 0) return 1;
    puts("libp2p_tcp_primitives: ok");
    return 0;
}
