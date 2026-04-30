#include "speer_internal.h"
#include "multistream.h"
#include "varint.h"
#include <stdio.h>
#include <string.h>

#define FAIL(...) do { fprintf(stderr, __VA_ARGS__); return 1; } while (0)

typedef struct {
    uint8_t buf[4096];
    size_t len;
} fifo_t;

static int fifo_push(fifo_t* f, const uint8_t* d, size_t n) {
    if (f->len + n > sizeof(f->buf)) return -1;
    if (n > 0) memcpy(f->buf + f->len, d, n);
    f->len += n;
    return 0;
}

static int fifo_send(void* user, const uint8_t* d, size_t n) {
    return fifo_push((fifo_t*)user, d, n);
}

static int fifo_recv(void* user, uint8_t* b, size_t cap, size_t* out_n) {
    fifo_t* f = (fifo_t*)user;
    if (f->len == 0) return -1;
    size_t n = cap < f->len ? cap : f->len;
    memcpy(b, f->buf, n);
    memmove(f->buf, f->buf + n, f->len - n);
    f->len -= n;
    *out_n = n;
    return 0;
}

static int append_lp_line(fifo_t* f, const char* s) {
    size_t sl = strlen(s);
    uint8_t hdr[10];
    size_t hl = speer_uvarint_encode(hdr, sizeof(hdr), sl + 1);
    if (hl == 0 || fifo_push(f, hdr, hl) != 0) return -1;
    if (fifo_push(f, (const uint8_t*)s, sl) != 0) return -1;
    uint8_t nl = (uint8_t)'\n';
    return fifo_push(f, &nl, 1);
}

typedef struct {
    fifo_t* out;
    fifo_t* in_q;
} ms_half_duplex_t;

static int hd_send(void* user, const uint8_t* d, size_t n) {
    ms_half_duplex_t* h = (ms_half_duplex_t*)user;
    return fifo_push(h->out, d, n);
}

static int hd_recv(void* user, uint8_t* b, size_t cap, size_t* out_n) {
    ms_half_duplex_t* h = (ms_half_duplex_t*)user;
    return fifo_recv(h->in_q, b, cap, out_n);
}

int main(void) {
    fifo_t loop;
    ZERO(&loop, sizeof(loop));
    if (speer_ms_send_protocol(&loop, fifo_send, "/noise/1.0.0") != 0) FAIL("ms_send_protocol\n");
    char got[256];
    if (speer_ms_recv_protocol(&loop, fifo_recv, got, sizeof(got)) != 0) FAIL("ms_recv_protocol\n");
    if (strcmp(got, "/noise/1.0.0") != 0) FAIL("ms payload mismatch\n");
    if (loop.len != 0) FAIL("fifo not drained\n");

    fifo_t to_listener, to_initiator;
    ZERO(&to_listener, sizeof(to_listener));
    ZERO(&to_initiator, sizeof(to_initiator));
    if (append_lp_line(&to_listener, MULTISTREAM_PROTO) != 0 ||
        append_lp_line(&to_listener, "/yamux/1.0.0") != 0)
        FAIL("append listener prereq\n");

    ms_half_duplex_t listener = { .out = &to_initiator, .in_q = &to_listener };
    const char* protos[] = { "/yamux/1.0.0", "/noise/1.0.0" };
    size_t sel = 999;
    if (speer_ms_negotiate_listener(&listener, hd_send, hd_recv, protos, 2, &sel) != 0)
        FAIL("negotiate_listener\n");
    if (sel != 0) FAIL("selected idx\n");

    ZERO(&to_listener, sizeof(to_listener));
    ZERO(&to_initiator, sizeof(to_initiator));
    if (append_lp_line(&to_initiator, MULTISTREAM_PROTO) != 0 ||
        append_lp_line(&to_initiator, "/noise/1.0.0") != 0)
        FAIL("append initiator prereq\n");

    ms_half_duplex_t initiator = { .out = &to_listener, .in_q = &to_initiator };
    if (speer_ms_negotiate_initiator(&initiator, hd_send, hd_recv, "/noise/1.0.0") != 0)
        FAIL("negotiate_initiator\n");

    puts("multistream: ok");
    return 0;
}
