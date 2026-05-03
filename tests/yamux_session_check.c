#include "speer_internal.h"

#include <stdio.h>

#include <string.h>

#include "yamux.h"

#define FAIL(...)                     \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        return 1;                     \
    } while (0)

#define MOCK_QCAP (384 * 1024)

typedef struct {
    uint8_t buf[MOCK_QCAP];
    size_t len;
} byteq_t;

typedef struct ymock_ep {
    byteq_t q;
    struct ymock_ep *peer;
} ymock_ep_t;

static int byteq_push(byteq_t *q, const uint8_t *d, size_t n) {
    if (n == 0) return 0;
    if (q->len + n > sizeof(q->buf)) return -1;
    memcpy(q->buf + q->len, d, n);
    q->len += n;
    return 0;
}

static int byteq_pop_exact(byteq_t *q, uint8_t *dst, size_t n) {
    if (q->len < n) return -1;
    memcpy(dst, q->buf, n);
    memmove(q->buf, q->buf + n, q->len - n);
    q->len -= n;
    return 0;
}

static int ymock_send(void *user, const uint8_t *d, size_t n) {
    ymock_ep_t *ep = (ymock_ep_t *)user;
    return byteq_push(&ep->peer->q, d, n);
}

static int ymock_recv(void *user, uint8_t *buf, size_t cap, size_t *out_n) {
    ymock_ep_t *ep = (ymock_ep_t *)user;
    if (byteq_pop_exact(&ep->q, buf, cap) != 0) return -1;
    *out_n = cap;
    return 0;
}

static speer_yamux_stream_t *stream_by_id(speer_yamux_session_t *s, uint32_t id) {
    for (speer_yamux_stream_t *st = s->streams; st; st = st->next) {
        if (st->id == id) return st;
    }
    return NULL;
}

static int peek_unpack(byteq_t *q, speer_yamux_hdr_t *h) {
    if (q->len < 12) return -1;
    return speer_yamux_hdr_unpack(h, q->buf);
}

static void drain_hdr(byteq_t *q) {
    uint8_t tmp[12];
    byteq_pop_exact(q, tmp, 12);
}

int main(void) {
    ymock_ep_t ca, cb;
    ZERO(&ca, sizeof(ca));
    ZERO(&cb, sizeof(cb));
    ca.peer = &cb;
    cb.peer = &ca;

    speer_yamux_session_t client, server;
    speer_yamux_init(&client, 1, ymock_send, ymock_recv, &ca);
    speer_yamux_init(&server, 0, ymock_send, ymock_recv, &cb);

    speer_yamux_stream_t *cst = speer_yamux_open_stream(&client);
    if (!cst || cst->id != 1) FAIL("client open_stream\n");
    if (speer_yamux_pump(&server) != 0) FAIL("server pump syn window\n");
    speer_yamux_stream_t *sst = stream_by_id(&server, 1);
    if (!sst) FAIL("server missing stream 1\n");

    static const uint8_t hello[] = "hello-yamux";
    if (speer_yamux_stream_write(&client, cst, hello, sizeof(hello) - 1) != 0)
        FAIL("client stream_write\n");
    if (speer_yamux_pump(&server) != 0) FAIL("server pump data\n");
    if (sst->recv_buf_len != sizeof(hello) - 1 ||
        memcmp(sst->recv_buf, hello, sizeof(hello) - 1) != 0)
        FAIL("server recv payload\n");

    if (speer_yamux_stream_close(&client, cst) != 0) FAIL("client stream_close\n");
    if (speer_yamux_pump(&server) != 0) FAIL("server pump fin\n");
    if (!sst->remote_closed) FAIL("server remote_closed after FIN\n");

    while (ca.q.len >= 12) {
        if (speer_yamux_pump(&client) != 0) break;
    }

    speer_yamux_hdr_t ping_syn = {
        .version = YAMUX_VERSION,
        .type = YAMUX_TYPE_PING,
        .flags = YAMUX_FLAG_SYN,
        .stream_id = 0,
        .length = 0xf1a9f1a9u,
    };
    uint8_t ph[12];
    speer_yamux_hdr_pack(ph, &ping_syn);
    if (byteq_push(&ca.q, ph, sizeof(ph)) != 0) FAIL("enqueue ping\n");
    size_t bb_before = cb.q.len;
    if (speer_yamux_pump(&client) != 0) FAIL("client pump ping\n");
    if (cb.q.len < bb_before + 12) FAIL("ping ack not sent\n");
    speer_yamux_hdr_t ackh;
    if (peek_unpack(&cb.q, &ackh) != 0) FAIL("peek ping ack\n");
    if (ackh.type != YAMUX_TYPE_PING || (ackh.flags & YAMUX_FLAG_ACK) == 0 ||
        ackh.length != 0xf1a9f1a9u)
        FAIL("ping ack fields\n");
    drain_hdr(&cb.q);

    speer_yamux_hdr_t ga = {
        .version = YAMUX_VERSION,
        .type = YAMUX_TYPE_GO_AWAY,
        .flags = 0,
        .stream_id = 0,
        .length = 7,
    };
    uint8_t gh[12];
    speer_yamux_hdr_pack(gh, &ga);
    if (byteq_push(&ca.q, gh, sizeof(gh)) != 0) FAIL("enqueue goaway\n");
    if (speer_yamux_pump(&client) != -1) FAIL("goaway should fail pump\n");

    speer_yamux_close(&client);
    speer_yamux_close(&server);
    ZERO(&ca, sizeof(ca));
    ZERO(&cb, sizeof(cb));
    ca.peer = &cb;
    cb.peer = &ca;
    speer_yamux_init(&client, 1, ymock_send, ymock_recv, &ca);
    speer_yamux_init(&server, 0, ymock_send, ymock_recv, &cb);
    cst = speer_yamux_open_stream(&client);
    if (!cst) FAIL("reopen client stream\n");
    if (speer_yamux_pump(&server) != 0) FAIL("server pump syn 2\n");

    speer_yamux_hdr_t rst = {
        .version = YAMUX_VERSION,
        .type = YAMUX_TYPE_DATA,
        .flags = YAMUX_FLAG_RST,
        .stream_id = 1,
        .length = 0,
    };
    uint8_t rh[12];
    speer_yamux_hdr_pack(rh, &rst);
    if (byteq_push(&cb.q, rh, sizeof(rh)) != 0) FAIL("enqueue rst\n");
    if (speer_yamux_pump(&server) != 0) FAIL("server pump rst\n");
    sst = stream_by_id(&server, 1);
    if (!sst || !sst->reset || !sst->remote_closed) FAIL("RST flags\n");

    speer_yamux_close(&client);
    speer_yamux_close(&server);
    puts("yamux_session: ok");
    return 0;
}
