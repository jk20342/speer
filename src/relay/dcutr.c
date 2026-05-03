#include "dcutr.h"

#include "speer_internal.h"

#include <stdio.h>

#include "log.h"
#include "protobuf.h"

#define DCUTR_TIMEOUT_MS        10000
#define DCUTR_RETRY_INTERVAL_MS 100

typedef enum {
    DCUTR_STATE_IDLE = 0,
    DCUTR_STATE_GATHERING,
    DCUTR_STATE_CONNECTING,
    DCUTR_STATE_SYNCING,
    DCUTR_STATE_COMPLETE,
    DCUTR_STATE_FAILED,
} dcutr_state_t;

typedef struct {
    struct sockaddr_storage addr;
    socklen_t addr_len;
    uint64_t last_attempt_ms;
    int attempts;
} dcutr_candidate_t;

typedef struct {
    dcutr_state_t state;
    uint64_t start_ms;
    uint64_t last_send_ms;

    dcutr_candidate_t local[DCUTR_MAX_ADDRS];
    size_t num_local;

    dcutr_candidate_t remote[DCUTR_MAX_ADDRS];
    size_t num_remote;

    speer_dcutr_msg_t pending_msg;
    int sync_count;

    speer_peer_t *peer;
    int is_initiator;
    speer_dcutr_send_fn send_fn;
    void *user;
    uint32_t stream_id;
} dcutr_ctx_t;

#define DCUTR_MAX_PEERS 16
static dcutr_ctx_t g_dcutr_ctxs[DCUTR_MAX_PEERS];
static speer_peer_t *g_dcutr_peers[DCUTR_MAX_PEERS];

#define g_dcutr_ctx (g_dcutr_ctxs[0])

static dcutr_ctx_t *find_or_alloc_ctx(speer_peer_t *peer) {
    if (!peer) return &g_dcutr_ctxs[0];
    for (size_t i = 0; i < DCUTR_MAX_PEERS; i++) {
        if (g_dcutr_peers[i] == peer) return &g_dcutr_ctxs[i];
    }
    for (size_t i = 0; i < DCUTR_MAX_PEERS; i++) {
        if (g_dcutr_peers[i] == NULL) {
            g_dcutr_peers[i] = peer;
            return &g_dcutr_ctxs[i];
        }
    }
    return NULL;
}

static dcutr_ctx_t *find_ctx(const speer_peer_t *peer) {
    if (!peer) return &g_dcutr_ctxs[0];
    for (size_t i = 0; i < DCUTR_MAX_PEERS; i++) {
        if (g_dcutr_peers[i] == peer) return &g_dcutr_ctxs[i];
    }
    return NULL;
}

static int add_ipv4_candidate(dcutr_candidate_t *out, size_t max, size_t *count,
                              const struct sockaddr_in *sin) {
    if (*count >= max || sin->sin_port == 0) return 0;
    ZERO(&out[*count], sizeof(out[*count]));
    COPY(&out[*count].addr, sin, sizeof(*sin));
    out[*count].addr_len = sizeof(*sin);
    (*count)++;
    return 1;
}

static int gather_local_addrs(dcutr_ctx_t *ctx, dcutr_candidate_t *out, size_t max) {
    size_t count = 0;
    speer_host_t *host = ctx->peer ? ctx->peer->host : NULL;
    if (host && host->socket >= 0) {
        struct sockaddr_storage bound;
        socklen_t bound_len = sizeof(bound);
        ZERO(&bound, sizeof(bound));
        if (getsockname(host->socket, (struct sockaddr *)&bound, &bound_len) == 0 &&
            bound.ss_family == AF_INET) {
            struct sockaddr_in sin = *(struct sockaddr_in *)&bound;
            if (sin.sin_addr.s_addr == htonl(INADDR_ANY)) sin.sin_addr.s_addr = htonl(0x7f000001);
            add_ipv4_candidate(out, max, &count, &sin);
        }
    }
    return (int)count;
}

#define STUB(x) (void)(x)

int speer_dcutr_init(speer_peer_t *peer, int is_initiator) {
    dcutr_ctx_t *ctx = find_or_alloc_ctx(peer);
    if (!ctx) return -1;
    speer_dcutr_send_fn send_fn = ctx->send_fn;
    void *user = ctx->user;
    uint32_t stream_id = ctx->stream_id;
    memset(ctx, 0, sizeof(*ctx));
    ctx->send_fn = send_fn;
    ctx->user = user;
    ctx->stream_id = stream_id;
    ctx->peer = peer;
    ctx->is_initiator = is_initiator;
    ctx->state = DCUTR_STATE_GATHERING;
    ctx->start_ms = speer_timestamp_ms();
    ctx->num_local = gather_local_addrs(ctx, ctx->local, DCUTR_MAX_ADDRS);
    ctx->sync_count = 0;
    return 0;
}

void speer_dcutr_set_transport(speer_dcutr_send_fn send_fn, void *user) {
    g_dcutr_ctx.send_fn = send_fn;
    g_dcutr_ctx.user = user;
    for (size_t i = 0; i < DCUTR_MAX_PEERS; i++) {
        if (g_dcutr_peers[i] != NULL && g_dcutr_ctxs[i].send_fn == NULL) {
            g_dcutr_ctxs[i].send_fn = send_fn;
            g_dcutr_ctxs[i].user = user;
        }
    }
}

static int send_stream(void *user, const uint8_t *data, size_t len) {
    dcutr_ctx_t *ctx = (dcutr_ctx_t *)user;
    if (!ctx || !ctx->peer) return -1;
    speer_stream_t *stream = (speer_stream_t *)calloc(1, sizeof(*stream));
    if (!stream) return -1;
    stream->peer = ctx->peer;
    stream->id = ctx->stream_id;
    int r = speer_stream_write(stream, data, len);
    free(stream);
    return r;
}

int speer_dcutr_start_stream(speer_peer_t *peer, uint32_t stream_id, int is_initiator) {
    if (!peer) return -1;
    dcutr_ctx_t *ctx = find_or_alloc_ctx(peer);
    if (!ctx) return -1;
    ctx->stream_id = stream_id;
    ctx->send_fn = send_stream;
    ctx->user = ctx;
    return speer_dcutr_init(peer, is_initiator);
}

int speer_dcutr_on_stream_data(speer_peer_t *peer, uint32_t stream_id, const uint8_t *data,
                               size_t len) {
    if (stream_id != DCUTR_STREAM_ID) return 0;
    dcutr_ctx_t *ctx = find_ctx(peer);
    int active = ctx && ctx->state != DCUTR_STATE_IDLE && ctx->state != DCUTR_STATE_COMPLETE &&
                 ctx->state != DCUTR_STATE_FAILED;
    if (!active) {
        ctx = find_or_alloc_ctx(peer);
        if (!ctx) return -1;
        ctx->stream_id = stream_id;
        ctx->send_fn = send_stream;
        ctx->user = ctx;
        if (speer_dcutr_init(peer, 0) != 0) return -1;
    }
    return speer_dcutr_on_msg(data, len);
}

void speer_dcutr_free(void) {
    memset(g_dcutr_ctxs, 0, sizeof(g_dcutr_ctxs));
    memset(g_dcutr_peers, 0, sizeof(g_dcutr_peers));
}

int speer_dcutr_is_active(void) {
    for (size_t i = 0; i < DCUTR_MAX_PEERS; i++) {
        dcutr_state_t s = g_dcutr_ctxs[i].state;
        if (s != DCUTR_STATE_IDLE && s != DCUTR_STATE_COMPLETE && s != DCUTR_STATE_FAILED) return 1;
    }
    return 0;
}

int speer_dcutr_success(void) {
    for (size_t i = 0; i < DCUTR_MAX_PEERS; i++) {
        if (g_dcutr_ctxs[i].state == DCUTR_STATE_COMPLETE) return 1;
    }
    return 0;
}

static int send_msg(dcutr_ctx_t *ctx, const speer_dcutr_msg_t *m) {
    uint8_t buf[256];
    size_t len;
    if (speer_dcutr_encode(m, buf, sizeof(buf), &len) != 0) return -1;
    if (ctx->send_fn) return ctx->send_fn(ctx->user, buf, len);
    return 0;
}

static void send_connect(dcutr_ctx_t *ctx) {
    speer_dcutr_msg_t m;
    ZERO(&m, sizeof(m));
    m.type = DCUTR_TYPE_CONNECT;
    m.num_addrs = ctx->num_local;
    for (size_t i = 0; i < ctx->num_local; i++) {
        if (ctx->local[i].addr.ss_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&ctx->local[i].addr;
            m.addrs[i].bytes[0] = 0x04;
            memcpy(&m.addrs[i].bytes[1], &sin->sin_addr, 4);
            memcpy(&m.addrs[i].bytes[5], &sin->sin_port, 2);
            m.addrs[i].len = 7;
        }
    }

    if (send_msg(ctx, &m) >= 0) {
        SPEER_LOG_DEBUG("dcutr", "sending CONNECT with %zu addrs", m.num_addrs);
    }
}

static void send_sync(dcutr_ctx_t *ctx) {
    speer_dcutr_msg_t m;
    ZERO(&m, sizeof(m));
    m.type = DCUTR_TYPE_SYNC;
    m.num_addrs = 0;

    if (send_msg(ctx, &m) >= 0) { SPEER_LOG_DEBUG("dcutr", "sending SYNC #%d", ctx->sync_count); }
}

static void try_connect(dcutr_ctx_t *ctx) {
    uint64_t now = speer_timestamp_ms();

    for (size_t i = 0; i < ctx->num_remote; i++) {
        dcutr_candidate_t *c = &ctx->remote[i];
        if (c->attempts >= 5) continue;
        if (now - c->last_attempt_ms < (uint64_t)(c->attempts + 1) * 50) continue;

        c->last_attempt_ms = now;
        c->attempts++;

        if (c->addr.ss_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&c->addr;
            char addr_str[32];
            snprintf(addr_str, sizeof(addr_str), "%d.%d.%d.%d:%d", ((uint8_t *)&sin->sin_addr)[0],
                     ((uint8_t *)&sin->sin_addr)[1], ((uint8_t *)&sin->sin_addr)[2],
                     ((uint8_t *)&sin->sin_addr)[3], ntohs(sin->sin_port));

            SPEER_LOG_DEBUG("dcutr", "attempting hole punch to %s (attempt %d)", addr_str,
                            c->attempts);

            if (ctx->peer && ctx->peer->host) { speer_peer_set_address(ctx->peer, addr_str); }
            if (ctx->peer && ctx->peer->host && ctx->peer->host->socket >= 0) {
                uint8_t probe = 0;
                speer_socket_send(ctx->peer->host->socket, &probe, sizeof(probe), &c->addr,
                                  c->addr_len);
            }
        }
    }
}

static void poll_ctx(dcutr_ctx_t *ctx, uint64_t now) {
    if (now - ctx->start_ms > DCUTR_TIMEOUT_MS) {
        SPEER_LOG_WARN("dcutr", "hole punching timed out");
        ctx->state = DCUTR_STATE_FAILED;
        return;
    }

    switch (ctx->state) {
    case DCUTR_STATE_GATHERING:
        ctx->state = DCUTR_STATE_CONNECTING;
        ctx->last_send_ms = now;
        send_connect(ctx);
        break;

    case DCUTR_STATE_CONNECTING:
        try_connect(ctx);
        if (ctx->peer && speer_peer_is_connected(ctx->peer)) {
            SPEER_LOG_INFO("dcutr", "direct connection established");
            ctx->state = DCUTR_STATE_COMPLETE;
            return;
        }
        if (now - ctx->last_send_ms > DCUTR_RETRY_INTERVAL_MS) {
            ctx->last_send_ms = now;
            if (ctx->sync_count < 20) {
                send_sync(ctx);
                ctx->sync_count++;
            }
        }
        break;

    case DCUTR_STATE_SYNCING:
        try_connect(ctx);
        if (ctx->peer && speer_peer_is_connected(ctx->peer)) {
            SPEER_LOG_INFO("dcutr", "direct connection established after sync");
            ctx->state = DCUTR_STATE_COMPLETE;
            return;
        }
        break;

    default:
        break;
    }
}

void speer_dcutr_poll(void) {
    uint64_t now = speer_timestamp_ms();
    for (size_t i = 0; i < DCUTR_MAX_PEERS; i++) {
        dcutr_ctx_t *ctx = &g_dcutr_ctxs[i];
        if (ctx->state == DCUTR_STATE_IDLE || ctx->state == DCUTR_STATE_COMPLETE ||
            ctx->state == DCUTR_STATE_FAILED)
            continue;
        poll_ctx(ctx, now);
    }
}

int speer_dcutr_on_msg(const uint8_t *data, size_t len) {
    dcutr_ctx_t *ctx = NULL;
    for (size_t i = 0; i < DCUTR_MAX_PEERS; i++) {
        if (g_dcutr_ctxs[i].state != DCUTR_STATE_IDLE &&
            g_dcutr_ctxs[i].state != DCUTR_STATE_COMPLETE &&
            g_dcutr_ctxs[i].state != DCUTR_STATE_FAILED) {
            ctx = &g_dcutr_ctxs[i];
            break;
        }
    }
    if (!ctx) ctx = &g_dcutr_ctxs[0];
    speer_dcutr_msg_t m;

    if (speer_dcutr_decode(&m, data, len) != 0) {
        SPEER_LOG_WARN("dcutr", "failed to decode message");
        return -1;
    }

    uint64_t now = speer_timestamp_ms();

    switch (m.type) {
    case DCUTR_TYPE_CONNECT:
        SPEER_LOG_DEBUG("dcutr", "received CONNECT with %zu addrs", m.num_addrs);
        for (size_t i = 0; i < m.num_addrs && ctx->num_remote < DCUTR_MAX_ADDRS; i++) {
            if (m.addrs[i].len >= 7 && m.addrs[i].bytes[0] == 0x04) {
                struct sockaddr_in cand;
                ZERO(&cand, sizeof(cand));
                cand.sin_family = AF_INET;
                memcpy(&cand.sin_addr, &m.addrs[i].bytes[1], 4);
                memcpy(&cand.sin_port, &m.addrs[i].bytes[5], 2);

                int trust = 0;
                if (ctx->peer && ctx->peer->addr.ss_family == AF_INET) {
                    const struct sockaddr_in *known = (const struct sockaddr_in *)&ctx->peer->addr;
                    uint32_t known_ip = ntohl(known->sin_addr.s_addr);
                    uint32_t cand_ip = ntohl(cand.sin_addr.s_addr);
                    if ((known_ip & 0xffffff00u) == (cand_ip & 0xffffff00u)) trust = 1;
                }
                if (!trust) continue;

                struct sockaddr_in *sin = (struct sockaddr_in *)&ctx->remote[ctx->num_remote].addr;
                *sin = cand;
                ctx->remote[ctx->num_remote].addr_len = sizeof(*sin);
                ctx->num_remote++;
            }
        }
        ctx->state = DCUTR_STATE_SYNCING;
        ctx->start_ms = now;
        send_sync(ctx);
        try_connect(ctx);
        break;

    case DCUTR_TYPE_SYNC:
        SPEER_LOG_DEBUG("dcutr", "received SYNC");
        if (ctx->state == DCUTR_STATE_CONNECTING) { try_connect(ctx); }
        break;

    default:
        SPEER_LOG_DEBUG("dcutr", "unknown message type %d", (int)m.type);
        break;
    }

    return 0;
}

int speer_dcutr_encode(const speer_dcutr_msg_t *m, uint8_t *out, size_t cap, size_t *out_len) {
    speer_pb_writer_t w;
    speer_pb_writer_init(&w, out, cap);
    if (speer_pb_write_int32_field(&w, 1, (int32_t)m->type) != 0) return -1;
    for (size_t i = 0; i < m->num_addrs; i++) {
        if (speer_pb_write_bytes_field(&w, 2, m->addrs[i].bytes, m->addrs[i].len) != 0) return -1;
    }
    if (out_len) *out_len = w.pos;
    return 0;
}

int speer_dcutr_decode(speer_dcutr_msg_t *m, const uint8_t *in, size_t in_len) {
    ZERO(m, sizeof(*m));
    speer_pb_reader_t r;
    speer_pb_reader_init(&r, in, in_len);
    while (r.pos < r.len) {
        uint32_t f, wire;
        if (speer_pb_read_tag(&r, &f, &wire) != 0) return -1;
        if (f == 1 && wire == PB_WIRE_VARINT) {
            int32_t v;
            if (speer_pb_read_int32(&r, &v) != 0) return -1;
            m->type = (speer_dcutr_type_t)v;
        } else if (f == 2 && wire == PB_WIRE_LEN) {
            const uint8_t *d;
            size_t l;
            if (speer_pb_read_bytes(&r, &d, &l) != 0) return -1;
            if (m->num_addrs < DCUTR_MAX_ADDRS && l <= sizeof(m->addrs[0].bytes)) {
                COPY(m->addrs[m->num_addrs].bytes, d, l);
                m->addrs[m->num_addrs].len = l;
                m->num_addrs++;
            }
        } else {
            if (speer_pb_skip(&r, wire) != 0) return -1;
        }
    }
    return 0;
}
