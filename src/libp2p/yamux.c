#include "yamux.h"

#include "speer_internal.h"

void speer_yamux_hdr_pack(uint8_t out[12], const speer_yamux_hdr_t *h) {
    out[0] = h->version;
    out[1] = h->type;
    STORE16_BE(out + 2, h->flags);
    STORE32_BE(out + 4, h->stream_id);
    STORE32_BE(out + 8, h->length);
}

int speer_yamux_hdr_unpack(speer_yamux_hdr_t *h, const uint8_t in[12]) {
    h->version = in[0];
    h->type = in[1];
    h->flags = LOAD16_BE(in + 2);
    h->stream_id = LOAD32_BE(in + 4);
    h->length = LOAD32_BE(in + 8);
    if (h->version != YAMUX_VERSION) return -1;
    if (h->type > YAMUX_TYPE_GO_AWAY) return -1;
    return 0;
}

void speer_yamux_init(speer_yamux_session_t *s, int is_initiator,
                      int (*send_raw)(void *, const uint8_t *, size_t),
                      int (*recv_raw)(void *, uint8_t *, size_t, size_t *), void *user) {
    ZERO(s, sizeof(*s));
    s->is_initiator = is_initiator;
    s->next_stream_id = is_initiator ? 1 : 2;
    s->send_raw = send_raw;
    s->recv_raw = recv_raw;
    s->user = user;
}

static speer_yamux_stream_t *find_stream(speer_yamux_session_t *s, uint32_t id) {
    for (speer_yamux_stream_t *st = s->streams; st; st = st->next) {
        if (st->id == id) return st;
    }
    return NULL;
}

static speer_yamux_stream_t *alloc_stream(speer_yamux_session_t *s, uint32_t id) {
    speer_yamux_stream_t *st = (speer_yamux_stream_t *)calloc(1, sizeof(*st));
    if (!st) return NULL;
    st->id = id;
    st->recv_window = YAMUX_INITIAL_WINDOW;
    st->send_window = YAMUX_INITIAL_WINDOW;
    st->next = s->streams;
    s->streams = st;
    return st;
}

void speer_yamux_close(speer_yamux_session_t *s) {
    speer_yamux_stream_t *st = s->streams;
    while (st) {
        speer_yamux_stream_t *n = st->next;
        free(st->recv_buf);
        free(st);
        st = n;
    }
    s->streams = NULL;
}

static int send_frame(speer_yamux_session_t *s, const speer_yamux_hdr_t *h, const uint8_t *body,
                      size_t body_len) {
    uint8_t hdr[12];
    speer_yamux_hdr_pack(hdr, h);
    if (s->send_raw(s->user, hdr, 12) != 0) return -1;
    if (body && body_len > 0) return s->send_raw(s->user, body, body_len);
    return 0;
}

speer_yamux_stream_t *speer_yamux_open_stream(speer_yamux_session_t *s) {
    uint32_t id = s->next_stream_id;
    s->next_stream_id += 2;
    speer_yamux_stream_t *st = alloc_stream(s, id);
    if (!st) return NULL;
    speer_yamux_hdr_t h = {.version = YAMUX_VERSION,
                           .type = YAMUX_TYPE_WINDOW_UPDATE,
                           .flags = YAMUX_FLAG_SYN,
                           .stream_id = id,
                           .length = 0};
    if (send_frame(s, &h, NULL, 0) != 0) return NULL;
    return st;
}

int speer_yamux_stream_write(speer_yamux_session_t *s, speer_yamux_stream_t *st,
                             const uint8_t *data, size_t len) {
    while (len > 0) {
        uint32_t chunk = (uint32_t)(len > st->send_window ? st->send_window : len);
        if (chunk > 65536) chunk = 65536;
        if (chunk == 0) return 0;
        speer_yamux_hdr_t h = {.version = YAMUX_VERSION,
                               .type = YAMUX_TYPE_DATA,
                               .flags = 0,
                               .stream_id = st->id,
                               .length = chunk};
        if (send_frame(s, &h, data, chunk) != 0) return -1;
        st->send_window -= chunk;
        data += chunk;
        len -= chunk;
    }
    return 0;
}

int speer_yamux_stream_close(speer_yamux_session_t *s, speer_yamux_stream_t *st) {
    if (st->local_closed) return 0;
    speer_yamux_hdr_t h = {.version = YAMUX_VERSION,
                           .type = YAMUX_TYPE_DATA,
                           .flags = YAMUX_FLAG_FIN,
                           .stream_id = st->id,
                           .length = 0};
    st->local_closed = 1;
    return send_frame(s, &h, NULL, 0);
}

int speer_yamux_stream_reset(speer_yamux_session_t *s, speer_yamux_stream_t *st, uint32_t code) {
    (void)code;
    speer_yamux_hdr_t h = {.version = YAMUX_VERSION,
                           .type = YAMUX_TYPE_DATA,
                           .flags = YAMUX_FLAG_RST,
                           .stream_id = st->id,
                           .length = 0};
    st->reset = 1;
    return send_frame(s, &h, NULL, 0);
}

int speer_yamux_send_window_update(speer_yamux_session_t *s, speer_yamux_stream_t *st,
                                   uint32_t inc) {
    speer_yamux_hdr_t h = {.version = YAMUX_VERSION,
                           .type = YAMUX_TYPE_WINDOW_UPDATE,
                           .flags = 0,
                           .stream_id = st->id,
                           .length = inc};
    return send_frame(s, &h, NULL, 0);
}

int speer_yamux_send_ping(speer_yamux_session_t *s, uint32_t opaque, int ack) {
    speer_yamux_hdr_t h = {.version = YAMUX_VERSION,
                           .type = YAMUX_TYPE_PING,
                           .flags = ack ? YAMUX_FLAG_ACK : YAMUX_FLAG_SYN,
                           .stream_id = 0,
                           .length = opaque};
    return send_frame(s, &h, NULL, 0);
}

int speer_yamux_send_go_away(speer_yamux_session_t *s, uint32_t code) {
    speer_yamux_hdr_t h = {.version = YAMUX_VERSION,
                           .type = YAMUX_TYPE_GO_AWAY,
                           .flags = 0,
                           .stream_id = 0,
                           .length = code};
    return send_frame(s, &h, NULL, 0);
}

static int append_recv(speer_yamux_stream_t *st, const uint8_t *data, size_t len) {
    if (st->recv_buf_len + len > st->recv_buf_cap) {
        size_t newcap = st->recv_buf_cap ? st->recv_buf_cap * 2 : 4096;
        while (newcap < st->recv_buf_len + len) newcap *= 2;
        uint8_t *nb = (uint8_t *)realloc(st->recv_buf, newcap);
        if (!nb) return -1;
        st->recv_buf = nb;
        st->recv_buf_cap = newcap;
    }
    COPY(st->recv_buf + st->recv_buf_len, data, len);
    st->recv_buf_len += len;
    return 0;
}

int speer_yamux_pump(speer_yamux_session_t *s) {
    uint8_t hbuf[12];
    size_t got = 0;
    int rc = s->recv_raw(s->user, hbuf, 12, &got);
    if (rc != 0 || got != 12) return rc;
    speer_yamux_hdr_t h;
    if (speer_yamux_hdr_unpack(&h, hbuf) != 0) return -1;

    if (h.type == YAMUX_TYPE_DATA) {
        if (h.length > YAMUX_INITIAL_WINDOW) return -1;
        speer_yamux_stream_t *st = find_stream(s, h.stream_id);
        if (!st && (h.flags & YAMUX_FLAG_SYN)) {
            st = alloc_stream(s, h.stream_id);
            if (!st) return -1;
        }
        if (h.length > 0 && st) {
            if (h.length > st->recv_window) return -1;
            uint8_t *tmp = (uint8_t *)malloc(h.length);
            if (!tmp) return -1;
            if (s->recv_raw(s->user, tmp, h.length, &got) != 0 || got != h.length) {
                free(tmp);
                return -1;
            }
            append_recv(st, tmp, h.length);
            free(tmp);
            st->recv_window -= h.length;
            if (st->recv_window < YAMUX_INITIAL_WINDOW / 2) {
                speer_yamux_send_window_update(s, st, YAMUX_INITIAL_WINDOW - st->recv_window);
                st->recv_window = YAMUX_INITIAL_WINDOW;
            }
        } else if (h.length > 0) {
            uint8_t *tmp = (uint8_t *)malloc(h.length);
            if (!tmp) return -1;
            if (s->recv_raw(s->user, tmp, h.length, &got) != 0 || got != h.length) {
                free(tmp);
                return -1;
            }
            free(tmp);
        }
        if (st && (h.flags & YAMUX_FLAG_FIN)) st->remote_closed = 1;
        if (st && (h.flags & YAMUX_FLAG_RST)) {
            st->reset = 1;
            st->remote_closed = 1;
        }
    } else if (h.type == YAMUX_TYPE_WINDOW_UPDATE) {
        speer_yamux_stream_t *st = find_stream(s, h.stream_id);
        if (!st && (h.flags & YAMUX_FLAG_SYN)) { st = alloc_stream(s, h.stream_id); }
        if (st) {
            uint64_t nw = (uint64_t)st->send_window + (uint64_t)h.length;
            if (nw > UINT32_MAX) nw = UINT32_MAX;
            st->send_window = (uint32_t)nw;
        }
    } else if (h.type == YAMUX_TYPE_PING) {
        if (h.flags & YAMUX_FLAG_SYN) { speer_yamux_send_ping(s, h.length, 1); }
    } else if (h.type == YAMUX_TYPE_GO_AWAY) {
        return -1;
    }
    return 0;
}
