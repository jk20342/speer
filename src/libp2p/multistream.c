#include "multistream.h"

#include "speer_internal.h"

#include <string.h>

#include "varint.h"

static size_t encode_lp_line(uint8_t *buf, size_t cap, const char *s) {
    size_t slen = strlen(s);
    size_t total_len = slen + 1;
    size_t hl = speer_uvarint_encode(buf, cap, total_len);
    if (hl == 0 || hl + total_len > cap) return 0;
    memcpy(buf + hl, s, slen);
    buf[hl + slen] = '\n';
    return hl + total_len;
}

static int write_lp_string(void *user, speer_ms_send_fn send_fn, const char *s) {
    uint8_t buf[10 + 256];
    size_t n = encode_lp_line(buf, sizeof(buf), s);
    if (n == 0) return -1;
    return send_fn(user, buf, n);
}

static int read_lp_string(void *user, speer_ms_recv_fn recv_fn, char *out, size_t cap) {
    uint8_t lp[10];
    size_t total = 0;
    size_t got = 0;
    while (total < 10) {
        if (recv_fn(user, lp + total, 1, &got) != 0 || got != 1) return -1;
        total++;
        if ((lp[total - 1] & 0x80) == 0) break;
    }
    uint64_t plen;
    if (speer_uvarint_decode(lp, total, &plen) == 0) return -1;
    if (plen == 0 || plen > cap) return -1;
    if (recv_fn(user, (uint8_t *)out, (size_t)plen, &got) != 0 || got != plen) return -1;
    if (out[plen - 1] != '\n') return -1;
    out[plen - 1] = 0;
    return 0;
}

int speer_ms_send_protocol(void *user, speer_ms_send_fn send_fn, const char *protocol) {
    return write_lp_string(user, send_fn, protocol);
}

int speer_ms_recv_protocol(void *user, speer_ms_recv_fn recv_fn, char *out, size_t out_cap) {
    return read_lp_string(user, recv_fn, out, out_cap);
}

int speer_ms_negotiate_initiator(void *user, speer_ms_send_fn send_fn, speer_ms_recv_fn recv_fn,
                                 const char *protocol) {
    uint8_t out[2 * (10 + 256)];
    size_t off = 0;
    size_t n;
    if ((n = encode_lp_line(out + off, sizeof(out) - off, MULTISTREAM_PROTO)) == 0) return -1;
    off += n;
    if ((n = encode_lp_line(out + off, sizeof(out) - off, protocol)) == 0) return -1;
    off += n;
    if (send_fn(user, out, off) != 0) return -1;

    char buf[256];
    if (read_lp_string(user, recv_fn, buf, sizeof(buf)) != 0) return -1;
    if (strcmp(buf, MULTISTREAM_PROTO) != 0) return -1;
    if (read_lp_string(user, recv_fn, buf, sizeof(buf)) != 0) return -1;
    if (strcmp(buf, protocol) != 0) return -1;
    return 0;
}

/* Maximum number of listener negotiation rounds before we close the stream.
   Each round is one received protocol name; bound prevents an authenticated
   peer from pinning the listener via an endless stream of unknown
   protocols. ls and unknown both count toward the cap. */
#define MULTISTREAM_LISTENER_MAX_ROUNDS 10

int speer_ms_negotiate_listener(void *user, speer_ms_send_fn send_fn, speer_ms_recv_fn recv_fn,
                                const char *const *protocols, size_t num_protocols,
                                size_t *selected_idx) {
    char buf[256];
    if (read_lp_string(user, recv_fn, buf, sizeof(buf)) != 0) return -1;
    if (strcmp(buf, MULTISTREAM_PROTO) != 0) return -1;
    if (write_lp_string(user, send_fn, MULTISTREAM_PROTO) != 0) return -1;

    int rounds = 0;
    while (rounds++ < MULTISTREAM_LISTENER_MAX_ROUNDS) {
        if (read_lp_string(user, recv_fn, buf, sizeof(buf)) != 0) return -1;
        if (strcmp(buf, MULTISTREAM_LS) == 0) {
            for (size_t i = 0; i < num_protocols; i++) write_lp_string(user, send_fn, protocols[i]);
            continue;
        }
        for (size_t i = 0; i < num_protocols; i++) {
            if (strcmp(buf, protocols[i]) == 0) {
                if (write_lp_string(user, send_fn, protocols[i]) != 0) return -1;
                if (selected_idx) *selected_idx = i;
                return 0;
            }
        }
        write_lp_string(user, send_fn, MULTISTREAM_NA);
    }
    return -1;
}
