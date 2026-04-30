#include "multistream.h"

#include "speer_internal.h"

#include <string.h>

#include "varint.h"

static int write_lp_string(void *user, speer_ms_send_fn send_fn, const char *s) {
    size_t slen = strlen(s);
    size_t total_len = slen + 1;
    uint8_t hdr[10];
    size_t hl = speer_uvarint_encode(hdr, sizeof(hdr), total_len);
    if (hl == 0) return -1;
    if (send_fn(user, hdr, hl) != 0) return -1;
    if (send_fn(user, (const uint8_t *)s, slen) != 0) return -1;
    uint8_t nl = (uint8_t)'\n';
    return send_fn(user, &nl, 1);
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
    if (out[plen - 1] == '\n')
        out[plen - 1] = 0;
    else if (plen < cap)
        out[plen] = 0;
    else
        return -1;
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
    if (write_lp_string(user, send_fn, MULTISTREAM_PROTO) != 0) return -1;
    if (write_lp_string(user, send_fn, protocol) != 0) return -1;

    char buf[256];
    if (read_lp_string(user, recv_fn, buf, sizeof(buf)) != 0) return -1;
    if (strcmp(buf, MULTISTREAM_PROTO) != 0) return -1;
    if (read_lp_string(user, recv_fn, buf, sizeof(buf)) != 0) return -1;
    if (strcmp(buf, protocol) != 0) return -1;
    return 0;
}

int speer_ms_negotiate_listener(void *user, speer_ms_send_fn send_fn, speer_ms_recv_fn recv_fn,
                                const char *const *protocols, size_t num_protocols,
                                size_t *selected_idx) {
    char buf[256];
    if (read_lp_string(user, recv_fn, buf, sizeof(buf)) != 0) return -1;
    if (strcmp(buf, MULTISTREAM_PROTO) != 0) return -1;
    if (write_lp_string(user, send_fn, MULTISTREAM_PROTO) != 0) return -1;

    while (1) {
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
}
