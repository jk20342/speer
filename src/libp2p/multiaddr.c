#include "speer_internal.h"
#include "multiaddr.h"
#include "varint.h"

#include <string.h>
#include <stdio.h>

static int append_uvar(speer_multiaddr_t* ma, uint64_t v) {
    size_t n = speer_uvarint_encode(ma->bytes + ma->len, sizeof(ma->bytes) - ma->len, v);
    if (n == 0) return -1;
    ma->len += n;
    return 0;
}

static int append_bytes(speer_multiaddr_t* ma, const uint8_t* d, size_t n) {
    if (ma->len + n > sizeof(ma->bytes)) return -1;
    COPY(ma->bytes + ma->len, d, n);
    ma->len += n;
    return 0;
}

static const char* tok_next(const char* s, const char** out_tok, size_t* out_len) {
    while (*s == '/') s++;
    if (!*s) return NULL;
    const char* start = s;
    while (*s && *s != '/') s++;
    *out_tok = start;
    *out_len = (size_t)(s - start);
    return s;
}

static int eq_tok(const char* tok, size_t len, const char* lit) {
    size_t l = 0;
    while (lit[l]) l++;
    if (l != len) return 0;
    for (size_t i = 0; i < l; i++) if (tok[i] != lit[i]) return 0;
    return 1;
}

static int parse_ipv4(const char* s, size_t len, uint8_t out[4]) {
    char buf[40];
    if (len >= sizeof(buf)) return -1;
    COPY(buf, s, len); buf[len] = 0;
    int a, b, c, d;
    if (sscanf(buf, "%d.%d.%d.%d", &a, &b, &c, &d) != 4) return -1;
    if (a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 || d < 0 || d > 255) return -1;
    out[0] = (uint8_t)a; out[1] = (uint8_t)b; out[2] = (uint8_t)c; out[3] = (uint8_t)d;
    return 0;
}

static int parse_u16(const char* s, size_t len, uint16_t* out) {
    char buf[8] = {0};
    if (len >= sizeof(buf)) return -1;
    COPY(buf, s, len);
    int v = atoi(buf);
    if (v < 0 || v > 65535) return -1;
    *out = (uint16_t)v;
    return 0;
}

int speer_multiaddr_parse(speer_multiaddr_t* out, const char* s) {
    out->len = 0;
    const char* p = s;
    while (p && *p) {
        const char* tok; size_t tlen;
        p = tok_next(p, &tok, &tlen);
        if (!p) break;
        if (eq_tok(tok, tlen, "ip4")) {
            const char* val; size_t vlen;
            p = tok_next(p, &val, &vlen);
            if (!p) return -1;
            uint8_t addr[4];
            if (parse_ipv4(val, vlen, addr) != 0) return -1;
            if (append_uvar(out, SPEER_MA_IP4) != 0) return -1;
            if (append_bytes(out, addr, 4) != 0) return -1;
        } else if (eq_tok(tok, tlen, "tcp") || eq_tok(tok, tlen, "udp")) {
            int proto = eq_tok(tok, tlen, "tcp") ? SPEER_MA_TCP : SPEER_MA_UDP;
            const char* val; size_t vlen;
            p = tok_next(p, &val, &vlen);
            if (!p) return -1;
            uint16_t port;
            if (parse_u16(val, vlen, &port) != 0) return -1;
            if (append_uvar(out, proto) != 0) return -1;
            uint8_t b[2] = { (uint8_t)(port >> 8), (uint8_t)port };
            if (append_bytes(out, b, 2) != 0) return -1;
        } else if (eq_tok(tok, tlen, "quic-v1")) {
            if (append_uvar(out, SPEER_MA_QUICV1) != 0) return -1;
        } else if (eq_tok(tok, tlen, "quic")) {
            if (append_uvar(out, SPEER_MA_QUIC) != 0) return -1;
        } else if (eq_tok(tok, tlen, "p2p-circuit")) {
            if (append_uvar(out, SPEER_MA_P2P_CIRCUIT) != 0) return -1;
        } else if (eq_tok(tok, tlen, "p2p")) {
            const char* val; size_t vlen;
            p = tok_next(p, &val, &vlen);
            if (!p) return -1;
            if (append_uvar(out, SPEER_MA_P2P) != 0) return -1;
            if (append_uvar(out, vlen) != 0) return -1;
            if (append_bytes(out, (const uint8_t*)val, vlen) != 0) return -1;
        } else {
            return -1;
        }
    }
    return 0;
}

int speer_multiaddr_to_string(const speer_multiaddr_t* ma, char* out, size_t cap) {
    size_t pos = 0;
    size_t i = 0;
    out[0] = 0;
    while (i < ma->len) {
        uint64_t code;
        size_t n = speer_uvarint_decode(ma->bytes + i, ma->len - i, &code);
        if (n == 0) return -1;
        i += n;
        switch (code) {
            case SPEER_MA_IP4:
                if (i + 4 > ma->len) return -1;
                pos += snprintf(out + pos, cap - pos, "/ip4/%u.%u.%u.%u",
                                ma->bytes[i], ma->bytes[i+1], ma->bytes[i+2], ma->bytes[i+3]);
                i += 4;
                break;
            case SPEER_MA_TCP:
            case SPEER_MA_UDP:
                if (i + 2 > ma->len) return -1;
                pos += snprintf(out + pos, cap - pos, "/%s/%u",
                                code == SPEER_MA_TCP ? "tcp" : "udp",
                                ((unsigned)ma->bytes[i] << 8) | ma->bytes[i+1]);
                i += 2;
                break;
            case SPEER_MA_QUIC:
                pos += snprintf(out + pos, cap - pos, "/quic");
                break;
            case SPEER_MA_QUICV1:
                pos += snprintf(out + pos, cap - pos, "/quic-v1");
                break;
            case SPEER_MA_P2P_CIRCUIT:
                pos += snprintf(out + pos, cap - pos, "/p2p-circuit");
                break;
            default:
                pos += snprintf(out + pos, cap - pos, "/unknown(%u)", (unsigned)code);
                return -1;
        }
        if (pos >= cap) return -1;
    }
    return 0;
}

int speer_multiaddr_to_host_port_v4(const speer_multiaddr_t* ma, char* host, size_t host_cap, uint16_t* port) {
    size_t i = 0;
    int got_ip = 0, got_port = 0;
    while (i < ma->len) {
        uint64_t code;
        size_t n = speer_uvarint_decode(ma->bytes + i, ma->len - i, &code);
        if (n == 0) return -1;
        i += n;
        if (code == SPEER_MA_IP4) {
            if (i + 4 > ma->len) return -1;
            snprintf(host, host_cap, "%u.%u.%u.%u",
                     ma->bytes[i], ma->bytes[i+1], ma->bytes[i+2], ma->bytes[i+3]);
            i += 4;
            got_ip = 1;
        } else if (code == SPEER_MA_TCP || code == SPEER_MA_UDP) {
            if (i + 2 > ma->len) return -1;
            *port = (uint16_t)((ma->bytes[i] << 8) | ma->bytes[i+1]);
            i += 2;
            got_port = 1;
        } else if (code == SPEER_MA_P2P) {
            uint64_t l;
            size_t k = speer_uvarint_decode(ma->bytes + i, ma->len - i, &l);
            if (k == 0) return -1;
            i += k + (size_t)l;
        } else {
            break;
        }
    }
    return (got_ip && got_port) ? 0 : -1;
}

int speer_multiaddr_get_p2p_id(const speer_multiaddr_t* ma, const uint8_t** id, size_t* id_len) {
    size_t i = 0;
    while (i < ma->len) {
        uint64_t code;
        size_t n = speer_uvarint_decode(ma->bytes + i, ma->len - i, &code);
        if (n == 0) return -1;
        i += n;
        if (code == SPEER_MA_P2P) {
            uint64_t l;
            size_t k = speer_uvarint_decode(ma->bytes + i, ma->len - i, &l);
            if (k == 0) return -1;
            *id = ma->bytes + i + k;
            *id_len = (size_t)l;
            return 0;
        } else if (code == SPEER_MA_IP4) i += 4;
        else if (code == SPEER_MA_IP6) i += 16;
        else if (code == SPEER_MA_TCP || code == SPEER_MA_UDP) i += 2;
    }
    return -1;
}
