#include "speer_libp2p_tcp.h"

#include "speer_internal.h"

#include <stdio.h>

#include <string.h>

#include "multistream.h"
#include "peer_id.h"
#include "transport_tcp.h"
#include "varint.h"

typedef struct {
    speer_libp2p_tcp_session_t *session;
    speer_yamux_stream_t *stream;
} stream_io_t;

static void sleep_ms(int ms) {
#if defined(_WIN32)
    Sleep((DWORD)ms);
#else
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
#endif
}

static int tcp_plain_send(void *user, const uint8_t *d, size_t n) {
    int fd = *(int *)user;
    return speer_tcp_send_all(fd, d, n);
}

static int tcp_plain_recv(void *user, uint8_t *b, size_t cap, size_t *out_n) {
    int fd = *(int *)user;
    if (speer_tcp_recv_all(fd, b, cap) != 0) return -1;
    if (out_n) *out_n = cap;
    return 0;
}

static int noise_send_frame(int fd, const uint8_t *m, size_t n) {
    if (n > 0xffff) return -1;
    uint8_t h[2] = {(uint8_t)(n >> 8), (uint8_t)n};
    if (speer_tcp_send_all(fd, h, 2) != 0) return -1;
    return speer_tcp_send_all(fd, m, n);
}

static int noise_recv_frame(int fd, uint8_t *m, size_t cap, size_t *o) {
    uint8_t h[2];
    if (speer_tcp_recv_all(fd, h, 2) != 0) return -1;
    size_t n = ((size_t)h[0] << 8) | h[1];
    if (n > cap) return -1;
    if (speer_tcp_recv_all(fd, m, n) != 0) return -1;
    if (o) *o = n;
    return 0;
}

static int io_crypt_send(void *user, const uint8_t *d, size_t n) {
    speer_libp2p_tcp_session_t *s = (speer_libp2p_tcp_session_t *)user;
    while (n > 0) {
        size_t chunk = n > 65519 ? 65519 : n;
        uint8_t ct[65535 + 16];
        size_t ct_len = 0;
        if (speer_libp2p_noise_seal(&s->noise, d, chunk, ct, &ct_len) != 0) return -1;
        if (ct_len > 0xffff) return -1;
        uint8_t h[2] = {(uint8_t)(ct_len >> 8), (uint8_t)ct_len};
        if (speer_tcp_send_all(s->fd, h, 2) != 0) return -1;
        if (speer_tcp_send_all(s->fd, ct, ct_len) != 0) return -1;
        d += chunk;
        n -= chunk;
    }
    return 0;
}

static int io_crypt_recv(void *user, uint8_t *b, size_t cap, size_t *out_n) {
    speer_libp2p_tcp_session_t *s = (speer_libp2p_tcp_session_t *)user;
    size_t got = 0;
    while (got < cap) {
        if (s->crypt_q_off < s->crypt_q_len) {
            size_t take = s->crypt_q_len - s->crypt_q_off;
            if (take > cap - got) take = cap - got;
            memcpy(b + got, s->crypt_q + s->crypt_q_off, take);
            s->crypt_q_off += take;
            got += take;
            if (s->crypt_q_off >= s->crypt_q_len) s->crypt_q_off = s->crypt_q_len = 0;
            continue;
        }
        uint8_t lb[2];
        if (speer_tcp_recv_all(s->fd, lb, 2) != 0) return -1;
        size_t ct_len = ((size_t)lb[0] << 8) | lb[1];
        if (ct_len < 16 || ct_len > sizeof(s->crypt_q)) return -1;
        uint8_t ct[65535 + 16];
        if (speer_tcp_recv_all(s->fd, ct, ct_len) != 0) return -1;
        size_t pt = 0;
        if (speer_libp2p_noise_open(&s->noise, ct, ct_len, s->crypt_q, &pt) != 0) return -1;
        s->crypt_q_len = pt;
        s->crypt_q_off = 0;
    }
    if (out_n) *out_n = got;
    return 0;
}

static int build_id_payload(speer_libp2p_noise_t *n, uint8_t *out, size_t cap, size_t *out_len) {
    uint8_t sig[64];
    size_t sig_len = 0;
    if (speer_libp2p_noise_sign_static(sig, sizeof(sig), &sig_len, n->local_keytype,
                                       n->local_libp2p_priv, n->local_libp2p_priv_len,
                                       n->local_static_pub) != 0)
        return -1;
    return speer_libp2p_noise_payload_make(out, cap, out_len, n->local_keytype, n->local_libp2p_pub,
                                           n->local_libp2p_pub_len, sig, sig_len);
}

static int verify_id_payload(speer_libp2p_noise_t *n, const uint8_t *p, size_t pl) {
    speer_libp2p_keytype_t kt;
    const uint8_t *id = NULL, *sig = NULL;
    size_t idl = 0, sl = 0;
    if (speer_libp2p_noise_payload_parse(p, pl, &kt, &id, &idl, &sig, &sl) != 0) return -1;
    if (speer_libp2p_noise_verify_static(kt, id, idl, n->hs.remote_pubkey, sig, sl) != 0) return -1;
    if (idl > sizeof(n->remote_libp2p_pub)) return -1;
    memcpy(n->remote_libp2p_pub, id, idl);
    n->remote_libp2p_pub_len = idl;
    n->remote_keytype = kt;
    memcpy(n->remote_static_pub, n->hs.remote_pubkey, 32);
    return 0;
}

static int derive_remote_pid_b58(const speer_libp2p_noise_t *n, char *out, size_t cap) {
    uint8_t pkproto[1024];
    size_t pkpl = 0;
    if (speer_libp2p_pubkey_proto_encode(pkproto, sizeof(pkproto), n->remote_keytype,
                                         n->remote_libp2p_pub, n->remote_libp2p_pub_len,
                                         &pkpl) != 0)
        return -1;
    uint8_t pid[64];
    size_t pidl = 0;
    if (speer_peer_id_from_pubkey_bytes(pid, sizeof(pid), pkproto, pkpl, &pidl) != 0) return -1;
    return speer_peer_id_to_b58(out, cap, pid, pidl);
}

static int noise_handshake_initiator(int fd, speer_libp2p_noise_t *n) {
    uint8_t m1[32];
    if (speer_noise_xx_write_msg1(&n->hs, m1) != 0) return -1;
    if (noise_send_frame(fd, m1, sizeof(m1)) != 0) return -1;

    uint8_t m2[2048];
    size_t m2l = 0;
    if (noise_recv_frame(fd, m2, sizeof(m2), &m2l) != 0) return -1;
    uint8_t pl[2048];
    size_t pll = 0;
    if (speer_noise_xx_read_msg2_p(&n->hs, m2, m2l, pl, sizeof(pl), &pll) != 0) return -1;
    if (verify_id_payload(n, pl, pll) != 0) return -1;

    uint8_t ip[1024];
    size_t ipl = 0;
    if (build_id_payload(n, ip, sizeof(ip), &ipl) != 0) return -1;
    uint8_t m3[2048];
    size_t m3l = 0;
    if (speer_noise_xx_write_msg3_p(&n->hs, ip, ipl, m3, sizeof(m3), &m3l) != 0) return -1;
    if (noise_send_frame(fd, m3, m3l) != 0) return -1;

    speer_noise_xx_split(&n->hs, n->send_key, n->recv_key);
    n->send_nonce = 0;
    n->recv_nonce = 0;
    return 0;
}

static int noise_handshake_listener(int fd, speer_libp2p_noise_t *n) {
    uint8_t m1[64];
    size_t m1l = 0;
    if (noise_recv_frame(fd, m1, sizeof(m1), &m1l) != 0) return -1;
    if (m1l != 32) return -1;
    if (speer_noise_xx_read_msg1(&n->hs, m1) != 0) return -1;

    uint8_t ip[1024];
    size_t ipl = 0;
    if (build_id_payload(n, ip, sizeof(ip), &ipl) != 0) return -1;
    uint8_t m2[2048];
    size_t m2l = 0;
    if (speer_noise_xx_write_msg2_p(&n->hs, ip, ipl, m2, sizeof(m2), &m2l) != 0) return -1;
    if (noise_send_frame(fd, m2, m2l) != 0) return -1;

    uint8_t m3[2048];
    size_t m3l = 0;
    if (noise_recv_frame(fd, m3, sizeof(m3), &m3l) != 0) return -1;
    uint8_t pl[2048];
    size_t pll = 0;
    if (speer_noise_xx_read_msg3_p(&n->hs, m3, m3l, pl, sizeof(pl), &pll) != 0) return -1;
    if (verify_id_payload(n, pl, pll) != 0) return -1;

    speer_noise_xx_split(&n->hs, n->recv_key, n->send_key);
    n->send_nonce = 0;
    n->recv_nonce = 0;
    return 0;
}

static int session_init_common(speer_libp2p_tcp_session_t *session, int fd, int is_initiator,
                               const speer_libp2p_identity_t *identity) {
    if (!session || !identity || !identity->static_pub || !identity->static_priv ||
        !identity->libp2p_pub || !identity->libp2p_priv)
        return -1;
    ZERO(session, sizeof(*session));
    session->fd = fd;
    session->is_initiator = is_initiator;
    if (speer_libp2p_noise_init(&session->noise, identity->static_pub, identity->static_priv,
                                identity->keytype, identity->libp2p_pub, identity->libp2p_pub_len,
                                identity->libp2p_priv, identity->libp2p_priv_len) != 0)
        return -1;
    return 0;
}

int speer_libp2p_tcp_session_init_dialer(speer_libp2p_tcp_session_t *session, int fd,
                                         const speer_libp2p_identity_t *identity) {
    if (session_init_common(session, fd, 1, identity) != 0) return -1;
    if (speer_ms_negotiate_initiator(&session->fd, tcp_plain_send, tcp_plain_recv, "/noise") != 0)
        return -1;
    if (noise_handshake_initiator(session->fd, &session->noise) != 0) return -1;
    if (speer_ms_negotiate_initiator(session, io_crypt_send, io_crypt_recv, "/yamux/1.0.0") != 0)
        return -1;
    speer_yamux_init(&session->mux, 1, io_crypt_send, io_crypt_recv, session);
    if (derive_remote_pid_b58(&session->noise, session->remote_peer_id_b58,
                              sizeof(session->remote_peer_id_b58)) != 0)
        snprintf(session->remote_peer_id_b58, sizeof(session->remote_peer_id_b58), "%s",
                 "(unknown)");
    return 0;
}

int speer_libp2p_tcp_session_init_listener(speer_libp2p_tcp_session_t *session, int fd,
                                           const speer_libp2p_identity_t *identity) {
    if (session_init_common(session, fd, 0, identity) != 0) return -1;
    const char *protos[1] = {"/noise"};
    size_t sel = 0;
    if (speer_ms_negotiate_listener(&session->fd, tcp_plain_send, tcp_plain_recv, protos, 1,
                                    &sel) != 0)
        return -1;
    if (noise_handshake_listener(session->fd, &session->noise) != 0) return -1;
    const char *ymux[1] = {"/yamux/1.0.0"};
    if (speer_ms_negotiate_listener(session, io_crypt_send, io_crypt_recv, ymux, 1, &sel) != 0)
        return -1;
    speer_yamux_init(&session->mux, 0, io_crypt_send, io_crypt_recv, session);
    if (derive_remote_pid_b58(&session->noise, session->remote_peer_id_b58,
                              sizeof(session->remote_peer_id_b58)) != 0)
        snprintf(session->remote_peer_id_b58, sizeof(session->remote_peer_id_b58), "%s",
                 "(unknown)");
    return 0;
}

void speer_libp2p_tcp_session_close(speer_libp2p_tcp_session_t *session) {
    if (!session) return;
    speer_yamux_close(&session->mux);
    if (session->fd >= 0) {
        speer_tcp_close(session->fd);
        session->fd = -1;
    }
}

static int ymux_stream_send(void *user, const uint8_t *d, size_t n) {
    stream_io_t *io = (stream_io_t *)user;
    return speer_yamux_stream_write(&io->session->mux, io->stream, d, n);
}

static int ymux_stream_recv(void *user, uint8_t *b, size_t cap, size_t *out_n) {
    stream_io_t *io = (stream_io_t *)user;
    while (io->stream->recv_buf_len < cap) {
        if (io->stream->reset) return -1;
        if (io->stream->remote_closed && io->stream->recv_buf_len < cap) return -1;
        if (speer_yamux_pump(&io->session->mux) != 0) return -1;
    }
    memcpy(b, io->stream->recv_buf, cap);
    memmove(io->stream->recv_buf, io->stream->recv_buf + cap, io->stream->recv_buf_len - cap);
    io->stream->recv_buf_len -= cap;
    if (out_n) *out_n = cap;
    return 0;
}

int speer_libp2p_tcp_open_protocol_stream(speer_libp2p_tcp_session_t *session, const char *protocol,
                                          speer_yamux_stream_t **out_stream) {
    if (!session || !protocol || !out_stream) return -1;
    *out_stream = speer_yamux_open_stream(&session->mux);
    if (!*out_stream) return -1;
    stream_io_t io = {.session = session, .stream = *out_stream};
    if (speer_ms_negotiate_initiator(&io, ymux_stream_send, ymux_stream_recv, protocol) != 0)
        return -1;
    return 0;
}

int speer_libp2p_tcp_accept_protocol_stream(speer_libp2p_tcp_session_t *session,
                                            const char *const *protocols, size_t num_protocols,
                                            size_t *selected_idx, speer_yamux_stream_t **out_stream,
                                            int timeout_ms, int pump_step_ms) {
    if (!session || !protocols || num_protocols == 0 || !out_stream) return -1;
    int waited = 0;
    int step = pump_step_ms > 0 ? pump_step_ms : 10;
    while (!session->mux.streams && (timeout_ms < 0 || waited < timeout_ms)) {
        if (speer_yamux_pump(&session->mux) != 0) return -1;
        if (session->mux.streams) break;
        sleep_ms(step);
        waited += step;
    }
    if (!session->mux.streams) return -1;
    *out_stream = session->mux.streams;
    stream_io_t io = {.session = session, .stream = *out_stream};
    return speer_ms_negotiate_listener(&io, ymux_stream_send, ymux_stream_recv, protocols,
                                       num_protocols, selected_idx);
}

int speer_libp2p_uvar_frame_send(void *user, speer_libp2p_send_fn send_fn, const uint8_t *payload,
                                 size_t payload_len) {
    uint8_t hdr[10];
    size_t hlen = speer_uvarint_encode(hdr, sizeof(hdr), payload_len);
    if (hlen == 0) return -1;
    if (send_fn(user, hdr, hlen) != 0) return -1;
    if (payload_len > 0 && send_fn(user, payload, payload_len) != 0) return -1;
    return 0;
}

int speer_libp2p_uvar_frame_recv(void *user, speer_libp2p_recv_fn recv_fn, uint8_t *out,
                                 size_t out_cap, size_t *out_len) {
    uint8_t hdr[10];
    size_t hdr_len = 0;
    size_t got = 0;
    while (hdr_len < sizeof(hdr)) {
        if (recv_fn(user, hdr + hdr_len, 1, &got) != 0 || got != 1) return -1;
        hdr_len++;
        if ((hdr[hdr_len - 1] & 0x80u) == 0) break;
    }
    uint64_t payload_len = 0;
    if (speer_uvarint_decode(hdr, hdr_len, &payload_len) == 0) return -1;
    if (payload_len == 0 || payload_len > out_cap) return -1;

    size_t need = (size_t)payload_len;
    size_t off = 0;
    while (off < need) {
        size_t chunk = need - off;
        if (recv_fn(user, out + off, chunk, &got) != 0 || got == 0 || got > chunk) return -1;
        off += got;
    }
    if (out_len) *out_len = need;
    return 0;
}

int speer_libp2p_tcp_stream_send_frame(speer_libp2p_tcp_session_t *session,
                                       speer_yamux_stream_t *st, const uint8_t *payload,
                                       size_t payload_len) {
    stream_io_t io = {.session = session, .stream = st};
    return speer_libp2p_uvar_frame_send(&io, ymux_stream_send, payload, payload_len);
}

int speer_libp2p_tcp_stream_recv_frame(speer_libp2p_tcp_session_t *session,
                                       speer_yamux_stream_t *st, uint8_t *out, size_t out_cap,
                                       size_t *out_len) {
    stream_io_t io = {.session = session, .stream = st};
    return speer_libp2p_uvar_frame_recv(&io, ymux_stream_recv, out, out_cap, out_len);
}
