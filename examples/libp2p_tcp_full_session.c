#include "speer_internal.h"

#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include "ed25519.h"
#include "libp2p_noise.h"
#include "multistream.h"
#include "transport_tcp.h"
#include "yamux.h"

#define CRYPT_Q_CAP (256 * 1024)

typedef struct {
    int fd;
    speer_libp2p_noise_t *noise;
    uint8_t q[CRYPT_Q_CAP];
    size_t q_len;
    size_t q_off;
} ioctx_t;

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

static int noise_send_lp(int fd, const uint8_t *msg, size_t len) {
    if (len > 0xffff) return -1;
    uint8_t hdr[2] = {(uint8_t)(len >> 8), (uint8_t)(len & 0xff)};
    if (speer_tcp_send_all(fd, hdr, 2) != 0) return -1;
    return speer_tcp_send_all(fd, msg, len);
}

static int noise_recv_lp(int fd, uint8_t *msg, size_t cap, size_t *out_len) {
    uint8_t hdr[2];
    if (speer_tcp_recv_all(fd, hdr, 2) != 0) return -1;
    size_t len = ((size_t)hdr[0] << 8) | (size_t)hdr[1];
    if (len > cap) return -1;
    if (speer_tcp_recv_all(fd, msg, len) != 0) return -1;
    *out_len = len;
    return 0;
}

static int io_crypt_send(void *user, const uint8_t *d, size_t n) {
    ioctx_t *io = (ioctx_t *)user;
    uint8_t ct[8192];
    size_t ct_len;
    if (n + 16 > sizeof(ct)) return -1;
    if (speer_libp2p_noise_seal(io->noise, d, n, ct, &ct_len) != 0) return -1;
    if (ct_len > 0xffff) return -1;
    uint8_t hdr[2] = {(uint8_t)(ct_len >> 8), (uint8_t)(ct_len & 0xff)};
    if (speer_tcp_send_all(io->fd, hdr, 2) != 0) return -1;
    return speer_tcp_send_all(io->fd, ct, ct_len);
}

static int io_crypt_recv(void *user, uint8_t *b, size_t cap, size_t *out_n) {
    ioctx_t *io = (ioctx_t *)user;
    size_t got = 0;
    while (got < cap) {
        if (io->q_off < io->q_len) {
            size_t take = MIN(io->q_len - io->q_off, cap - got);
            COPY(b + got, io->q + io->q_off, take);
            io->q_off += take;
            got += take;
            if (io->q_off >= io->q_len) io->q_off = io->q_len = 0;
            continue;
        }
        uint8_t lb[2];
        if (speer_tcp_recv_all(io->fd, lb, 2) != 0) return -1;
        size_t ct_len = ((size_t)lb[0] << 8) | (size_t)lb[1];
        if (ct_len > sizeof(io->q) || ct_len < 16) return -1;
        uint8_t ctstack[8192];
        if (ct_len > sizeof(ctstack)) return -1;
        if (speer_tcp_recv_all(io->fd, ctstack, ct_len) != 0) return -1;
        size_t pt_len = 0;
        if (speer_libp2p_noise_open(io->noise, ctstack, ct_len, io->q, &pt_len) != 0) return -1;
        io->q_len = pt_len;
        io->q_off = 0;
    }
    *out_n = got;
    return 0;
}

static int make_noise_keys(speer_libp2p_noise_t *n, uint8_t static_pub[32], uint8_t static_priv[32],
                           uint8_t ed_pub[32], uint8_t ed_seed[32]) {
    speer_random_bytes(static_priv, 32);
    speer_x25519_base(static_pub, static_priv);
    speer_random_bytes(ed_seed, 32);
    speer_ed25519_keypair(ed_pub, ed_seed, ed_seed);
    return speer_libp2p_noise_init(n, static_pub, static_priv, SPEER_LIBP2P_KEY_ED25519, ed_pub, 32,
                                   ed_seed, 32);
}

static int noise_handshake_client(int fd, speer_libp2p_noise_t *n) {
    uint8_t m1[32], m2[80], m3[48];
    size_t l2;

    if (speer_noise_xx_write_msg1(&n->hs, m1) != 0) return -1;
    if (noise_send_lp(fd, m1, sizeof(m1)) != 0) return -1;

    if (noise_recv_lp(fd, m2, sizeof(m2), &l2) != 0 || l2 != 80) return -1;
    if (speer_noise_xx_read_msg2(&n->hs, m2) != 0) return -1;

    if (speer_noise_xx_write_msg3(&n->hs, m3) != 0) return -1;
    if (noise_send_lp(fd, m3, sizeof(m3)) != 0) return -1;

    speer_noise_xx_split(&n->hs, n->send_key, n->recv_key);
    n->send_nonce = 0;
    n->recv_nonce = 0;
    return 0;
}

static int noise_handshake_server(int fd, speer_libp2p_noise_t *n) {
    uint8_t m1[32], m2[80], m3[48];
    size_t l1, l3;

    if (noise_recv_lp(fd, m1, sizeof(m1), &l1) != 0 || l1 != 32) return -1;
    if (speer_noise_xx_read_msg1(&n->hs, m1) != 0) return -1;

    if (speer_noise_xx_write_msg2(&n->hs, m2) != 0) return -1;
    if (noise_send_lp(fd, m2, sizeof(m2)) != 0) return -1;

    if (noise_recv_lp(fd, m3, sizeof(m3), &l3) != 0 || l3 != 48) return -1;
    if (speer_noise_xx_read_msg3(&n->hs, m3) != 0) return -1;

    speer_noise_xx_split(&n->hs, n->recv_key, n->send_key);
    n->send_nonce = 0;
    n->recv_nonce = 0;
    return 0;
}

static int run_dial(const char *host, uint16_t port) {
    int fd = -1;
    if (speer_tcp_dial(&fd, host, port) != 0) {
        fprintf(stderr, "dial failed\n");
        return 1;
    }

    if (speer_ms_negotiate_initiator(&fd, tcp_plain_send, tcp_plain_recv, "/noise") != 0) {
        fprintf(stderr, "multistream /noise failed\n");
        speer_tcp_close(fd);
        return 1;
    }

    speer_libp2p_noise_t noise;
    uint8_t spub[32], spriv[32], edpub[32], edseed[32];
    if (make_noise_keys(&noise, spub, spriv, edpub, edseed) != 0) {
        speer_tcp_close(fd);
        return 1;
    }

    if (noise_handshake_client(fd, &noise) != 0) {
        fprintf(stderr, "Noise XX (client) failed\n");
        WIPE(spriv, sizeof(spriv));
        WIPE(edseed, sizeof(edseed));
        speer_tcp_close(fd);
        return 1;
    }
    printf("Noise handshake complete (initiator)\n");

    ioctx_t io = {.fd = fd, .noise = &noise};
    if (speer_ms_negotiate_initiator(&io, io_crypt_send, io_crypt_recv, "/yamux/1.0.0") != 0) {
        fprintf(stderr, "encrypted multistream yamux failed\n");
        WIPE(spriv, sizeof(spriv));
        WIPE(edseed, sizeof(edseed));
        speer_tcp_close(fd);
        return 1;
    }

    speer_yamux_session_t ymux;
    speer_yamux_init(&ymux, 1, io_crypt_send, io_crypt_recv, &io);
    speer_yamux_stream_t *st = speer_yamux_open_stream(&ymux);
    if (!st) {
        fprintf(stderr, "yamux open stream failed\n");
        speer_yamux_close(&ymux);
        WIPE(spriv, sizeof(spriv));
        WIPE(edseed, sizeof(edseed));
        speer_tcp_close(fd);
        return 1;
    }

    static const uint8_t payload[] = "echo-check";
    if (speer_yamux_stream_write(&ymux, st, payload, sizeof(payload) - 1) != 0) {
        fprintf(stderr, "yamux write failed\n");
        speer_yamux_close(&ymux);
        WIPE(spriv, sizeof(spriv));
        WIPE(edseed, sizeof(edseed));
        speer_tcp_close(fd);
        return 1;
    }

    int ok = 0;
    for (int i = 0; i < 5000 && !ok; i++) {
        if (speer_yamux_pump(&ymux) != 0) break;
        if (st->recv_buf_len >= sizeof(payload) - 1 &&
            memcmp(st->recv_buf, payload, sizeof(payload) - 1) == 0)
            ok = 1;
    }

    speer_yamux_close(&ymux);
    WIPE(spriv, sizeof(spriv));
    WIPE(edseed, sizeof(edseed));
    speer_tcp_close(fd);

    if (!ok) {
        fprintf(stderr, "did not receive echo (start listener first?)\n");
        return 1;
    }
    printf("yamux echo: ok (got %zu bytes)\n", sizeof(payload) - 1);
    return 0;
}

static int echo_streams(speer_yamux_session_t *mux) {
    for (speer_yamux_stream_t *st = mux->streams; st; st = st->next) {
        if (st->recv_buf_len == 0) continue;
        size_t n = st->recv_buf_len;
        if (speer_yamux_stream_write(mux, st, st->recv_buf, n) != 0) return -1;
        st->recv_buf_len = 0;
    }
    return 0;
}

static int run_listen(uint16_t port) {
    int lfd = -1, fd = -1;
    if (speer_tcp_listen(&lfd, NULL, port) != 0) {
        fprintf(stderr, "listen failed\n");
        return 1;
    }
    char peer[64];
    if (speer_tcp_accept(lfd, &fd, peer, sizeof(peer)) != 0) {
        fprintf(stderr, "accept failed\n");
        speer_tcp_close(lfd);
        return 1;
    }
    printf("accepted %s\n", peer);
    speer_tcp_close(lfd);

    const char *protos[] = {"/noise"};
    size_t selected = 0;
    if (speer_ms_negotiate_listener(&fd, tcp_plain_send, tcp_plain_recv, protos, 1, &selected) !=
        0) {
        fprintf(stderr, "multistream listener /noise failed\n");
        speer_tcp_close(fd);
        return 1;
    }

    speer_libp2p_noise_t noise;
    uint8_t spub[32], spriv[32], edpub[32], edseed[32];
    if (make_noise_keys(&noise, spub, spriv, edpub, edseed) != 0) {
        speer_tcp_close(fd);
        return 1;
    }

    if (noise_handshake_server(fd, &noise) != 0) {
        fprintf(stderr, "Noise XX (server) failed\n");
        WIPE(spriv, sizeof(spriv));
        WIPE(edseed, sizeof(edseed));
        speer_tcp_close(fd);
        return 1;
    }
    printf("Noise handshake complete (responder)\n");

    ioctx_t io = {.fd = fd, .noise = &noise};
    const char *yamux_protos[] = {"/yamux/1.0.0"};
    if (speer_ms_negotiate_listener(&io, io_crypt_send, io_crypt_recv, yamux_protos, 1,
                                    &selected) != 0) {
        fprintf(stderr, "encrypted multistream yamux (listener) failed\n");
        WIPE(spriv, sizeof(spriv));
        WIPE(edseed, sizeof(edseed));
        speer_tcp_close(fd);
        return 1;
    }

    speer_yamux_session_t ymux;
    speer_yamux_init(&ymux, 0, io_crypt_send, io_crypt_recv, &io);

    for (int i = 0; i < 8000; i++) {
        if (speer_yamux_pump(&ymux) != 0) break;
        if (echo_streams(&ymux) != 0) break;
    }

    speer_yamux_close(&ymux);
    WIPE(spriv, sizeof(spriv));
    WIPE(edseed, sizeof(edseed));
    speer_tcp_close(fd);
    printf("listener: session finished\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr,
                "usage:\n"
                "  %s listen PORT\n"
                "  %s dial HOST PORT\n",
                argv[0], argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "listen") == 0 && argc >= 3) { return run_listen((uint16_t)atoi(argv[2])); }
    if (strcmp(argv[1], "dial") == 0 && argc >= 4) {
        return run_dial(argv[2], (uint16_t)atoi(argv[3]));
    }
    fprintf(stderr, "bad arguments\n");
    return 1;
}
