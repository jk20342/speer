#include "speer_internal.h"

#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include "ed25519.h"
#include "speer_libp2p_tcp.h"
#include "transport_tcp.h"

typedef struct {
    uint8_t static_pub[32];
    uint8_t static_priv[32];
    uint8_t ed_pub[32];
    uint8_t ed_seed[32];
} key_material_t;

static void make_identity(key_material_t *km, speer_libp2p_identity_t *id) {
    speer_random_bytes(km->static_priv, sizeof(km->static_priv));
    speer_x25519_base(km->static_pub, km->static_priv);
    speer_random_bytes(km->ed_seed, sizeof(km->ed_seed));
    speer_ed25519_keypair(km->ed_pub, km->ed_seed, km->ed_seed);

    id->static_pub = km->static_pub;
    id->static_priv = km->static_priv;
    id->keytype = SPEER_LIBP2P_KEY_ED25519;
    id->libp2p_pub = km->ed_pub;
    id->libp2p_pub_len = sizeof(km->ed_pub);
    id->libp2p_priv = km->ed_seed;
    id->libp2p_priv_len = sizeof(km->ed_seed);
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

static int run_dial(const char *host, uint16_t port) {
    int fd = -1;
    if (speer_tcp_dial(&fd, host, port) != 0) {
        fprintf(stderr, "dial failed\n");
        return 1;
    }

    key_material_t keys;
    speer_libp2p_identity_t id;
    make_identity(&keys, &id);

    speer_libp2p_tcp_session_t session;
    if (speer_libp2p_tcp_session_init_dialer(&session, fd, &id) != 0) {
        fprintf(stderr, "libp2p session bootstrap (dialer) failed\n");
        WIPE(keys.static_priv, sizeof(keys.static_priv));
        WIPE(keys.ed_seed, sizeof(keys.ed_seed));
        speer_tcp_close(fd);
        return 1;
    }
    printf("session ready with peer %s\n", session.remote_peer_id_b58);

    speer_yamux_stream_t *st = NULL;
    if (speer_libp2p_tcp_open_protocol_stream(&session, "/echo/1.0.0", &st) != 0) {
        fprintf(stderr, "open+negotiate stream failed\n");
        speer_libp2p_tcp_session_close(&session);
        WIPE(keys.static_priv, sizeof(keys.static_priv));
        WIPE(keys.ed_seed, sizeof(keys.ed_seed));
        return 1;
    }

    static const uint8_t payload[] = "echo-check";
    if (speer_yamux_stream_write(&session.mux, st, payload, sizeof(payload) - 1) != 0) {
        fprintf(stderr, "yamux write failed\n");
        speer_libp2p_tcp_session_close(&session);
        WIPE(keys.static_priv, sizeof(keys.static_priv));
        WIPE(keys.ed_seed, sizeof(keys.ed_seed));
        return 1;
    }

    int ok = 0;
    for (int i = 0; i < 5000 && !ok; i++) {
        if (speer_yamux_pump(&session.mux) != 0) break;
        if (st->recv_buf_len >= sizeof(payload) - 1 &&
            memcmp(st->recv_buf, payload, sizeof(payload) - 1) == 0)
            ok = 1;
    }

    speer_libp2p_tcp_session_close(&session);
    WIPE(keys.static_priv, sizeof(keys.static_priv));
    WIPE(keys.ed_seed, sizeof(keys.ed_seed));

    if (!ok) {
        fprintf(stderr, "did not receive echo (start listener first?)\n");
        return 1;
    }
    printf("yamux echo: ok (got %zu bytes)\n", sizeof(payload) - 1);
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

    key_material_t keys;
    speer_libp2p_identity_t id;
    make_identity(&keys, &id);

    speer_libp2p_tcp_session_t session;
    if (speer_libp2p_tcp_session_init_listener(&session, fd, &id) != 0) {
        fprintf(stderr, "libp2p session bootstrap (listener) failed\n");
        WIPE(keys.static_priv, sizeof(keys.static_priv));
        WIPE(keys.ed_seed, sizeof(keys.ed_seed));
        speer_tcp_close(fd);
        return 1;
    }
    printf("session ready with peer %s\n", session.remote_peer_id_b58);

    speer_yamux_stream_t *stream = NULL;
    const char *protos[] = {"/echo/1.0.0"};
    if (speer_libp2p_tcp_accept_protocol_stream(&session, protos, 1, NULL, &stream, 5000, 25) !=
        0) {
        fprintf(stderr, "accept+negotiate stream failed\n");
        speer_libp2p_tcp_session_close(&session);
        WIPE(keys.static_priv, sizeof(keys.static_priv));
        WIPE(keys.ed_seed, sizeof(keys.ed_seed));
        return 1;
    }

    for (int i = 0; i < 8000; i++) {
        if (speer_yamux_pump(&session.mux) != 0) break;
        if (echo_streams(&session.mux) != 0) break;
    }

    speer_libp2p_tcp_session_close(&session);
    WIPE(keys.static_priv, sizeof(keys.static_priv));
    WIPE(keys.ed_seed, sizeof(keys.ed_seed));
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
