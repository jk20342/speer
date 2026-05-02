#include "speer_internal.h"

#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include "ed25519.h"
#include "speer_libp2p_kad.h"
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

static int run_ping(const char *host, uint16_t port) {
    int fd = -1;
    if (speer_tcp_dial(&fd, host, port) != 0) {
        fprintf(stderr, "tcp dial failed for %s:%u\n", host, (unsigned)port);
        return 1;
    }
    (void)speer_tcp_set_io_timeout(fd, 10000);

    key_material_t keys;
    speer_libp2p_identity_t id;
    make_identity(&keys, &id);

    speer_libp2p_tcp_session_t session;
    if (speer_libp2p_tcp_session_init_dialer(&session, fd, &id) != 0) {
        fprintf(stderr, "libp2p tcp/noise/yamux session failed\n");
        WIPE(keys.static_priv, sizeof(keys.static_priv));
        WIPE(keys.ed_seed, sizeof(keys.ed_seed));
        speer_tcp_close(fd);
        return 1;
    }
    printf("session ready with peer %s\n", session.remote_peer_id_b58);

    speer_libp2p_kad_msg_t ping = {.type = SPEER_LIBP2P_KAD_PING};
    uint8_t request[128];
    size_t request_len = sizeof(request);
    if (speer_libp2p_kad_encode_message(&ping, request, sizeof(request), &request_len) != 0) {
        fprintf(stderr, "kad ping encode failed\n");
        speer_libp2p_tcp_session_close(&session);
        WIPE(keys.static_priv, sizeof(keys.static_priv));
        WIPE(keys.ed_seed, sizeof(keys.ed_seed));
        return 1;
    }

    uint8_t response[4096];
    size_t response_len = sizeof(response);
    int rc = speer_libp2p_kad_stream_roundtrip(&session, request, request_len, response,
                                               &response_len);
    speer_libp2p_tcp_session_close(&session);
    WIPE(keys.static_priv, sizeof(keys.static_priv));
    WIPE(keys.ed_seed, sizeof(keys.ed_seed));
    if (rc != 0) {
        fprintf(stderr, "kad /ipfs/kad/1.0.0 roundtrip failed\n");
        return 1;
    }

    speer_libp2p_kad_msg_t out;
    speer_libp2p_kad_peer_t peers[SPEER_LIBP2P_KAD_MAX_PEERS];
    if (speer_libp2p_kad_decode_message(response, response_len, &out, peers,
                                        SPEER_LIBP2P_KAD_MAX_PEERS) != 0) {
        fprintf(stderr, "kad response decode failed (%zu bytes)\n", response_len);
        return 1;
    }
    printf("kad response type=%u peers=%zu value_len=%zu\n", (unsigned)out.type,
           out.num_closer_peers, out.value_len);
    return out.type == SPEER_LIBP2P_KAD_PING ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s HOST PORT\n", argv[0]);
        return 1;
    }
    return run_ping(argv[1], (uint16_t)atoi(argv[2]));
}
