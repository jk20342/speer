#if SPEER_RELAY

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ed25519.h"
#include "relay_client.h"
#include "speer.h"
#include "speer_libp2p_tcp.h"
#include "transport_tcp.h"

#define SKIP_EXIT 77

#define DEFAULT_RELAY_HOST "104.131.131.82"
#define DEFAULT_RELAY_PORT 4001u
#define EXPECTED_BOOTSTRAP_PEER_B58 "QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ"

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

static const char *env_str(const char *k, const char *d) {
    const char *v = getenv(k);
    return (v && v[0]) ? v : d;
}

int main(void) {
    const char *skip = getenv("SPEER_SKIP_NETWORK_TESTS");
    if (skip && skip[0] && (skip[0] == '1' || skip[0] == 'y' || skip[0] == 'Y')) {
        fprintf(stderr, "relay_public_hop_check: skipped (SPEER_SKIP_NETWORK_TESTS)\n");
        return SKIP_EXIT;
    }

    const char *host = env_str("SPEER_PUBLIC_RELAY_HOST", DEFAULT_RELAY_HOST);
    const char *port_s = getenv("SPEER_PUBLIC_RELAY_PORT");
    uint16_t port = DEFAULT_RELAY_PORT;
    if (port_s && port_s[0]) {
        unsigned long p = strtoul(port_s, NULL, 10);
        if (p > 0 && p < 65536) port = (uint16_t)p;
    }

    int fd = -1;
    if (speer_tcp_dial(&fd, host, port) != 0) {
        fprintf(stderr, "relay_public_hop_check: TCP dial %s:%u failed (offline or blocked?)\n",
                host, (unsigned)port);
        return 1;
    }

    key_material_t keys;
    speer_libp2p_identity_t lib_id;
    make_identity(&keys, &lib_id);

    speer_libp2p_tcp_session_t session;
    if (speer_libp2p_tcp_session_init_dialer(&session, fd, &lib_id) != 0) {
        fprintf(stderr, "relay_public_hop_check: libp2p session failed (need Noise peer)\n");
        memset(keys.static_priv, 0, sizeof(keys.static_priv));
        memset(keys.ed_seed, 0, sizeof(keys.ed_seed));
        speer_tcp_close(fd);
        return 1;
    }

    if (strcmp(session.remote_peer_id_b58, EXPECTED_BOOTSTRAP_PEER_B58) != 0) {
        fprintf(stderr,
                "relay_public_hop_check: peer %s (expected %s per bootstrap list; continuing)\n",
                session.remote_peer_id_b58, EXPECTED_BOOTSTRAP_PEER_B58);
    }

    speer_yamux_stream_t *hop = NULL;
    if (speer_libp2p_tcp_open_protocol_stream(&session, "/libp2p/circuit/relay/0.2.0/hop",
                                              &hop) != 0) {
        fprintf(stderr, "relay_public_hop_check: open hop stream failed\n");
        memset(keys.static_priv, 0, sizeof(keys.static_priv));
        memset(keys.ed_seed, 0, sizeof(keys.ed_seed));
        speer_libp2p_tcp_session_close(&session);
        return 1;
    }

    relay_client_t relay;
    relay_client_init(&relay);
    if (relay_client_attach_libp2p_hop(&relay, &session, hop) != 0) {
        fprintf(stderr, "relay_public_hop_check: attach hop failed\n");
        relay_client_free(&relay);
        memset(keys.static_priv, 0, sizeof(keys.static_priv));
        memset(keys.ed_seed, 0, sizeof(keys.ed_seed));
        speer_libp2p_tcp_session_close(&session);
        return 1;
    }

    if (relay_client_reserve(&relay) != 0) {
        fprintf(stderr, "relay_public_hop_check: reserve send failed\n");
        relay_client_free(&relay);
        memset(keys.static_priv, 0, sizeof(keys.static_priv));
        memset(keys.ed_seed, 0, sizeof(keys.ed_seed));
        speer_libp2p_tcp_session_close(&session);
        return 1;
    }

    int reserved = 0;
    uint64_t deadline = speer_timestamp_ms() + 60000u;
    while (speer_timestamp_ms() < deadline) {
        if (relay_client_poll(&relay, speer_timestamp_ms()) != 0) {
            fprintf(stderr, "relay_public_hop_check: poll / yamux error\n");
            break;
        }
        if (relay.state == RELAY_STATE_RESERVED) {
            reserved = 1;
            break;
        }
        if (relay.state == RELAY_STATE_ERROR) {
            fprintf(stderr, "relay_public_hop_check: relay ERROR after reserve\n");
            break;
        }
    }

    char peer_b58[64];
    strncpy(peer_b58, session.remote_peer_id_b58, sizeof(peer_b58) - 1);
    peer_b58[sizeof(peer_b58) - 1] = 0;

    relay_client_free(&relay);
    memset(keys.static_priv, 0, sizeof(keys.static_priv));
    memset(keys.ed_seed, 0, sizeof(keys.ed_seed));
    speer_libp2p_tcp_session_close(&session);

    if (!reserved) {
        fprintf(stderr,
                "relay_public_hop_check: did not reach RESERVED (timeout or hop rejected)\n");
        return 1;
    }

    printf("relay_public_hop_check: ok (reserved on %s, peer %s)\n", host, peer_b58);
    return 0;
}

#else

#include <stdio.h>

int main(void) {
    fprintf(stderr, "relay_public_hop_check: SPEER_RELAY disabled\n");
    return 0;
}

#endif
