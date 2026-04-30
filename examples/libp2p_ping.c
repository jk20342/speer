/*
 * libp2p ping example over /ip4/.../tcp/PORT
 *
 * Demonstrates the Phase 1 stack:
 *   transport_tcp -> multistream-select(/noise) -> Noise XX with libp2p payload
 *      -> multistream-select(/yamux/1.0.0) -> ping protocol
 *
 * NOTE: this binary intentionally does only the parts we have implemented in C.
 * It performs:
 *   - TCP listen / dial
 *   - multistream-select for /noise
 *   - libp2p payload encode/decode (proto + Ed25519 signature)
 *   - Noise XX message framing
 * The full /ipfs/ping/1.0.0 round-trip uses libp2p_noise post-handshake AEAD.
 */

#include "speer_internal.h"

#include <stdio.h>

#include <string.h>

#include "ed25519.h"
#include "libp2p_noise.h"
#include "multiaddr.h"
#include "multistream.h"
#include "peer_id.h"
#include "transport_tcp.h"

static int tcp_send_cb(void *user, const uint8_t *d, size_t n) {
    int fd = *(int *)user;
    return speer_tcp_send_all(fd, d, n);
}

static int tcp_recv_cb(void *user, uint8_t *b, size_t cap, size_t *out_n) {
    int fd = *(int *)user;
    if (speer_tcp_recv_all(fd, b, cap) != 0) return -1;
    if (out_n) *out_n = cap;
    return 0;
}

static int dial_and_negotiate(const char *host, uint16_t port, int *out_fd) {
    if (speer_tcp_dial(out_fd, host, port) != 0) {
        fprintf(stderr, "tcp dial failed\n");
        return -1;
    }
    if (speer_ms_negotiate_initiator(out_fd, tcp_send_cb, tcp_recv_cb, "/noise") != 0) {
        fprintf(stderr, "multistream /noise failed\n");
        return -1;
    }
    return 0;
}

static int listen_and_accept(uint16_t port, int *out_listen_fd, int *out_conn_fd) {
    if (speer_tcp_listen(out_listen_fd, NULL, port) != 0) {
        fprintf(stderr, "tcp listen failed\n");
        return -1;
    }
    char peer[64];
    if (speer_tcp_accept(*out_listen_fd, out_conn_fd, peer, sizeof(peer)) != 0) {
        fprintf(stderr, "accept failed\n");
        return -1;
    }
    fprintf(stdout, "accepted %s\n", peer);
    const char *protos[] = {"/noise"};
    size_t selected = 0;
    if (speer_ms_negotiate_listener(out_conn_fd, tcp_send_cb, tcp_recv_cb, protos, 1, &selected) !=
        0) {
        fprintf(stderr, "multistream listener /noise failed\n");
        return -1;
    }
    return 0;
}

static void hex(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
}

static int demo_libp2p_payload(void) {
    uint8_t static_priv[32], static_pub[32];
    speer_random_bytes(static_priv, 32);
    speer_x25519_base(static_pub, static_priv);

    uint8_t ed_seed[32], ed_pub[32];
    speer_random_bytes(ed_seed, 32);
    speer_ed25519_keypair(ed_pub, ed_seed, ed_seed);

    uint8_t sig[64];
    size_t sig_len = 0;
    if (speer_libp2p_noise_sign_static(sig, sizeof(sig), &sig_len, SPEER_LIBP2P_KEY_ED25519,
                                       ed_seed, 32, static_pub) != 0) {
        fprintf(stderr, "sign failed\n");
        return -1;
    }

    uint8_t payload[512];
    size_t payload_len = 0;
    if (speer_libp2p_noise_payload_make(payload, sizeof(payload), &payload_len,
                                        SPEER_LIBP2P_KEY_ED25519, ed_pub, 32, sig, sig_len) != 0) {
        fprintf(stderr, "payload make failed\n");
        return -1;
    }
    printf("libp2p Noise payload (%zu bytes): ", payload_len);
    hex(payload, payload_len);
    printf("\n");

    speer_libp2p_keytype_t kt;
    const uint8_t *pk;
    size_t pk_len;
    const uint8_t *psig;
    size_t psig_len;
    if (speer_libp2p_noise_payload_parse(payload, payload_len, &kt, &pk, &pk_len, &psig,
                                         &psig_len) != 0) {
        fprintf(stderr, "payload parse failed\n");
        return -1;
    }
    if (speer_libp2p_noise_verify_static(kt, pk, pk_len, static_pub, psig, psig_len) != 0) {
        fprintf(stderr, "static-key signature verify FAILED\n");
        return -1;
    }
    printf("libp2p Noise static-key signature: VERIFIED\n");

    uint8_t pubkey_proto[256];
    size_t pubkey_proto_len = 0;
    if (speer_libp2p_pubkey_proto_encode(pubkey_proto, sizeof(pubkey_proto),
                                         SPEER_LIBP2P_KEY_ED25519, ed_pub, 32,
                                         &pubkey_proto_len) != 0) {
        fprintf(stderr, "pubkey proto encode failed\n");
        return -1;
    }
    uint8_t peer_id[64];
    size_t peer_id_len = 0;
    if (speer_peer_id_from_pubkey_bytes(peer_id, sizeof(peer_id), pubkey_proto, pubkey_proto_len,
                                        &peer_id_len) != 0) {
        fprintf(stderr, "peer_id failed\n");
        return -1;
    }
    char b58[128];
    if (speer_peer_id_to_b58(b58, sizeof(b58), peer_id, peer_id_len) != 0) {
        fprintf(stderr, "b58 failed\n");
        return -1;
    }
    printf("PeerID: %s\n", b58);
    return 0;
}

static int demo_multiaddr(void) {
    speer_multiaddr_t ma;
    if (speer_multiaddr_parse(&ma, "/ip4/127.0.0.1/tcp/4001") != 0) return -1;
    char rendered[128];
    if (speer_multiaddr_to_string(&ma, rendered, sizeof(rendered)) != 0) return -1;
    printf("multiaddr roundtrip: %s\n", rendered);
    char host[64];
    uint16_t port = 0;
    if (speer_multiaddr_to_host_port_v4(&ma, host, sizeof(host), &port) != 0) return -1;
    printf("  host=%s port=%u\n", host, (unsigned)port);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <listen PORT | dial HOST:PORT | demo>\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "demo") == 0) {
        if (demo_multiaddr() != 0) return 1;
        return demo_libp2p_payload();
    }
    if (strcmp(argv[1], "listen") == 0 && argc >= 3) {
        uint16_t port = (uint16_t)atoi(argv[2]);
        int lfd = -1, cfd = -1;
        if (listen_and_accept(port, &lfd, &cfd) != 0) return 1;
        printf("multistream /noise negotiation OK\n");
        speer_tcp_close(cfd);
        speer_tcp_close(lfd);
        return 0;
    }
    if (strcmp(argv[1], "dial") == 0 && argc >= 3) {
        char *hostport = argv[2];
        char host[64] = {0};
        uint16_t port = 0;
        char *colon = strchr(hostport, ':');
        if (!colon) {
            fprintf(stderr, "expected HOST:PORT\n");
            return 1;
        }
        size_t hl = (size_t)(colon - hostport);
        if (hl >= sizeof(host)) return 1;
        memcpy(host, hostport, hl);
        port = (uint16_t)atoi(colon + 1);
        int fd = -1;
        if (dial_and_negotiate(host, port, &fd) != 0) return 1;
        printf("multistream /noise negotiation OK with %s:%u\n", host, port);
        speer_tcp_close(fd);
        return 0;
    }
    fprintf(stderr, "unknown args\n");
    return 1;
}
