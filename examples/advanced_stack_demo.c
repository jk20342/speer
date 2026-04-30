/*
 * Runnable walkthrough of speer's higher-level building blocks:
 *   - Layer 1: Noise-based host (UDP) identity and poll
 *   - libp2p: multiaddr, PeerID (base58), Ed25519 signing for Noise static key
 *   - Layer 2 (optional argv): TCP dial + multistream-select /noise probe
 *   - Relay + DCUtR (when built with SPEER_RELAY): client init and event-loop notes
 *
 * Usage:
 *   advanced_stack_demo              -> identity + multiaddr + relay notes
 *   advanced_stack_demo tcp HOST PORT -> TCP multistream /noise (like libp2p_ping dial)
 */

#include "speer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ed25519.h"
#include "libp2p_noise.h"
#include "multiaddr.h"
#include "multistream.h"
#include "peer_id.h"
#include "transport_tcp.h"

#if SPEER_RELAY
#include "dcutr.h"
#include "relay_client.h"
#endif

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

static int demo_tcp_noise_dial(const char *host, uint16_t port) {
    int fd = -1;
    if (speer_tcp_dial(&fd, host, port) != 0) {
        fprintf(stderr, "TCP dial %s:%u failed (is a libp2p listener there?)\n", host, (unsigned)port);
        return 1;
    }
    if (speer_ms_negotiate_initiator(&fd, tcp_send_cb, tcp_recv_cb, "/noise") != 0) {
        fprintf(stderr, "multistream /noise negotiation failed\n");
        speer_tcp_close(fd);
        return 1;
    }
    printf("OK: TCP + multistream selected /noise to %s:%u\n", host, (unsigned)port);
    speer_tcp_close(fd);
    return 0;
}

static int demo_multiaddr_peerid(void) {
    speer_multiaddr_t ma;
    if (speer_multiaddr_parse(&ma, "/ip4/192.0.2.1/tcp/4001") != 0) return -1;
    char rendered[128];
    if (speer_multiaddr_to_string(&ma, rendered, sizeof(rendered)) != 0) return -1;
    printf("multiaddr example: %s\n", rendered);

    uint8_t ed_seed[32], ed_pub[32];
    speer_random_bytes(ed_seed, sizeof(ed_seed));
    speer_ed25519_keypair(ed_pub, ed_seed, ed_seed);

    uint8_t pubkey_proto[256];
    size_t pubkey_proto_len = 0;
    if (speer_libp2p_pubkey_proto_encode(pubkey_proto, sizeof(pubkey_proto), SPEER_LIBP2P_KEY_ED25519,
                                         ed_pub, 32, &pubkey_proto_len) != 0)
        return -1;

    uint8_t peer_id[64];
    size_t peer_id_len = 0;
    if (speer_peer_id_from_pubkey_bytes(peer_id, sizeof(peer_id), pubkey_proto, pubkey_proto_len,
                                         &peer_id_len) != 0)
        return -1;
    char b58[128];
    if (speer_peer_id_to_b58(b58, sizeof(b58), peer_id, peer_id_len) != 0) return -1;
    printf("sample PeerID (Ed25519): %s\n", b58);
    return 0;
}

#if SPEER_RELAY
static void demo_relay_client_structure(void) {
    relay_client_t relay;
    relay_client_init(&relay);
    printf("\nRelay client (Circuit v2) — typical order:\n");
    printf("  1) relay_client_connect()  TCP to relay\n");
    printf("  2) relay_client_reserve()  HOP reserve\n");
    printf("  3) relay_client_poll()     until RELAY_STATE_RESERVED\n");
    printf("  4) relay_client_connect_to_peer(target_peer_id)  open circuit\n");
    printf("  5) relay_client_poll()     until circuit CONNECTED; send app data via relay_client_send()\n");
    printf("  6) relay_client_start_dcutr(circuit_id, speer_peer, initiator)\n");
    printf("     Each loop: relay_client_poll(), speer_dcutr_poll(), speer_host_poll()\n");
    printf("     DCUtR frames on the circuit are dispatched from relay_client_poll via speer_dcutr_on_msg.\n");
    relay_client_free(&relay);
}
#endif

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "tcp") == 0) {
        if (argc < 4) {
            fprintf(stderr, "usage: %s tcp HOST PORT\n", argv[0]);
            return 1;
        }
        uint16_t port = (uint16_t)atoi(argv[3]);
        return demo_tcp_noise_dial(argv[2], port);
    }

    printf("=== speer advanced stack demo ===\n\n");

    uint8_t seed[32];
    speer_random_bytes(seed, sizeof(seed));
    speer_config_t cfg;
    speer_config_default(&cfg);
    cfg.bind_port = 0;

    speer_host_t *host = speer_host_new(seed, &cfg);
    if (!host) {
        fprintf(stderr, "speer_host_new failed\n");
        return 1;
    }

    printf("Layer-1 host bound port: %d\n", speer_host_get_port(host));
    printf("Ed25519 public key: ");
    const uint8_t *pk = speer_host_get_public_key(host);
    for (int i = 0; i < SPEER_PUBLIC_KEY_SIZE; i++) printf("%02x", pk[i]);
    printf("\n");

    speer_host_poll(host, 1);

    if (demo_multiaddr_peerid() != 0) fprintf(stderr, "(multiaddr/peers demo failed)\n");

#if SPEER_RELAY
    demo_relay_client_structure();
#else
    printf("\n(Rebuild with SPEER_ENABLE_RELAY for relay + DCUtR API notes.)\n");
#endif

    printf("\nTry: %s tcp 127.0.0.1 4001  (against a libp2p-style /noise TCP listener)\n", argv[0]);

    speer_host_free(host);
    return 0;
}
