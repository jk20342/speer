#include "speer_internal.h"
#include "multiaddr.h"
#include "peer_id.h"
#include <stdio.h>
#include <string.h>

#define FAIL(...) do { fprintf(stderr, __VA_ARGS__); return 1; } while (0)

int main(void) {
    speer_multiaddr_t ma;

    if (speer_multiaddr_parse(&ma, "/ip4/192.168.0.42/tcp/4001") != 0) FAIL("multiaddr parse ip4/tcp\n");

    char host[64];
    uint16_t port = 0;
    if (speer_multiaddr_to_host_port_v4(&ma, host, sizeof(host), &port) != 0 ||
        port != 4001 || strcmp(host, "192.168.0.42") != 0)
        FAIL("to_host_port_v4\n");

    char s[256];
    if (speer_multiaddr_to_string(&ma, s, sizeof(s)) != 0 || strcmp(s, "/ip4/192.168.0.42/tcp/4001") != 0)
        FAIL("multiaddr_to_string\n");

    speer_multiaddr_t mq;
    if (speer_multiaddr_parse(&mq, "/ip4/127.0.0.1/udp/443/quic-v1") != 0) FAIL("parse quic-v1\n");
    if (speer_multiaddr_to_host_port_v4(&mq, host, sizeof(host), &port) != 0 || port != 443)
        FAIL("udp host port\n");

    speer_multiaddr_t mc;
    if (speer_multiaddr_parse(&mc, "/ip4/10.0.0.1/tcp/1/p2p-circuit/p2p/QmAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") != 0)
        FAIL("parse circuit+p2p\n");
    const uint8_t* pid = NULL;
    size_t pid_len = 0;
    if (speer_multiaddr_get_p2p_id(&mc, &pid, &pid_len) != 0 || pid_len == 0 ||
        memcmp(pid, "QmAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", pid_len) != 0)
        FAIL("get_p2p_id\n");

    if (speer_multiaddr_parse(&ma, "/ip4/bad") == 0) FAIL("reject bad ip\n");
    if (speer_multiaddr_parse(&ma, "/ip4/") == 0) FAIL("reject incomplete ip4\n");
    if (speer_multiaddr_parse(&ma, "/nope/1") == 0) FAIL("reject unknown protocol\n");

    uint8_t ed[32];
    for (size_t i = 0; i < sizeof(ed); i++) ed[i] = (uint8_t)(i + 1);

    uint8_t proto[128];
    size_t proto_len = 0;
    if (speer_libp2p_pubkey_proto_encode(proto, sizeof(proto), SPEER_LIBP2P_KEY_ED25519, ed, sizeof(ed),
                                          &proto_len) != 0)
        FAIL("pubkey_proto_encode\n");

    speer_libp2p_keytype_t kt = SPEER_LIBP2P_KEY_RSA;
    const uint8_t* key = NULL;
    size_t key_len = 0;
    if (speer_libp2p_pubkey_proto_decode(proto, proto_len, &kt, &key, &key_len) != 0 ||
        kt != SPEER_LIBP2P_KEY_ED25519 || key_len != sizeof(ed) || memcmp(key, ed, sizeof(ed)) != 0)
        FAIL("pubkey_proto_decode\n");

    if (speer_libp2p_pubkey_proto_decode(proto, proto_len - 1, &kt, &key, &key_len) == 0)
        FAIL("decode should fail truncated\n");

    uint8_t peerid[64];
    size_t peerid_len = 0;
    if (speer_peer_id_from_pubkey_bytes(peerid, sizeof(peerid), proto, proto_len, &peerid_len) != 0 ||
        peerid_len == 0 || peerid_len > SPEER_PEERID_MAX_BYTES)
        FAIL("peer_id_from_pubkey\n");

    char b58[128];
    if (speer_peer_id_to_b58(b58, sizeof(b58), peerid, peerid_len) != 0 || strlen(b58) < 8)
        FAIL("peer_id_to_b58\n");

    if (speer_peer_id_to_b58(b58, sizeof(b58), peerid, 0) == 0) FAIL("b58 reject empty\n");

    puts("multiaddr_peer_id: ok");
    return 0;
}
