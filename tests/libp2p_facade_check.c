#include <stdio.h>

#include <string.h>

#include "speer_libp2p_identify.h"
#include "speer_libp2p_kad.h"

#define FAIL(...)                     \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        return 1;                     \
    } while (0)

int main(void) {
    speer_libp2p_identify_info_t id = {0};
    memcpy(id.pubkey_proto, "pub", 3);
    id.pubkey_proto_len = 3;
    snprintf(id.protocols[0], sizeof(id.protocols[0]), "%s", SPEER_LIBP2P_KAD_PROTOCOL_STR);
    id.num_protocols = 1;
    snprintf(id.agent_version, sizeof(id.agent_version), "%s", "speer/0.1");
    snprintf(id.protocol_version, sizeof(id.protocol_version), "%s", "ipfs/0.1.0");

    uint8_t encoded[512];
    size_t encoded_len = sizeof(encoded);
    if (speer_libp2p_identify_encode(&id, encoded, sizeof(encoded), &encoded_len) != 0)
        FAIL("identify encode\n");

    speer_libp2p_identify_info_t decoded;
    if (speer_libp2p_identify_decode(&decoded, encoded, encoded_len) != 0)
        FAIL("identify decode\n");
    if (decoded.pubkey_proto_len != 3 || memcmp(decoded.pubkey_proto, "pub", 3) != 0)
        FAIL("identify pubkey mismatch\n");
    if (strcmp(decoded.protocols[0], SPEER_LIBP2P_KAD_PROTOCOL_STR) != 0)
        FAIL("identify protocol mismatch\n");

    uint8_t key[SPEER_LIBP2P_KAD_ID_BYTES] = {1};
    speer_libp2p_kad_msg_t msg = {
        .type = SPEER_LIBP2P_KAD_FIND_NODE,
        .key = key,
        .key_len = sizeof(key),
    };
    uint8_t msg_buf[512];
    size_t msg_len = sizeof(msg_buf);
    if (speer_libp2p_kad_encode_message(&msg, msg_buf, sizeof(msg_buf), &msg_len) != 0)
        FAIL("kad encode\n");

    speer_libp2p_kad_msg_t out;
    speer_libp2p_kad_peer_t peers[4];
    if (speer_libp2p_kad_decode_message(msg_buf, msg_len, &out, peers, 4) != 0)
        FAIL("kad decode\n");
    if (out.type != SPEER_LIBP2P_KAD_FIND_NODE || out.key_len != sizeof(key))
        FAIL("kad mismatch\n");

    puts("libp2p_facade: ok");
    return 0;
}
