#include <stdio.h>

#include <string.h>

#include "dht_libp2p.h"

#define FAIL(...)                     \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        return 1;                     \
    } while (0)

int main(void) {
    uint8_t key[DHT_ID_BYTES] = {1, 2, 3};
    uint8_t buf[512];
    size_t len = sizeof(buf);
    if (dht_libp2p_encode_query(DHT_LIBP2P_FIND_NODE, key, sizeof(key), buf, sizeof(buf), &len) !=
        0)
        FAIL("encode\n");

    uint8_t rpc;
    const uint8_t *got_key;
    size_t got_key_len;
    if (dht_libp2p_decode_query(buf, len, &rpc, &got_key, &got_key_len) != 0) FAIL("decode\n");
    if (rpc != DHT_RPC_FIND_NODE) FAIL("rpc map\n");
    if (got_key_len != sizeof(key) || memcmp(got_key, key, sizeof(key)) != 0) FAIL("key\n");

    len = sizeof(buf);
    if (dht_libp2p_encode_query(DHT_LIBP2P_GET_VALUE, key, sizeof(key), buf, sizeof(buf), &len) !=
        0)
        FAIL("encode value\n");
    if (dht_libp2p_decode_query(buf, len, &rpc, &got_key, &got_key_len) != 0)
        FAIL("decode value\n");
    if (rpc != DHT_RPC_FIND_VALUE) FAIL("value map\n");

    dht_libp2p_peer_t peer;
    memset(&peer, 0, sizeof(peer));
    peer.id[0] = 9;
    strcpy(peer.address, "peer:1");
    uint8_t value[] = {7, 8, 9};
    dht_libp2p_msg_t msg = {.type = DHT_LIBP2P_GET_VALUE,
                            .key = key,
                            .key_len = sizeof(key),
                            .value = value,
                            .value_len = sizeof(value),
                            .closer_peers = &peer,
                            .num_closer_peers = 1};
    len = sizeof(buf);
    if (dht_libp2p_encode_message(&msg, buf, sizeof(buf), &len) != 0) FAIL("msg encode\n");
    dht_libp2p_peer_t peers[2];
    dht_libp2p_msg_t got;
    if (dht_libp2p_decode_message(buf, len, &got, peers, 2) != 0) FAIL("msg decode\n");
    if (got.type != DHT_LIBP2P_GET_VALUE || got.value_len != sizeof(value) ||
        memcmp(got.value, value, sizeof(value)) != 0)
        FAIL("value roundtrip\n");
    if (got.num_closer_peers != 1 || peers[0].id[0] != 9 || strcmp(peers[0].address, "peer:1") != 0)
        FAIL("peer roundtrip\n");

    uint8_t frame[600];
    size_t frame_len;
    if (dht_libp2p_frame(buf, len, frame, sizeof(frame), &frame_len) != 0) FAIL("frame\n");
    const uint8_t *framed_msg;
    size_t framed_len, used;
    if (dht_libp2p_unframe(frame, frame_len, &framed_msg, &framed_len, &used) != 0)
        FAIL("unframe\n");
    if (used != frame_len || framed_len != len || memcmp(framed_msg, buf, len) != 0)
        FAIL("frame roundtrip\n");

    puts("dht_libp2p: ok");
    return 0;
}
