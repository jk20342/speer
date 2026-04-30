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
    uint8_t buf[128];
    size_t len = sizeof(buf);
    if (dht_libp2p_encode_query(DHT_LIBP2P_FIND_NODE, key, sizeof(key), buf, sizeof(buf), &len) != 0)
        FAIL("encode\n");

    uint8_t rpc;
    const uint8_t *got_key;
    size_t got_key_len;
    if (dht_libp2p_decode_query(buf, len, &rpc, &got_key, &got_key_len) != 0) FAIL("decode\n");
    if (rpc != DHT_RPC_FIND_NODE) FAIL("rpc map\n");
    if (got_key_len != sizeof(key) || memcmp(got_key, key, sizeof(key)) != 0) FAIL("key\n");

    len = sizeof(buf);
    if (dht_libp2p_encode_query(DHT_LIBP2P_GET_VALUE, key, sizeof(key), buf, sizeof(buf), &len) != 0)
        FAIL("encode value\n");
    if (dht_libp2p_decode_query(buf, len, &rpc, &got_key, &got_key_len) != 0) FAIL("decode value\n");
    if (rpc != DHT_RPC_FIND_VALUE) FAIL("value map\n");

    puts("dht_libp2p: ok");
    return 0;
}
