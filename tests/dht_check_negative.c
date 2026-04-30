#include "speer_internal.h"

#include <stdio.h>

#include <string.h>

#include "dht.h"

#define FAIL(...)                     \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        return 1;                     \
    } while (0)

int main(void) {
    dht_t dht;
    uint8_t my_id[DHT_ID_BYTES] = {0};
    if (dht_init(&dht, my_id) != 0) FAIL("dht_init\n");

    uint8_t key[DHT_ID_BYTES] = {1};
    uint8_t pub[DHT_ID_BYTES] = {2};
    uint8_t value[DHT_VALUE_MAX_SIZE + 16];
    memset(value, 0xab, sizeof(value));

    if (dht_handle_store(&dht, key, value, sizeof(value), pub) == 0)
        FAIL("store accepted oversized value\n");
    if (dht_handle_store(&dht, key, value, 0, pub) == 0) FAIL("store accepted zero-length\n");

    uint8_t token[16];
    if (dht_compute_store_token(&dht, "1.2.3.4:5", token) != 0) FAIL("compute_token failed\n");
    if (dht_handle_store_with_token(&dht, "1.2.3.4:5", token, key, value, 16, pub) != 0)
        FAIL("store_with_token rejected good token\n");
    token[0] ^= 1;
    if (dht_handle_store_with_token(&dht, "1.2.3.4:5", token, key, value, 16, pub) == 0)
        FAIL("store_with_token accepted bad token\n");

    if (dht_compute_store_token(&dht, "1.2.3.4:5", token) != 0) FAIL("compute_token2 failed\n");
    if (dht_handle_store_with_token(&dht, "9.8.7.6:5", token, key, value, 16, pub) == 0)
        FAIL("store_with_token cross-binding accepted\n");

    dht_free(&dht);
    puts("dht_check_negative: ok");
    return 0;
}
