#include <stdio.h>

#include "dht.h"

#define FAIL(...)                     \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        return 1;                     \
    } while (0)

int main(void) {
    dht_t dht;
    uint8_t self[DHT_ID_BYTES] = {1};
    uint8_t peer[DHT_ID_BYTES] = {2};
    if (dht_init(&dht, self) != 0) FAIL("init\n");
    if (dht_add_node(&dht, peer, "peer:1") != 0) FAIL("add\n");
    if (!dht.root || dht.root->node_count != 1) FAIL("root node\n");

    dht.root->nodes[0].last_seen_ms = 1;
    dht_refresh_buckets(&dht, DHT_REFRESH_INTERVAL_MS + 2);
    if (dht.total_nodes != 0) FAIL("stale node not removed\n");

    dht_free(&dht);
    puts("dht_maintenance: ok");
    return 0;
}
