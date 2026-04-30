#include "dht.h"
#include <stdio.h>
#include <string.h>

#define FAIL(...) do { fprintf(stderr, __VA_ARGS__); return 1; } while (0)

int main(void) {
    dht_t dht;
    uint8_t node_id[DHT_ID_BYTES] = {0x01, 0x02, 0x03, 0x04};

    if (dht_init(&dht, node_id) != 0) FAIL("dht_init failed\n");
    if (dht.total_nodes != 0) FAIL("dht should start empty\n");

    uint8_t peer_id[DHT_ID_BYTES];
    for (int i = 0; i < DHT_ID_BYTES; i++) peer_id[i] = 0xFF - i;
    if (dht_add_node(&dht, peer_id, "192.168.1.1:4001") != 0) FAIL("dht_add_node failed\n");
    if (dht.total_nodes != 1) FAIL("dht should have 1 node\n");

    if (dht_add_node(&dht, node_id, "127.0.0.1:4001") == 0) FAIL("should not add self\n");

    dht_node_t nodes[DHT_K];
    int count = dht_get_closest_nodes(&dht, peer_id, nodes, DHT_K);
    if (count != 1) FAIL("should find 1 closest node\n");
    if (memcmp(nodes[0].id, peer_id, DHT_ID_BYTES) != 0) FAIL("closest node mismatch\n");

    uint8_t target[DHT_ID_BYTES] = {0xAA, 0xBB, 0xCC, 0xDD};
    for (int i = 4; i < DHT_ID_BYTES; i++) target[i] = i;
    for (int i = 0; i < DHT_K + 5; i++) {
        uint8_t id[DHT_ID_BYTES];
        memcpy(id, target, DHT_ID_BYTES);
        id[0] ^= (i * 17);
        char addr[64];
        snprintf(addr, sizeof(addr), "192.168.1.%d:4001", i + 2);
        dht_add_node(&dht, id, addr);
    }
    if (dht.total_nodes < DHT_K) FAIL("should have at least K nodes\n");

    count = dht_get_closest_nodes(&dht, target, nodes, DHT_K);
    if (count != DHT_K) FAIL("should return K closest nodes\n");
    for (int i = 0; i < count - 1; i++) {
        uint8_t d1[DHT_ID_BYTES], d2[DHT_ID_BYTES];
        dht_distance(nodes[i].id, target, d1);
        dht_distance(nodes[i + 1].id, target, d2);
        int cmp = dht_distance_cmp(nodes[i].id, nodes[i + 1].id, target);
        if (cmp > 0) FAIL("nodes not sorted by distance\n");
    }

    uint8_t dist_a[DHT_ID_BYTES] = {0x00, 0x00, 0x00, 0x01};
    uint8_t dist_b[DHT_ID_BYTES] = {0x00, 0x00, 0x00, 0x02};
    if (dht_distance_cmp(dist_a, dist_b, target) >= 0) FAIL("distance comparison wrong\n");

    uint8_t result[DHT_ID_BYTES];
    dht_distance(target, target, result);
    for (int i = 0; i < DHT_ID_BYTES; i++) {
        if (result[i] != 0) FAIL("distance to self should be zero\n");
    }

    uint8_t key[DHT_ID_BYTES] = {0x11, 0x22, 0x33, 0x44};
    uint8_t value[] = "test value data";
    if (dht_handle_store(&dht, key, value, sizeof(value), node_id) != 0)
        FAIL("dht_handle_store failed\n");

    uint8_t response[2048];
    size_t response_len = sizeof(response);
    dht_value_t found;
    int ret = dht_handle_find_value(&dht, key, response, &response_len, &found);
    if (ret != 1) FAIL("should find stored value\n");
    if (found.value_len != sizeof(value)) FAIL("value length mismatch\n");
    if (memcmp(found.value, value, sizeof(value)) != 0) FAIL("value data mismatch\n");

    uint8_t missing_key[DHT_ID_BYTES] = {0x99, 0x88, 0x77, 0x66};
    response_len = sizeof(response);
    ret = dht_handle_find_value(&dht, missing_key, response, &response_len, &found);
    if (ret != 0) FAIL("should return nodes for missing key\n");

    dht_free(&dht);
    if (dht.root != NULL) FAIL("dht_free should clear root\n");

    puts("dht: ok");
    return 0;
}
