#include "speer_internal.h"

#include <stdio.h>

#include <string.h>

#include "dht.h"

#define FAIL(...)                     \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        return 1;                     \
    } while (0)

typedef struct {
    dht_t *remote;
    uint8_t remote_id[DHT_ID_BYTES];
    uint8_t value_key[DHT_ID_BYTES];
    uint8_t value[32];
    size_t value_len;
} mock_net_t;

static int mock_rpc(void *user, const char *addr, uint8_t op, const uint8_t *request,
                    size_t request_len, uint8_t *response, size_t *response_len) {
    mock_net_t *m = (mock_net_t *)user;
    if (strcmp(addr, "remote:1") != 0) return -1;
    if (op == DHT_RPC_PING) {
        if (*response_len < DHT_ID_BYTES) return -1;
        COPY(response, m->remote_id, DHT_ID_BYTES);
        *response_len = DHT_ID_BYTES;
        return 0;
    }
    if (op == DHT_RPC_FIND_NODE) {
        if (request_len != DHT_ID_BYTES) return -1;
        return dht_handle_find_node(m->remote, request, response, response_len);
    }
    if (op == DHT_RPC_FIND_VALUE) {
        dht_value_t unused;
        if (request_len != DHT_ID_BYTES) return -1;
        return dht_handle_find_value(m->remote, request, response, response_len, &unused) >= 0 ? 0
                                                                                               : -1;
    }
    return -1;
}

int main(void) {
    uint8_t local_id[DHT_ID_BYTES] = {1};
    uint8_t remote_id[DHT_ID_BYTES] = {2};
    uint8_t target[DHT_ID_BYTES] = {3};
    uint8_t key[DHT_ID_BYTES] = {4};
    uint8_t value[] = "remote value";

    dht_t local;
    dht_t remote;
    if (dht_init(&local, local_id) != 0) FAIL("local init\n");
    if (dht_init(&remote, remote_id) != 0) FAIL("remote init\n");

    uint8_t closer[DHT_ID_BYTES] = {3, 1};
    dht_add_node(&remote, closer, "closer:1");
    dht_handle_store(&remote, key, value, sizeof(value), remote_id);

    mock_net_t net;
    ZERO(&net, sizeof(net));
    net.remote = &remote;
    COPY(net.remote_id, remote_id, DHT_ID_BYTES);
    local.send_rpc = mock_rpc;
    local.user = &net;

    dht_bootstrap_list_t bootstrap;
    dht_bootstrap_init(&bootstrap);
    dht_bootstrap_add(&bootstrap, "remote:1");
    if (dht_bootstrap_run(&local, &bootstrap, 123) != 0) FAIL("bootstrap\n");
    if (!dht_is_bootstrapped(&local) || local.total_nodes != 1) FAIL("bootstrap state\n");

    dht_node_t nodes[DHT_K];
    int n = dht_iterative_find_node(&local, target, nodes, DHT_K);
    if (n < 1) FAIL("iterative find node\n");

    uint8_t got[64];
    size_t got_len = sizeof(got);
    if (dht_iterative_find_value(&local, key, got, &got_len) != 0) FAIL("iterative find value\n");
    if (got_len != sizeof(value) || memcmp(got, value, sizeof(value)) != 0)
        FAIL("value mismatch\n");

    dht_free(&remote);
    dht_free(&local);
    puts("dht_iterative: ok");
    return 0;
}
