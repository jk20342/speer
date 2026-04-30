#include "speer.h"

#include <stdio.h>
#include <stdlib.h>

#include <signal.h>
#include <string.h>

#include "dht.h"

#define BOOTSTRAP_NODES 3

static const char *bootstrap_addrs[BOOTSTRAP_NODES] = {
    "router.bittorrent.com:6881",
    "router.utorrent.com:6881",
    "dht.transmissionbt.com:6881",
};

static volatile int running = 1;
static dht_t g_dht;
static dht_bootstrap_list_t g_bootstrap;

static void on_signal(int sig) {
    (void)sig;
    running = 0;
}

static void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
}

static int send_rpc(void *user, const char *addr, const uint8_t *data, size_t len) {
    (void)user;
    (void)addr;
    (void)data;
    (void)len;
    return 0;
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    uint8_t seed[32] = {0};
    speer_random_bytes(seed, 32);

    uint8_t node_id[DHT_ID_BYTES];
    speer_generate_keypair(node_id, seed, seed);

    dht_init(&g_dht, node_id);
    g_dht.send_rpc = send_rpc;
    g_dht.user = NULL;

    dht_bootstrap_init(&g_bootstrap);
    for (int i = 0; i < BOOTSTRAP_NODES; i++) {
        dht_bootstrap_add(&g_bootstrap, bootstrap_addrs[i]);
    }

    speer_config_t cfg;
    speer_config_default(&cfg);
    cfg.bind_port = 6881;

    speer_host_t *host = speer_host_new(seed, &cfg);
    if (!host) {
        fprintf(stderr, "Failed to create host\n");
        return 1;
    }

    printf("DHT node started\n");
    printf("Node ID: ");
    const uint8_t *pk = speer_host_get_public_key(host);
    print_hex(pk, 32);
    printf("\n");
    printf("Port: %d\n", speer_host_get_port(host));
    printf("Bootstrap nodes: %d\n", BOOTSTRAP_NODES);
    for (int i = 0; i < BOOTSTRAP_NODES; i++) { printf("  - %s\n", bootstrap_addrs[i]); }
    printf("\n");

    uint64_t last_bootstrap = 0;

    while (running) {
        uint64_t now = speer_timestamp_ms();

        if (now - last_bootstrap > 30000) {
            int bootstrapped = dht_bootstrap_run(&g_dht, &g_bootstrap, now);
            if (bootstrapped > 0) { printf("Bootstrap: contacted %d nodes\n", bootstrapped); }
            if (dht_is_bootstrapped(&g_dht)) {
                printf("DHT bootstrapped, total nodes: %d\n", g_dht.total_nodes);
            }
            last_bootstrap = now;
        }

        speer_host_poll(host, 100);
    }

    printf("\nShutting down...\n");
    speer_host_free(host);
    dht_free(&g_dht);

    return 0;
}
