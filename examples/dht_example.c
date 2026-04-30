#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "speer.h"
#include "dht.h"

#define BOOTSTRAP_NODES 3

static const char* bootstrap_addrs[BOOTSTRAP_NODES] = {
    "router.bittorrent.com:6881",
    "router.utorrent.com:6881",
    "dht.transmissionbt.com:6881",
};

static volatile int running = 1;

static void on_signal(int sig) {
    (void)sig;
    running = 0;
}

static void print_hex(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
}

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    uint8_t seed[32] = {0};
    speer_random_bytes(seed, 32);

    speer_config_t cfg;
    speer_config_default(&cfg);
    cfg.bind_port = 6881;

    speer_host_t* host = speer_host_new(seed, &cfg);
    if (!host) {
        fprintf(stderr, "Failed to create host\n");
        return 1;
    }

    printf("DHT node started\n");
    printf("Node ID: ");
    const uint8_t* pk = speer_host_get_public_key(host);
    print_hex(pk, 32);
    printf("\n");
    printf("Port: %d\n", speer_host_get_port(host));
    printf("Bootstrap nodes: %d\n", BOOTSTRAP_NODES);
    for (int i = 0; i < BOOTSTRAP_NODES; i++) {
        printf("  - %s\n", bootstrap_addrs[i]);
    }
    printf("\nPress Ctrl+C to exit\n\n");
    fflush(stdout);

    while (running) {
        speer_host_poll(host, 100);
    }

    printf("\nShutting down...\n");
    speer_host_free(host);

    return 0;
}
