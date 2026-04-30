#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "speer.h"
#include "relay_client.h"

static volatile int running = 1;

static void on_signal(int sig) {
    (void)sig;
    running = 0;
}

static void on_event(speer_host_t* host, const speer_event_t* ev, void* user) {
    (void)host;
    (void)user;

    switch (ev->type) {
        case SPEER_EVENT_PEER_CONNECTED:
            printf("[+] Peer connected via relay\n");
            break;
        case SPEER_EVENT_PEER_DISCONNECTED:
            printf("[-] Peer disconnected\n");
            break;
        case SPEER_EVENT_STREAM_DATA:
            printf("[<] Received %zu bytes\n", ev->len);
            break;
        default:
            break;
    }
    fflush(stdout);
}

static int hex_to_bytes(const char* hex, uint8_t* out, size_t out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int b;
        if (sscanf(hex + 2*i, "%2x", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        printf("Usage: %s <relay_addr> <target_pubkey>\n", argv[0]);
        printf("\nExample:\n");
        printf("  %s 192.168.1.1:4001 abc123...\n", argv[0]);
        printf("\nThe relay must support libp2p Circuit Relay v2.\n");
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    uint8_t target_key[32];
    if (hex_to_bytes(argv[2], target_key, 32) != 0) {
        fprintf(stderr, "Invalid target public key (expected 64 hex chars)\n");
        return 1;
    }

    printf("Connecting to relay at %s...\n", argv[1]);

    uint8_t seed[32] = {0};
    speer_random_bytes(seed, 32);

    speer_config_t cfg;
    speer_config_default(&cfg);
    cfg.relay_server = argv[1];

    speer_host_t* host = speer_host_new(seed, &cfg);
    if (!host) {
        fprintf(stderr, "Failed to create host\n");
        return 1;
    }

    printf("Host created, port=%d\n", speer_host_get_port(host));
    printf("Public key: ");
    const uint8_t* pk = speer_host_get_public_key(host);
    for (int i = 0; i < 32; i++) printf("%02x", pk[i]);
    printf("\n");

    printf("Connecting to target through relay...\n");
    speer_peer_t* peer = speer_connect(host, target_key, NULL);
    if (!peer) {
        fprintf(stderr, "Failed to initiate connection\n");
        speer_host_free(host);
        return 1;
    }

    speer_host_set_callback(host, on_event, NULL);

    int connected = 0;
    for (int i = 0; i < 100 && !connected && running; i++) {
        speer_host_poll(host, 100);
        if (speer_peer_is_connected(peer)) {
            connected = 1;
            printf("Connected through relay!\n");
        }
    }

    if (!connected) {
        printf("Connection timeout\n");
        speer_host_free(host);
        return 1;
    }

    speer_stream_t* stream = speer_stream_open(peer, 1);
    if (!stream) {
        fprintf(stderr, "Failed to open stream\n");
        speer_host_free(host);
        return 1;
    }

    printf("Stream opened. Type messages (Ctrl+C to exit):\n");
    fflush(stdout);

    char line[1024];
    while (running && fgets(line, sizeof(line), stdin)) {
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') line[--len] = '\0';

        if (len > 0) {
            printf("[>] Sending %zu bytes\n", len);
            speer_stream_write(stream, (uint8_t*)line, len);
        }

        speer_host_poll(host, 10);
    }

    printf("\nClosing...\n");
    speer_stream_close(stream);
    speer_host_free(host);

    return 0;
}
