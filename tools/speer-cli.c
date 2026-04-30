#include "speer.h"

#include <stdio.h>
#include <stdlib.h>

#include <signal.h>
#include <string.h>

static volatile int running = 1;

static void on_signal(int sig) {
    (void)sig;
    running = 0;
}

static void print_event(const speer_event_t *ev) {
    switch (ev->type) {
    case SPEER_EVENT_PEER_CONNECTED:
        printf("[CONNECTED] peer=%p\n", (void *)ev->peer);
        break;
    case SPEER_EVENT_PEER_DISCONNECTED:
        printf("[DISCONNECTED] peer=%p reason=%d\n", (void *)ev->peer, ev->disconnect_reason);
        break;
    case SPEER_EVENT_STREAM_OPENED:
        printf("[STREAM_OPENED] peer=%p stream=%u\n", (void *)ev->peer, ev->stream_id);
        break;
    case SPEER_EVENT_STREAM_DATA:
        printf("[STREAM_DATA] peer=%p stream=%u len=%zu\n", (void *)ev->peer, ev->stream_id,
               ev->len);
        break;
    case SPEER_EVENT_STREAM_CLOSED:
        printf("[STREAM_CLOSED] peer=%p stream=%u\n", (void *)ev->peer, ev->stream_id);
        break;
    case SPEER_EVENT_ERROR:
        printf("[ERROR] peer=%p code=%d\n", (void *)ev->peer, ev->error_code);
        break;
    default:
        break;
    }
    fflush(stdout);
}

static void on_event(speer_host_t *host, const speer_event_t *ev, void *user) {
    (void)host;
    (void)user;
    print_event(ev);
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int b;
        if (sscanf(hex + 2 * i, "%2x", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    return 0;
}

static void print_usage(const char *prog) {
    printf("Usage: %s <command> [options]\n\n", prog);
    printf("Commands:\n");
    printf("  server [PORT]        Run echo server\n");
    printf("  connect PUBKEY ADDR  Connect to peer\n");
    printf("  ping PUBKEY ADDR     Send ping and measure RTT\n");
    printf("  info                 Show local host info\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s server 4242\n", prog);
    printf("  %s connect abc123... 192.168.1.100:4242\n", prog);
    printf("  %s ping abc123... 10.0.0.5:4242\n", prog);
}

static int cmd_server(int argc, char **argv) {
    uint16_t port = (argc > 2) ? (uint16_t)atoi(argv[2]) : 0;

    uint8_t seed[32] = {0};
    speer_random_bytes(seed, 32);

    speer_config_t cfg;
    speer_config_default(&cfg);
    cfg.bind_port = port;

    speer_host_t *host = speer_host_new(seed, &cfg);
    if (!host) {
        fprintf(stderr, "Failed to create host\n");
        return 1;
    }

    printf("Server running on port %d\n", speer_host_get_port(host));
    printf("Public key: ");
    const uint8_t *pk = speer_host_get_public_key(host);
    for (int i = 0; i < 32; i++) printf("%02x", pk[i]);
    printf("\n");
    fflush(stdout);

    speer_host_set_callback(host, on_event, NULL);

    while (running) { speer_host_poll(host, 100); }

    printf("\nShutting down...\n");
    speer_host_free(host);
    return 0;
}

static int cmd_connect(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: connect PUBKEY ADDR\n");
        return 1;
    }

    uint8_t peer_key[32];
    if (hex_to_bytes(argv[2], peer_key, 32) != 0) {
        fprintf(stderr, "Invalid public key (expected 64 hex chars)\n");
        return 1;
    }

    uint8_t seed[32] = {0};
    speer_random_bytes(seed, 32);

    speer_host_t *host = speer_host_new(seed, NULL);
    if (!host) {
        fprintf(stderr, "Failed to create host\n");
        return 1;
    }

    printf("Connecting to %s...\n", argv[3]);
    fflush(stdout);

    speer_peer_t *peer = speer_connect(host, peer_key, argv[3]);
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
            printf("Connected! Type messages (Ctrl+C to exit):\n");
        }
    }

    if (!connected) {
        fprintf(stderr, "Connection timeout\n");
        speer_host_free(host);
        return 1;
    }

    speer_stream_t *stream = speer_stream_open(peer, 1);
    if (!stream) {
        fprintf(stderr, "Failed to open stream\n");
        speer_host_free(host);
        return 1;
    }

    char line[1024];
    while (running && fgets(line, sizeof(line), stdin)) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') line[--len] = '\0';

        if (len > 0) { speer_stream_write(stream, (uint8_t *)line, len); }

        speer_host_poll(host, 10);
    }

    speer_stream_close(stream);
    speer_host_free(host);
    return 0;
}

static int cmd_ping(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: ping PUBKEY ADDR\n");
        return 1;
    }

    uint8_t peer_key[32];
    if (hex_to_bytes(argv[2], peer_key, 32) != 0) {
        fprintf(stderr, "Invalid public key\n");
        return 1;
    }

    uint8_t seed[32] = {0};
    speer_random_bytes(seed, 32);

    speer_host_t *host = speer_host_new(seed, NULL);
    if (!host) {
        fprintf(stderr, "Failed to create host\n");
        return 1;
    }

    uint64_t start = speer_timestamp_ms();
    speer_peer_t *peer = speer_connect(host, peer_key, argv[3]);

    if (!peer) {
        fprintf(stderr, "Failed to initiate connection\n");
        speer_host_free(host);
        return 1;
    }

    int connected = 0;
    for (int i = 0; i < 100 && !connected; i++) {
        speer_host_poll(host, 50);
        if (speer_peer_is_connected(peer)) connected = 1;
    }

    uint64_t rtt = speer_timestamp_ms() - start;

    if (connected) {
        printf("Connected to peer, RTT=%lums\n", (unsigned long)rtt);
    } else {
        printf("Connection timeout after %lums\n", (unsigned long)rtt);
    }

    speer_host_free(host);
    return connected ? 0 : 1;
}

static int cmd_info(void) {
    uint8_t seed[32] = {0};
    speer_random_bytes(seed, 32);

    speer_host_t *host = speer_host_new(seed, NULL);
    if (!host) {
        fprintf(stderr, "Failed to create host\n");
        return 1;
    }

    printf("speer version: %d.%d.%d\n", SPEER_VERSION_MAJOR, SPEER_VERSION_MINOR,
           SPEER_VERSION_PATCH);
    printf("Public key: ");
    const uint8_t *pk = speer_host_get_public_key(host);
    for (int i = 0; i < 32; i++) printf("%02x", pk[i]);
    printf("\n");
    printf("Port: %d\n", speer_host_get_port(host));

    speer_host_free(host);
    return 0;
}

int main(int argc, char **argv) {
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "server") == 0) { return cmd_server(argc, argv); }
    if (strcmp(cmd, "connect") == 0) { return cmd_connect(argc, argv); }
    if (strcmp(cmd, "ping") == 0) { return cmd_ping(argc, argv); }
    if (strcmp(cmd, "info") == 0) { return cmd_info(); }
    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    fprintf(stderr, "Unknown command: %s\n", cmd);
    print_usage(argv[0]);
    return 1;
}
