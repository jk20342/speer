#include "speer.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

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
            printf("peer connected: %p\n", (void*)ev->peer);
            fflush(stdout);
            break;
            
        case SPEER_EVENT_PEER_DISCONNECTED:
            printf("peer disconnected: %p\n", (void*)ev->peer);
            break;
            
        case SPEER_EVENT_STREAM_OPENED:
            printf("stream opened: %u on peer %p\n", ev->stream_id, (void*)ev->peer);
            break;
            
        case SPEER_EVENT_STREAM_DATA:
            printf("received %zu bytes on stream %u\n", ev->len, ev->stream_id);
            if (ev->stream && ev->len > 0) {
                char buf[1024];
                size_t echo_len = ev->len < sizeof(buf) - 1 ? ev->len : sizeof(buf) - 1;
                memcpy(buf, ev->data, echo_len);
                buf[echo_len] = 0;
                printf("echo: %s\n", buf);
                fflush(stdout);
                speer_stream_write(ev->stream, (uint8_t*)buf, echo_len);
            }
            break;
            
        case SPEER_EVENT_STREAM_CLOSED:
            printf("stream closed: %u\n", ev->stream_id);
            break;
            
        case SPEER_EVENT_ERROR:
            printf("error: %d\n", ev->error_code);
            break;
            
        default:
            break;
    }
}

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    
    uint8_t seed[32] = {0};
    speer_config_t cfg;
    speer_config_default(&cfg);
    cfg.bind_port = argc > 1 ? (uint16_t)atoi(argv[1]) : 0;
    
    speer_host_t* host = speer_host_new(seed, &cfg);
    if (!host) {
        fprintf(stderr, "failed to create host\n");
        return 1;
    }
    
    printf("speer echo server running on port %d\n", speer_host_get_port(host));
    printf("public key: ");
    const uint8_t* pk = speer_host_get_public_key(host);
    for (int i = 0; i < 32; i++) printf("%02x", pk[i]);
    printf("\n");
    fflush(stdout);
    
    speer_host_set_callback(host, on_event, NULL);
    
    while (running) {
        speer_host_poll(host, 100);
    }
    
    printf("shutting down...\n");
    speer_host_free(host);
    
    return 0;
}
