#include "speer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    speer_peer_t* peer;
    int connected;
    int echoed;
    char data[64];
} test_state_t;

static void server_cb(speer_host_t* host, const speer_event_t* ev, void* user) {
    (void)host;
    (void)user;
    if (ev->type == SPEER_EVENT_STREAM_DATA && ev->stream && ev->len) {
        speer_stream_write(ev->stream, ev->data, ev->len);
    }
}

static void client_cb(speer_host_t* host, const speer_event_t* ev, void* user) {
    (void)host;
    test_state_t* st = (test_state_t*)user;
    if (ev->type == SPEER_EVENT_PEER_CONNECTED) {
        st->peer = ev->peer;
        st->connected = 1;
    } else if (ev->type == SPEER_EVENT_STREAM_DATA) {
        size_t n = ev->len < sizeof(st->data) - 1 ? ev->len : sizeof(st->data) - 1;
        memcpy(st->data, ev->data, n);
        st->data[n] = 0;
        st->echoed = 1;
    }
}

static void poll_pair(speer_host_t* a, speer_host_t* b, int rounds) {
    for (int i = 0; i < rounds; i++) {
        speer_host_poll(a, 1);
        speer_host_poll(b, 1);
    }
}

static int wait_connected(speer_host_t* a, speer_host_t* b, test_state_t* st, speer_peer_t* peer) {
    for (int i = 0; i < 1000; i++) {
        poll_pair(a, b, 1);
        if (st->connected && speer_peer_is_connected(peer)) return 1;
    }
    return 0;
}

static int wait_echo(speer_host_t* a, speer_host_t* b, test_state_t* st) {
    for (int i = 0; i < 1000; i++) {
        poll_pair(a, b, 1);
        if (st->echoed) return 1;
    }
    return 0;
}

int main(void) {
    uint8_t server_seed[32] = {0};
    uint8_t client_seed[32] = {8};
    speer_config_t cfg;
    speer_config_default(&cfg);
    cfg.bind_address = "127.0.0.1";
    cfg.bind_port = 0;

    speer_host_t* server = speer_host_new(server_seed, &cfg);
    speer_host_t* client = speer_host_new(client_seed, &cfg);
    if (!server || !client) {
        puts("host create failed");
        return 1;
    }

    test_state_t st;
    memset(&st, 0, sizeof(st));
    speer_host_set_callback(server, server_cb, NULL);
    speer_host_set_callback(client, client_cb, &st);

    char addr[64];
    snprintf(addr, sizeof(addr), "127.0.0.1:%u", speer_host_get_port(server));
    speer_peer_t* peer = speer_connect(client, speer_host_get_public_key(server), addr);
    if (!peer) {
        puts("connect create failed");
        return 1;
    }

    if (!wait_connected(client, server, &st, peer)) {
        puts("connect failed");
        return 1;
    }

    speer_stream_t* s = speer_stream_open(peer, 0);
    if (!s) {
        puts("stream open failed");
        return 1;
    }
    if (speer_stream_write(s, (const uint8_t*)"hi", 2) != 2) {
        puts("stream write failed");
        return 1;
    }

    if (!wait_echo(client, server, &st) || strcmp(st.data, "hi") != 0) {
        printf("echo failed: '%s'\n", st.data);
        return 1;
    }

    speer_stream_close(s);
    speer_host_free(client);
    speer_host_free(server);
    puts("integration echo: ok");
    return 0;
}
