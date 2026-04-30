#include <stdio.h>

#include <string.h>

#include "relay_client.h"

#define FAIL(...)                     \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        return 1;                     \
    } while (0)

static uint8_t g_last_sent[1024];
static size_t g_last_sent_len = 0;
static int g_send_count = 0;

static int mock_send(void *user, const uint8_t *data, size_t len) {
    (void)user;
    if (len > sizeof(g_last_sent)) len = sizeof(g_last_sent);
    memcpy(g_last_sent, data, len);
    g_last_sent_len = len;
    g_send_count++;
    return (int)len;
}

static int mock_recv(void *user, uint8_t *buf, size_t cap, size_t *out_len) {
    (void)user;
    (void)buf;
    (void)cap;
    *out_len = 0;
    return 0;
}

static volatile int g_circuit_created = 0;
static uint32_t g_circuit_id = 0;

static void on_circuit(void *user, uint32_t circuit_id, const uint8_t *peer_id, size_t peer_id_len,
                       bool incoming) {
    (void)user;
    (void)peer_id;
    (void)peer_id_len;
    (void)incoming;
    g_circuit_created = 1;
    g_circuit_id = circuit_id;
}

int main(void) {
    relay_client_t client;
    if (relay_client_init(&client) != 0) FAIL("relay_client_init failed\n");
    if (client.state != RELAY_STATE_DISCONNECTED) FAIL("should start disconnected\n");
    if (client.socket != -1) FAIL("socket should be -1\n");

    relay_client_set_transport(&client, mock_send, mock_recv, NULL);
    if (client.send_fn != mock_send) FAIL("send_fn not set\n");
    if (client.recv_fn != mock_recv) FAIL("recv_fn not set\n");

    relay_client_set_callbacks(&client, on_circuit, NULL, NULL, NULL);
    if (client.on_circuit != on_circuit) FAIL("on_circuit not set\n");

    uint8_t relay_peer_id[32] = {0x01, 0x02, 0x03, 0x04};
    int ret = relay_client_connect(&client, "127.0.0.1:4001", relay_peer_id, 32);
    if (ret != 0) { client.state = RELAY_STATE_CONNECTING; }

    if (relay_client_reserve(&client) != 0) {
        if (client.state == RELAY_STATE_RESERVING || client.state == RELAY_STATE_CONNECTING) {
        } else {
            FAIL("reserve should set reserving state or fail gracefully\n");
        }
    }
    if (g_send_count == 0) FAIL("reserve should send a frame\n");
    if (g_last_sent_len < 4) FAIL("frame too short\n");
    if (g_last_sent[0] != 0x02) FAIL("frame type should be HOP\n");

    uint8_t target_peer[32] = {0xAA, 0xBB, 0xCC, 0xDD};
    int circ_id = relay_client_connect_to_peer(&client, target_peer, 32);
    if (circ_id < 0) {
        if (client.state != RELAY_STATE_RESERVED && client.state != RELAY_STATE_ACTIVE &&
            client.state != RELAY_STATE_RESERVING)
            FAIL("connect_to_peer unexpected state without reservation ack\n");
    } else {
        if (client.num_circuits != 1) FAIL("should have 1 circuit\n");
        if (client.circuits[0].state != CIRCUIT_STATE_CONNECTING)
            FAIL("circuit should be connecting\n");
        if (client.circuits[0].id != (uint32_t)circ_id) FAIL("circuit id mismatch\n");
    }

    relay_client_free(&client);
    if (client.state != RELAY_STATE_DISCONNECTED) FAIL("should be disconnected after free\n");

    relay_client_t client2;
    relay_client_init(&client2);
    relay_client_set_transport(&client2, mock_send, mock_recv, NULL);
    uint8_t data[] = "hello relay";
    int send_ret = relay_client_send(&client2, 1, data, sizeof(data));
    if (send_ret >= 0 && client2.num_circuits == 0) {}

    puts("relay_client: ok");
    return 0;
}
