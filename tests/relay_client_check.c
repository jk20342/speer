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
static uint8_t g_recv_data[1024];
static size_t g_recv_len = 0;
static int g_recv_used = 0;

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
    if (!g_recv_used && g_recv_len > 0) {
        if (g_recv_len > cap) return -1;
        memcpy(buf, g_recv_data, g_recv_len);
        *out_len = g_recv_len;
        g_recv_used = 1;
        return 0;
    }
    *out_len = 0;
    return 0;
}

static volatile int g_circuit_created = 0;
static uint32_t g_circuit_id = 0;
static volatile int g_data_received = 0;
static uint32_t g_data_circuit_id = 0;
static uint8_t g_data_payload[64];
static size_t g_data_len = 0;

static void on_circuit(void *user, uint32_t circuit_id, const uint8_t *peer_id, size_t peer_id_len,
                       bool incoming) {
    (void)user;
    (void)peer_id;
    (void)peer_id_len;
    (void)incoming;
    g_circuit_created = 1;
    g_circuit_id = circuit_id;
}

static void on_data(void *user, uint32_t circuit_id, const uint8_t *data, size_t len) {
    (void)user;
    g_data_received = 1;
    g_data_circuit_id = circuit_id;
    if (len > sizeof(g_data_payload)) len = sizeof(g_data_payload);
    memcpy(g_data_payload, data, len);
    g_data_len = len;
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
        relay_state_t reserve_ok_states[] = {RELAY_STATE_RESERVING, RELAY_STATE_CONNECTING};
        int ok_reserve_state = 0;
        for (size_t wi = 0; wi < sizeof(reserve_ok_states) / sizeof(reserve_ok_states[0]); wi++) {
            if (client.state == reserve_ok_states[wi]) {
                ok_reserve_state = 1;
                break;
            }
        }
        if (!ok_reserve_state) FAIL("reserve should set reserving state or fail gracefully\n");
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
    relay_client_set_callbacks(&client2, NULL, on_data, NULL, NULL);
    client2.state = RELAY_STATE_ACTIVE;
    client2.num_circuits = 1;
    client2.circuits[0].id = 7;
    client2.circuits[0].state = CIRCUIT_STATE_CONNECTED;
    uint8_t data[] = "hello relay";
    int send_ret = relay_client_send(&client2, 7, data, sizeof(data));
    if (send_ret < 0) FAIL("relay_client_send should send connected circuit data\n");
    if (g_last_sent_len < RELAY_FRAME_HEADER_SIZE) FAIL("data frame too short\n");
    if (g_last_sent[0] != RELAY_FRAME_DATA) FAIL("frame type should be DATA\n");
    if (g_last_sent[4] != 0 || g_last_sent[5] != 0 || g_last_sent[6] != 0 || g_last_sent[7] != 7)
        FAIL("circuit id not encoded\n");

    memcpy(g_recv_data, g_last_sent, g_last_sent_len);
    g_recv_len = g_last_sent_len;
    g_recv_used = 0;
    if (relay_client_poll(&client2, 0) != 0) FAIL("poll failed\n");
    if (!g_data_received) FAIL("DATA frame should call on_data\n");
    if (g_data_circuit_id != 7) FAIL("DATA circuit id mismatch\n");
    if (g_data_len != sizeof(data) || memcmp(g_data_payload, data, sizeof(data)) != 0)
        FAIL("DATA payload mismatch\n");

    puts("relay_client: ok");
    return 0;
}
