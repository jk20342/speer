#include "speer_internal.h"

#include <stdio.h>

#include <string.h>

#include "dcutr.h"
#include "relay_client.h"

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#define FAIL(...)                     \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        return 1;                     \
    } while (0)

static uint8_t g_sent[1024];
static size_t g_sent_len;
static int g_send_count;
static uint8_t g_recv[1024];
static size_t g_recv_len;
static int g_recv_used;

static int mock_send(void *user, const uint8_t *data, size_t len) {
    (void)user;
    if (len > sizeof(g_sent)) return -1;
    memcpy(g_sent, data, len);
    g_sent_len = len;
    g_send_count++;
    return (int)len;
}

static int mock_recv(void *user, uint8_t *buf, size_t cap, size_t *out_len) {
    (void)user;
    if (!g_recv_used && g_recv_len > 0) {
        if (g_recv_len > cap) return -1;
        memcpy(buf, g_recv, g_recv_len);
        *out_len = g_recv_len;
        g_recv_used = 1;
        return 0;
    }
    *out_len = 0;
    return 0;
}

static uint32_t read_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void write_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)((v >> 8) & 0xff);
    p[1] = (uint8_t)(v & 0xff);
}

static void write_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)((v >> 24) & 0xff);
    p[1] = (uint8_t)((v >> 16) & 0xff);
    p[2] = (uint8_t)((v >> 8) & 0xff);
    p[3] = (uint8_t)(v & 0xff);
}

static int relay_payload(uint32_t circuit_id, speer_dcutr_msg_t *out) {
    if (g_sent_len < RELAY_FRAME_HEADER_SIZE) return -1;
    if (g_sent[0] != RELAY_FRAME_DATA) return -1;
    if (read_be32(g_sent + 4) != circuit_id) return -1;
    return speer_dcutr_decode(out, g_sent + RELAY_FRAME_HEADER_SIZE,
                              g_sent_len - RELAY_FRAME_HEADER_SIZE);
}

static int make_relay_data(uint8_t *out, size_t cap, uint32_t circuit_id, const uint8_t *payload,
                           size_t payload_len, size_t *out_len) {
    if (payload_len + RELAY_FRAME_HEADER_SIZE > cap || payload_len > 0xffffu) return -1;
    out[0] = RELAY_FRAME_DATA;
    out[1] = 0;
    write_be16(out + 2, (uint16_t)payload_len);
    write_be32(out + 4, circuit_id);
    memcpy(out + RELAY_FRAME_HEADER_SIZE, payload, payload_len);
    *out_len = RELAY_FRAME_HEADER_SIZE + payload_len;
    return 0;
}

int main(void) {
    const uint32_t circuit_id = 42;
    relay_client_t client;
    relay_client_init(&client);
    relay_client_set_transport(&client, mock_send, mock_recv, NULL);
    client.state = RELAY_STATE_ACTIVE;
    client.num_circuits = 1;
    client.circuits[0].id = circuit_id;
    client.circuits[0].state = CIRCUIT_STATE_CONNECTED;

    speer_peer_t peer;
    memset(&peer, 0, sizeof(peer));

    if (relay_client_start_dcutr(&client, circuit_id, &peer, true) != 0)
        FAIL("relay_client_start_dcutr failed\n");
    speer_dcutr_poll();

    speer_dcutr_msg_t msg;
    if (g_send_count != 1) FAIL("DCUtR poll should send through relay\n");
    if (relay_payload(circuit_id, &msg) != 0) FAIL("relay CONNECT payload decode failed\n");
    if (msg.type != DCUTR_TYPE_CONNECT) FAIL("expected relay CONNECT\n");

    speer_dcutr_msg_t remote;
    memset(&remote, 0, sizeof(remote));
    remote.type = DCUTR_TYPE_CONNECT;
    remote.num_addrs = 1;
    remote.addrs[0].bytes[0] = 0x04;
    remote.addrs[0].bytes[1] = 127;
    remote.addrs[0].bytes[2] = 0;
    remote.addrs[0].bytes[3] = 0;
    remote.addrs[0].bytes[4] = 1;
    uint16_t port = htons(4001);
    memcpy(remote.addrs[0].bytes + 5, &port, sizeof(port));
    remote.addrs[0].len = 7;

    uint8_t encoded[256];
    size_t encoded_len = 0;
    if (speer_dcutr_encode(&remote, encoded, sizeof(encoded), &encoded_len) != 0)
        FAIL("remote CONNECT encode failed\n");
    if (make_relay_data(g_recv, sizeof(g_recv), circuit_id, encoded, encoded_len, &g_recv_len) != 0)
        FAIL("remote relay frame encode failed\n");
    g_recv_used = 0;
    g_sent_len = 0;
    g_send_count = 0;

    if (relay_client_poll(&client, speer_timestamp_ms()) != 0) FAIL("relay poll failed\n");
    if (g_send_count != 1) FAIL("remote CONNECT should produce relay SYNC\n");
    if (relay_payload(circuit_id, &msg) != 0) FAIL("relay SYNC payload decode failed\n");
    if (msg.type != DCUTR_TYPE_SYNC) FAIL("expected relay SYNC\n");

    speer_dcutr_free();
    relay_client_free(&client);
    puts("dcutr relay integration: ok");
    return 0;
}
