#include <stdio.h>

#include <string.h>

#include "dcutr.h"

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

static uint8_t g_last_sent[256];
static size_t g_last_sent_len;
static int g_send_count;

static int mock_send(void *user, const uint8_t *data, size_t len) {
    (void)user;
    if (len > sizeof(g_last_sent)) return -1;
    memcpy(g_last_sent, data, len);
    g_last_sent_len = len;
    g_send_count++;
    return (int)len;
}

int main(void) {
    speer_dcutr_set_transport(mock_send, NULL);
    if (speer_dcutr_init(NULL, 1) != 0) FAIL("speer_dcutr_init failed\n");
    speer_dcutr_poll();
    if (g_send_count != 1) FAIL("poll should send CONNECT\n");

    speer_dcutr_msg_t decoded;
    if (speer_dcutr_decode(&decoded, g_last_sent, g_last_sent_len) != 0)
        FAIL("CONNECT decode failed\n");
    if (decoded.type != DCUTR_TYPE_CONNECT) FAIL("expected CONNECT\n");

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
    memcpy(&remote.addrs[0].bytes[5], &port, sizeof(port));
    remote.addrs[0].len = 7;

    uint8_t encoded[256];
    size_t encoded_len = 0;
    if (speer_dcutr_encode(&remote, encoded, sizeof(encoded), &encoded_len) != 0)
        FAIL("remote CONNECT encode failed\n");
    if (speer_dcutr_on_msg(encoded, encoded_len) != 0) FAIL("remote CONNECT handling failed\n");
    if (g_send_count < 2) FAIL("remote CONNECT should send SYNC\n");

    if (speer_dcutr_decode(&decoded, g_last_sent, g_last_sent_len) != 0)
        FAIL("SYNC decode failed\n");
    if (decoded.type != DCUTR_TYPE_SYNC) FAIL("expected SYNC\n");

    speer_dcutr_free();
    puts("dcutr: ok");
    return 0;
}
