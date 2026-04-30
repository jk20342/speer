#include <stdio.h>

#include <string.h>

#include "dht_libp2p.h"
#include "multistream.h"
#include "varint.h"

#define FAIL(...)                     \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        return 1;                     \
    } while (0)

typedef struct {
    uint8_t in[4096];
    size_t in_len;
    size_t in_pos;
    uint8_t out[4096];
    size_t out_len;
} mem_io_t;

static int mem_send(void *user, const uint8_t *data, size_t len) {
    mem_io_t *m = (mem_io_t *)user;
    if (m->out_len + len > sizeof(m->out)) return -1;
    memcpy(m->out + m->out_len, data, len);
    m->out_len += len;
    return 0;
}

static int mem_recv(void *user, uint8_t *buf, size_t cap, size_t *out_n) {
    mem_io_t *m = (mem_io_t *)user;
    if (m->in_pos >= m->in_len) return -1;
    size_t n = m->in_len - m->in_pos;
    if (n > cap) n = cap;
    memcpy(buf, m->in + m->in_pos, n);
    m->in_pos += n;
    *out_n = n;
    return 0;
}

static int append_lp(mem_io_t *m, const char *s) {
    size_t slen = strlen(s);
    uint8_t hdr[10];
    size_t hdr_len = speer_uvarint_encode(hdr, sizeof(hdr), slen + 1);
    if (hdr_len == 0 || m->in_len + hdr_len + slen + 1 > sizeof(m->in)) return -1;
    memcpy(m->in + m->in_len, hdr, hdr_len);
    m->in_len += hdr_len;
    memcpy(m->in + m->in_len, s, slen);
    m->in_len += slen;
    m->in[m->in_len++] = '\n';
    return 0;
}

static int append_frame(mem_io_t *m, const uint8_t *msg, size_t msg_len) {
    size_t n;
    if (dht_libp2p_frame(msg, msg_len, m->in + m->in_len, sizeof(m->in) - m->in_len, &n) != 0)
        return -1;
    m->in_len += n;
    return 0;
}

static int roundtrip(void *user, const char *addr, const uint8_t *request, size_t request_len,
                     uint8_t *response, size_t *response_len) {
    (void)addr;
    return dht_libp2p_dispatch((dht_t *)user, request, request_len, response, response_len);
}

int main(void) {
    uint8_t local_id[DHT_ID_BYTES] = {1};
    uint8_t peer_id[DHT_ID_BYTES] = {2};
    uint8_t key[DHT_ID_BYTES] = {3};
    uint8_t value[] = {4, 5, 6};
    dht_t dht;
    if (dht_init(&dht, local_id) != 0) FAIL("init\n");
    if (dht_add_node(&dht, peer_id, "peer:1") != 0) FAIL("add node\n");
    if (dht_handle_store(&dht, key, value, sizeof(value), local_id) != 0) FAIL("store\n");

    dht_libp2p_msg_t req = {.type = DHT_LIBP2P_GET_VALUE, .key = key, .key_len = sizeof(key)};
    uint8_t req_buf[256];
    size_t req_len = sizeof(req_buf);
    if (dht_libp2p_encode_message(&req, req_buf, sizeof(req_buf), &req_len) != 0)
        FAIL("req encode\n");

    mem_io_t server_io = {0};
    if (append_lp(&server_io, MULTISTREAM_PROTO) != 0 ||
        append_lp(&server_io, SPEER_LIBP2P_KAD_PROTOCOL) != 0 ||
        append_frame(&server_io, req_buf, req_len) != 0)
        FAIL("server input\n");
    if (dht_libp2p_stream_server(&dht, &server_io, mem_send, mem_recv) != 0) FAIL("server\n");

    uint8_t resp_buf[256];
    size_t resp_len = sizeof(resp_buf);
    dht_libp2p_rpc_t rpc = {.roundtrip = roundtrip, .user = &dht};
    if (dht_libp2p_send_rpc(&rpc, "peer:1", DHT_RPC_FIND_VALUE, key, sizeof(key), resp_buf,
                            &resp_len) != 0)
        FAIL("send rpc\n");
    if (resp_len != 3 + sizeof(value) || resp_buf[0] != 0xff ||
        memcmp(resp_buf + 3, value, sizeof(value)) != 0)
        FAIL("rpc value\n");

    dht_free(&dht);
    puts("dht_libp2p_stream: ok");
    return 0;
}
