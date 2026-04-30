#ifndef SPEER_DHT_LIBP2P_H
#define SPEER_DHT_LIBP2P_H

#include <stddef.h>
#include <stdint.h>

#include "dht.h"

#define SPEER_LIBP2P_KAD_PROTOCOL "/ipfs/kad/1.0.0"

#define DHT_LIBP2P_PUT_VALUE      0
#define DHT_LIBP2P_GET_VALUE      1
#define DHT_LIBP2P_ADD_PROVIDER   2
#define DHT_LIBP2P_GET_PROVIDERS  3
#define DHT_LIBP2P_FIND_NODE      4
#define DHT_LIBP2P_PING           5

typedef struct {
    uint8_t id[DHT_ID_BYTES];
    char address[64];
} dht_libp2p_peer_t;

typedef struct {
    uint8_t type;
    const uint8_t *key;
    size_t key_len;
    const uint8_t *value;
    size_t value_len;
    const dht_libp2p_peer_t *closer_peers;
    size_t num_closer_peers;
} dht_libp2p_msg_t;

int dht_libp2p_encode_query(uint8_t msg_type, const uint8_t *key, size_t key_len, uint8_t *out,
                            size_t cap, size_t *out_len);
int dht_libp2p_decode_query(const uint8_t *msg, size_t msg_len, uint8_t *out_rpc,
                            const uint8_t **out_key, size_t *out_key_len);
int dht_libp2p_encode_message(const dht_libp2p_msg_t *msg, uint8_t *out, size_t cap,
                              size_t *out_len);
int dht_libp2p_decode_message(const uint8_t *msg, size_t msg_len, dht_libp2p_msg_t *out,
                              dht_libp2p_peer_t *peers, size_t max_peers);
int dht_libp2p_frame(const uint8_t *msg, size_t msg_len, uint8_t *out, size_t cap, size_t *out_len);
int dht_libp2p_unframe(const uint8_t *frame, size_t frame_len, const uint8_t **msg, size_t *msg_len,
                       size_t *used);
int dht_libp2p_dispatch(dht_t *dht, const uint8_t *request, size_t request_len, uint8_t *response,
                        size_t *response_len);

typedef int (*dht_libp2p_send_fn)(void *user, const uint8_t *data, size_t len);
typedef int (*dht_libp2p_recv_fn)(void *user, uint8_t *buf, size_t cap, size_t *out_n);
typedef int (*dht_libp2p_roundtrip_fn)(void *user, const char *addr, const uint8_t *request,
                                       size_t request_len, uint8_t *response, size_t *response_len);

typedef struct {
    dht_libp2p_roundtrip_fn roundtrip;
    void *user;
} dht_libp2p_rpc_t;

int dht_libp2p_stream_client(void *user, dht_libp2p_send_fn send_fn, dht_libp2p_recv_fn recv_fn,
                             const uint8_t *request, size_t request_len, uint8_t *response,
                             size_t *response_len);
int dht_libp2p_stream_server(dht_t *dht, void *user, dht_libp2p_send_fn send_fn,
                             dht_libp2p_recv_fn recv_fn);
int dht_libp2p_send_rpc(void *user, const char *addr, uint8_t op, const uint8_t *request,
                        size_t request_len, uint8_t *response, size_t *response_len);

#endif
