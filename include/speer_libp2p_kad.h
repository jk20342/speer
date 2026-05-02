#ifndef SPEER_LIBP2P_KAD_H
#define SPEER_LIBP2P_KAD_H

#include <stddef.h>
#include <stdint.h>

#include "speer_libp2p_tcp.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SPEER_LIBP2P_KAD_PROTOCOL_STR  "/ipfs/kad/1.0.0"
#define SPEER_LIBP2P_KAD_ID_BYTES      32
#define SPEER_LIBP2P_KAD_ADDR_MAX      64
#define SPEER_LIBP2P_KAD_MAX_PEERS     20

#define SPEER_LIBP2P_KAD_PUT_VALUE     0
#define SPEER_LIBP2P_KAD_GET_VALUE     1
#define SPEER_LIBP2P_KAD_ADD_PROVIDER  2
#define SPEER_LIBP2P_KAD_GET_PROVIDERS 3
#define SPEER_LIBP2P_KAD_FIND_NODE     4
#define SPEER_LIBP2P_KAD_PING          5

typedef struct {
    uint8_t id[SPEER_LIBP2P_KAD_ID_BYTES];
    char address[SPEER_LIBP2P_KAD_ADDR_MAX];
} speer_libp2p_kad_peer_t;

typedef struct {
    uint8_t type;
    const uint8_t *key;
    size_t key_len;
    const uint8_t *value;
    size_t value_len;
    const speer_libp2p_kad_peer_t *closer_peers;
    size_t num_closer_peers;
} speer_libp2p_kad_msg_t;

int speer_libp2p_kad_encode_query(uint8_t msg_type, const uint8_t *key, size_t key_len,
                                  uint8_t *out, size_t cap, size_t *out_len);
int speer_libp2p_kad_encode_message(const speer_libp2p_kad_msg_t *msg, uint8_t *out, size_t cap,
                                    size_t *out_len);
int speer_libp2p_kad_decode_message(const uint8_t *msg, size_t msg_len, speer_libp2p_kad_msg_t *out,
                                    speer_libp2p_kad_peer_t *peers, size_t max_peers);
int speer_libp2p_kad_stream_roundtrip(speer_libp2p_tcp_session_t *session, const uint8_t *request,
                                      size_t request_len, uint8_t *response, size_t *response_len);

#ifdef __cplusplus
}
#endif

#endif
