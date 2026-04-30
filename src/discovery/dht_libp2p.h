#ifndef SPEER_DHT_LIBP2P_H
#define SPEER_DHT_LIBP2P_H

#include <stddef.h>
#include <stdint.h>

#include "dht.h"

#define SPEER_LIBP2P_KAD_PROTOCOL "/ipfs/kad/1.0.0"

#define DHT_LIBP2P_PUT_VALUE     0
#define DHT_LIBP2P_GET_VALUE     1
#define DHT_LIBP2P_ADD_PROVIDER  2
#define DHT_LIBP2P_GET_PROVIDERS 3
#define DHT_LIBP2P_FIND_NODE     4
#define DHT_LIBP2P_PING          5

int dht_libp2p_encode_query(uint8_t msg_type, const uint8_t *key, size_t key_len, uint8_t *out,
                            size_t cap, size_t *out_len);
int dht_libp2p_decode_query(const uint8_t *msg, size_t msg_len, uint8_t *out_rpc,
                            const uint8_t **out_key, size_t *out_key_len);

#endif
