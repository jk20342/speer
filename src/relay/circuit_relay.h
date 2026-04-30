#ifndef SPEER_CIRCUIT_RELAY_H
#define SPEER_CIRCUIT_RELAY_H

#include <stdint.h>
#include <stddef.h>

#define CIRCUIT_RELAY_HOP_PROTO  "/libp2p/circuit/relay/0.2.0/hop"
#define CIRCUIT_RELAY_STOP_PROTO "/libp2p/circuit/relay/0.2.0/stop"

typedef enum {
    HOP_TYPE_RESERVE = 0,
    HOP_TYPE_CONNECT = 1,
    STOP_TYPE_CONNECT = 0,
} speer_relay_msg_type_t;

typedef enum {
    RELAY_STATUS_OK = 100,
    RELAY_STATUS_CONNECTION_FAILED = 200,
    RELAY_STATUS_RESERVATION_REFUSED = 201,
    RELAY_STATUS_RESOURCE_LIMIT_EXCEEDED = 202,
    RELAY_STATUS_PERMISSION_DENIED = 203,
    RELAY_STATUS_NO_RESERVATION = 204,
    RELAY_STATUS_MALFORMED_MESSAGE = 400,
    RELAY_STATUS_UNEXPECTED_MESSAGE = 401,
} speer_relay_status_t;

typedef struct {
    uint8_t  peer_id[64];
    size_t   peer_id_len;
    uint64_t expire;
    uint8_t  voucher[512];
    size_t   voucher_len;
} speer_relay_reservation_t;

int speer_relay_encode_hop_reserve(uint8_t* out, size_t cap, size_t* out_len);
int speer_relay_encode_hop_connect(uint8_t* out, size_t cap, size_t* out_len,
                                     const uint8_t* peer_id, size_t peer_id_len);
int speer_relay_encode_hop_status(uint8_t* out, size_t cap, size_t* out_len,
                                    int status, const speer_relay_reservation_t* res);
int speer_relay_encode_stop_connect(uint8_t* out, size_t cap, size_t* out_len,
                                      const uint8_t* src_peer_id, size_t src_peer_id_len);
int speer_relay_encode_stop_status(uint8_t* out, size_t cap, size_t* out_len, int status);

int speer_relay_decode(const uint8_t* in, size_t in_len,
                        speer_relay_msg_type_t* type,
                        int* status,
                        speer_relay_reservation_t* opt_reservation,
                        uint8_t* opt_peer_id, size_t* opt_peer_id_len);

#endif
