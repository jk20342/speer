#ifndef SPEER_RELAY_CLIENT_H
#define SPEER_RELAY_CLIENT_H

#include "speer.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "circuit_relay.h"

#define RELAY_MAX_RELAYS            8
#define RELAY_MAX_CIRCUITS          16
#define RELAY_CONNECT_TIMEOUT_MS    10000
#define RELAY_KEEPALIVE_INTERVAL_MS 60000
#define RELAY_MAX_FRAME_SIZE        65535
#define RELAY_FRAME_HEADER_SIZE     8

typedef enum {
    RELAY_STATE_DISCONNECTED = 0,
    RELAY_STATE_CONNECTING,
    RELAY_STATE_RESERVING,
    RELAY_STATE_RESERVED,
    RELAY_STATE_CONNECTING_TO_PEER,
    RELAY_STATE_ACTIVE,
    RELAY_STATE_ERROR
} relay_state_t;

typedef enum {
    CIRCUIT_STATE_NONE = 0,
    CIRCUIT_STATE_CONNECTING,
    CIRCUIT_STATE_CONNECTED,
    CIRCUIT_STATE_CLOSED
} circuit_state_t;

typedef enum {
    RELAY_FRAME_DATA = 0x01,
    RELAY_FRAME_HOP = 0x02,
    RELAY_FRAME_STOP = 0x03,
    RELAY_FRAME_STATUS = 0x04,
    RELAY_FRAME_KEEPALIVE = 0x05,
} relay_frame_type_t;

typedef struct {
    uint32_t id;
    uint8_t peer_id[64];
    size_t peer_id_len;
    circuit_state_t state;
    uint64_t created_ms;
    uint64_t last_activity_ms;
    void *user_data;
} relay_circuit_t;

typedef struct {
    char address[64];
    uint8_t relay_peer_id[64];
    size_t relay_peer_id_len;
    relay_state_t state;
    int socket;
    speer_relay_reservation_t reservation;
    uint64_t reservation_expires_ms;
    relay_circuit_t circuits[RELAY_MAX_CIRCUITS];
    uint32_t num_circuits;
    uint32_t next_circuit_id;
    bool dcutr_enabled;
    uint32_t dcutr_circuit_id;
    speer_peer_t *dcutr_peer;
    int (*send_fn)(void *user, const uint8_t *data, size_t len);
    int (*recv_fn)(void *user, uint8_t *buf, size_t cap, size_t *out_len);
    void (*on_circuit)(void *user, uint32_t circuit_id, const uint8_t *peer_id, size_t peer_id_len,
                       bool incoming);
    void (*on_data)(void *user, uint32_t circuit_id, const uint8_t *data, size_t len);
    void (*on_circuit_closed)(void *user, uint32_t circuit_id);
    void *user;
    uint8_t recv_buf[RELAY_MAX_FRAME_SIZE];
    size_t recv_len;
    uint8_t frame_buf[RELAY_MAX_FRAME_SIZE];
    size_t frame_len;
    uint64_t last_send_ms;
    uint64_t last_recv_ms;
    uint64_t connected_ms;
} relay_client_t;

int relay_client_init(relay_client_t *client);
void relay_client_free(relay_client_t *client);
int relay_client_connect(relay_client_t *client, const char *relay_addr,
                         const uint8_t *relay_peer_id, size_t relay_peer_id_len);
void relay_client_disconnect(relay_client_t *client);
bool relay_client_is_connected(const relay_client_t *client);
bool relay_client_has_reservation(const relay_client_t *client);
int relay_client_reserve(relay_client_t *client);
int relay_client_connect_to_peer(relay_client_t *client, const uint8_t *target_peer_id,
                                 size_t target_peer_id_len);
int relay_client_send(relay_client_t *client, uint32_t circuit_id, const uint8_t *data, size_t len);
int relay_client_start_dcutr(relay_client_t *client, uint32_t circuit_id, speer_peer_t *peer,
                             bool is_initiator);
void relay_client_close_circuit(relay_client_t *client, uint32_t circuit_id);
int relay_client_poll(relay_client_t *client, uint64_t now_ms);
void relay_client_set_transport(relay_client_t *client,
                                int (*send_fn)(void *, const uint8_t *, size_t),
                                int (*recv_fn)(void *, uint8_t *, size_t, size_t *), void *user);
void relay_client_set_callbacks(relay_client_t *client,
                                void (*on_circuit)(void *, uint32_t, const uint8_t *, size_t, bool),
                                void (*on_data)(void *, uint32_t, const uint8_t *, size_t),
                                void (*on_circuit_closed)(void *, uint32_t), void *user);

#endif
