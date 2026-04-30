#ifndef SPEER_RELAY_SERVER_H
#define SPEER_RELAY_SERVER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "circuit_relay.h"

#define RELAY_SERVER_MAX_CONNECTIONS 128
#define RELAY_SERVER_MAX_RESERVATIONS 64
#define RELAY_SERVER_MAX_CIRCUITS_PER_CONN 4
#define RELAY_SERVER_RESERVATION_TTL_MS 7200000

#define RELAY_HOP_LIMIT 32

typedef struct {
    uint8_t peer_id[64];
    size_t peer_id_len;
    uint64_t expires_ms;
    struct sockaddr_storage addr;
    socklen_t addr_len;
} relay_reservation_t;

typedef struct {
    uint32_t id;
    uint8_t src_peer[64];
    size_t src_len;
    uint8_t dst_peer[64];
    size_t dst_len;
    struct sockaddr_storage src_addr;
    struct sockaddr_storage dst_addr;
    socklen_t src_addr_len;
    socklen_t dst_addr_len;
    uint8_t hop_limit;
    uint64_t created_ms;
    uint64_t last_activity_ms;
    bool active;
} relay_circuit_t;

typedef struct {
    relay_reservation_t reservations[RELAY_SERVER_MAX_RESERVATIONS];
    uint32_t num_reservations;
    relay_circuit_t circuits[RELAY_SERVER_MAX_CONNECTIONS];
    uint32_t num_circuits;
    uint32_t next_circuit_id;
    uint64_t bytes_relayed;
    uint64_t packets_relayed;
    int (*send_fn)(void* user, const struct sockaddr_storage* addr,
                   socklen_t addr_len, const uint8_t* data, size_t len);
    void* user;
} relay_server_t;

int relay_server_init(relay_server_t* srv);
void relay_server_free(relay_server_t* srv);

int relay_server_on_hop(relay_server_t* srv, const uint8_t* data, size_t len,
                          const struct sockaddr_storage* from, socklen_t from_len,
                          uint8_t* response, size_t* response_len);
int relay_server_on_stop(relay_server_t* srv, const uint8_t* data, size_t len,
                         const struct sockaddr_storage* from, socklen_t from_len,
                         uint8_t* response, size_t* response_len);
int relay_server_relay_data(relay_server_t* srv, uint32_t circuit_id,
                            const uint8_t* data, size_t len,
                            const struct sockaddr_storage* from, socklen_t from_len);

void relay_server_expire(relay_server_t* srv, uint64_t now_ms);
void relay_server_get_stats(relay_server_t* srv, uint64_t* bytes, uint64_t* packets,
                            uint32_t* active_circuits);

#endif
