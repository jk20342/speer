#include "relay_server.h"

#include "speer_internal.h"

#include "circuit_relay.h"
#include "log.h"

int relay_server_init(relay_server_t *srv) {
    if (!srv) return -1;
    ZERO(srv, sizeof(relay_server_t));
    srv->next_circuit_id = 1;
    return 0;
}

void relay_server_free(relay_server_t *srv) {
    if (!srv) return;
    ZERO(srv, sizeof(relay_server_t));
}

static relay_reservation_t *find_reservation(relay_server_t *srv, const uint8_t *peer_id,
                                             size_t peer_id_len) {
    for (uint32_t i = 0; i < srv->num_reservations; i++) {
        if (srv->reservations[i].peer_id_len == peer_id_len &&
            memcmp(srv->reservations[i].peer_id, peer_id, peer_id_len) == 0) {
            return &srv->reservations[i];
        }
    }
    return NULL;
}

static relay_reservation_t *alloc_reservation(relay_server_t *srv) {
    if (srv->num_reservations >= RELAY_SERVER_MAX_RESERVATIONS) { return NULL; }
    return &srv->reservations[srv->num_reservations++];
}

static void free_reservation(relay_server_t *srv, relay_reservation_t *res) {
    uint32_t idx = (uint32_t)(res - srv->reservations);
    if (idx >= srv->num_reservations) return;
    for (uint32_t i = idx; i < srv->num_reservations - 1; i++) {
        COPY(&srv->reservations[i], &srv->reservations[i + 1], sizeof(relay_reservation_t));
    }
    srv->num_reservations--;
}

static relay_circuit_t *find_circuit(relay_server_t *srv, uint32_t circuit_id) {
    for (uint32_t i = 0; i < srv->num_circuits; i++) {
        if (srv->circuits[i].id == circuit_id && srv->circuits[i].active) {
            return &srv->circuits[i];
        }
    }
    return NULL;
}

static relay_circuit_t *alloc_circuit(relay_server_t *srv) {
    for (uint32_t i = 0; i < RELAY_SERVER_MAX_CONNECTIONS; i++) {
        if (!srv->circuits[i].active) {
            ZERO(&srv->circuits[i], sizeof(relay_circuit_t));
            srv->circuits[i].id = srv->next_circuit_id++;
            srv->circuits[i].active = true;
            srv->num_circuits++;
            return &srv->circuits[i];
        }
    }
    return NULL;
}

static void free_circuit(relay_server_t *srv, relay_circuit_t *circ) {
    if (!circ || !circ->active) return;
    circ->active = false;
    srv->num_circuits--;
}

int relay_server_on_hop(relay_server_t *srv, const uint8_t *auth_peer_id, size_t auth_peer_id_len,
                        const uint8_t *data, size_t len, const struct sockaddr_storage *from,
                        socklen_t from_len, uint8_t *response, size_t *response_len) {
    speer_relay_msg_type_t type;
    int status;
    speer_relay_reservation_t res;
    uint8_t peer_id[64];
    size_t peer_id_len = 0;

    if (auth_peer_id_len == 0 || auth_peer_id_len > sizeof(peer_id)) {
        return speer_relay_encode_hop_status(response, *response_len, response_len,
                                             RELAY_STATUS_PERMISSION_DENIED, NULL);
    }
    size_t protobuf_peer_cap = sizeof(peer_id);
    if (speer_relay_decode(data, len, &type, &status, &res, peer_id, &protobuf_peer_cap) != 0) {
        return speer_relay_encode_hop_status(response, *response_len, response_len,
                                             RELAY_STATUS_MALFORMED_MESSAGE, NULL);
    }
    if (protobuf_peer_cap > 0 && protobuf_peer_cap <= sizeof(peer_id)) {
        peer_id_len = protobuf_peer_cap;
    }

    if (type == HOP_TYPE_RESERVE) {
        if (!srv->auth_fn ||
            srv->auth_fn(srv->user, auth_peer_id, auth_peer_id_len, from, from_len) != 0) {
            return speer_relay_encode_hop_status(response, *response_len, response_len,
                                                 RELAY_STATUS_PERMISSION_DENIED, NULL);
        }
        if (srv->num_reservations >= RELAY_SERVER_MAX_RESERVATIONS) {
            return speer_relay_encode_hop_status(response, *response_len, response_len,
                                                 RELAY_STATUS_RESOURCE_LIMIT_EXCEEDED, NULL);
        }

        relay_reservation_t *existing = find_reservation(srv, auth_peer_id, auth_peer_id_len);
        if (existing) {
            existing->expires_ms = speer_timestamp_ms() + RELAY_SERVER_RESERVATION_TTL_MS;
            COPY(&existing->addr, from, from_len);
            existing->addr_len = from_len;
            return speer_relay_encode_hop_status(response, *response_len, response_len,
                                                 RELAY_STATUS_OK, NULL);
        }

        relay_reservation_t *new_res = alloc_reservation(srv);
        if (!new_res) {
            return speer_relay_encode_hop_status(response, *response_len, response_len,
                                                 RELAY_STATUS_RESOURCE_LIMIT_EXCEEDED, NULL);
        }

        COPY(new_res->peer_id, auth_peer_id, auth_peer_id_len);
        new_res->peer_id_len = auth_peer_id_len;
        new_res->expires_ms = speer_timestamp_ms() + RELAY_SERVER_RESERVATION_TTL_MS;
        COPY(&new_res->addr, from, from_len);
        new_res->addr_len = from_len;

        SPEER_LOG_INFO("relay", "new reservation for peer, total=%d", srv->num_reservations);

        return speer_relay_encode_hop_status(response, *response_len, response_len, RELAY_STATUS_OK,
                                             NULL);
    }

    if (type == HOP_TYPE_CONNECT) {
        if (peer_id_len == 0) {
            return speer_relay_encode_hop_status(response, *response_len, response_len,
                                                 RELAY_STATUS_MALFORMED_MESSAGE, NULL);
        }
        relay_reservation_t *target = find_reservation(srv, peer_id, peer_id_len);
        if (!target || target->expires_ms < speer_timestamp_ms()) {
            return speer_relay_encode_hop_status(response, *response_len, response_len,
                                                 RELAY_STATUS_NO_RESERVATION, NULL);
        }

        if (srv->num_circuits >= RELAY_SERVER_MAX_CONNECTIONS) {
            return speer_relay_encode_hop_status(response, *response_len, response_len,
                                                 RELAY_STATUS_RESOURCE_LIMIT_EXCEEDED, NULL);
        }

        relay_circuit_t *circ = alloc_circuit(srv);
        if (!circ) {
            return speer_relay_encode_hop_status(response, *response_len, response_len,
                                                 RELAY_STATUS_RESOURCE_LIMIT_EXCEEDED, NULL);
        }

        COPY(&circ->src_addr, from, from_len);
        circ->src_addr_len = from_len;
        COPY(circ->src_peer, auth_peer_id, auth_peer_id_len);
        circ->src_len = auth_peer_id_len;
        COPY(&circ->dst_addr, &target->addr, target->addr_len);
        circ->dst_addr_len = target->addr_len;
        COPY(circ->dst_peer, peer_id, peer_id_len);
        circ->dst_len = peer_id_len;
        circ->packet_quota_remaining = RELAY_CIRCUIT_PACKET_QUOTA;
        circ->created_ms = speer_timestamp_ms();
        circ->last_activity_ms = circ->created_ms;

        SPEER_LOG_INFO("relay", "new circuit %d, active=%d", circ->id, srv->num_circuits);

        return speer_relay_encode_hop_status(response, *response_len, response_len, RELAY_STATUS_OK,
                                             NULL);
    }

    return speer_relay_encode_hop_status(response, *response_len, response_len,
                                         RELAY_STATUS_UNEXPECTED_MESSAGE, NULL);
}

int relay_server_on_stop(relay_server_t *srv, const uint8_t *auth_peer_id, size_t auth_peer_id_len,
                         const uint8_t *data, size_t len, uint8_t *response, size_t *response_len) {
    speer_relay_msg_type_t type;
    int status;
    speer_relay_reservation_t res;
    uint8_t peer_id[64];
    size_t protobuf_peer_cap = sizeof(peer_id);

    if (auth_peer_id_len == 0 || auth_peer_id_len > sizeof(peer_id)) {
        return speer_relay_encode_stop_status(response, *response_len, response_len,
                                              RELAY_STATUS_PERMISSION_DENIED);
    }
    if (speer_relay_decode(data, len, &type, &status, &res, peer_id, &protobuf_peer_cap) != 0) {
        return speer_relay_encode_stop_status(response, *response_len, response_len,
                                              RELAY_STATUS_MALFORMED_MESSAGE);
    }

    relay_reservation_t *target = find_reservation(srv, auth_peer_id, auth_peer_id_len);
    if (!target || target->expires_ms < speer_timestamp_ms()) {
        return speer_relay_encode_stop_status(response, *response_len, response_len,
                                              RELAY_STATUS_NO_RESERVATION);
    }

    return speer_relay_encode_stop_status(response, *response_len, response_len, RELAY_STATUS_OK);
}

int relay_server_relay_data(relay_server_t *srv, uint32_t circuit_id, const uint8_t *data,
                            size_t len, const struct sockaddr_storage *from, socklen_t from_len) {
    relay_circuit_t *circ = find_circuit(srv, circuit_id);
    if (!circ || !circ->active) { return -1; }

    circ->last_activity_ms = speer_timestamp_ms();
    if (circ->packet_quota_remaining == 0) {
        SPEER_LOG_WARN("relay", "circuit %d packet quota exceeded", circuit_id);
        free_circuit(srv, circ);
        return -1;
    }
    circ->packet_quota_remaining--;

    const struct sockaddr_storage *target;
    socklen_t target_len;

    if (from_len == circ->src_addr_len && memcmp(from, &circ->src_addr, from_len) == 0) {
        target = &circ->dst_addr;
        target_len = circ->dst_addr_len;
    } else if (from_len == circ->dst_addr_len && memcmp(from, &circ->dst_addr, from_len) == 0) {
        target = &circ->src_addr;
        target_len = circ->src_addr_len;
    } else {
        return -1;
    }

    if (srv->send_fn) { srv->send_fn(srv->user, target, target_len, data, len); }

    srv->bytes_relayed += len;
    srv->packets_relayed++;

    return 0;
}

void relay_server_expire(relay_server_t *srv, uint64_t now_ms) {
    for (int i = (int)srv->num_reservations - 1; i >= 0; i--) {
        if (srv->reservations[i].expires_ms < now_ms) {
            SPEER_LOG_DEBUG("relay", "expiring reservation");
            free_reservation(srv, &srv->reservations[i]);
        }
    }

    for (uint32_t i = 0; i < RELAY_SERVER_MAX_CONNECTIONS; i++) {
        if (srv->circuits[i].active && now_ms - srv->circuits[i].last_activity_ms > 300000) {
            SPEER_LOG_DEBUG("relay", "expiring circuit %d", srv->circuits[i].id);
            free_circuit(srv, &srv->circuits[i]);
        }
    }
}

void relay_server_get_stats(relay_server_t *srv, uint64_t *bytes, uint64_t *packets,
                            uint32_t *active_circuits) {
    if (bytes) *bytes = srv->bytes_relayed;
    if (packets) *packets = srv->packets_relayed;
    if (active_circuits) *active_circuits = srv->num_circuits;
}
