#include "relay_client.h"

#include <stdlib.h>

#include <string.h>

#include "circuit_relay.h"
#include "dcutr.h"

#if defined(_WIN32)
#include <winsock2.h>

#include <ws2tcpip.h>
typedef int socklen_t;
#define CLOSESOCKET closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#define CLOSESOCKET close
#endif

#define MIN(a, b)           ((a) < (b) ? (a) : (b))
#define MAX(a, b)           ((a) > (b) ? (a) : (b))
#define COPY(dst, src, len) memcpy((dst), (src), (len))
#define ZERO(p, len)        memset((p), 0, (len))
#define EQUAL(a, b, len)    (memcmp((a), (b), (len)) == 0)

extern uint64_t speer_timestamp_ms(void);

static uint16_t read_be16(const uint8_t *p) {
    return ((uint16_t)p[0] << 8) | p[1];
}

static void write_be16(uint8_t *p, uint16_t v) {
    p[0] = (v >> 8) & 0xFF;
    p[1] = v & 0xFF;
}

static uint32_t read_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void write_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)((v >> 24) & 0xFF);
    p[1] = (uint8_t)((v >> 16) & 0xFF);
    p[2] = (uint8_t)((v >> 8) & 0xFF);
    p[3] = (uint8_t)(v & 0xFF);
}

static int relay_frame_encode(uint8_t *out, size_t out_cap, relay_frame_type_t type,
                              uint32_t circuit_id, const uint8_t *payload, size_t payload_len) {
    if (payload_len + RELAY_FRAME_HEADER_SIZE > out_cap) return -1;
    if (payload_len > RELAY_MAX_FRAME_SIZE) return -1;
    out[0] = (uint8_t)type;
    out[1] = 0;
    write_be16(out + 2, (uint16_t)payload_len);
    write_be32(out + 4, circuit_id);
    if (payload_len > 0 && payload) { COPY(out + RELAY_FRAME_HEADER_SIZE, payload, payload_len); }
    return RELAY_FRAME_HEADER_SIZE + (int)payload_len;
}

int relay_client_init(relay_client_t *client) {
    ZERO(client, sizeof(relay_client_t));
    client->socket = -1;
    client->state = RELAY_STATE_DISCONNECTED;
    return 0;
}

void relay_client_free(relay_client_t *client) {
    relay_client_disconnect(client);
    ZERO(client, sizeof(relay_client_t));
    client->socket = -1;
}

void relay_client_set_transport(relay_client_t *client,
                                int (*send_fn)(void *, const uint8_t *, size_t),
                                int (*recv_fn)(void *, uint8_t *, size_t, size_t *), void *user) {
    client->send_fn = send_fn;
    client->recv_fn = recv_fn;
    client->user = user;
}

void relay_client_set_callbacks(relay_client_t *client,
                                void (*on_circuit)(void *, uint32_t, const uint8_t *, size_t, bool),
                                void (*on_data)(void *, uint32_t, const uint8_t *, size_t),
                                void (*on_circuit_closed)(void *, uint32_t), void *user) {
    client->on_circuit = on_circuit;
    client->on_data = on_data;
    client->on_circuit_closed = on_circuit_closed;
    client->user = user;
}

int relay_client_connect(relay_client_t *client, const char *relay_addr,
                         const uint8_t *relay_peer_id, size_t relay_peer_id_len) {
    if (client->state != RELAY_STATE_DISCONNECTED) relay_client_disconnect(client);
    char host[64];
    ZERO(host, sizeof(host));
    uint16_t port = 4001;
    const char *colon = strrchr(relay_addr, ':');
    if (colon) {
        size_t host_len = colon - relay_addr;
        if (host_len >= sizeof(host)) host_len = sizeof(host) - 1;
        COPY(host, relay_addr, host_len);
        host[host_len] = 0;
        port = (uint16_t)atoi(colon + 1);
    } else {
        size_t addr_len = strlen(relay_addr);
        if (addr_len >= sizeof(host)) addr_len = sizeof(host) - 1;
        COPY(host, relay_addr, addr_len);
        host[addr_len] = 0;
    }
    {
        size_t addr_len = strlen(relay_addr);
        if (addr_len >= sizeof(client->address)) addr_len = sizeof(client->address) - 1;
        COPY(client->address, relay_addr, addr_len);
        client->address[addr_len] = 0;
    }
    if (relay_peer_id && relay_peer_id_len > 0 &&
        relay_peer_id_len <= sizeof(client->relay_peer_id)) {
        COPY(client->relay_peer_id, relay_peer_id, relay_peer_id_len);
        client->relay_peer_id_len = relay_peer_id_len;
    } else {
        client->relay_peer_id_len = 0;
    }
    struct sockaddr_in sin;
    ZERO(&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
#if defined(_WIN32)
    sin.sin_addr.s_addr = inet_addr(host);
    if (sin.sin_addr.s_addr == INADDR_NONE) {
        struct hostent *he = gethostbyname(host);
        if (he && he->h_addrtype == AF_INET) COPY(&sin.sin_addr, he->h_addr, 4);
    }
#else
    inet_pton(AF_INET, host, &sin.sin_addr);
#endif
    client->socket = (int)socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client->socket < 0) return -1;
    if (connect(client->socket, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        CLOSESOCKET(client->socket);
        client->socket = -1;
        return -1;
    }
#if defined(_WIN32)
    u_long mode = 1;
    ioctlsocket(client->socket, FIONBIO, &mode);
#else
    int flags = fcntl(client->socket, F_GETFL, 0);
    fcntl(client->socket, F_SETFL, flags | O_NONBLOCK);
#endif
    client->state = RELAY_STATE_CONNECTING;
    client->connected_ms = speer_timestamp_ms();
    client->last_recv_ms = client->connected_ms;
    client->last_send_ms = client->connected_ms;
    client->recv_len = 0;
    client->frame_len = 0;
    return 0;
}

void relay_client_disconnect(relay_client_t *client) {
    for (uint32_t i = 0; i < client->num_circuits; i++) {
        if (client->circuits[i].state != CIRCUIT_STATE_NONE && client->on_circuit_closed) {
            client->on_circuit_closed(client->user, client->circuits[i].id);
        }
    }
    client->num_circuits = 0;
    if (client->socket >= 0) {
        CLOSESOCKET(client->socket);
        client->socket = -1;
    }
    ZERO(&client->reservation, sizeof(client->reservation));
    client->reservation_expires_ms = 0;
    client->state = RELAY_STATE_DISCONNECTED;
}

bool relay_client_is_connected(const relay_client_t *client) {
    return client->state == RELAY_STATE_RESERVED || client->state == RELAY_STATE_ACTIVE ||
           client->state == RELAY_STATE_CONNECTING_TO_PEER;
}

bool relay_client_has_reservation(const relay_client_t *client) {
    return client->state == RELAY_STATE_RESERVED || client->state == RELAY_STATE_ACTIVE;
}

int relay_client_reserve(relay_client_t *client) {
    if (client->state != RELAY_STATE_CONNECTING && client->state != RELAY_STATE_RESERVED) return -1;
    client->state = RELAY_STATE_RESERVING;
    uint8_t payload[256];
    size_t payload_len = 0;
    if (speer_relay_encode_hop_reserve(payload, sizeof(payload), &payload_len) != 0) return -1;
    uint8_t frame[RELAY_MAX_FRAME_SIZE];
    int frame_len = relay_frame_encode(frame, sizeof(frame), RELAY_FRAME_HOP, 0, payload,
                                       payload_len);
    if (frame_len < 0) return -1;
    if (client->send_fn) {
        int ret = client->send_fn(client->user, frame, (size_t)frame_len);
        if (ret < 0) return ret;
    }
    client->last_send_ms = speer_timestamp_ms();
    return 0;
}

int relay_client_connect_to_peer(relay_client_t *client, const uint8_t *target_peer_id,
                                 size_t target_peer_id_len) {
    if (client->state != RELAY_STATE_RESERVED && client->state != RELAY_STATE_ACTIVE) return -1;
    if (client->num_circuits >= RELAY_MAX_CIRCUITS) return -1;
    uint8_t payload[512];
    size_t payload_len = 0;
    if (speer_relay_encode_hop_connect(payload, sizeof(payload), &payload_len, target_peer_id,
                                       target_peer_id_len) != 0)
        return -1;
    uint8_t frame[RELAY_MAX_FRAME_SIZE];
    int frame_len = relay_frame_encode(frame, sizeof(frame), RELAY_FRAME_HOP, 0, payload,
                                       payload_len);
    if (frame_len < 0) return -1;
    if (client->send_fn) {
        int ret = client->send_fn(client->user, frame, (size_t)frame_len);
        if (ret < 0) return ret;
    }
    client->state = RELAY_STATE_CONNECTING_TO_PEER;
    client->last_send_ms = speer_timestamp_ms();
    relay_circuit_t *circ = &client->circuits[client->num_circuits];
    circ->id = ++client->next_circuit_id;
    circ->state = CIRCUIT_STATE_CONNECTING;
    circ->created_ms = speer_timestamp_ms();
    circ->last_activity_ms = circ->created_ms;
    if (target_peer_id_len <= sizeof(circ->peer_id)) {
        COPY(circ->peer_id, target_peer_id, target_peer_id_len);
        circ->peer_id_len = target_peer_id_len;
    }
    client->num_circuits++;
    return (int)circ->id;
}

static relay_circuit_t *find_circuit(relay_client_t *client, uint32_t circuit_id) {
    for (uint32_t i = 0; i < client->num_circuits; i++) {
        if (client->circuits[i].id == circuit_id) return &client->circuits[i];
    }
    return NULL;
}

void relay_client_close_circuit(relay_client_t *client, uint32_t circuit_id) {
    for (uint32_t i = 0; i < client->num_circuits; i++) {
        if (client->circuits[i].id == circuit_id) {
            client->circuits[i].state = CIRCUIT_STATE_CLOSED;
            if (client->on_circuit_closed) client->on_circuit_closed(client->user, circuit_id);
            for (uint32_t j = i; j < client->num_circuits - 1; j++) {
                COPY(&client->circuits[j], &client->circuits[j + 1], sizeof(relay_circuit_t));
            }
            client->num_circuits--;
            return;
        }
    }
}

int relay_client_send(relay_client_t *client, uint32_t circuit_id, const uint8_t *data,
                      size_t len) {
    relay_circuit_t *circ = find_circuit(client, circuit_id);
    if (!circ || circ->state != CIRCUIT_STATE_CONNECTED) return -1;
    uint8_t frame[RELAY_MAX_FRAME_SIZE];
    if (len > RELAY_MAX_FRAME_SIZE - RELAY_FRAME_HEADER_SIZE)
        len = RELAY_MAX_FRAME_SIZE - RELAY_FRAME_HEADER_SIZE;
    int frame_len = relay_frame_encode(frame, sizeof(frame), RELAY_FRAME_DATA, circuit_id, data,
                                       len);
    if (frame_len < 0) return -1;
    if (client->send_fn) {
        int ret = client->send_fn(client->user, frame, (size_t)frame_len);
        if (ret >= 0) {
            circ->last_activity_ms = speer_timestamp_ms();
            client->last_send_ms = circ->last_activity_ms;
        }
        return ret;
    }
    return -1;
}

static int relay_dcutr_send(void *user, const uint8_t *data, size_t len) {
    relay_client_t *client = (relay_client_t *)user;
    if (!client || !client->dcutr_enabled) return -1;
    return relay_client_send(client, client->dcutr_circuit_id, data, len);
}

int relay_client_start_dcutr(relay_client_t *client, uint32_t circuit_id, speer_peer_t *peer,
                             bool is_initiator) {
    if (!client || !peer) return -1;
    relay_circuit_t *circ = find_circuit(client, circuit_id);
    if (!circ || circ->state != CIRCUIT_STATE_CONNECTED) return -1;
    client->dcutr_enabled = true;
    client->dcutr_circuit_id = circuit_id;
    client->dcutr_peer = peer;
    speer_dcutr_set_transport(relay_dcutr_send, client);
    return speer_dcutr_init(peer, is_initiator ? 1 : 0);
}

static void handle_hop_status(relay_client_t *client, const uint8_t *payload, size_t payload_len) {
    speer_relay_msg_type_t type;
    int status;
    speer_relay_reservation_t res;
    uint8_t peer_id[64];
    size_t peer_id_len = sizeof(peer_id);
    ZERO(&res, sizeof(res));
    if (speer_relay_decode(payload, payload_len, &type, &status, &res, peer_id, &peer_id_len) != 0)
        return;
    if (client->state == RELAY_STATE_RESERVING) {
        if (status == RELAY_STATUS_OK) {
            COPY(&client->reservation, &res, sizeof(res));
            client->reservation_expires_ms = res.expire;
            client->state = RELAY_STATE_RESERVED;
        } else {
            client->state = RELAY_STATE_ERROR;
        }
    } else if (client->state == RELAY_STATE_CONNECTING_TO_PEER) {
        for (uint32_t i = 0; i < client->num_circuits; i++) {
            if (client->circuits[i].state == CIRCUIT_STATE_CONNECTING) {
                if (status == RELAY_STATUS_OK) {
                    client->circuits[i].state = CIRCUIT_STATE_CONNECTED;
                    client->state = RELAY_STATE_ACTIVE;
                    if (client->on_circuit) {
                        client->on_circuit(client->user, client->circuits[i].id, peer_id,
                                           peer_id_len, false);
                    }
                } else {
                    client->circuits[i].state = CIRCUIT_STATE_CLOSED;
                }
                break;
            }
        }
    }
}

static void handle_stop_connect(relay_client_t *client, const uint8_t *payload,
                                size_t payload_len) {
    if (client->num_circuits >= RELAY_MAX_CIRCUITS) return;
    speer_relay_msg_type_t type;
    int status;
    uint8_t peer_id[64];
    size_t peer_id_len = sizeof(peer_id);
    ZERO(&type, sizeof(type));
    if (speer_relay_decode(payload, payload_len, &type, &status, NULL, peer_id, &peer_id_len) != 0)
        return;
    relay_circuit_t *circ = &client->circuits[client->num_circuits];
    circ->id = ++client->next_circuit_id;
    circ->state = CIRCUIT_STATE_CONNECTED;
    circ->created_ms = speer_timestamp_ms();
    circ->last_activity_ms = circ->created_ms;
    if (peer_id_len <= sizeof(circ->peer_id)) {
        COPY(circ->peer_id, peer_id, peer_id_len);
        circ->peer_id_len = peer_id_len;
    }
    client->num_circuits++;
    client->state = RELAY_STATE_ACTIVE;
    if (client->on_circuit) {
        client->on_circuit(client->user, circ->id, peer_id, peer_id_len, true);
    }
}

static void process_frame(relay_client_t *client, relay_frame_type_t type, uint32_t circuit_id,
                          const uint8_t *payload, size_t payload_len) {
    switch (type) {
    case RELAY_FRAME_HOP:
        handle_hop_status(client, payload, payload_len);
        break;
    case RELAY_FRAME_STOP:
        handle_stop_connect(client, payload, payload_len);
        break;
    case RELAY_FRAME_DATA:
        if (client->dcutr_enabled && circuit_id == client->dcutr_circuit_id) {
            speer_dcutr_on_msg(payload, payload_len);
            break;
        }
        if (client->on_data && circuit_id > 0) {
            client->on_data(client->user, circuit_id, payload, payload_len);
        }
        break;
    case RELAY_FRAME_KEEPALIVE:
        break;
    default:
        break;
    }
}

static void consume_recv_buf(relay_client_t *client) {
    while (client->recv_len >= RELAY_FRAME_HEADER_SIZE) {
        size_t payload_len = read_be16(client->recv_buf + 2);
        size_t frame_total = RELAY_FRAME_HEADER_SIZE + payload_len;
        if (client->recv_len < frame_total) break;
        relay_frame_type_t type = (relay_frame_type_t)client->recv_buf[0];
        uint32_t circuit_id = read_be32(client->recv_buf + 4);
        process_frame(client, type, circuit_id, client->recv_buf + RELAY_FRAME_HEADER_SIZE,
                      payload_len);
        if (client->recv_len > frame_total) {
            memmove(client->recv_buf, client->recv_buf + frame_total,
                    client->recv_len - frame_total);
        }
        client->recv_len -= frame_total;
    }
}

int relay_client_poll(relay_client_t *client, uint64_t now_ms) {
    if (client->state == RELAY_STATE_DISCONNECTED) return 0;
    if (client->state == RELAY_STATE_CONNECTING || client->state == RELAY_STATE_RESERVING ||
        client->state == RELAY_STATE_CONNECTING_TO_PEER) {
        if (now_ms - client->connected_ms > RELAY_CONNECT_TIMEOUT_MS) {
            client->state = RELAY_STATE_ERROR;
            return -1;
        }
    }
    if (client->reservation_expires_ms > 0 && now_ms > client->reservation_expires_ms) {
        client->reservation_expires_ms = 0;
        ZERO(&client->reservation, sizeof(client->reservation));
        if (client->state == RELAY_STATE_RESERVED) client->state = RELAY_STATE_CONNECTING;
    }
    if (client->recv_fn) {
        uint8_t buf[4096];
        size_t len;
        while (client->recv_fn(client->user, buf, sizeof(buf), &len) == 0 && len > 0) {
            client->last_recv_ms = now_ms;
            if (client->recv_len + len < sizeof(client->recv_buf)) {
                COPY(client->recv_buf + client->recv_len, buf, len);
                client->recv_len += len;
                consume_recv_buf(client);
            }
        }
    }
    uint64_t keepalive_now = speer_timestamp_ms();
    if (client->last_send_ms > 0 &&
        (client->state == RELAY_STATE_RESERVED || client->state == RELAY_STATE_ACTIVE) &&
        keepalive_now - client->last_send_ms > RELAY_KEEPALIVE_INTERVAL_MS) {
        uint8_t frame[RELAY_FRAME_HEADER_SIZE];
        int frame_len = relay_frame_encode(frame, sizeof(frame), RELAY_FRAME_KEEPALIVE, 0, NULL, 0);
        if (frame_len > 0 && client->send_fn) {
            client->send_fn(client->user, frame, (size_t)frame_len);
            client->last_send_ms = keepalive_now;
        }
    }
    uint32_t i = 0;
    while (i < client->num_circuits) {
        if (client->circuits[i].state == CIRCUIT_STATE_CLOSED) {
            for (uint32_t j = i; j < client->num_circuits - 1; j++) {
                COPY(&client->circuits[j], &client->circuits[j + 1], sizeof(relay_circuit_t));
            }
            client->num_circuits--;
        } else {
            i++;
        }
    }
    return 0;
}

int speer_relay_connect(const char *relay_server, const uint8_t local_pubkey[32],
                        const uint8_t remote_pubkey[32]) {
    (void)relay_server;
    (void)local_pubkey;
    (void)remote_pubkey;
    return -1;
}
