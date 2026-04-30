#include "speer_internal.h"

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <arpa/inet.h>

#include <netdb.h>
#endif

#define PACKET_TYPE_INITIAL   0x00
#define PACKET_TYPE_HANDSHAKE 0x01
#define PACKET_TYPE_1RTT      0x02

static int init_packet(speer_peer_t *peer, uint32_t stream_id, uint8_t *out, size_t *out_len,
                       const uint8_t *data, size_t len) {
    if (peer->state != SPEER_STATE_ESTABLISHED) { return SPEER_ERROR_HANDSHAKE; }
    if (len > SPEER_MAX_PACKET_SIZE - 64) { return SPEER_ERROR_BUFFER_TOO_SMALL; }

    uint8_t frames[SPEER_MAX_PACKET_SIZE];
    size_t frames_len = speer_frame_encode_stream(frames, stream_id, 0, data, len, 0);

    return speer_packet_encode(out, out_len, frames, frames_len, peer->conn.cid, peer->conn.cid_len,
                               peer->conn.pkt_num, peer->send_cipher.key);
}

static int process_initial(speer_host_t *host, speer_peer_t *peer, const uint8_t *data, size_t len,
                           const struct sockaddr_storage *addr, socklen_t addr_len) {
    if (len != 80) return -1;
    if (speer_noise_xx_read_msg2(&peer->handshake, data) != 0) return -1;
    if (!EQUAL(peer->handshake.remote_pubkey, peer->pubkey, SPEER_PUBLIC_KEY_SIZE)) return -1;

    uint8_t final_msg[48];
    if (speer_noise_xx_write_msg3(&peer->handshake, final_msg) != 0) return -1;

    uint8_t packet[128];
    size_t packet_len = 0;
    packet[packet_len++] = SPEER_PACKET_VERSION;
    packet[packet_len++] = PACKET_TYPE_HANDSHAKE;
    packet[packet_len++] = peer->conn.cid_len;
    COPY(packet + packet_len, peer->conn.cid, peer->conn.cid_len);
    packet_len += peer->conn.cid_len;
    packet_len += speer_varint_encode(packet + packet_len, peer->conn.pkt_num++);
    COPY(packet + packet_len, final_msg, sizeof(final_msg));
    packet_len += sizeof(final_msg);
    if (speer_socket_send(host->socket, packet, packet_len, addr, addr_len) < 0) return -1;

    speer_noise_xx_split(&peer->handshake, peer->send_cipher.key, peer->recv_cipher.key);
    peer->state = SPEER_STATE_ESTABLISHED;
    COPY(&peer->addr, addr, addr_len);
    peer->addr_len = addr_len;
    peer->conn.last_recv_ms = speer_timestamp_ms();
    peer->conn.last_send_ms = peer->conn.last_recv_ms;

    speer_event_t ev = {.type = SPEER_EVENT_PEER_CONNECTED, .peer = peer};
    if (host->callback) host->callback(host, &ev, host->user_data);
    return 0;
}

static int process_handshake_response(speer_host_t *host, speer_peer_t *peer, const uint8_t *data,
                                      size_t len, const struct sockaddr_storage *addr,
                                      socklen_t addr_len) {
    if (len != 32) return -1;
    if (speer_noise_xx_read_msg1(&peer->handshake, data) != 0) return -1;

    COPY(&peer->addr, addr, addr_len);
    peer->addr_len = addr_len;
    peer->conn.last_recv_ms = speer_timestamp_ms();
    peer->conn.last_send_ms = peer->conn.last_recv_ms;
    peer->state = SPEER_STATE_HANDSHAKE;

    uint8_t response[128];
    size_t resp_len = 0;
    response[resp_len++] = SPEER_PACKET_VERSION;
    response[resp_len++] = PACKET_TYPE_HANDSHAKE;
    response[resp_len++] = peer->conn.cid_len;
    COPY(response + resp_len, peer->conn.cid, peer->conn.cid_len);
    resp_len += peer->conn.cid_len;
    resp_len += speer_varint_encode(response + resp_len, peer->conn.pkt_num++);
    if (speer_noise_xx_write_msg2(&peer->handshake, response + resp_len) != 0) return -1;
    resp_len += 80;
    return speer_socket_send(host->socket, response, resp_len, addr, addr_len) < 0 ? -1 : 0;
}

static int process_handshake_final(speer_host_t *host, speer_peer_t *peer, const uint8_t *data,
                                   size_t len, const struct sockaddr_storage *addr,
                                   socklen_t addr_len) {
    if (len != 48) return -1;
    if (speer_noise_xx_read_msg3(&peer->handshake, data) != 0) return -1;

    COPY(peer->pubkey, peer->handshake.remote_pubkey, SPEER_PUBLIC_KEY_SIZE);
    speer_noise_xx_split(&peer->handshake, peer->recv_cipher.key, peer->send_cipher.key);
    peer->state = SPEER_STATE_ESTABLISHED;
    COPY(&peer->addr, addr, addr_len);
    peer->addr_len = addr_len;
    peer->conn.last_recv_ms = speer_timestamp_ms();
    peer->conn.last_send_ms = peer->conn.last_recv_ms;

    speer_event_t ev = {.type = SPEER_EVENT_PEER_CONNECTED, .peer = peer};
    if (host->callback) host->callback(host, &ev, host->user_data);
    return 0;
}

static void buffer_stream_data(speer_peer_t *peer, uint32_t stream_id, const uint8_t *data,
                               size_t len) {
    speer_stream_internal_t *s = speer_stream_lookup(peer, stream_id);
    if (!s) {
        s = speer_stream_create(peer, stream_id);
        if (!s) return;
    }
    size_t needed = s->recv_buf_len + len;
    if (needed > s->recv_buf_cap) {
        size_t new_cap = s->recv_buf_cap ? s->recv_buf_cap * 2 : 4096;
        while (new_cap < needed) new_cap *= 2;
        if (new_cap > 65536) new_cap = 65536;
        uint8_t *new_buf = (uint8_t *)realloc(s->recv_buf, new_cap);
        if (!new_buf) return;
        s->recv_buf = new_buf;
        s->recv_buf_cap = new_cap;
    }
    COPY(s->recv_buf + s->recv_buf_len, data, len);
    s->recv_buf_len += len;
}

static void emit_stream_frames(speer_host_t *host, speer_peer_t *peer, const uint8_t *data,
                               size_t len) {
    size_t pos = 0;
    while (pos < len) {
        uint8_t type = data[pos++];
        if (type != 0x06 && type != 0x07) return;
        uint64_t stream_id = 0, offset = 0, data_len = 0;
        if (pos >= len) return;
        size_t n = speer_varint_decode(data + pos, &stream_id);
        if (n == 0 || pos + n > len) return;
        pos += n;
        if (pos >= len) return;
        n = speer_varint_decode(data + pos, &data_len);
        if (n == 0 || pos + n > len) return;
        pos += n;
        if (pos + data_len > len) return;
        (void)offset;
        buffer_stream_data(peer, (uint32_t)stream_id, data + pos, (size_t)data_len);
        speer_stream_t stream = {.peer = peer, .id = (uint32_t)stream_id};
        speer_event_t ev = {.type = SPEER_EVENT_STREAM_DATA,
                            .peer = peer,
                            .stream = &stream,
                            .stream_id = (uint32_t)stream_id,
                            .data = data + pos,
                            .len = (size_t)data_len};
        if (host->callback) host->callback(host, &ev, host->user_data);
        pos += (size_t)data_len;
    }
}

static int process_packet(speer_host_t *host, const uint8_t *data, size_t len,
                          const struct sockaddr_storage *addr, socklen_t addr_len) {
    if (len < 4) return -1;

    uint8_t version = data[0];
    if (version != SPEER_PACKET_VERSION) return -1;

    uint8_t type = data[1];

    uint8_t cid[SPEER_MAX_CID_LEN];
    uint8_t cid_len;
    uint64_t pkt_num;

    size_t hdr_len = 2;
    cid_len = data[hdr_len++];
    if (cid_len > SPEER_MAX_CID_LEN || hdr_len + cid_len > len) return -1;
    COPY(cid, data + hdr_len, cid_len);
    hdr_len += cid_len;

    hdr_len += speer_varint_decode(data + hdr_len, &pkt_num);

    speer_peer_t *peer = speer_peer_lookup(host, cid, cid_len);

    if (type == PACKET_TYPE_INITIAL) {
        if (!peer) {
            peer = speer_peer_create(host, NULL);
            if (!peer) return -1;

            COPY(peer->conn.cid, cid, cid_len);
            peer->conn.cid_len = cid_len;

            speer_noise_xx_init(&peer->handshake, host->pubkey, host->privkey);

            peer->host->bind_addr_len = 0;
            return process_handshake_response(host, peer, data + hdr_len, len - hdr_len, addr,
                                              addr_len);
        }
    } else if (type == PACKET_TYPE_HANDSHAKE) {
        if (peer && peer->state == SPEER_STATE_HANDSHAKE) {
            size_t body_len = len - hdr_len;
            if (body_len == 80) {
                return process_initial(host, peer, data + hdr_len, body_len, addr, addr_len);
            }
            if (body_len == 48) {
                return process_handshake_final(host, peer, data + hdr_len, body_len, addr,
                                               addr_len);
            }
        }
    } else if (type == PACKET_TYPE_1RTT) {
        if (!peer || peer->state != SPEER_STATE_ESTABLISHED) return -1;

        uint8_t plaintext[SPEER_MAX_PACKET_SIZE];
        size_t plaintext_len;

        if (speer_packet_decode(plaintext, &plaintext_len, data, len, cid, &cid_len, &pkt_num,
                                peer->recv_cipher.key) != 0) {
            return -1;
        }

        peer->conn.last_recv_ms = speer_timestamp_ms();

        emit_stream_frames(host, peer, plaintext, plaintext_len);
    }

    return 0;
}

speer_host_t *speer_host_new(const uint8_t seed_key[SPEER_PRIVATE_KEY_SIZE],
                             const speer_config_t *config) {
    speer_host_t *host = (speer_host_t *)calloc(1, sizeof(speer_host_t));
    if (!host) return NULL;

    if (config) {
        COPY(&host->config, config, sizeof(speer_config_t));
    } else {
        speer_config_default(&host->config);
    }
    host->max_peers = host->config.max_peers ? host->config.max_peers : SPEER_MAX_PEERS;

    speer_generate_keypair(host->pubkey, host->privkey, seed_key);
    speer_random_bytes((uint8_t *)host->next_cid, sizeof(host->next_cid));

    host->socket = speer_socket_create(host->config.bind_port, host->config.bind_address);
    if (host->socket < 0) {
        free(host);
        return NULL;
    }

    speer_socket_set_nonblocking(host->socket);

    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    if (getsockname(host->socket, (struct sockaddr *)&addr, &addr_len) == 0) {
        if (addr.ss_family == AF_INET) {
            host->config.bind_port = ntohs(((struct sockaddr_in *)&addr)->sin_port);
        } else if (addr.ss_family == AF_INET6) {
            host->config.bind_port = ntohs(((struct sockaddr_in6 *)&addr)->sin6_port);
        }
    }

    host->last_poll_ms = speer_timestamp_ms();

    return host;
}

void speer_host_free(speer_host_t *host) {
    if (!host) return;

    while (host->peers) {
        speer_peer_t *p = host->peers;
        host->peers = p->next;
        speer_peer_destroy(p);
    }

    WIPE(host->privkey, sizeof(host->privkey));

    speer_socket_close(host->socket);
    free(host);
}

int speer_host_poll(speer_host_t *host, int timeout_ms) {
    uint8_t buf[SPEER_MAX_PACKET_SIZE];
    struct sockaddr_storage from;
    socklen_t from_len;

    uint64_t start = speer_timestamp_ms();
    int processed = 0;

    while (1) {
        from_len = sizeof(from);
        int n = speer_socket_recv(host->socket, buf, sizeof(buf), &from, &from_len);

        if (n < 0) {
#if defined(_WIN32)
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK || err == WSAETIMEDOUT) break;
            break;
#else
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            break;
#endif
        }

        if (n > 0) {
            process_packet(host, buf, n, &from, from_len);
            processed++;
        }

        uint64_t elapsed = speer_timestamp_ms() - start;
        if (elapsed >= (uint64_t)timeout_ms) break;
    }

    speer_peer_check_all_timeouts(host);

    host->last_poll_ms = speer_timestamp_ms();

    return processed;
}

void speer_host_set_callback(speer_host_t *host,
                             void (*callback)(speer_host_t *host, const speer_event_t *event,
                                              void *user_data),
                             void *user_data) {
    host->callback = callback;
    host->user_data = user_data;
}

const uint8_t *speer_host_get_public_key(const speer_host_t *host) {
    return host ? host->pubkey : NULL;
}

uint16_t speer_host_get_port(const speer_host_t *host) {
    return host ? host->config.bind_port : 0;
}

int speer_peer_set_address(speer_peer_t *peer, const char *address) {
    if (!peer || !address) return SPEER_ERROR_INVALID_PARAM;

    char host[256];
    char *port_str = NULL;

    COPY(host, address, sizeof(host) - 1);
    host[sizeof(host) - 1] = 0;

    char *colon = strrchr(host, ':');
    if (colon) {
        *colon = 0;
        port_str = colon + 1;
    }

    uint16_t port = port_str ? (uint16_t)atoi(port_str) : 0;
    if (port == 0) port = speer_host_get_port(peer->host);

    struct sockaddr_in *sin = (struct sockaddr_in *)&peer->addr;
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);

#if defined(_WIN32)
    sin->sin_addr.s_addr = inet_addr(host);
    if (sin->sin_addr.s_addr == INADDR_NONE) {
        struct hostent *he = gethostbyname(host);
        if (he && he->h_addrtype == AF_INET) {
            memcpy(&sin->sin_addr, he->h_addr, 4);
        } else {
            return SPEER_ERROR_NETWORK;
        }
    }
#else
    if (inet_pton(AF_INET, host, &sin->sin_addr) != 1) {
        struct hostent *he = gethostbyname(host);
        if (he && he->h_addrtype == AF_INET) {
            memcpy(&sin->sin_addr, he->h_addr_list[0], 4);
        } else {
            return SPEER_ERROR_NETWORK;
        }
    }
#endif

    peer->addr_len = sizeof(struct sockaddr_in);
    return SPEER_OK;
}

speer_peer_t *speer_connect(speer_host_t *host, const uint8_t public_key[SPEER_PUBLIC_KEY_SIZE],
                            const char *address) {
    speer_peer_t *existing = speer_peer_lookup_by_pubkey(host, public_key);
    if (existing) return existing;

    speer_peer_t *peer = speer_peer_create(host, public_key);
    if (!peer) return NULL;

    peer->state = SPEER_STATE_HANDSHAKE;

    if (address && speer_peer_set_address(peer, address) != SPEER_OK) {
        speer_peer_destroy(peer);
        return NULL;
    }

    uint8_t packet[SPEER_MAX_PACKET_SIZE];
    size_t packet_len = 0;

    packet[packet_len++] = SPEER_PACKET_VERSION;
    packet[packet_len++] = PACKET_TYPE_INITIAL;
    packet[packet_len++] = peer->conn.cid_len;
    COPY(packet + packet_len, peer->conn.cid, peer->conn.cid_len);
    packet_len += peer->conn.cid_len;
    packet_len += speer_varint_encode(packet + packet_len, peer->conn.pkt_num);
    speer_noise_xx_init(&peer->handshake, host->pubkey, host->privkey);
    if (speer_noise_xx_write_msg1(&peer->handshake, packet + packet_len) != 0) {
        speer_peer_destroy(peer);
        return NULL;
    }
    packet_len += 32;

    if (address && peer->addr_len > 0) {
        if (speer_socket_send(host->socket, packet, packet_len, &peer->addr, peer->addr_len) < 0) {
            speer_peer_destroy(peer);
            return NULL;
        }
        for (int i = 0; i < 10 && peer->state != SPEER_STATE_ESTABLISHED; i++) {
            speer_host_poll(host, 50);
        }
    }

    return peer;
}

speer_stream_t *speer_stream_open(speer_peer_t *peer, uint32_t stream_id) {
    if (!peer || peer->state != SPEER_STATE_ESTABLISHED) return NULL;

    speer_stream_internal_t *s = speer_stream_lookup(peer, stream_id);
    if (!s) {
        s = speer_stream_create(peer, stream_id);
        if (!s) return NULL;

        speer_event_t ev = {.type = SPEER_EVENT_STREAM_OPENED,
                            .peer = peer,
                            .stream = (speer_stream_t *)s,
                            .stream_id = stream_id};
        if (peer->host->callback) { peer->host->callback(peer->host, &ev, peer->host->user_data); }
    }

    speer_stream_t *wrapper = (speer_stream_t *)malloc(sizeof(speer_stream_t));
    if (!wrapper) return NULL;

    wrapper->peer = peer;
    wrapper->id = stream_id;

    return wrapper;
}

void speer_stream_close(speer_stream_t *stream) {
    if (!stream) return;

    speer_stream_internal_t *s = speer_stream_lookup(stream->peer, stream->id);
    if (s) {
        speer_stream_destroy(stream->peer, s);

        speer_event_t ev = {.type = SPEER_EVENT_STREAM_CLOSED,
                            .peer = stream->peer,
                            .stream = stream,
                            .stream_id = stream->id};
        if (stream->peer->host->callback) {
            stream->peer->host->callback(stream->peer->host, &ev, stream->peer->host->user_data);
        }
    }

    free(stream);
}

int speer_stream_write(speer_stream_t *stream, const uint8_t *data, size_t len) {
    if (!stream || !stream->peer) return SPEER_ERROR_INVALID_PARAM;

    speer_peer_t *peer = stream->peer;
    if (peer->state != SPEER_STATE_ESTABLISHED) return SPEER_ERROR_HANDSHAKE;

    uint8_t packet[SPEER_MAX_PACKET_SIZE];
    size_t packet_len;

    int ret = init_packet(peer, stream->id, packet, &packet_len, data, len);
    if (ret != 0) return ret;

    int n = speer_socket_send(peer->host->socket, packet, packet_len, &peer->addr, peer->addr_len);
    if (n < 0) return SPEER_ERROR_NETWORK;

    peer->conn.pkt_num++;
    peer->conn.last_send_ms = speer_timestamp_ms();

    return (int)len;
}

int speer_stream_read(speer_stream_t *stream, uint8_t *buf, size_t cap) {
    if (!stream || !buf || cap == 0) return SPEER_ERROR_INVALID_PARAM;
    if (!stream->peer) return SPEER_ERROR_INVALID_PARAM;
    speer_stream_internal_t *s = speer_stream_lookup(stream->peer, stream->id);
    if (!s) return SPEER_ERROR_STREAM_CLOSED;
    size_t available = s->recv_buf_len - s->recv_buf_rdpos;
    if (available == 0) return 0;
    size_t to_read = (available < cap) ? available : cap;
    COPY(buf, s->recv_buf + s->recv_buf_rdpos, to_read);
    s->recv_buf_rdpos += to_read;
    if (s->recv_buf_rdpos >= s->recv_buf_len) {
        s->recv_buf_rdpos = 0;
        s->recv_buf_len = 0;
    }
    return (int)to_read;
}

bool speer_stream_is_open(const speer_stream_t *stream) {
    if (!stream || !stream->peer) return false;
    speer_stream_internal_t *s = speer_stream_lookup(stream->peer, stream->id);
    return s != NULL && s->state != 0;
}

uint32_t speer_stream_get_id(const speer_stream_t *stream) {
    return stream ? stream->id : 0;
}
