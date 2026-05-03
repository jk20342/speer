#include "speer_internal.h"

#if SPEER_RELAY
#include "dcutr.h"
#endif

speer_peer_t *speer_peer_lookup(speer_host_t *host, const uint8_t cid[SPEER_MAX_CID_LEN],
                                uint8_t cid_len) {
    for (speer_peer_t *p = host->peers; p; p = p->next) {
        if (p->conn.cid_len == cid_len && EQUAL(p->conn.cid, cid, cid_len)) { return p; }
    }
    return NULL;
}

speer_peer_t *speer_peer_lookup_by_pubkey(speer_host_t *host,
                                          const uint8_t pubkey[SPEER_PUBLIC_KEY_SIZE]) {
    for (speer_peer_t *p = host->peers; p; p = p->next) {
        if (EQUAL(p->pubkey, pubkey, SPEER_PUBLIC_KEY_SIZE)) { return p; }
    }
    return NULL;
}

static int generate_cid(uint8_t *cid, uint8_t *cid_len) {
    *cid_len = SPEER_CONNECTION_ID_SIZE;
    return speer_random_bytes_or_fail(cid, SPEER_CONNECTION_ID_SIZE);
}

speer_peer_t *speer_peer_create(speer_host_t *host, const uint8_t pubkey[SPEER_PUBLIC_KEY_SIZE]) {
    if (host->peer_count >= host->max_peers) return NULL;

    speer_peer_t *peer = (speer_peer_t *)calloc(1, sizeof(speer_peer_t));
    if (!peer) return NULL;

    peer->host = host;
    peer->ref_count = 1;
    peer->created_ms = speer_timestamp_ms();
    peer->state = SPEER_STATE_INITIAL;

    if (pubkey) { COPY(peer->pubkey, pubkey, SPEER_PUBLIC_KEY_SIZE); }

    speer_conn_init(&peer->conn);
    if (generate_cid(peer->conn.cid, &peer->conn.cid_len) != 0) {
        free(peer);
        return NULL;
    }

    peer->next_stream_id = 0;
    peer->max_streams = host->config.max_streams;

    DLIST_INSERT_HEAD(host->peers, peer, next, prev);
    host->peer_count++;

    return peer;
}

void speer_peer_destroy(speer_peer_t *peer) {
    if (!peer) return;

#if SPEER_RELAY
    speer_dcutr_peer_reset(peer);
#endif

    speer_transport_cleanup(peer);

    while (peer->streams) { speer_stream_destroy(peer, peer->streams); }

    WIPE(&peer->handshake, sizeof(peer->handshake));
    WIPE(&peer->send_cipher, sizeof(peer->send_cipher));
    WIPE(&peer->recv_cipher, sizeof(peer->recv_cipher));

    peer->host->peer_count--;
    DLIST_REMOVE(peer->host->peers, peer, next, prev);
    free(peer);
}

void speer_peer_close(speer_peer_t *peer) {
    if (!peer) return;
    peer->state = SPEER_STATE_CLOSED;
}

bool speer_peer_is_connected(const speer_peer_t *peer) {
    return peer && peer->state == SPEER_STATE_ESTABLISHED;
}

const uint8_t *speer_peer_get_public_key(const speer_peer_t *peer) {
    return peer ? peer->pubkey : NULL;
}

speer_stream_internal_t *speer_stream_lookup(speer_peer_t *peer, uint32_t stream_id) {
    for (speer_stream_internal_t *s = peer->streams; s; s = s->next) {
        if (s->id == stream_id) return s;
    }
    return NULL;
}

speer_stream_internal_t *speer_stream_create(speer_peer_t *peer, uint32_t stream_id) {
    speer_stream_internal_t *s = (speer_stream_internal_t *)calloc(1,
                                                                   sizeof(speer_stream_internal_t));
    if (!s) return NULL;

    s->id = stream_id;
    s->state = 1;

    DLIST_INSERT_HEAD(peer->streams, s, next, prev);
    return s;
}

void speer_stream_destroy(speer_peer_t *peer, speer_stream_internal_t *stream) {
    if (!stream) return;
    DLIST_REMOVE(peer->streams, stream, next, prev);
    if (stream->recv_buf) {
        WIPE(stream->recv_buf, stream->recv_buf_cap);
        free(stream->recv_buf);
    }
    free(stream);
}

static void peer_check_timeouts(speer_peer_t *peer, uint64_t now_ms) {
    if (peer->state == SPEER_STATE_HANDSHAKE) {
        uint32_t elapsed = (uint32_t)(now_ms - peer->created_ms);
        if (elapsed > peer->host->config.handshake_timeout_ms) { peer->state = SPEER_STATE_CLOSED; }
    }

    if (peer->state == SPEER_STATE_ESTABLISHED) {
        uint32_t elapsed = (uint32_t)(now_ms - peer->conn.last_recv_ms);
        if (elapsed > peer->host->config.keepalive_interval_ms * 3) {
            peer->state = SPEER_STATE_CLOSED;
        }
    }
}

void speer_peer_check_all_timeouts(speer_host_t *host) {
    uint64_t now = speer_timestamp_ms();
    speer_peer_t *p = host->peers;
    while (p) {
        speer_peer_t *next = p->next;
        peer_check_timeouts(p, now);
        if (p->state == SPEER_STATE_CLOSED) {
            speer_event_t ev = {.type = SPEER_EVENT_PEER_DISCONNECTED,
                                .peer = p,
                                .disconnect_reason = SPEER_DISCONNECT_TIMEOUT};
            if (host->callback) host->callback(host, &ev, host->user_data);
            speer_peer_destroy(p);
        }
        p = next;
    }
}
