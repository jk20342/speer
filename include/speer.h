#ifndef SPEER_H
#define SPEER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SPEER_VERSION_MAJOR      0
#define SPEER_VERSION_MINOR      2
#define SPEER_VERSION_PATCH      0

#define SPEER_PUBLIC_KEY_SIZE    32
#define SPEER_PRIVATE_KEY_SIZE   32
#define SPEER_CONNECTION_ID_SIZE 8
#define SPEER_MAX_PACKET_SIZE    1350
#define SPEER_MAX_STREAMS        1024
#define SPEER_MAX_PEERS          256

typedef struct speer_host speer_host_t;

typedef struct speer_peer speer_peer_t;

typedef struct speer_stream speer_stream_t;

typedef enum {
    SPEER_OK = 0,
    SPEER_ERROR_INVALID_PARAM = -1,
    SPEER_ERROR_NO_MEMORY = -2,
    SPEER_ERROR_NETWORK = -3,
    SPEER_ERROR_CRYPTO = -4,
    SPEER_ERROR_HANDSHAKE = -5,
    SPEER_ERROR_TIMEOUT = -6,
    SPEER_ERROR_PEER_NOT_FOUND = -7,
    SPEER_ERROR_STREAM_CLOSED = -8,
    SPEER_ERROR_BUFFER_TOO_SMALL = -9,
} speer_result_t;

typedef enum {
    SPEER_EVENT_NONE = 0,
    SPEER_EVENT_PEER_CONNECTED,
    SPEER_EVENT_PEER_DISCONNECTED,
    SPEER_EVENT_STREAM_OPENED,
    SPEER_EVENT_STREAM_DATA,
    SPEER_EVENT_STREAM_CLOSED,
    SPEER_EVENT_ERROR,
} speer_event_type_t;

typedef enum {
    SPEER_DISCONNECT_NORMAL = 0,
    SPEER_DISCONNECT_TIMEOUT,
    SPEER_DISCONNECT_HANDSHAKE_FAILED,
    SPEER_DISCONNECT_PROTOCOL_ERROR,
    SPEER_DISCONNECT_APPLICATION,
} speer_disconnect_reason_t;

typedef struct {
    speer_event_type_t type;
    speer_peer_t *peer;
    speer_stream_t *stream;
    uint32_t stream_id;
    const uint8_t *data;
    size_t len;
    int error_code;
    speer_disconnect_reason_t disconnect_reason;
} speer_event_t;

typedef struct {
    uint16_t bind_port;
    const char *bind_address;
    const char *stun_server;
    const char *relay_server;
    uint32_t max_peers;
    uint32_t max_streams;
    uint32_t handshake_timeout_ms;
    uint32_t keepalive_interval_ms;
} speer_config_t;

static inline void speer_config_default(speer_config_t *cfg) {
    cfg->bind_port = 0;
    cfg->bind_address = NULL;
    cfg->stun_server = NULL;
    cfg->relay_server = NULL;
    cfg->max_peers = SPEER_MAX_PEERS;
    cfg->max_streams = SPEER_MAX_STREAMS;
    cfg->handshake_timeout_ms = 10000;
    cfg->keepalive_interval_ms = 5000;
}

speer_host_t *speer_host_new(const uint8_t seed_key[SPEER_PRIVATE_KEY_SIZE],
                             const speer_config_t *config);

void speer_host_free(speer_host_t *host);

/* When set, speer_host_poll runs speer_dcutr_poll after UDP I/O (see speer_host_poll_ex). */
#define SPEER_POLL_DCUTR 1u

int speer_host_poll_ex(speer_host_t *host, int timeout_ms, unsigned flags);

int speer_host_poll(speer_host_t *host, int timeout_ms);

void speer_host_set_callback(speer_host_t *host,
                             void (*callback)(speer_host_t *host, const speer_event_t *event,
                                              void *user_data),
                             void *user_data);

const uint8_t *speer_host_get_public_key(const speer_host_t *host);

uint16_t speer_host_get_port(const speer_host_t *host);

speer_peer_t *speer_connect(speer_host_t *host, const uint8_t public_key[SPEER_PUBLIC_KEY_SIZE],
                            const char *address);

void speer_peer_close(speer_peer_t *peer);

int speer_peer_set_address(speer_peer_t *peer, const char *address);

bool speer_peer_is_connected(const speer_peer_t *peer);

const uint8_t *speer_peer_get_public_key(const speer_peer_t *peer);

speer_stream_t *speer_stream_open(speer_peer_t *peer, uint32_t stream_id);

void speer_stream_close(speer_stream_t *stream);

int speer_stream_write(speer_stream_t *stream, const uint8_t *data, size_t len);

int speer_stream_read(speer_stream_t *stream, uint8_t *buf, size_t cap);

bool speer_stream_is_open(const speer_stream_t *stream);

uint32_t speer_stream_get_id(const speer_stream_t *stream);

int speer_generate_keypair(uint8_t public_key[SPEER_PUBLIC_KEY_SIZE],
                           uint8_t private_key[SPEER_PRIVATE_KEY_SIZE], const uint8_t seed[32]);

void speer_random_bytes(uint8_t *buf, size_t len);

int speer_random_bytes_or_fail(uint8_t *buf, size_t len);

uint64_t speer_timestamp_ms(void);

#ifdef __cplusplus
}
#endif

#endif
