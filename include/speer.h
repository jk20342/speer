/**
 * @file speer.h
 * @brief speer - A tiny libp2p implementation in C
 *
 * speer is a minimal peer-to-peer networking library implementing the libp2p
 * protocol stack. It provides a layered architecture from low-level crypto
 * to high-level P2P abstractions, all in ~20k lines of C with zero dependencies.
 *
 * @author speer contributors
 * @version 0.1.0
 * @date 2024
 *
 * @copyright MIT License
 *
 * @section layers Architecture Layers
 *
 * - Layer 1: speer-native - Noise XX handshake + reliable UDP + ChaCha20-Poly1305
 * - Layer 2: libp2p over TCP - libp2p Noise, yamux, multistream-select
 * - Layer 3: QUIC v1 - Full QUIC protocol with TLS 1.3
 * - Layer 4: Web PKI - X.509, RSA, ECDSA for certificate verification (optional)
 *
 * @section quickstart Quick Start
 * @code{c}
 * #include "speer.h"
 *
 * uint8_t seed[32] = {0}; // Use proper seed in production!
 * speer_host_t* host = speer_host_new(seed, NULL);
 *
 * const uint8_t* my_pubkey = speer_host_get_public_key(host);
 * printf("My public key: ");
 * for (int i = 0; i < 32; i++) printf("%02x", my_pubkey[i]);
 * printf("\n");
 *
 * // Event-driven processing
 * speer_host_set_callback(host, on_event, NULL);
 * while (running) {
 *     speer_host_poll(host, 100);
 * }
 *
 * speer_host_free(host);
 * @endcode
 */

#ifndef SPEER_H
#define SPEER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @name Version Constants */
/**@{*/
#define SPEER_VERSION_MAJOR 0 /**< Major version number */
#define SPEER_VERSION_MINOR 1 /**< Minor version number */
#define SPEER_VERSION_PATCH 0 /**< Patch version number */
/**@}*/

/** @name Size Constants */
/**@{*/
#define SPEER_PUBLIC_KEY_SIZE    32   /**< Ed25519 public key size in bytes */
#define SPEER_PRIVATE_KEY_SIZE   32   /**< Ed25519 private key size in bytes */
#define SPEER_CONNECTION_ID_SIZE 8    /**< Connection ID size in bytes */
#define SPEER_MAX_PACKET_SIZE    1350 /**< Maximum UDP packet payload size */
#define SPEER_MAX_STREAMS        1024 /**< Maximum concurrent streams per peer */
#define SPEER_MAX_PEERS          256  /**< Maximum connected peers per host */
/**@}*/

/**
 * @brief Opaque handle to a speer host instance
 *
 * A host represents a local node in the P2P network. It manages the UDP socket,
 * all peer connections, cryptographic keys, and the event loop.
 */
typedef struct speer_host speer_host_t;

/**
 * @brief Opaque handle to a peer connection
 *
 * A peer represents a remote node that this host has established (or is
 * establishing) a connection with.
 */
typedef struct speer_peer speer_peer_t;

/**
 * @brief Opaque handle to a stream
 *
 * A stream is a bidirectional byte stream multiplexed over a peer connection.
 * Multiple streams can exist simultaneously over a single peer connection.
 */
typedef struct speer_stream speer_stream_t;

/**
 * @brief Result codes for speer operations
 */
typedef enum {
    SPEER_OK = 0,                      /**< Success */
    SPEER_ERROR_INVALID_PARAM = -1,    /**< Invalid parameter passed */
    SPEER_ERROR_NO_MEMORY = -2,        /**< Memory allocation failed */
    SPEER_ERROR_NETWORK = -3,          /**< Network operation failed */
    SPEER_ERROR_CRYPTO = -4,           /**< Cryptographic operation failed */
    SPEER_ERROR_HANDSHAKE = -5,        /**< Handshake failed or invalid */
    SPEER_ERROR_TIMEOUT = -6,          /**< Operation timed out */
    SPEER_ERROR_PEER_NOT_FOUND = -7,   /**< Peer not found */
    SPEER_ERROR_STREAM_CLOSED = -8,    /**< Stream is closed */
    SPEER_ERROR_BUFFER_TOO_SMALL = -9, /**< Buffer too small */
} speer_result_t;

/**
 * @brief Event types passed to the host callback
 */
typedef enum {
    SPEER_EVENT_NONE = 0,          /**< No event (placeholder) */
    SPEER_EVENT_PEER_CONNECTED,    /**< Peer connection established */
    SPEER_EVENT_PEER_DISCONNECTED, /**< Peer connection closed */
    SPEER_EVENT_STREAM_OPENED,     /**< New stream opened */
    SPEER_EVENT_STREAM_DATA,       /**< Data received on stream */
    SPEER_EVENT_STREAM_CLOSED,     /**< Stream closed */
    SPEER_EVENT_ERROR,             /**< Error occurred */
} speer_event_type_t;

/**
 * @brief Reasons for peer disconnection
 */
typedef enum {
    SPEER_DISCONNECT_NORMAL = 0,       /**< Normal/requested disconnect */
    SPEER_DISCONNECT_TIMEOUT,          /**< Connection timed out */
    SPEER_DISCONNECT_HANDSHAKE_FAILED, /**< Handshake failed */
    SPEER_DISCONNECT_PROTOCOL_ERROR,   /**< Protocol error occurred */
    SPEER_DISCONNECT_APPLICATION,      /**< Application requested disconnect */
} speer_disconnect_reason_t;

/**
 * @brief Event structure passed to the host callback
 *
 * This structure contains all information about an event that occurred.
 * The valid fields depend on the event type.
 */
typedef struct {
    speer_event_type_t type;                     /**< Type of event */
    speer_peer_t *peer;                          /**< Associated peer (if applicable) */
    speer_stream_t *stream;                      /**< Associated stream (if applicable) */
    uint32_t stream_id;                          /**< Stream ID (for stream events) */
    const uint8_t *data;                         /**< Data pointer (for STREAM_DATA) */
    size_t len;                                  /**< Data length (for STREAM_DATA) */
    int error_code;                              /**< Error code (for ERROR events) */
    speer_disconnect_reason_t disconnect_reason; /**< Disconnect reason */
} speer_event_t;

/**
 * @brief Configuration options for speer_host_new()
 *
 * Use speer_config_default() to initialize with sensible defaults before
 * modifying specific fields.
 */
typedef struct {
    uint16_t bind_port;             /**< UDP port to bind (0 = auto) */
    const char *bind_address;       /**< Bind address (NULL = all interfaces) */
    const char *stun_server;        /**< STUN server address (NULL = disabled) */
    const char *relay_server;       /**< Relay server address (NULL = disabled) */
    uint32_t max_peers;             /**< Maximum peers (default: SPEER_MAX_PEERS) */
    uint32_t max_streams;           /**< Maximum streams (default: SPEER_MAX_STREAMS) */
    uint32_t handshake_timeout_ms;  /**< Handshake timeout in milliseconds */
    uint32_t keepalive_interval_ms; /**< Keepalive interval in milliseconds */
} speer_config_t;

/**
 * @brief Initialize configuration with default values
 *
 * @param cfg Pointer to configuration structure to initialize
 *
 * @note Always call this before modifying config to ensure forward compatibility
 */
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

/** @name Host Management */
/**@{*/

/**
 * @brief Create a new speer host
 *
 * Creates a new host instance with the given seed key and configuration.
 * The seed key is used to deterministically generate the Ed25519 keypair.
 *
 * @param seed_key 32-byte seed for key generation (use random bytes in production)
 * @param config Configuration options (NULL for defaults)
 * @return New host instance, or NULL on error
 *
 * @note The host takes ownership of the socket and will bind to the configured port
 * @note Use speer_host_free() to release resources
 */
speer_host_t *speer_host_new(const uint8_t seed_key[SPEER_PRIVATE_KEY_SIZE],
                             const speer_config_t *config);

/**
 * @brief Free a host and all associated resources
 *
 * Closes all peer connections, frees all memory, and closes the socket.
 * The host pointer is invalid after this call.
 *
 * @param host Host to free (may be NULL)
 */
void speer_host_free(speer_host_t *host);

/**
 * @brief Poll for network events
 *
 * Processes incoming packets, handles timeouts, and invokes callbacks.
 * This is the main event loop function and should be called regularly.
 *
 * @param host Host instance
 * @param timeout_ms Maximum time to block waiting for events (0 = non-blocking)
 * @return Number of packets processed, or negative on error
 */
int speer_host_poll(speer_host_t *host, int timeout_ms);

/**
 * @brief Set the event callback function
 *
 * The callback is invoked for all significant events (connections, data, errors).
 *
 * @param host Host instance
 * @param callback Function to call for events (NULL to disable)
 * @param user_data User data passed to callback
 */
void speer_host_set_callback(speer_host_t *host,
                             void (*callback)(speer_host_t *host, const speer_event_t *event,
                                              void *user_data),
                             void *user_data);

/**
 * @brief Get the host's public key
 *
 * Returns the Ed25519 public key that identifies this host.
 *
 * @param host Host instance
 * @return Pointer to 32-byte public key, or NULL
 */
const uint8_t *speer_host_get_public_key(const speer_host_t *host);

/**
 * @brief Get the host's bound port
 *
 * @param host Host instance
 * @return UDP port number, or 0 on error
 */
uint16_t speer_host_get_port(const speer_host_t *host);

/**@}*/

/** @name Peer Management */
/**@{*/

/**
 * @brief Connect to a remote peer
 *
 * Initiates a connection to a peer with the given public key.
 * If address is provided, sends the initial handshake packet.
 *
 * @param host Host instance
 * @param public_key Remote peer's 32-byte Ed25519 public key
 * @param address Remote address as "host:port" string (may be NULL for DHT discovery)
 * @return Peer handle, or NULL on error
 *
 * @note The peer may not be immediately connected - wait for SPEER_EVENT_PEER_CONNECTED
 */
speer_peer_t *speer_connect(speer_host_t *host, const uint8_t public_key[SPEER_PUBLIC_KEY_SIZE],
                            const char *address);

/**
 * @brief Close a peer connection
 *
 * Gracefully closes the connection and frees the peer handle.
 *
 * @param peer Peer to close (may be NULL)
 */
void speer_peer_close(speer_peer_t *peer);

/**
 * @brief Set/update the peer's network address
 *
 * Updates where to send packets for this peer. Used for NAT traversal
 * after discovering the peer's mapped address via STUN or DHT.
 *
 * @param peer Peer instance
 * @param address New address as "host:port" string
 * @return SPEER_OK on success, error code on failure
 */
int speer_peer_set_address(speer_peer_t *peer, const char *address);

/**
 * @brief Check if peer connection is established
 *
 * @param peer Peer instance
 * @return true if handshake complete and connection established
 */
bool speer_peer_is_connected(const speer_peer_t *peer);

/**
 * @brief Get the peer's public key
 *
 * @param peer Peer instance
 * @return Pointer to 32-byte public key, or NULL
 */
const uint8_t *speer_peer_get_public_key(const speer_peer_t *peer);

/**@}*/

/** @name Stream Management */
/**@{*/

/**
 * @brief Open a new stream to a peer
 *
 * Creates a new bidirectional stream over the peer connection.
 * If stream_id is 0, auto-assigns the next available ID.
 *
 * @param peer Peer instance
 * @param stream_id Stream ID (0 for auto-assign)
 * @return New stream handle, or NULL on error
 */
speer_stream_t *speer_stream_open(speer_peer_t *peer, uint32_t stream_id);

/**
 * @brief Close a stream
 *
 * Closes the stream and notifies the remote peer.
 *
 * @param stream Stream to close (may be NULL)
 */
void speer_stream_close(speer_stream_t *stream);

/**
 * @brief Write data to a stream
 *
 * Sends data to the remote peer on this stream.
 *
 * @param stream Stream instance
 * @param data Data to send
 * @param len Number of bytes to send
 * @return Number of bytes sent, or negative error code
 */
int speer_stream_write(speer_stream_t *stream, const uint8_t *data, size_t len);

/**
 * @brief Read data from a stream
 *
 * Reads data from the stream's receive buffer. This is non-blocking
 * and returns immediately if no data is available.
 *
 * @param stream Stream instance
 * @param buf Buffer to receive data
 * @param cap Capacity of buffer in bytes
 * @return Number of bytes read, 0 if no data, or negative error code
 */
int speer_stream_read(speer_stream_t *stream, uint8_t *buf, size_t cap);

/**
 * @brief Check if a stream is open
 *
 * @param stream Stream instance
 * @return true if stream is open and can be used
 */
bool speer_stream_is_open(const speer_stream_t *stream);

/**
 * @brief Get the stream ID
 *
 * @param stream Stream instance
 * @return Stream ID, or 0 on error
 */
uint32_t speer_stream_get_id(const speer_stream_t *stream);

/**@}*/

/** @name Cryptographic Utilities */
/**@{*/

/**
 * @brief Generate an Ed25519 keypair from a seed
 *
 * Deterministically generates a keypair from the given seed.
 * The same seed always produces the same keypair.
 *
 * @param[out] public_key Buffer to receive 32-byte public key
 * @param[out] private_key Buffer to receive 32-byte private key
 * @param seed 32-byte seed value
 * @return SPEER_OK on success, error code on failure
 */
int speer_generate_keypair(uint8_t public_key[SPEER_PUBLIC_KEY_SIZE],
                           uint8_t private_key[SPEER_PRIVATE_KEY_SIZE], const uint8_t seed[32]);

/**
 * @brief Generate cryptographically secure random bytes
 *
 * Uses the system CSPRNG (e.g., getrandom on Linux, BCryptGenRandom on Windows).
 *
 * @param[out] buf Buffer to fill with random bytes
 * @param len Number of bytes to generate
 */
void speer_random_bytes(uint8_t *buf, size_t len);

/**
 * @brief Get current timestamp in milliseconds
 *
 * Returns the number of milliseconds since an arbitrary epoch.
 * Suitable for measuring intervals and timeouts.
 *
 * @return Timestamp in milliseconds
 */
uint64_t speer_timestamp_ms(void);

/**@}*/

#ifdef __cplusplus
}
#endif

#endif /* SPEER_H */
