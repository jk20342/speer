#ifndef SPEER_INTERNAL_H
#define SPEER_INTERNAL_H

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200112L
#endif

#include "speer.h"

#include <stdlib.h>

#include <assert.h>
#include <string.h>

#if defined(_WIN32)
#include <winsock2.h>
#include <windows.h>

#include <ws2tcpip.h>
typedef int socklen_t;
#define CLOSESOCKET closesocket
#define SHUT_RDWR   SD_BOTH
#ifndef SHUT_WR
#define SHUT_WR SD_SEND
#endif
#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY 27
#endif
#else
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <time.h>
#include <unistd.h>
#define CLOSESOCKET close
#endif

#define SPEER_STATE_INITIAL      0
#define SPEER_STATE_HANDSHAKE    1
#define SPEER_STATE_ESTABLISHED  2
#define SPEER_STATE_CLOSING      3
#define SPEER_STATE_CLOSED       4

#define SPEER_PACKET_VERSION     1
#define SPEER_MAX_CID_LEN        20
#define SPEER_MIN_CID_LEN        8
#define SPEER_INITIAL_TIMEOUT_MS 500
#define SPEER_MAX_TIMEOUT_MS     60000
#define SPEER_DEFAULT_MTU        1350

#if defined(_MSC_VER)
#define ALIGN(n)    __declspec(align(n))
#define LIKELY(x)   (x)
#define UNLIKELY(x) (x)
#define INLINE      __forceinline
#define NOINLINE    __declspec(noinline)
#define ATTR_PURE
#define ATTR_CONST
#define PACKED
#else
#define ALIGN(n)    __attribute__((aligned(n)))
#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#define INLINE      inline __attribute__((always_inline))
#define NOINLINE    __attribute__((noinline))
#define ATTR_PURE   __attribute__((pure))
#define ATTR_CONST  __attribute__((const))
#define PACKED      __attribute__((packed))
#endif

#define ARRAY_SIZE(arr)  (sizeof(arr) / sizeof((arr)[0]))
#define MIN(a, b)        ((a) < (b) ? (a) : (b))
#define MAX(a, b)        ((a) > (b) ? (a) : (b))
#define CLAMP(x, lo, hi) MAX((lo), MIN((x), (hi)))
#define SWAP32(a, b)               \
    do {                           \
        uint32_t tmp[32];          \
        COPY(tmp, a, sizeof(tmp)); \
        COPY(a, b, sizeof(tmp));   \
        COPY(b, tmp, sizeof(tmp)); \
    } while (0)

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))
#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

#define LOAD32_LE(p)                                                                 \
    (((uint32_t)((p)[0])) | ((uint32_t)((p)[1]) << 8) | ((uint32_t)((p)[2]) << 16) | \
     ((uint32_t)((p)[3]) << 24))

#define STORE32_LE(p, v)               \
    do {                               \
        (p)[0] = (uint8_t)((v));       \
        (p)[1] = (uint8_t)((v) >> 8);  \
        (p)[2] = (uint8_t)((v) >> 16); \
        (p)[3] = (uint8_t)((v) >> 24); \
    } while (0)

#define LOAD64_LE(p) (((uint64_t)LOAD32_LE(p)) | ((uint64_t)LOAD32_LE((p) + 4) << 32))

#define STORE64_LE(p, v)                            \
    do {                                            \
        STORE32_LE((p), (uint32_t)((v)));           \
        STORE32_LE((p) + 4, (uint32_t)((v) >> 32)); \
    } while (0)

#define LOAD32_BE(p)                                                                       \
    (((uint32_t)((p)[0]) << 24) | ((uint32_t)((p)[1]) << 16) | ((uint32_t)((p)[2]) << 8) | \
     ((uint32_t)((p)[3])))

#define STORE32_BE(p, v)               \
    do {                               \
        (p)[0] = (uint8_t)((v) >> 24); \
        (p)[1] = (uint8_t)((v) >> 16); \
        (p)[2] = (uint8_t)((v) >> 8);  \
        (p)[3] = (uint8_t)(v);         \
    } while (0)

#define STORE16_BE(p, v)              \
    do {                              \
        (p)[0] = (uint8_t)((v) >> 8); \
        (p)[1] = (uint8_t)(v);        \
    } while (0)

#define LOAD16_BE(p)        (((uint16_t)((p)[0]) << 8) | ((uint16_t)((p)[1])))

#define U8V(v)              ((uint8_t)(v) & 0xFFU)
#define U16V(v)             ((uint16_t)(v) & 0xFFFFU)
#define U32V(v)             ((uint32_t)(v) & 0xFFFFFFFFU)
#define U64V(v)             ((uint64_t)(v))

#define ZERO(dst, len)      memset((dst), 0, (len))
#define COPY(dst, src, len) memcpy((dst), (src), (len))
#define EQUAL(a, b, len)    (memcmp((a), (b), (len)) == 0)

#define WIPE(ptr, len)                                    \
    do {                                                  \
        volatile uint8_t *_p = (volatile uint8_t *)(ptr); \
        size_t _n = (len);                                \
        while (_n--) *_p++ = 0;                           \
    } while (0)

typedef struct {
    uint8_t data[32];
} ALIGN(32) speer_key_t;

typedef struct {
    uint32_t state[16];
    size_t idx;
} speer_chacha_ctx_t;

typedef struct {
    uint8_t cid[SPEER_MAX_CID_LEN];
    uint8_t cid_len;
    uint64_t pkt_num;
    uint64_t ack_num;
    uint32_t rtt_ms;
    uint32_t rtt_var_ms;
    uint32_t timeout_ms;
    uint64_t last_send_ms;
    uint64_t last_recv_ms;
    uint64_t bytes_sent;
    uint64_t bytes_recv;
    uint32_t cwnd;
    uint32_t ssthresh;
    uint16_t mtu;
} speer_conn_t;

typedef struct speer_stream_s {
    uint32_t id;
    uint32_t state;
    uint64_t send_offset;
    uint64_t recv_offset;
    uint64_t max_send_offset;
    uint64_t max_recv_offset;
    struct speer_stream_s *next;
    struct speer_stream_s *prev;
    uint8_t *recv_buf;
    size_t recv_buf_len;
    size_t recv_buf_cap;
    size_t recv_buf_rdpos;
} speer_stream_internal_t;

typedef struct {
    uint8_t local_pubkey[SPEER_PUBLIC_KEY_SIZE];
    uint8_t local_privkey[SPEER_PRIVATE_KEY_SIZE];
    uint8_t remote_pubkey[SPEER_PUBLIC_KEY_SIZE];
    uint8_t ephemeral_key[32];
    uint8_t remote_ephemeral[32];
    uint8_t chaining_key[32];
    uint8_t handshake_hash[32];
    uint8_t send_key[32];
    uint8_t recv_key[32];
    uint8_t nonce[12];
    uint64_t cipher_n;
    uint32_t state;
    uint32_t step;
} speer_handshake_t;

typedef struct {
    uint8_t rekey_counter;
    uint8_t nonce[12];
    uint8_t key[32];
} speer_cipher_t;

struct speer_peer {
    speer_host_t *host;
    uint8_t pubkey[SPEER_PUBLIC_KEY_SIZE];
    struct sockaddr_storage addr;
    socklen_t addr_len;

    uint32_t state;
    uint32_t ref_count;
    uint64_t created_ms;

    speer_handshake_t handshake;
    speer_cipher_t send_cipher;
    speer_cipher_t recv_cipher;
    speer_conn_t conn;

    speer_stream_internal_t *streams;
    uint32_t next_stream_id;
    uint32_t max_streams;

    void *user_data;
    speer_peer_t *next;
    speer_peer_t *prev;
};

struct speer_host {
    int socket;
    struct sockaddr_storage bind_addr;
    socklen_t bind_addr_len;

    uint8_t pubkey[SPEER_PUBLIC_KEY_SIZE];
    uint8_t privkey[SPEER_PRIVATE_KEY_SIZE];

    speer_peer_t *peers;
    uint32_t peer_count;
    uint32_t max_peers;

    speer_config_t config;

    void (*callback)(speer_host_t *, const speer_event_t *, void *);
    void *user_data;

    uint64_t last_poll_ms;
    uint32_t next_cid[4];

    uint8_t handshake_buf[512];
    size_t handshake_len;
};

struct speer_stream {
    speer_peer_t *peer;
    uint32_t id;
};

void speer_crypto_init(void);
void speer_chacha_init(speer_chacha_ctx_t *ctx, const uint8_t key[32], const uint8_t nonce[12]);
void speer_chacha_block(speer_chacha_ctx_t *ctx, uint8_t out[64]);
void speer_chacha_crypt(speer_chacha_ctx_t *ctx, uint8_t *out, const uint8_t *in, size_t len);
int speer_chacha_block_counter_at_max(const speer_chacha_ctx_t *ctx);

int speer_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);
void speer_x25519_base(uint8_t out[32], const uint8_t scalar[32]);

void speer_poly1305(uint8_t mac[16], const uint8_t *msg, size_t len, const uint8_t key[32]);

int speer_aes_gcm_encrypt(uint8_t *out, const uint8_t *in, size_t len, const uint8_t key[32],
                          const uint8_t iv[12], const uint8_t *aad, size_t aad_len,
                          uint8_t tag[16]);
int speer_aes_gcm_decrypt(uint8_t *out, const uint8_t *in, size_t len, const uint8_t key[32],
                          const uint8_t iv[12], const uint8_t *aad, size_t aad_len,
                          const uint8_t tag[16]);

void speer_sha256(uint8_t out[32], const uint8_t *in, size_t len);
void speer_sha384(uint8_t out[48], const uint8_t *in, size_t len);
void speer_sha512(uint8_t out[64], const uint8_t *in, size_t len);
typedef struct {
    uint32_t state[8];
    uint64_t bit_count;
    uint8_t buffer[64];
    size_t buffer_used;
} sha256_ctx_t;

void speer_sha256_init(void *state);
void speer_sha256_update(void *state, const uint8_t *in, size_t len);
void speer_sha256_final(void *state, uint8_t out[32]);

typedef struct {
    uint64_t state[8];
    uint64_t bit_count_lo;
    uint64_t bit_count_hi;
    uint8_t buffer[128];
    size_t buffer_used;
    size_t digest_size;
} sha512_ctx_t;

void speer_sha512_init(sha512_ctx_t *ctx);
void speer_sha384_init(sha512_ctx_t *ctx);
void speer_sha512_update(sha512_ctx_t *ctx, const uint8_t *in, size_t len);
void speer_sha512_final(sha512_ctx_t *ctx, uint8_t *out);

void speer_hkdf(uint8_t *okm, size_t okm_len, const uint8_t *salt, size_t salt_len,
                const uint8_t *ikm, size_t ikm_len, const uint8_t *info, size_t info_len);

void speer_hkdf_extract(uint8_t prk[32], const uint8_t *salt, size_t salt_len, const uint8_t *ikm,
                        size_t ikm_len);
void speer_hkdf_expand(uint8_t *okm, size_t okm_len, const uint8_t prk[32], const uint8_t *info,
                       size_t info_len);

int speer_noise_xx_init(speer_handshake_t *hs, const uint8_t local_pubkey[32],
                        const uint8_t local_privkey[32]);
int speer_noise_xx_write_e(speer_handshake_t *hs, uint8_t *out, size_t *len);
int speer_noise_xx_read_e(speer_handshake_t *hs, const uint8_t *in, size_t len);
int speer_noise_xx_write_s(speer_handshake_t *hs, uint8_t *out, size_t *len);
int speer_noise_xx_read_s(speer_handshake_t *hs, const uint8_t *in, size_t len);
void speer_noise_xx_split(speer_handshake_t *hs, uint8_t send_key[32], uint8_t recv_key[32]);
int speer_noise_xx_write_msg1(speer_handshake_t *hs, uint8_t out[32]);
int speer_noise_xx_read_msg1(speer_handshake_t *hs, const uint8_t in[32]);
int speer_noise_xx_write_msg2(speer_handshake_t *hs, uint8_t out[80]);
int speer_noise_xx_read_msg2(speer_handshake_t *hs, const uint8_t in[80]);
int speer_noise_xx_write_msg3(speer_handshake_t *hs, uint8_t out[48]);
int speer_noise_xx_read_msg3(speer_handshake_t *hs, const uint8_t in[48]);

int speer_noise_xx_write_msg2_p(speer_handshake_t *hs, const uint8_t *payload, size_t payload_len,
                                uint8_t *out, size_t out_cap, size_t *out_len);
int speer_noise_xx_read_msg2_p(speer_handshake_t *hs, const uint8_t *in, size_t in_len,
                               uint8_t *payload_out, size_t payload_cap, size_t *payload_len);
int speer_noise_xx_write_msg3_p(speer_handshake_t *hs, const uint8_t *payload, size_t payload_len,
                                uint8_t *out, size_t out_cap, size_t *out_len);
int speer_noise_xx_read_msg3_p(speer_handshake_t *hs, const uint8_t *in, size_t in_len,
                               uint8_t *payload_out, size_t payload_cap, size_t *payload_len);

int speer_packet_encode(uint8_t *out, size_t *out_len, const uint8_t *in, size_t in_len,
                        const uint8_t cid[SPEER_MAX_CID_LEN], uint8_t cid_len, uint64_t pkt_num,
                        const uint8_t key[32]);
int speer_packet_decode(uint8_t *out, size_t *out_len, const uint8_t *in, size_t in_len,
                        uint8_t cid[SPEER_MAX_CID_LEN], uint8_t *cid_len, uint64_t *pkt_num,
                        const uint8_t key[32]);

size_t speer_varint_encode(uint8_t *out, uint64_t val);
size_t speer_varint_decode(const uint8_t *in, size_t avail, uint64_t *val);

void speer_conn_init(speer_conn_t *conn);
void speer_conn_update_rtt(speer_conn_t *conn, uint32_t rtt_sample);
uint32_t speer_conn_get_timeout(speer_conn_t *conn);

speer_peer_t *speer_peer_lookup(speer_host_t *host, const uint8_t cid[SPEER_MAX_CID_LEN],
                                uint8_t cid_len);
speer_peer_t *speer_peer_lookup_by_pubkey(speer_host_t *host,
                                          const uint8_t pubkey[SPEER_PUBLIC_KEY_SIZE]);
speer_peer_t *speer_peer_create(speer_host_t *host, const uint8_t pubkey[SPEER_PUBLIC_KEY_SIZE]);
void speer_peer_destroy(speer_peer_t *peer);

speer_stream_internal_t *speer_stream_lookup(speer_peer_t *peer, uint32_t stream_id);
speer_stream_internal_t *speer_stream_create(speer_peer_t *peer, uint32_t stream_id);
void speer_stream_destroy(speer_peer_t *peer, speer_stream_internal_t *stream);

int speer_socket_create(uint16_t port, const char *bind_addr);
int speer_socket_recv(int sock, uint8_t *buf, size_t len, struct sockaddr_storage *addr,
                      socklen_t *addr_len);
int speer_socket_send(int sock, const uint8_t *buf, size_t len, const struct sockaddr_storage *addr,
                      socklen_t addr_len);
void speer_socket_close(int sock);
int speer_socket_set_nonblocking(int sock);

int speer_stun_get_mapped_addr(const char *stun_server, struct sockaddr_storage *mapped_addr,
                               socklen_t *mapped_len);

int speer_relay_connect(const char *relay_server, const uint8_t local_pubkey[SPEER_PUBLIC_KEY_SIZE],
                        const uint8_t remote_pubkey[SPEER_PUBLIC_KEY_SIZE]);

size_t speer_frame_encode_ack(uint8_t *out, uint64_t largest_acked, uint64_t ack_delay,
                              const uint8_t *ranges, size_t num_ranges);
size_t speer_frame_encode_stream(uint8_t *out, uint32_t stream_id, uint64_t offset,
                                 const uint8_t *data, size_t len, bool fin);

void speer_transport_cleanup(speer_peer_t *peer);
void speer_peer_check_all_timeouts(speer_host_t *host);

int speer_peer_set_address(speer_peer_t *peer, const char *address);

#endif
