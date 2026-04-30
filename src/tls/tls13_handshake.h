#ifndef SPEER_TLS13_HANDSHAKE_H
#define SPEER_TLS13_HANDSHAKE_H

#include <stddef.h>
#include <stdint.h>

#include "peer_id.h"
#include "tls13_keysched.h"
#include "tls13_record.h"

#define SPEER_TLS_OK       0
#define SPEER_TLS_NEED_OUT 1
#define SPEER_TLS_DONE     2
#define SPEER_TLS_ERR      -1

typedef enum {
    SPEER_TLS_ROLE_CLIENT = 0,
    SPEER_TLS_ROLE_SERVER = 1,
} speer_tls_role_t;

typedef enum {
    TLS_ST_START = 0,
    TLS_ST_WAIT_SH,
    TLS_ST_WAIT_EE,
    TLS_ST_WAIT_CERT_OR_REQ,
    TLS_ST_WAIT_CERT,
    TLS_ST_WAIT_CV,
    TLS_ST_WAIT_FINISHED,
    TLS_ST_WAIT_CH,
    TLS_ST_NEGOTIATED,
    TLS_ST_WAIT_FLIGHT2,
    TLS_ST_WAIT_CERT_VERIFY,
    TLS_ST_WAIT_CFIN,
    TLS_ST_DONE,
    TLS_ST_ERROR,
} speer_tls_state_t;

typedef struct {
    speer_tls_role_t role;
    speer_tls_state_t state;

    speer_tls13_keysched_t ks;
    uint16_t cipher_suite;

    uint8_t our_x25519_priv[32];
    uint8_t our_x25519_pub[32];
    uint8_t peer_x25519_pub[32];

    uint8_t client_random[32];
    uint8_t server_random[32];
    uint8_t hrr_seen;
    uint16_t offered_cipher_suites[3];
    size_t offered_cipher_suites_len;
    uint16_t offered_sigalgs[8];
    size_t offered_sigalgs_len;

    uint8_t *transcript;
    size_t transcript_len;
    size_t transcript_cap;

    uint8_t cert_der[4096];
    size_t cert_der_len;

    uint8_t our_cert_priv[32];
    uint8_t our_cert_pub[32];
    uint8_t psk[64];
    size_t psk_len;

    uint8_t libp2p_pubkey_proto[256];
    size_t libp2p_pubkey_proto_len;
    uint8_t libp2p_priv[32];
    uint8_t libp2p_pub[32];

    uint8_t hs_transcript_hash[SPEER_TLS13_MAX_HASH];
    speer_tls13_keys_t client_hs_keys;
    speer_tls13_keys_t server_hs_keys;
    speer_tls13_keys_t client_app_keys;
    speer_tls13_keys_t server_app_keys;

    uint8_t transcript_hash_after_cert[SPEER_TLS13_MAX_HASH];
    uint8_t transcript_hash_after_cv[SPEER_TLS13_MAX_HASH];
    uint8_t transcript_hash_after_sfin[SPEER_TLS13_MAX_HASH];

    uint8_t peer_libp2p_pub[64];
    size_t peer_libp2p_pub_len;
    speer_libp2p_keytype_t peer_libp2p_kt;
    int peer_libp2p_verified;
    int peer_cert_outer_verified;

    uint8_t peer_spki_pubkey[600];
    size_t peer_spki_pubkey_len;
    uint16_t peer_spki_alg_tls_id;

    const char *alpn;
    char negotiated_alpn[32];

    const char *server_name;
    char peer_server_name[256];

    uint8_t out_buf[8192];
    size_t out_len;

    uint64_t client_record_seq;
    uint64_t server_record_seq;

    uint8_t alert_level;
    uint8_t alert_description;

    int require_client_auth;
    int client_finished_sent;
    int server_finished_received;
    int cert_request_seen;
} speer_tls13_t;

int speer_tls13_init_handshake(speer_tls13_t *h, speer_tls_role_t role, const uint8_t cert_priv[32],
                               const uint8_t cert_pub[32], speer_libp2p_keytype_t libp2p_kt,
                               const uint8_t *libp2p_pub, size_t libp2p_pub_len,
                               const uint8_t *libp2p_priv, size_t libp2p_priv_len, const char *alpn,
                               const char *server_name);

int speer_tls13_handshake_start(speer_tls13_t *h);
int speer_tls13_set_psk(speer_tls13_t *h, const uint8_t *psk, size_t psk_len);
int speer_tls13_set_require_client_auth(speer_tls13_t *h, int required);
int speer_tls13_handshake_consume(speer_tls13_t *h, uint8_t msg_type, const uint8_t *body,
                                  size_t body_len);
int speer_tls13_handshake_take_output(speer_tls13_t *h, uint8_t *out, size_t cap, size_t *out_len);

int speer_tls13_send_key_update(speer_tls13_t *h, int request_peer_update);
int speer_tls13_send_new_session_ticket(speer_tls13_t *h, uint32_t lifetime,
                                        const uint8_t *ticket, size_t ticket_len);

int speer_tls13_export_traffic_secret(const speer_tls13_t *h, int from_server, int application,
                                      uint8_t *out, size_t *out_len);

int speer_tls13_is_done(const speer_tls13_t *h);

#endif
