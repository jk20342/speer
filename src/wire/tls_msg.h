#ifndef SPEER_TLS_MSG_H
#define SPEER_TLS_MSG_H

#include <stddef.h>
#include <stdint.h>

#define TLS_HS_CLIENT_HELLO                  0x01
#define TLS_HS_SERVER_HELLO                  0x02
#define TLS_HS_NEW_SESSION_TICKET            0x04
#define TLS_HS_END_OF_EARLY_DATA             0x05
#define TLS_HS_ENCRYPTED_EXTS                0x08
#define TLS_HS_CERTIFICATE                   0x0b
#define TLS_HS_CERT_REQUEST                  0x0d
#define TLS_HS_CERT_VERIFY                   0x0f
#define TLS_HS_FINISHED                      0x14
#define TLS_HS_KEY_UPDATE                    0x18
#define TLS_HS_MESSAGE_HASH                  0xfe

#define TLS_EXT_SERVER_NAME                  0x0000
#define TLS_EXT_SUPPORTED_GROUPS             0x000a
#define TLS_EXT_SIGNATURE_ALGORITHMS         0x000d
#define TLS_EXT_ALPN                         0x0010
#define TLS_EXT_PRE_SHARED_KEY               0x0029
#define TLS_EXT_EARLY_DATA                   0x002a
#define TLS_EXT_SUPPORTED_VERSIONS           0x002b
#define TLS_EXT_PSK_KEY_EXCHANGE_MODES       0x002d
#define TLS_EXT_KEY_SHARE                    0x0033
#define TLS_EXT_QUIC_TRANSPORT_PARAMS        0x0039

#define TLS_GROUP_X25519                     0x001d
#define TLS_GROUP_SECP256R1                  0x0017

#define TLS_SIGSCHEME_RSA_PKCS1_SHA256       0x0401
#define TLS_SIGSCHEME_RSA_PKCS1_SHA384       0x0501
#define TLS_SIGSCHEME_RSA_PKCS1_SHA512       0x0601
#define TLS_SIGSCHEME_ECDSA_SECP256R1_SHA256 0x0403
#define TLS_SIGSCHEME_ECDSA_SECP384R1_SHA384 0x0503
#define TLS_SIGSCHEME_RSA_PSS_RSAE_SHA256    0x0804
#define TLS_SIGSCHEME_RSA_PSS_RSAE_SHA384    0x0805
#define TLS_SIGSCHEME_RSA_PSS_RSAE_SHA512    0x0806
#define TLS_SIGSCHEME_ED25519                0x0807

#define TLS_CS_AES_128_GCM_SHA256            0x1301
#define TLS_CS_AES_256_GCM_SHA384            0x1302
#define TLS_CS_CHACHA20_POLY1305_SHA256      0x1303

typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t pos;
    int err;
} speer_tls_writer_t;

typedef struct {
    const uint8_t *buf;
    size_t len;
    size_t pos;
    int err;
} speer_tls_reader_t;

void speer_tls_writer_init(speer_tls_writer_t *w, uint8_t *buf, size_t cap);
int speer_tls_w_u8(speer_tls_writer_t *w, uint8_t v);
int speer_tls_w_u16(speer_tls_writer_t *w, uint16_t v);
int speer_tls_w_u24(speer_tls_writer_t *w, uint32_t v);
int speer_tls_w_bytes(speer_tls_writer_t *w, const uint8_t *d, size_t n);
int speer_tls_w_vec_u8(speer_tls_writer_t *w, const uint8_t *d, size_t n);
int speer_tls_w_vec_u16(speer_tls_writer_t *w, const uint8_t *d, size_t n);
int speer_tls_w_vec_u24(speer_tls_writer_t *w, const uint8_t *d, size_t n);
size_t speer_tls_w_save(speer_tls_writer_t *w);
int speer_tls_w_finish_vec_u16(speer_tls_writer_t *w, size_t saved);
int speer_tls_w_finish_vec_u24(speer_tls_writer_t *w, size_t saved);
int speer_tls_w_handshake_header(speer_tls_writer_t *w, uint8_t type, size_t body_len);

void speer_tls_reader_init(speer_tls_reader_t *r, const uint8_t *buf, size_t len);
int speer_tls_r_u8(speer_tls_reader_t *r, uint8_t *v);
int speer_tls_r_u16(speer_tls_reader_t *r, uint16_t *v);
int speer_tls_r_u24(speer_tls_reader_t *r, uint32_t *v);
int speer_tls_r_bytes(speer_tls_reader_t *r, const uint8_t **d, size_t n);
int speer_tls_r_vec_u8(speer_tls_reader_t *r, const uint8_t **d, size_t *n);
int speer_tls_r_vec_u16(speer_tls_reader_t *r, const uint8_t **d, size_t *n);
int speer_tls_r_vec_u24(speer_tls_reader_t *r, const uint8_t **d, size_t *n);

#endif
