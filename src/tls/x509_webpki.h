#ifndef SPEER_X509_WEBPKI_H
#define SPEER_X509_WEBPKI_H

#include <stddef.h>
#include <stdint.h>

#define SPEER_X509_MAX_CHAIN      8
#define SPEER_X509_MAX_DNS        8
#define SPEER_X509_NAME_MAX       256

#define X509_KU_DIGITAL_SIGNATURE 0x80
#define X509_KU_KEY_CERT_SIGN     0x04

#define X509_EKU_SERVER_AUTH      1
#define X509_EKU_CLIENT_AUTH      2

typedef struct {
    const uint8_t *tbs;
    size_t tbs_len;
    const uint8_t *sig;
    size_t sig_len;
    const uint8_t *sig_alg_oid;
    size_t sig_alg_oid_len;
    const uint8_t *spki;
    size_t spki_len;
    const uint8_t *spki_alg_oid;
    size_t spki_alg_oid_len;
    const uint8_t *spki_pubkey;
    size_t spki_pubkey_len;
    const uint8_t *issuer_dn;
    size_t issuer_dn_len;
    const uint8_t *subject_dn;
    size_t subject_dn_len;
    int64_t not_before_utc;
    int64_t not_after_utc;
    int is_ca;
    int has_basic_constraints;
    int has_path_len;
    int path_len_constraint;
    int key_usage;
    int has_key_usage;
    int ext_key_usage;
    int has_ext_key_usage;
    int unknown_critical_ext;
    char san_dns[SPEER_X509_MAX_DNS][SPEER_X509_NAME_MAX];
    size_t num_san_dns;
} speer_x509_t;

int speer_x509_parse(speer_x509_t *out, const uint8_t *der, size_t der_len);

typedef struct {
    const uint8_t *der;
    size_t der_len;
    size_t spki_offset;
    size_t spki_len;
    size_t subject_offset;
    size_t subject_len;
    int64_t not_before_utc;
    int64_t not_after_utc;
} speer_ca_entry_t;

typedef struct {
    const speer_ca_entry_t *entries;
    size_t count;
} speer_ca_store_t;

int speer_x509_verify_chain(const speer_ca_store_t *store, const speer_x509_t *leaf,
                            const speer_x509_t *intermediates, size_t num_intermediates,
                            const char *hostname, int64_t now_utc);

int speer_x509_match_hostname(const speer_x509_t *cert, const char *hostname);

#endif
