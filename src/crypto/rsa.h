#ifndef SPEER_RSA_H
#define SPEER_RSA_H

#include <stddef.h>
#include <stdint.h>

#include "hash_iface.h"

int speer_rsa_pkcs1_v15_verify(const uint8_t *n, size_t n_len, const uint8_t *e, size_t e_len,
                               const speer_hash_iface_t *hash, const uint8_t *msg_hash,
                               size_t msg_hash_len, const uint8_t *sig, size_t sig_len);

int speer_rsa_pss_verify(const uint8_t *n, size_t n_len, const uint8_t *e, size_t e_len,
                         const speer_hash_iface_t *hash, const uint8_t *msg_hash,
                         size_t msg_hash_len, const uint8_t *sig, size_t sig_len, size_t salt_len);

#endif
