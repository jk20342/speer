#ifndef SPEER_ECDSA_P256_H
#define SPEER_ECDSA_P256_H

#include <stddef.h>
#include <stdint.h>

int speer_ecdsa_p256_verify(const uint8_t pubkey[64], const uint8_t *msg_hash, size_t msg_hash_len,
                            const uint8_t *sig_r, size_t sig_r_len, const uint8_t *sig_s,
                            size_t sig_s_len);

#endif
