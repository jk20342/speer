#ifndef SPEER_ED25519_H
#define SPEER_ED25519_H

#include <stddef.h>
#include <stdint.h>

#define SPEER_ED25519_PUBKEY_SIZE  32
#define SPEER_ED25519_PRIVKEY_SIZE 32
#define SPEER_ED25519_SIG_SIZE     64

void speer_ed25519_keypair(uint8_t pk[32], uint8_t sk[32], const uint8_t seed[32]);
void speer_ed25519_sign(uint8_t sig[64], const uint8_t *msg, size_t msg_len, const uint8_t pk[32],
                        const uint8_t sk[32]);
int speer_ed25519_verify(const uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                         const uint8_t pk[32]);

#endif
