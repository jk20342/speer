#ifndef SPEER_SIG_DISPATCH_H
#define SPEER_SIG_DISPATCH_H

#include <stdint.h>
#include <stddef.h>
#include "tls_msg.h"

int speer_sig_verify(uint16_t alg_id,
                     const uint8_t* pubkey, size_t pubkey_len,
                     const uint8_t* msg, size_t msg_len,
                     const uint8_t* sig, size_t sig_len);

int speer_sig_verify_prehashed(uint16_t alg_id,
                                const uint8_t* pubkey, size_t pubkey_len,
                                const uint8_t* msg_hash, size_t msg_hash_len,
                                const uint8_t* sig, size_t sig_len);

#endif
