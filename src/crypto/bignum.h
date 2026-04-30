#ifndef SPEER_BIGNUM_H
#define SPEER_BIGNUM_H

#include <stddef.h>
#include <stdint.h>

/* This bignum is intended for PUBLIC-data verification only (RSA-PKCS1/PSS
   verify, ECDSA verify, EC point validation). The control flow of bn_mod,
   bn_modinv, bn_modexp via bn_mulmod->bn_mod, and pt_scalar_mul is
   data-dependent on the input. Do not use for signing or any operation
   involving private keys. */

#define SPEER_BN_MAX_LIMBS 128

typedef struct {
    uint32_t limbs[SPEER_BN_MAX_LIMBS];
    size_t n;
} speer_bn_t;

void speer_bn_zero(speer_bn_t *a);
void speer_bn_copy(speer_bn_t *r, const speer_bn_t *a);
int speer_bn_from_bytes_be(speer_bn_t *a, const uint8_t *in, size_t len);
int speer_bn_to_bytes_be(uint8_t *out, size_t out_len, const speer_bn_t *a);
size_t speer_bn_byte_size(const speer_bn_t *a);
int speer_bn_cmp(const speer_bn_t *a, const speer_bn_t *b);
int speer_bn_is_zero(const speer_bn_t *a);
int speer_bn_is_odd(const speer_bn_t *a);
int speer_bn_get_bit(const speer_bn_t *a, size_t i);
size_t speer_bn_bit_size(const speer_bn_t *a);

void speer_bn_add(speer_bn_t *r, const speer_bn_t *a, const speer_bn_t *b);
int speer_bn_sub(speer_bn_t *r, const speer_bn_t *a, const speer_bn_t *b);
void speer_bn_shr1(speer_bn_t *a);
void speer_bn_shl1(speer_bn_t *a);
void speer_bn_mod(speer_bn_t *r, const speer_bn_t *a, const speer_bn_t *m);
void speer_bn_addmod(speer_bn_t *r, const speer_bn_t *a, const speer_bn_t *b, const speer_bn_t *m);
void speer_bn_submod(speer_bn_t *r, const speer_bn_t *a, const speer_bn_t *b, const speer_bn_t *m);
void speer_bn_mulmod(speer_bn_t *r, const speer_bn_t *a, const speer_bn_t *b, const speer_bn_t *m);
void speer_bn_modexp(speer_bn_t *r, const speer_bn_t *a, const speer_bn_t *e, const speer_bn_t *m);
int speer_bn_modinv(speer_bn_t *r, const speer_bn_t *a, const speer_bn_t *m);

#endif
