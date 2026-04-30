#ifndef SPEER_FIELD25519_H
#define SPEER_FIELD25519_H

#include <stdint.h>
#include <stddef.h>

typedef int64_t fe25519[16];

void fe25519_0(fe25519 r);
void fe25519_1(fe25519 r);
void fe25519_copy(fe25519 r, const fe25519 a);
void fe25519_add(fe25519 r, const fe25519 a, const fe25519 b);
void fe25519_sub(fe25519 r, const fe25519 a, const fe25519 b);
void fe25519_mul(fe25519 r, const fe25519 a, const fe25519 b);
void fe25519_sq(fe25519 r, const fe25519 a);
void fe25519_invert(fe25519 r, const fe25519 a);
void fe25519_pow22523(fe25519 r, const fe25519 a);
void fe25519_neg(fe25519 r, const fe25519 a);
void fe25519_cswap(fe25519 a, fe25519 b, int swap);
int  fe25519_iszero(const fe25519 a);
int  fe25519_isnegative(const fe25519 a);
void fe25519_frombytes(fe25519 r, const uint8_t in[32]);
void fe25519_tobytes(uint8_t out[32], const fe25519 a);

#endif
