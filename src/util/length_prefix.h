#ifndef SPEER_LENGTH_PREFIX_H
#define SPEER_LENGTH_PREFIX_H

#include <stddef.h>
#include <stdint.h>

int speer_lp_u16_write(uint8_t *out, size_t cap, const uint8_t *data, size_t len, size_t *written);
int speer_lp_u16_read(const uint8_t *in, size_t in_len, const uint8_t **payload,
                      size_t *payload_len, size_t *consumed);

int speer_lp_uvar_write(uint8_t *out, size_t cap, const uint8_t *data, size_t len, size_t *written);
int speer_lp_uvar_read(const uint8_t *in, size_t in_len, const uint8_t **payload,
                       size_t *payload_len, size_t *consumed);

#endif
