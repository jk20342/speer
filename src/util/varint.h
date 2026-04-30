#ifndef SPEER_VARINT_H
#define SPEER_VARINT_H

#include <stddef.h>
#include <stdint.h>

size_t speer_uvarint_encode(uint8_t *out, size_t cap, uint64_t v);
size_t speer_uvarint_decode(const uint8_t *in, size_t in_len, uint64_t *out);
size_t speer_uvarint_size(uint64_t v);

size_t speer_qvarint_encode(uint8_t *out, size_t cap, uint64_t v);
size_t speer_qvarint_decode(const uint8_t *in, size_t in_len, uint64_t *out);
size_t speer_qvarint_size(uint64_t v);
size_t speer_qvarint_peek_len(uint8_t first_byte);

#endif
