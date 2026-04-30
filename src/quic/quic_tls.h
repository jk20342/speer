#ifndef SPEER_QUIC_TLS_H
#define SPEER_QUIC_TLS_H

#include <stddef.h>
#include <stdint.h>

#include "quic_pkt.h"
#include "tls/tls13_keysched.h"

int speer_quic_tls_set_keys_from_secret(speer_quic_keys_t *k, const speer_tls13_suite_t *suite,
                                        const uint8_t *traffic_secret);

int speer_quic_tls_make_crypto_frames(uint8_t *out, size_t cap, size_t *out_len,
                                      uint64_t *offset_inout, const uint8_t *tls_msg,
                                      size_t tls_msg_len);

int speer_quic_tls_consume_crypto_frame(uint64_t frame_offset, const uint8_t *data, size_t data_len,
                                        uint8_t *reassembly_buf, size_t *reassembly_len,
                                        size_t reassembly_cap);

#endif
