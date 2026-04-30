#ifndef SPEER_MULTISTREAM_H
#define SPEER_MULTISTREAM_H

#include <stdint.h>
#include <stddef.h>

#define MULTISTREAM_PROTO "/multistream/1.0.0"
#define MULTISTREAM_NA "na"
#define MULTISTREAM_LS "ls"

typedef int (*speer_ms_send_fn)(void* user, const uint8_t* data, size_t len);
typedef int (*speer_ms_recv_fn)(void* user, uint8_t* buf, size_t cap, size_t* out_n);

int speer_ms_send_protocol(void* user, speer_ms_send_fn send_fn, const char* protocol);
int speer_ms_recv_protocol(void* user, speer_ms_recv_fn recv_fn, char* out, size_t out_cap);

int speer_ms_negotiate_initiator(void* user, speer_ms_send_fn send_fn, speer_ms_recv_fn recv_fn,
                                  const char* protocol);
int speer_ms_negotiate_listener(void* user, speer_ms_send_fn send_fn, speer_ms_recv_fn recv_fn,
                                 const char* const* protocols, size_t num_protocols,
                                 size_t* selected_idx);

#endif
