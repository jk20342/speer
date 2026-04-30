#ifndef SPEER_DCUTR_H
#define SPEER_DCUTR_H

#include "speer.h"

#include <stddef.h>
#include <stdint.h>

#include "multiaddr.h"

#ifndef __GNUC__
#define __attribute__(x)
#endif

#define DCUTR_PROTO     "/libp2p/dcutr"
#define DCUTR_MAX_ADDRS 8
#define DCUTR_STREAM_ID 0xDC00u

typedef enum {
    DCUTR_TYPE_CONNECT = 100,
    DCUTR_TYPE_SYNC = 300,
} speer_dcutr_type_t;

typedef struct {
    speer_dcutr_type_t type;
    speer_multiaddr_t addrs[DCUTR_MAX_ADDRS];
    size_t num_addrs;
} speer_dcutr_msg_t;

typedef int (*speer_dcutr_send_fn)(void *user, const uint8_t *data, size_t len);

int speer_dcutr_init(speer_peer_t *peer, int is_initiator);
void speer_dcutr_set_transport(speer_dcutr_send_fn send_fn, void *user);
int speer_dcutr_start_stream(speer_peer_t *peer, uint32_t stream_id, int is_initiator);
int speer_dcutr_on_stream_data(speer_peer_t *peer, uint32_t stream_id, const uint8_t *data,
                               size_t len);
void speer_dcutr_free(void);
int speer_dcutr_is_active(void);
int speer_dcutr_success(void);
void speer_dcutr_poll(void);
int speer_dcutr_on_msg(const uint8_t *data, size_t len);
int speer_dcutr_encode(const speer_dcutr_msg_t *m, uint8_t *out, size_t cap, size_t *out_len);
int speer_dcutr_decode(speer_dcutr_msg_t *m, const uint8_t *in, size_t in_len);

#endif
