#ifndef SPEER_DCUTR_H
#define SPEER_DCUTR_H

#include <stdint.h>
#include <stddef.h>
#include "multiaddr.h"

typedef struct speer_peer speer_peer_t;

#ifndef __GNUC__
#define __attribute__(x)
#endif

#define DCUTR_PROTO "/libp2p/dcutr"
#define DCUTR_MAX_ADDRS 8

typedef enum {
    DCUTR_TYPE_CONNECT = 100,
    DCUTR_TYPE_SYNC    = 300,
} speer_dcutr_type_t;

typedef struct {
    speer_dcutr_type_t type;
    speer_multiaddr_t addrs[DCUTR_MAX_ADDRS];
    size_t num_addrs;
} speer_dcutr_msg_t;

int speer_dcutr_init(speer_peer_t* peer, int is_initiator);
void speer_dcutr_free(void);
int speer_dcutr_is_active(void);
int speer_dcutr_success(void);
void speer_dcutr_poll(void);
int speer_dcutr_on_msg(const uint8_t* data, size_t len);
int speer_dcutr_encode(const speer_dcutr_msg_t* m, uint8_t* out, size_t cap, size_t* out_len);
int speer_dcutr_decode(speer_dcutr_msg_t* m, const uint8_t* in, size_t in_len);

#endif
