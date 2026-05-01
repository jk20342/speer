#ifndef SPEER_IDENTIFY_H
#define SPEER_IDENTIFY_H

#include <stddef.h>
#include <stdint.h>

#include "multiaddr.h"

#define IDENTIFY_PROTO                "/ipfs/id/1.0.0"
#define IDENTIFY_PUSH_PROTO           "/ipfs/id/push/1.0.0"

#define IDENTIFY_MAX_PROTOCOLS        64
#define IDENTIFY_MAX_LISTEN_ADDRS     16
#define IDENTIFY_AGENT_VERSION_MAX    64
#define IDENTIFY_PROTOCOL_VERSION_MAX 32
#define IDENTIFY_PUBKEY_PROTO_MAX     1024

typedef struct {
    uint8_t pubkey_proto[IDENTIFY_PUBKEY_PROTO_MAX];
    size_t pubkey_proto_len;
    speer_multiaddr_t listen_addrs[IDENTIFY_MAX_LISTEN_ADDRS];
    size_t num_listen_addrs;
    char protocols[IDENTIFY_MAX_PROTOCOLS][64];
    size_t num_protocols;
    char agent_version[IDENTIFY_AGENT_VERSION_MAX];
    char protocol_version[IDENTIFY_PROTOCOL_VERSION_MAX];
    speer_multiaddr_t observed_addr;
    int has_observed;
} speer_identify_t;

int speer_identify_encode(const speer_identify_t *id, uint8_t *out, size_t cap, size_t *out_len);
int speer_identify_decode(speer_identify_t *id, const uint8_t *in, size_t in_len);

#endif
