#ifndef SPEER_LIBP2P_IDENTIFY_H
#define SPEER_LIBP2P_IDENTIFY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SPEER_LIBP2P_IDENTIFY_PROTOCOL             "/ipfs/id/1.0.0"
#define SPEER_LIBP2P_IDENTIFY_PUSH_PROTOCOL        "/ipfs/id/push/1.0.0"

#define SPEER_LIBP2P_IDENTIFY_MAX_PROTOCOLS        64
#define SPEER_LIBP2P_IDENTIFY_MAX_LISTEN_ADDRS     16
#define SPEER_LIBP2P_IDENTIFY_AGENT_VERSION_MAX    64
#define SPEER_LIBP2P_IDENTIFY_PROTOCOL_VERSION_MAX 32
#define SPEER_LIBP2P_IDENTIFY_PUBKEY_PROTO_MAX     1024
#define SPEER_LIBP2P_IDENTIFY_MULTIADDR_MAX        512

typedef struct {
    uint8_t pubkey_proto[SPEER_LIBP2P_IDENTIFY_PUBKEY_PROTO_MAX];
    size_t pubkey_proto_len;
    uint8_t listen_addrs[SPEER_LIBP2P_IDENTIFY_MAX_LISTEN_ADDRS]
                        [SPEER_LIBP2P_IDENTIFY_MULTIADDR_MAX];
    size_t listen_addr_lens[SPEER_LIBP2P_IDENTIFY_MAX_LISTEN_ADDRS];
    size_t num_listen_addrs;
    char protocols[SPEER_LIBP2P_IDENTIFY_MAX_PROTOCOLS][64];
    size_t num_protocols;
    char agent_version[SPEER_LIBP2P_IDENTIFY_AGENT_VERSION_MAX];
    char protocol_version[SPEER_LIBP2P_IDENTIFY_PROTOCOL_VERSION_MAX];
    uint8_t observed_addr[SPEER_LIBP2P_IDENTIFY_MULTIADDR_MAX];
    size_t observed_addr_len;
    int has_observed;
} speer_libp2p_identify_info_t;

int speer_libp2p_identify_encode(const speer_libp2p_identify_info_t *info, uint8_t *out, size_t cap,
                                 size_t *out_len);
int speer_libp2p_identify_decode(speer_libp2p_identify_info_t *info, const uint8_t *in,
                                 size_t in_len);

#ifdef __cplusplus
}
#endif

#endif
