#ifndef SPEER_MULTIADDR_H
#define SPEER_MULTIADDR_H

#include <stddef.h>
#include <stdint.h>

#define SPEER_MA_IP4         4
#define SPEER_MA_TCP         6
#define SPEER_MA_UDP         273
#define SPEER_MA_DNS         53
#define SPEER_MA_DNS4        54
#define SPEER_MA_DNS6        55
#define SPEER_MA_IP6         41
#define SPEER_MA_QUIC        460
#define SPEER_MA_QUICV1      461
#define SPEER_MA_P2P         421
#define SPEER_MA_P2P_CIRCUIT 290

typedef struct {
    uint8_t bytes[256];
    size_t len;
} speer_multiaddr_t;

int speer_multiaddr_parse(speer_multiaddr_t *out, const char *s);
int speer_multiaddr_to_string(const speer_multiaddr_t *ma, char *out, size_t cap);
int speer_multiaddr_to_host_port_v4(const speer_multiaddr_t *ma, char *host, size_t host_cap,
                                    uint16_t *port);
int speer_multiaddr_get_p2p_id(const speer_multiaddr_t *ma, const uint8_t **id, size_t *id_len);

#endif
