#ifndef SPEER_QUIC_PKT_H
#define SPEER_QUIC_PKT_H

#include <stdint.h>
#include <stddef.h>
#include "aead_iface.h"
#include "header_protect.h"

#define QUIC_VERSION_V1 0x00000001

#define QUIC_PT_INITIAL    0x0
#define QUIC_PT_0RTT       0x1
#define QUIC_PT_HANDSHAKE  0x2
#define QUIC_PT_RETRY      0x3

#define QUIC_PNS_INITIAL   0
#define QUIC_PNS_HANDSHAKE 1
#define QUIC_PNS_APP       2

#define QUIC_MAX_CID_LEN 20
#define QUIC_MAX_PKT_LEN 1500

typedef struct {
    const speer_aead_iface_t* aead;
    speer_hp_ctx_t hp;
    uint8_t key[32];
    size_t  key_len;
    uint8_t iv[12];
    uint64_t next_send_pn;
    uint64_t largest_acked;
} speer_quic_keys_t;

typedef struct {
    int      is_long;
    uint8_t  pkt_type;
    uint32_t version;
    uint8_t  scid[QUIC_MAX_CID_LEN]; size_t scid_len;
    uint8_t  dcid[QUIC_MAX_CID_LEN]; size_t dcid_len;
    uint64_t pkt_num;
    size_t   pn_length;
    const uint8_t* token;
    size_t   token_len;
    const uint8_t* payload;
    size_t   payload_len;
} speer_quic_pkt_t;

int speer_quic_keys_init_initial(speer_quic_keys_t* client_keys,
                                   speer_quic_keys_t* server_keys,
                                   const uint8_t* initial_dcid, size_t initial_dcid_len);

int speer_quic_pkt_encode_long(uint8_t* out, size_t out_cap, size_t* out_len,
                                 const speer_quic_pkt_t* p,
                                 speer_quic_keys_t* keys);

int speer_quic_pkt_decode_long(speer_quic_pkt_t* p,
                                 uint8_t* pkt, size_t pkt_len,
                                 speer_quic_keys_t* keys);

int speer_quic_pkt_encode_short(uint8_t* out, size_t out_cap, size_t* out_len,
                                  const uint8_t* dcid, size_t dcid_len,
                                  uint64_t pn, size_t pn_length,
                                  const uint8_t* payload, size_t payload_len,
                                  speer_quic_keys_t* keys,
                                  int spin_bit, int key_phase);

int speer_quic_pkt_decode_short(speer_quic_pkt_t* p,
                                  uint8_t* pkt, size_t pkt_len,
                                  size_t expected_dcid_len,
                                  speer_quic_keys_t* keys);

#endif
