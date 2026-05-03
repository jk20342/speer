#include <stdio.h>

#include <string.h>

#include "circuit_relay.h"
#include "varint.h"

int main(void) {
    uint8_t pb[256];
    size_t pl = 0;
    if (speer_relay_encode_hop_reserve(pb, sizeof(pb), &pl) != 0) {
        fprintf(stderr, "encode hop reserve failed\n");
        return 1;
    }
    uint8_t on_wire[320];
    size_t hl = speer_uvarint_encode(on_wire, sizeof(on_wire), pl);
    if (hl == 0) {
        fprintf(stderr, "uvarint len failed\n");
        return 1;
    }
    if (hl + pl > sizeof(on_wire)) return 1;
    memcpy(on_wire + hl, pb, pl);
    uint64_t decoded_len = 0;
    if (speer_uvarint_decode(on_wire, hl, &decoded_len) == 0) return 1;
    if (decoded_len != pl) return 1;
    if (memcmp(on_wire + hl, pb, pl) != 0) return 1;
    puts("relay libp2p hop framing: ok");
    return 0;
}
