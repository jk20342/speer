#include "speer_internal.h"

#include <stdio.h>

int main(void) {
    uint8_t key[32] = {9};
    uint8_t cid[SPEER_MAX_CID_LEN] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t out[SPEER_MAX_PACKET_SIZE], dec[SPEER_MAX_PACKET_SIZE], got_cid[SPEER_MAX_CID_LEN];
    uint8_t msg[] = {0x06, 0x00, 0x02, 'h', 'i'};
    size_t out_len = 0, dec_len = 0;
    uint8_t got_cid_len = 0;
    uint64_t pkt_num = 42;

    if (speer_packet_encode(out, &out_len, msg, sizeof(msg), cid, 8, pkt_num, key) != 0) {
        puts("packet encode failed");
        return 1;
    }
    if (speer_packet_decode(dec, &dec_len, out, out_len, got_cid, &got_cid_len, &pkt_num, key) !=
        0) {
        puts("packet decode failed");
        return 1;
    }
    if (dec_len != sizeof(msg) || got_cid_len != 8 || pkt_num != 42 ||
        memcmp(dec, msg, sizeof(msg)) != 0 || memcmp(got_cid, cid, 8) != 0) {
        puts("packet roundtrip mismatch");
        return 1;
    }
    out[out_len - 1] ^= 1;
    if (speer_packet_decode(dec, &dec_len, out, out_len, got_cid, &got_cid_len, &pkt_num, key) ==
        0) {
        puts("packet tamper accepted");
        return 1;
    }
    puts("packet roundtrip: ok");
    return 0;
}
