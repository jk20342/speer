#include "speer_internal.h"

#include <stdio.h>

#include <string.h>

#include "header_protect.h"
#include "quic_frame.h"
#include "quic_pkt.h"
#include "varint.h"

static void hex(const char *tag, const uint8_t *b, size_t n) {
    printf("%s (%zu): ", tag, n);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

int main(void) {
    uint8_t dcid[8];
    speer_random_bytes(dcid, sizeof(dcid));
    uint8_t scid[8];
    speer_random_bytes(scid, sizeof(scid));

    speer_quic_keys_t ck, sk;
    speer_quic_keys_init_initial(&ck, &sk, dcid, sizeof(dcid));

    uint8_t fake_ch[64];
    for (size_t i = 0; i < sizeof(fake_ch); i++) fake_ch[i] = (uint8_t)i;

    uint8_t crypto_buf[256];
    speer_qf_writer_t fw;
    speer_qf_writer_init(&fw, crypto_buf, sizeof(crypto_buf));
    if (speer_qf_encode_crypto(&fw, 0, fake_ch, sizeof(fake_ch)) != 0) {
        fprintf(stderr, "crypto frame fail\n");
        return 1;
    }

    speer_quic_pkt_t out_pkt;
    ZERO(&out_pkt, sizeof(out_pkt));
    out_pkt.is_long = 1;
    out_pkt.pkt_type = QUIC_PT_INITIAL;
    out_pkt.version = QUIC_VERSION_V1;
    COPY(out_pkt.dcid, dcid, 8);
    out_pkt.dcid_len = 8;
    COPY(out_pkt.scid, scid, 8);
    out_pkt.scid_len = 8;
    out_pkt.pkt_num = 0;
    out_pkt.pn_length = 1;
    out_pkt.payload = crypto_buf;
    out_pkt.payload_len = fw.pos;

    uint8_t pkt[1500];
    size_t pkt_len = 0;
    if (speer_quic_pkt_encode_long(pkt, sizeof(pkt), &pkt_len, &out_pkt, &ck) != 0) {
        fprintf(stderr, "encode fail\n");
        return 1;
    }
    hex("encoded Initial", pkt, pkt_len);

    speer_quic_keys_t rck, rsk;
    speer_quic_keys_init_initial(&rck, &rsk, dcid, sizeof(dcid));

    speer_quic_pkt_t in_pkt;
    if (speer_quic_pkt_decode_long(&in_pkt, pkt, pkt_len, &rck) != 0) {
        fprintf(stderr, "decode fail\n");
        return 1;
    }
    if (in_pkt.pkt_type != QUIC_PT_INITIAL) {
        fprintf(stderr, "wrong pkt type\n");
        return 1;
    }
    if (in_pkt.pkt_num != 0) {
        fprintf(stderr, "wrong pn\n");
        return 1;
    }
    if (memcmp(in_pkt.dcid, dcid, 8) != 0) {
        fprintf(stderr, "dcid mismatch\n");
        return 1;
    }
    if (memcmp(in_pkt.scid, scid, 8) != 0) {
        fprintf(stderr, "scid mismatch\n");
        return 1;
    }

    speer_qf_reader_t fr;
    speer_qf_reader_init(&fr, in_pkt.payload, in_pkt.payload_len);
    uint8_t ftype;
    if (speer_qf_r_u8(&fr, &ftype) != 0 || ftype != QF_CRYPTO) {
        fprintf(stderr, "bad frame type\n");
        return 1;
    }
    uint64_t off, l;
    if (speer_qf_r_varint(&fr, &off) != 0 || speer_qf_r_varint(&fr, &l) != 0) {
        fprintf(stderr, "frame parse fail\n");
        return 1;
    }
    if (off != 0 || l != sizeof(fake_ch)) {
        fprintf(stderr, "frame off/len mismatch\n");
        return 1;
    }
    const uint8_t *fdata;
    if (speer_qf_r_bytes(&fr, &fdata, (size_t)l) != 0) {
        fprintf(stderr, "frame data fail\n");
        return 1;
    }
    if (memcmp(fdata, fake_ch, sizeof(fake_ch)) != 0) {
        fprintf(stderr, "frame payload mismatch\n");
        return 1;
    }

    printf("QUIC v1 Initial roundtrip: ok (CRYPTO frame intact)\n");
    return 0;
}
