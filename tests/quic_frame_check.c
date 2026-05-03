#include "speer_internal.h"

#include <stdio.h>

#include <string.h>

#include "quic_frame.h"

#define FAIL(...)                     \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        return 1;                     \
    } while (0)

/*
 * encode sample quic frames and decode them again to guard wire layout regressions
 * covers ping crypto ack stream path_challenge/response handshake_done cc
 * replays decoder state machine against writer cursor to detect length varint drift
 */
int main(void) {
    uint8_t buf[512];
    speer_qf_writer_t w;
    speer_qf_writer_init(&w, buf, sizeof(buf));

    if (speer_qf_encode_ping(&w) != 0) FAIL("ping\n");

    const uint8_t tlsfrag[] = {0x01, 0x02, 0x03};
    if (speer_qf_encode_crypto(&w, 7, tlsfrag, sizeof(tlsfrag)) != 0) FAIL("crypto\n");

    uint64_t ack_pairs[] = {0, 3, 10, 2};
    if (speer_qf_encode_ack(&w, 12, 5000, ack_pairs, 2) != 0) FAIL("ack\n");

    const uint8_t stream_data[] = "quic";
    if (speer_qf_encode_stream(&w, 4, 0, stream_data, sizeof(stream_data) - 1, 0) != 0)
        FAIL("stream off0\n");
    if (speer_qf_encode_stream(&w, 4, 100, stream_data, sizeof(stream_data) - 1, 1) != 0)
        FAIL("stream off fin\n");

    uint8_t pc[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    if (speer_qf_encode_path_challenge(&w, pc) != 0) FAIL("path_challenge\n");
    if (speer_qf_encode_path_response(&w, pc) != 0) FAIL("path_response\n");
    if (speer_qf_encode_handshake_done(&w) != 0) FAIL("handshake_done\n");
    if (speer_qf_encode_connection_close(&w, 0x100u, 6, "bye") != 0) FAIL("conn_close\n");

    uint8_t cid[] = {0xde, 0xad};
    uint8_t tok[16];
    for (size_t i = 0; i < sizeof(tok); i++) tok[i] = (uint8_t)i;
    if (speer_qf_encode_new_connection_id(&w, 3, 1, cid, sizeof(cid), tok) != 0)
        FAIL("new_conn_id\n");

    speer_qf_reader_t r;
    speer_qf_reader_init(&r, buf, w.pos);

    uint8_t ty;
    if (speer_qf_r_u8(&r, &ty) != 0 || ty != QF_PING) FAIL("read ping\n");

    if (speer_qf_r_u8(&r, &ty) != 0 || ty != QF_CRYPTO) FAIL("read crypto type\n");
    uint64_t off, ln;
    if (speer_qf_r_varint(&r, &off) != 0 || off != 7) FAIL("crypto off\n");
    if (speer_qf_r_varint(&r, &ln) != 0 || ln != sizeof(tlsfrag)) FAIL("crypto len\n");
    const uint8_t *body;
    if (speer_qf_r_bytes(&r, &body, sizeof(tlsfrag)) != 0 ||
        memcmp(body, tlsfrag, sizeof(tlsfrag)) != 0)
        FAIL("crypto body\n");

    if (speer_qf_r_u8(&r, &ty) != 0 || ty != QF_ACK) FAIL("ack type\n");
    uint64_t largest, delay, count, first_ack_range;
    if (speer_qf_r_varint(&r, &largest) != 0 || largest != 12) FAIL("ack largest\n");
    if (speer_qf_r_varint(&r, &delay) != 0 || delay != 5000) FAIL("ack delay\n");
    if (speer_qf_r_varint(&r, &count) != 0 || count != 1) FAIL("ack count\n");
    if (speer_qf_r_varint(&r, &first_ack_range) != 0 || first_ack_range != ack_pairs[1])
        FAIL("ack first range\n");
    uint64_t gap, block;
    if (speer_qf_r_varint(&r, &gap) != 0 || gap != ack_pairs[2]) FAIL("ack gap\n");
    if (speer_qf_r_varint(&r, &block) != 0 || block != ack_pairs[3]) FAIL("ack block\n");

    if (speer_qf_r_u8(&r, &ty) != 0 || ty != (QF_STREAM_BASE | 0x02)) FAIL("stream ty1\n");
    uint64_t sid;
    if (speer_qf_r_varint(&r, &sid) != 0 || sid != 4) FAIL("stream id1\n");
    if (speer_qf_r_varint(&r, &ln) != 0 || ln != sizeof(stream_data) - 1) FAIL("stream len1\n");
    if (speer_qf_r_bytes(&r, &body, (size_t)ln) != 0 || memcmp(body, stream_data, (size_t)ln) != 0)
        FAIL("stream data1\n");

    if (speer_qf_r_u8(&r, &ty) != 0 || ty != (QF_STREAM_BASE | 0x02 | 0x04 | 0x01))
        FAIL("stream ty2\n");
    if (speer_qf_r_varint(&r, &sid) != 0 || sid != 4) FAIL("stream id2\n");
    if (speer_qf_r_varint(&r, &off) != 0 || off != 100) FAIL("stream off2\n");
    if (speer_qf_r_varint(&r, &ln) != 0 || ln != sizeof(stream_data) - 1) FAIL("stream len2\n");
    if (speer_qf_r_bytes(&r, &body, (size_t)ln) != 0 || memcmp(body, stream_data, (size_t)ln) != 0)
        FAIL("stream data2\n");

    if (speer_qf_r_u8(&r, &ty) != 0 || ty != QF_PATH_CHALLENGE) FAIL("pc\n");
    if (speer_qf_r_bytes(&r, &body, 8) != 0 || memcmp(body, pc, 8) != 0) FAIL("pc data\n");
    if (speer_qf_r_u8(&r, &ty) != 0 || ty != QF_PATH_RESPONSE) FAIL("pr\n");
    if (speer_qf_r_bytes(&r, &body, 8) != 0 || memcmp(body, pc, 8) != 0) FAIL("pr data\n");

    if (speer_qf_r_u8(&r, &ty) != 0 || ty != QF_HANDSHAKE_DONE) FAIL("hs done\n");

    if (speer_qf_r_u8(&r, &ty) != 0 || ty != QF_CONNECTION_CLOSE) FAIL("cc type\n");
    uint64_t ec, ft, rl;
    if (speer_qf_r_varint(&r, &ec) != 0 || ec != 0x100u) FAIL("cc ec\n");
    if (speer_qf_r_varint(&r, &ft) != 0 || ft != 6) FAIL("cc ft\n");
    if (speer_qf_r_varint(&r, &rl) != 0 || rl != 3) FAIL("cc rlen\n");
    if (speer_qf_r_bytes(&r, &body, (size_t)rl) != 0 || memcmp(body, "bye", 3) != 0)
        FAIL("cc reason\n");

    if (speer_qf_r_u8(&r, &ty) != 0 || ty != QF_NEW_CONNECTION_ID) FAIL("ncid\n");
    uint64_t seq, retire;
    if (speer_qf_r_varint(&r, &seq) != 0 || seq != 3) FAIL("ncid seq\n");
    if (speer_qf_r_varint(&r, &retire) != 0 || retire != 1) FAIL("ncid retire\n");
    uint8_t clen;
    if (speer_qf_r_u8(&r, &clen) != 0 || clen != sizeof(cid)) FAIL("ncid clen\n");
    if (speer_qf_r_bytes(&r, &body, clen) != 0 || memcmp(body, cid, sizeof(cid)) != 0)
        FAIL("ncid cid\n");
    if (speer_qf_r_bytes(&r, &body, 16) != 0 || memcmp(body, tok, 16) != 0) FAIL("ncid tok\n");

    if (!speer_qf_r_eof(&r)) FAIL("expected eof\n");

    puts("quic_frame: ok");
    return 0;
}
