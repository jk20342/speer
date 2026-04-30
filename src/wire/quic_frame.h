#ifndef SPEER_QUIC_FRAME_H
#define SPEER_QUIC_FRAME_H

#include <stddef.h>
#include <stdint.h>

#define QF_PADDING              0x00
#define QF_PING                 0x01
#define QF_ACK                  0x02
#define QF_ACK_ECN              0x03
#define QF_RESET_STREAM         0x04
#define QF_STOP_SENDING         0x05
#define QF_CRYPTO               0x06
#define QF_NEW_TOKEN            0x07
#define QF_STREAM_BASE          0x08
#define QF_MAX_DATA             0x10
#define QF_MAX_STREAM_DATA      0x11
#define QF_MAX_STREAMS_BIDI     0x12
#define QF_MAX_STREAMS_UNI      0x13
#define QF_DATA_BLOCKED         0x14
#define QF_STREAM_DATA_BLOCKED  0x15
#define QF_STREAMS_BLOCKED_BIDI 0x16
#define QF_STREAMS_BLOCKED_UNI  0x17
#define QF_NEW_CONNECTION_ID    0x18
#define QF_RETIRE_CONNECTION_ID 0x19
#define QF_PATH_CHALLENGE       0x1a
#define QF_PATH_RESPONSE        0x1b
#define QF_CONNECTION_CLOSE     0x1c
#define QF_CONNECTION_CLOSE_APP 0x1d
#define QF_HANDSHAKE_DONE       0x1e

typedef struct {
    uint8_t *buf;
    size_t cap;
    size_t pos;
    int err;
} speer_qf_writer_t;

typedef struct {
    const uint8_t *buf;
    size_t len;
    size_t pos;
    int err;
} speer_qf_reader_t;

void speer_qf_writer_init(speer_qf_writer_t *w, uint8_t *buf, size_t cap);
int speer_qf_w_varint(speer_qf_writer_t *w, uint64_t v);
int speer_qf_w_u8(speer_qf_writer_t *w, uint8_t v);
int speer_qf_w_bytes(speer_qf_writer_t *w, const uint8_t *d, size_t n);

void speer_qf_reader_init(speer_qf_reader_t *r, const uint8_t *buf, size_t len);
int speer_qf_r_varint(speer_qf_reader_t *r, uint64_t *v);
int speer_qf_r_u8(speer_qf_reader_t *r, uint8_t *v);
int speer_qf_r_bytes(speer_qf_reader_t *r, const uint8_t **d, size_t n);
int speer_qf_r_eof(const speer_qf_reader_t *r);

int speer_qf_encode_padding(speer_qf_writer_t *w, size_t n);
int speer_qf_encode_ping(speer_qf_writer_t *w);
int speer_qf_encode_crypto(speer_qf_writer_t *w, uint64_t offset, const uint8_t *data, size_t len);
int speer_qf_encode_ack(speer_qf_writer_t *w, uint64_t largest, uint64_t delay,
                        const uint64_t *gaps_lengths, size_t pairs);
int speer_qf_encode_stream(speer_qf_writer_t *w, uint64_t stream_id, uint64_t offset,
                           const uint8_t *data, size_t len, int fin);
int speer_qf_encode_path_challenge(speer_qf_writer_t *w, const uint8_t data[8]);
int speer_qf_encode_path_response(speer_qf_writer_t *w, const uint8_t data[8]);
int speer_qf_encode_handshake_done(speer_qf_writer_t *w);
int speer_qf_encode_connection_close(speer_qf_writer_t *w, uint64_t error_code, uint64_t frame_type,
                                     const char *reason);
int speer_qf_encode_new_connection_id(speer_qf_writer_t *w, uint64_t seq, uint64_t retire_prior_to,
                                      const uint8_t *cid, size_t cid_len,
                                      const uint8_t reset_token[16]);

#endif
