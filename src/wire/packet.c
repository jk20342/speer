#include "speer_internal.h"

#define PACKET_TYPE_INITIAL       0x00
#define PACKET_TYPE_HANDSHAKE     0x01
#define PACKET_TYPE_1RTT          0x02

#define FRAME_PADDING             0x00
#define FRAME_PING                0x01
#define FRAME_ACK                 0x02
#define FRAME_RESET_STREAM        0x03
#define FRAME_STOP_SENDING        0x04
#define FRAME_CRYPTO              0x05
#define FRAME_STREAM              0x06
#define FRAME_MAX_DATA            0x07
#define FRAME_MAX_STREAM_DATA     0x08
#define FRAME_MAX_STREAMS         0x09
#define FRAME_DATA_BLOCKED        0x0a
#define FRAME_STREAM_DATA_BLOCKED 0x0b
#define FRAME_STREAMS_BLOCKED     0x0c
#define FRAME_CONNECTION_CLOSE    0x0d
#define FRAME_PATH_CHALLENGE      0x0e
#define FRAME_PATH_RESPONSE       0x0f

size_t speer_varint_encode(uint8_t *out, uint64_t val) {
    if (val < 64) {
        out[0] = (uint8_t)val;
        return 1;
    } else if (val < 16384) {
        out[0] = (uint8_t)(0x40 | (val & 0x3f));
        out[1] = (uint8_t)((val >> 6) & 0xff);
        return 2;
    } else if (val < 1073741824) {
        out[0] = (uint8_t)(0x80 | (val & 0x3f));
        out[1] = (uint8_t)((val >> 6) & 0xff);
        out[2] = (uint8_t)((val >> 14) & 0xff);
        out[3] = (uint8_t)((val >> 22) & 0xff);
        return 4;
    } else {
        out[0] = (uint8_t)(0xc0 | (val & 0x3f));
        out[1] = (uint8_t)((val >> 6) & 0xff);
        out[2] = (uint8_t)((val >> 14) & 0xff);
        out[3] = (uint8_t)((val >> 22) & 0xff);
        out[4] = (uint8_t)((val >> 30) & 0xff);
        out[5] = (uint8_t)((val >> 38) & 0xff);
        out[6] = (uint8_t)((val >> 46) & 0xff);
        out[7] = (uint8_t)((val >> 54) & 0xff);
        return 8;
    }
}

size_t speer_varint_decode(const uint8_t *in, uint64_t *val) {
    uint8_t type = in[0] >> 6;

    switch (type) {
    case 0:
        *val = in[0] & 0x3f;
        return 1;
    case 1:
        *val = ((uint64_t)(in[0] & 0x3f)) | (((uint64_t)in[1]) << 6);
        return 2;
    case 2:
        *val = ((uint64_t)(in[0] & 0x3f)) | (((uint64_t)in[1]) << 6) | (((uint64_t)in[2]) << 14) |
               (((uint64_t)in[3]) << 22);
        return 4;
    case 3:
        *val = ((uint64_t)(in[0] & 0x3f)) | (((uint64_t)in[1]) << 6) | (((uint64_t)in[2]) << 14) |
               (((uint64_t)in[3]) << 22) | (((uint64_t)in[4]) << 30) | (((uint64_t)in[5]) << 38) |
               (((uint64_t)in[6]) << 46) | (((uint64_t)in[7]) << 54);
        return 8;
    }
    return 0;
}

static size_t encode_cid(uint8_t *out, const uint8_t cid[SPEER_MAX_CID_LEN], uint8_t cid_len) {
    out[0] = cid_len;
    COPY(out + 1, cid, cid_len);
    return 1 + cid_len;
}

static size_t decode_cid(const uint8_t *in, uint8_t cid[SPEER_MAX_CID_LEN], uint8_t *cid_len) {
    *cid_len = in[0];
    if (*cid_len > SPEER_MAX_CID_LEN) return 0;
    COPY(cid, in + 1, *cid_len);
    return 1 + *cid_len;
}

static size_t encode_header(uint8_t *out, uint8_t type, const uint8_t cid[SPEER_MAX_CID_LEN],
                            uint8_t cid_len, uint64_t pkt_num) {
    out[0] = SPEER_PACKET_VERSION;
    out[1] = type;
    size_t n = 2;
    n += encode_cid(out + n, cid, cid_len);
    n += speer_varint_encode(out + n, pkt_num);
    return n;
}

static size_t decode_header(const uint8_t *in, size_t in_len, uint8_t *type,
                            uint8_t cid[SPEER_MAX_CID_LEN], uint8_t *cid_len, uint64_t *pkt_num) {
    if (in_len < 4) return 0;
    if (in[0] != SPEER_PACKET_VERSION) return 0;

    if (type) *type = in[1];
    size_t n = 2;

    size_t d = decode_cid(in + n, cid, cid_len);
    if (d == 0) return 0;
    n += d;

    n += speer_varint_decode(in + n, pkt_num);
    return n;
}

int speer_packet_encode(uint8_t *out, size_t *out_len, const uint8_t *in, size_t in_len,
                        const uint8_t cid[SPEER_MAX_CID_LEN], uint8_t cid_len, uint64_t pkt_num,
                        const uint8_t key[32]) {
    uint8_t *body = out;
    size_t body_len = 0;

    body_len += encode_header(body, PACKET_TYPE_1RTT, cid, cid_len, pkt_num);

    uint8_t nonce[12] = {0};
    STORE64_LE(nonce, pkt_num);
    speer_chacha_ctx_t ctx;
    speer_chacha_init(&ctx, key, nonce);

    uint8_t poly_block[64];
    speer_chacha_block(&ctx, poly_block);

    speer_chacha_crypt(&ctx, body + body_len, in, in_len);
    body_len += in_len;

    uint8_t mac[16];
    speer_poly1305(mac, body, body_len, poly_block);
    COPY(body + body_len, mac, 16);
    body_len += 16;

    *out_len = body_len;
    return 0;
}

int speer_packet_decode(uint8_t *out, size_t *out_len, const uint8_t *in, size_t in_len,
                        uint8_t cid[SPEER_MAX_CID_LEN], uint8_t *cid_len, uint64_t *pkt_num,
                        const uint8_t key[32]) {
    if (in_len < 20) return -1;

    size_t hdr_len = decode_header(in, in_len, NULL, cid, cid_len, pkt_num);
    if (hdr_len == 0) return -1;

    size_t body_len = in_len - 16;
    if (body_len < hdr_len) return -1;

    uint8_t nonce[12] = {0};
    STORE64_LE(nonce, *pkt_num);
    speer_chacha_ctx_t ctx;
    speer_chacha_init(&ctx, key, nonce);

    uint8_t poly_block[64];
    speer_chacha_block(&ctx, poly_block);

    uint8_t mac[16];
    speer_poly1305(mac, in, body_len, poly_block);

    if (!EQUAL(mac, in + body_len, 16)) return -1;

    uint8_t *ciphertext = (uint8_t *)in + hdr_len;
    size_t ciphertext_len = body_len - hdr_len;

    speer_chacha_crypt(&ctx, out, ciphertext, ciphertext_len);

    *out_len = ciphertext_len;
    return 0;
}

typedef struct {
    uint8_t *buf;
    size_t len;
    size_t cap;
} frame_buf_t;

static INLINE void frame_init(frame_buf_t *f, uint8_t *buf, size_t cap) {
    f->buf = buf;
    f->len = 0;
    f->cap = cap;
}

static INLINE void frame_write_u8(frame_buf_t *f, uint8_t v) {
    if (f->len < f->cap) f->buf[f->len++] = v;
}

static INLINE void frame_write_varint(frame_buf_t *f, uint64_t v) {
    f->len += speer_varint_encode(f->buf + f->len, v);
}

static INLINE void frame_write_bytes(frame_buf_t *f, const uint8_t *data, size_t len) {
    if (f->len + len <= f->cap) {
        COPY(f->buf + f->len, data, len);
        f->len += len;
    }
}

size_t speer_frame_encode_padding(uint8_t *out, size_t len) {
    frame_buf_t f;
    frame_init(&f, out, len);
    frame_write_u8(&f, FRAME_PADDING);
    for (size_t i = 1; i < len; i++) frame_write_u8(&f, 0);
    return f.len;
}

size_t speer_frame_encode_ping(uint8_t *out) {
    frame_buf_t f;
    frame_init(&f, out, 1);
    frame_write_u8(&f, FRAME_PING);
    return f.len;
}

size_t speer_frame_encode_ack(uint8_t *out, uint64_t largest_acked, uint64_t ack_delay,
                              const uint8_t *ranges, size_t num_ranges) {
    frame_buf_t f;
    frame_init(&f, out, 64);
    frame_write_u8(&f, FRAME_ACK);
    frame_write_varint(&f, largest_acked);
    frame_write_varint(&f, ack_delay);
    frame_write_varint(&f, num_ranges);
    for (size_t i = 0; i < num_ranges; i++) {
        frame_write_varint(&f, ranges[i * 2]);
        frame_write_varint(&f, ranges[i * 2 + 1]);
    }
    return f.len;
}

size_t speer_frame_encode_stream(uint8_t *out, uint32_t stream_id, uint64_t offset,
                                 const uint8_t *data, size_t len, bool fin) {
    frame_buf_t f;
    frame_init(&f, out, 16 + len);
    uint8_t type = FRAME_STREAM;
    if (offset > 0) type |= 0x04;
    if (len > 0) type |= 0x02;
    if (fin) type |= 0x01;
    frame_write_u8(&f, type);
    frame_write_varint(&f, stream_id);
    if (offset > 0) frame_write_varint(&f, offset);
    if (len > 0) frame_write_varint(&f, len);
    frame_write_bytes(&f, data, len);
    return f.len;
}

size_t speer_frame_encode_crypto(uint8_t *out, uint64_t offset, const uint8_t *data, size_t len) {
    frame_buf_t f;
    frame_init(&f, out, 16 + len);
    frame_write_u8(&f, FRAME_CRYPTO);
    frame_write_varint(&f, offset);
    frame_write_varint(&f, len);
    frame_write_bytes(&f, data, len);
    return f.len;
}

size_t speer_frame_encode_max_stream_data(uint8_t *out, uint32_t stream_id, uint64_t limit) {
    frame_buf_t f;
    frame_init(&f, out, 16);
    frame_write_u8(&f, FRAME_MAX_STREAM_DATA);
    frame_write_varint(&f, stream_id);
    frame_write_varint(&f, limit);
    return f.len;
}

size_t speer_frame_encode_connection_close(uint8_t *out, uint64_t error_code, const uint8_t *reason,
                                           size_t reason_len) {
    frame_buf_t f;
    frame_init(&f, out, 32 + reason_len);
    frame_write_u8(&f, FRAME_CONNECTION_CLOSE);
    frame_write_varint(&f, error_code);
    frame_write_varint(&f, 0);
    frame_write_varint(&f, reason_len);
    frame_write_bytes(&f, reason, reason_len);
    return f.len;
}

typedef struct {
    const uint8_t *buf;
    size_t len;
    size_t pos;
} frame_parser_t;

static INLINE void parser_init(frame_parser_t *p, const uint8_t *buf, size_t len) {
    p->buf = buf;
    p->len = len;
    p->pos = 0;
}

static INLINE size_t parser_avail(const frame_parser_t *p) {
    return p->len - p->pos;
}

static INLINE uint8_t parser_read_u8(frame_parser_t *p) {
    if (p->pos >= p->len) return 0;
    return p->buf[p->pos++];
}

static INLINE uint64_t parser_read_varint(frame_parser_t *p) {
    if (p->pos >= p->len) return 0;
    uint64_t val;
    size_t n = speer_varint_decode(p->buf + p->pos, &val);
    p->pos += n;
    return val;
}

static INLINE const uint8_t *parser_read_bytes(frame_parser_t *p, size_t len) {
    if (p->pos + len > p->len) return NULL;
    const uint8_t *ptr = p->buf + p->pos;
    p->pos += len;
    return ptr;
}

int speer_frame_parse(const uint8_t *in, size_t in_len,
                      int (*on_frame)(uint8_t type, const uint8_t *data, size_t len, void *user),
                      void *user) {
    frame_parser_t p;
    parser_init(&p, in, in_len);

    while (parser_avail(&p) > 0) {
        uint8_t type = parser_read_u8(&p);
        size_t start = p.pos;

        switch (type) {
        case FRAME_PADDING:
            while (p.pos < p.len && p.buf[p.pos] == 0) p.pos++;
            break;

        case FRAME_PING:
            break;

        case FRAME_ACK: {
            parser_read_varint(&p);
            parser_read_varint(&p);
            uint64_t num_ranges = parser_read_varint(&p);
            for (uint64_t i = 0; i < num_ranges; i++) {
                parser_read_varint(&p);
                parser_read_varint(&p);
            }
            break;
        }

        case FRAME_STREAM: {
            parser_read_varint(&p);
            if (type & 0x04) parser_read_varint(&p);
            uint64_t len = 0;
            if (type & 0x02) len = parser_read_varint(&p);
            parser_read_bytes(&p, len);
            break;
        }

        case FRAME_CRYPTO: {
            parser_read_varint(&p);
            uint64_t len = parser_read_varint(&p);
            parser_read_bytes(&p, len);
            break;
        }

        case FRAME_CONNECTION_CLOSE: {
            parser_read_varint(&p);
            parser_read_varint(&p);
            uint64_t len = parser_read_varint(&p);
            parser_read_bytes(&p, len);
            break;
        }

        case FRAME_MAX_DATA:
            parser_read_varint(&p);
            break;

        case FRAME_MAX_STREAM_DATA:
            parser_read_varint(&p);
            parser_read_varint(&p);
            break;

        default:
            return -1;
        }

        if (on_frame(type, p.buf + start, p.pos - start, user) != 0) { return -1; }
    }

    return 0;
}
