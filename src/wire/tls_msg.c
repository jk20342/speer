#include "tls_msg.h"

#include "speer_internal.h"

#include <string.h>

void speer_tls_writer_init(speer_tls_writer_t *w, uint8_t *buf, size_t cap) {
    w->buf = buf;
    w->cap = cap;
    w->pos = 0;
    w->err = 0;
}

int speer_tls_w_u8(speer_tls_writer_t *w, uint8_t v) {
    if (w->err || w->pos + 1 > w->cap) {
        w->err = 1;
        return -1;
    }
    w->buf[w->pos++] = v;
    return 0;
}

int speer_tls_w_u16(speer_tls_writer_t *w, uint16_t v) {
    if (w->err || w->pos + 2 > w->cap) {
        w->err = 1;
        return -1;
    }
    w->buf[w->pos++] = (uint8_t)(v >> 8);
    w->buf[w->pos++] = (uint8_t)v;
    return 0;
}

int speer_tls_w_u24(speer_tls_writer_t *w, uint32_t v) {
    if (w->err || w->pos + 3 > w->cap) {
        w->err = 1;
        return -1;
    }
    w->buf[w->pos++] = (uint8_t)(v >> 16);
    w->buf[w->pos++] = (uint8_t)(v >> 8);
    w->buf[w->pos++] = (uint8_t)v;
    return 0;
}

int speer_tls_w_bytes(speer_tls_writer_t *w, const uint8_t *d, size_t n) {
    if (w->err || w->pos + n > w->cap) {
        w->err = 1;
        return -1;
    }
    if (n > 0) memcpy(w->buf + w->pos, d, n);
    w->pos += n;
    return 0;
}

int speer_tls_w_vec_u8(speer_tls_writer_t *w, const uint8_t *d, size_t n) {
    if (n > 0xff) {
        w->err = 1;
        return -1;
    }
    if (speer_tls_w_u8(w, (uint8_t)n) != 0) return -1;
    return speer_tls_w_bytes(w, d, n);
}

int speer_tls_w_vec_u16(speer_tls_writer_t *w, const uint8_t *d, size_t n) {
    if (n > 0xffff) {
        w->err = 1;
        return -1;
    }
    if (speer_tls_w_u16(w, (uint16_t)n) != 0) return -1;
    return speer_tls_w_bytes(w, d, n);
}

int speer_tls_w_vec_u24(speer_tls_writer_t *w, const uint8_t *d, size_t n) {
    if (n > 0xffffff) {
        w->err = 1;
        return -1;
    }
    if (speer_tls_w_u24(w, (uint32_t)n) != 0) return -1;
    return speer_tls_w_bytes(w, d, n);
}

size_t speer_tls_w_save(speer_tls_writer_t *w) {
    return w->pos;
}

int speer_tls_w_finish_vec_u16(speer_tls_writer_t *w, size_t saved) {
    if (w->err) return -1;
    if (w->pos < saved + 2) {
        w->err = 1;
        return -1;
    }
    size_t body_len = w->pos - saved - 2;
    if (body_len > 0xffff) {
        w->err = 1;
        return -1;
    }
    w->buf[saved + 0] = (uint8_t)(body_len >> 8);
    w->buf[saved + 1] = (uint8_t)body_len;
    return 0;
}

int speer_tls_w_finish_vec_u24(speer_tls_writer_t *w, size_t saved) {
    if (w->err) return -1;
    if (w->pos < saved + 3) {
        w->err = 1;
        return -1;
    }
    size_t body_len = w->pos - saved - 3;
    if (body_len > 0xffffff) {
        w->err = 1;
        return -1;
    }
    w->buf[saved + 0] = (uint8_t)(body_len >> 16);
    w->buf[saved + 1] = (uint8_t)(body_len >> 8);
    w->buf[saved + 2] = (uint8_t)body_len;
    return 0;
}

int speer_tls_w_handshake_header(speer_tls_writer_t *w, uint8_t type, size_t body_len) {
    if (speer_tls_w_u8(w, type) != 0) return -1;
    return speer_tls_w_u24(w, (uint32_t)body_len);
}

void speer_tls_reader_init(speer_tls_reader_t *r, const uint8_t *buf, size_t len) {
    r->buf = buf;
    r->len = len;
    r->pos = 0;
    r->err = 0;
}

int speer_tls_r_u8(speer_tls_reader_t *r, uint8_t *v) {
    if (r->err || r->pos + 1 > r->len) {
        r->err = 1;
        return -1;
    }
    if (v) *v = r->buf[r->pos];
    r->pos++;
    return 0;
}

int speer_tls_r_u16(speer_tls_reader_t *r, uint16_t *v) {
    if (r->err || r->pos + 2 > r->len) {
        r->err = 1;
        return -1;
    }
    if (v) *v = ((uint16_t)r->buf[r->pos] << 8) | r->buf[r->pos + 1];
    r->pos += 2;
    return 0;
}

int speer_tls_r_u24(speer_tls_reader_t *r, uint32_t *v) {
    if (r->err || r->pos + 3 > r->len) {
        r->err = 1;
        return -1;
    }
    if (v)
        *v = ((uint32_t)r->buf[r->pos] << 16) | ((uint32_t)r->buf[r->pos + 1] << 8) |
             r->buf[r->pos + 2];
    r->pos += 3;
    return 0;
}

int speer_tls_r_bytes(speer_tls_reader_t *r, const uint8_t **d, size_t n) {
    if (r->err || r->pos + n > r->len) {
        r->err = 1;
        return -1;
    }
    if (d) *d = r->buf + r->pos;
    r->pos += n;
    return 0;
}

int speer_tls_r_vec_u8(speer_tls_reader_t *r, const uint8_t **d, size_t *n) {
    uint8_t l;
    if (speer_tls_r_u8(r, &l) != 0) return -1;
    if (n) *n = l;
    return speer_tls_r_bytes(r, d, l);
}

int speer_tls_r_vec_u16(speer_tls_reader_t *r, const uint8_t **d, size_t *n) {
    uint16_t l;
    if (speer_tls_r_u16(r, &l) != 0) return -1;
    if (n) *n = l;
    return speer_tls_r_bytes(r, d, l);
}

int speer_tls_r_vec_u24(speer_tls_reader_t *r, const uint8_t **d, size_t *n) {
    uint32_t l;
    if (speer_tls_r_u24(r, &l) != 0) return -1;
    if (n) *n = l;
    return speer_tls_r_bytes(r, d, l);
}
