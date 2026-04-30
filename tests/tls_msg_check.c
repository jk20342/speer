#include "speer_internal.h"
#include "tls_msg.h"
#include <stdio.h>
#include <string.h>

#define FAIL(...) do { fprintf(stderr, __VA_ARGS__); return 1; } while (0)

int main(void) {
    uint8_t buf[256];
    speer_tls_writer_t w;
    speer_tls_writer_init(&w, buf, sizeof(buf));

    if (speer_tls_w_handshake_header(&w, TLS_HS_CLIENT_HELLO, 5) != 0) FAIL("hs hdr\n");
    uint8_t body[] = { 1, 2, 3, 4, 5 };
    if (speer_tls_w_bytes(&w, body, sizeof(body)) != 0) FAIL("hs body\n");

    speer_tls_reader_t r;
    speer_tls_reader_init(&r, buf, w.pos);
    uint8_t ty;
    uint32_t blen;
    if (speer_tls_r_u8(&r, &ty) != 0 || ty != TLS_HS_CLIENT_HELLO) FAIL("r hs type\n");
    if (speer_tls_r_u24(&r, &blen) != 0 || blen != 5) FAIL("r hs len\n");
    const uint8_t* got;
    if (speer_tls_r_bytes(&r, &got, 5) != 0 || memcmp(got, body, 5) != 0) FAIL("r hs bytes\n");

    speer_tls_writer_init(&w, buf, sizeof(buf));
    uint8_t u8pair[] = { 9, 8 };
    if (speer_tls_w_vec_u8(&w, u8pair, sizeof(u8pair)) != 0) FAIL("vec8 write\n");
    speer_tls_reader_init(&r, buf, w.pos);
    size_t vn;
    if (speer_tls_r_vec_u8(&r, &got, &vn) != 0 || vn != 2 || got[0] != 9 || got[1] != 8)
        FAIL("vec8 read\n");

    speer_tls_writer_init(&w, buf, sizeof(buf));
    uint8_t mid[] = { 0xaa, 0xbb };
    if (speer_tls_w_vec_u16(&w, mid, sizeof(mid)) != 0) FAIL("vec16 write\n");
    speer_tls_reader_init(&r, buf, w.pos);
    if (speer_tls_r_vec_u16(&r, &got, &vn) != 0 || vn != 2) FAIL("vec16 read\n");

    speer_tls_writer_init(&w, buf, sizeof(buf));
    size_t save = speer_tls_w_save(&w);
    if (speer_tls_w_u16(&w, 0) != 0) FAIL("vec16 placeholder\n");
    if (speer_tls_w_bytes(&w, (const uint8_t*)"tls13", 5) != 0) FAIL("defer body\n");
    if (speer_tls_w_finish_vec_u16(&w, save) != 0) FAIL("finish vec16\n");
    speer_tls_reader_init(&r, buf, w.pos);
    if (speer_tls_r_vec_u16(&r, &got, &vn) != 0 || vn != 5 || memcmp(got, "tls13", 5) != 0)
        FAIL("defer roundtrip\n");

    speer_tls_writer_init(&w, buf, sizeof(buf));
    save = speer_tls_w_save(&w);
    if (speer_tls_w_u24(&w, 0) != 0) FAIL("vec24 placeholder\n");
    if (speer_tls_w_u8(&w, 7) != 0) FAIL("vec24 byte\n");
    if (speer_tls_w_finish_vec_u24(&w, save) != 0) FAIL("finish vec24\n");
    speer_tls_reader_init(&r, buf, w.pos);
    if (speer_tls_r_vec_u24(&r, &got, &vn) != 0 || vn != 1 || got[0] != 7) FAIL("vec24 read\n");

    puts("tls_msg: ok");
    return 0;
}
