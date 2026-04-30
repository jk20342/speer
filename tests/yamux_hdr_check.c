#include "speer_internal.h"

#include <stdio.h>

#include <string.h>

#include "yamux.h"

#define FAIL(...)                     \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        return 1;                     \
    } while (0)

int main(void) {
    speer_yamux_hdr_t h = {
        .version = YAMUX_VERSION,
        .type = YAMUX_TYPE_DATA,
        .flags = (uint16_t)(YAMUX_FLAG_SYN | YAMUX_FLAG_ACK),
        .stream_id = 0x01020304u,
        .length = 99,
    };
    uint8_t raw[12];
    speer_yamux_hdr_pack(raw, &h);

    speer_yamux_hdr_t g;
    memset(&g, 0, sizeof(g));
    if (speer_yamux_hdr_unpack(&g, raw) != 0) FAIL("yamux unpack ok hdr\n");
    if (g.version != h.version || g.type != h.type || g.flags != h.flags ||
        g.stream_id != h.stream_id || g.length != h.length)
        FAIL("yamux roundtrip mismatch\n");

    raw[0] = 0xff;
    if (speer_yamux_hdr_unpack(&g, raw) == 0) FAIL("yamux bad version\n");
    raw[0] = YAMUX_VERSION;
    raw[1] = YAMUX_TYPE_GO_AWAY + 1;
    if (speer_yamux_hdr_unpack(&g, raw) == 0) FAIL("yamux bad type\n");

    puts("yamux_hdr: ok");
    return 0;
}
