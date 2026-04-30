#include <stdio.h>

#include <string.h>

#include "mdns.h"
#if defined(_WIN32)
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#define FAIL(...)                     \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        return 1;                     \
    } while (0)

static volatile int g_peer_found = 0;
static char g_found_peer_id[128];

static void on_discover(void *user, const char *peer_id, const char *multiaddr) {
    (void)user;
    (void)multiaddr;
    g_peer_found = 1;
    strncpy(g_found_peer_id, peer_id, sizeof(g_found_peer_id) - 1);
}

int main(void) {
    mdns_ctx_t ctx;
    if (mdns_init(&ctx) != 0) FAIL("mdns_init failed\n");
    if (ctx.socket_ipv4 < 0) FAIL("mdns should create socket\n");
    if (ctx.num_services != 0) FAIL("mdns should start with no services\n");

    uint8_t txt_data[] = "\x10id=test_peer_123";
    if (mdns_register_service(&ctx, "MyNode", "_p2p._tcp", 4001, txt_data, sizeof(txt_data) - 1) !=
        0)
        FAIL("mdns_register_service failed\n");
    if (ctx.num_services != 1) FAIL("should have 1 service\n");
    if (strcmp(ctx.services[0].instance_name, "MyNode") != 0) FAIL("instance name mismatch\n");
    if (ctx.services[0].srv.port != 4001) FAIL("port mismatch\n");
    if (ctx.services[0].txt.num_fields != 1) FAIL("should have 1 txt field\n");
    if (strcmp(ctx.services[0].txt.fields[0].key, "id") != 0) FAIL("txt key mismatch\n");
    if (strcmp(ctx.services[0].txt.fields[0].value, "test_peer_123") != 0)
        FAIL("txt value mismatch\n");

    uint8_t packet[512];
    size_t len = sizeof(packet);
    if (mdns_build_announcement(packet, &len, &ctx.services[0]) != 0)
        FAIL("mdns_build_announcement failed\n");
    if (len < 12) FAIL("announcement too short\n");

    mdns_set_discovery_callback(&ctx, on_discover, NULL);
    if (ctx.on_peer_discovered != on_discover) FAIL("callback not set\n");

    uint8_t test_packet[] = {0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                             0x00, 0x06, 0x4d, 0x79, 0x4e, 0x6f, 0x64, 0x65, 0x05, 0x5f, 0x70,
                             0x32, 0x70, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63,
                             0x61, 0x6c, 0x00, 0x00, 0x21, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78,
                             0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xa1, 0x00, 0x00};
    char peer_id[128], multiaddr[256];
    int ret = mdns_parse_packet(&ctx, test_packet, sizeof(test_packet), peer_id, sizeof(peer_id),
                                multiaddr, sizeof(multiaddr), htonl(0x7f000001));
    (void)ret;

    uint8_t peer_pubkey[32] = {0xAB, 0xCD, 0xEF};
    char svc_name[256];
    if (mdns_build_libp2p_service_name(svc_name, sizeof(svc_name), peer_pubkey) != 0)
        FAIL("mdns_build_libp2p_service_name failed\n");
    if (strstr(svc_name, "_p2p._tcp.local") == NULL) FAIL("service name format wrong\n");

    mdns_free(&ctx);
    if (ctx.socket_ipv4 != -1) FAIL("mdns_free should close socket\n");

    puts("mdns: ok");
    return 0;
}
