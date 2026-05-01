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

    /* libp2p-mdns format: a single dnsaddr=<multiaddr-with-/p2p/peerid> TXT
     * record. The parser pulls the peer id out of the /p2p/ component. */
    static const char dnsaddr_txt[] = "dnsaddr=/ip4/127.0.0.1/tcp/4001/p2p/test_peer_123";
    uint8_t txt_data[1 + sizeof(dnsaddr_txt) - 1];
    txt_data[0] = (uint8_t)(sizeof(dnsaddr_txt) - 1);
    memcpy(txt_data + 1, dnsaddr_txt, sizeof(dnsaddr_txt) - 1);
    if (mdns_register_service(&ctx, "MyNode", "_p2p._udp", 4001, txt_data, sizeof(txt_data)) != 0)
        FAIL("mdns_register_service failed\n");
    if (ctx.num_services != 1) FAIL("should have 1 service\n");
    if (strcmp(ctx.services[0].instance_name, "MyNode") != 0) FAIL("instance name mismatch\n");
    if (ctx.services[0].srv.port != 4001) FAIL("port mismatch\n");
    if (ctx.services[0].txt.num_fields != 1) FAIL("should have 1 txt field\n");
    if (strcmp(ctx.services[0].txt.fields[0].key, "dnsaddr") != 0) FAIL("txt key mismatch\n");
    if (strcmp(ctx.services[0].txt.fields[0].value, "/ip4/127.0.0.1/tcp/4001/p2p/test_peer_123") !=
        0)
        FAIL("txt value mismatch\n");
    if (!ctx.services[0].txt.fields[0].has_value) FAIL("txt value marker mismatch\n");

    uint8_t packet[512];
    size_t len = sizeof(packet);
    if (mdns_build_announcement(packet, &len, &ctx.services[0]) != 0)
        FAIL("mdns_build_announcement failed\n");
    if (len < 12) FAIL("announcement too short\n");

    mdns_set_discovery_callback(&ctx, on_discover, NULL);
    if (ctx.on_peer_discovered != on_discover) FAIL("callback not set\n");

    char peer_id[128], multiaddr[256];
    int ret = mdns_parse_packet(&ctx, packet, len, peer_id, sizeof(peer_id), multiaddr,
                                sizeof(multiaddr), htonl(0x7f000001));
    if (ret != 0) FAIL("mdns_parse_packet should parse built announcement\n");
    if (strcmp(peer_id, "test_peer_123") != 0) FAIL("parsed peer id mismatch (got '%s')\n", peer_id);
    if (strcmp(multiaddr, "/ip4/127.0.0.1/tcp/4001/p2p/test_peer_123") != 0)
        FAIL("parsed multiaddr mismatch (got '%s')\n", multiaddr);

    uint8_t peer_pubkey[32] = {0xAB, 0xCD, 0xEF};
    char svc_name[256];
    if (mdns_build_libp2p_service_name(svc_name, sizeof(svc_name), peer_pubkey) != 0)
        FAIL("mdns_build_libp2p_service_name failed\n");
    if (strcmp(svc_name, "_p2p._udp.local") != 0) FAIL("service name format wrong\n");

    if (mdns_unregister_service(&ctx, "MyNode") != 0) FAIL("mdns_unregister_service failed\n");
    if (ctx.num_services != 0) FAIL("unregister should remove service\n");

    len = sizeof(packet);
    if (mdns_build_probe(packet, &len, "_p2p._udp.local") != 0) FAIL("mdns_build_probe failed\n");
    if (len <= 12) FAIL("probe too short\n");

    mdns_free(&ctx);
    if (ctx.socket_ipv4 != -1) FAIL("mdns_free should close socket\n");

    puts("mdns: ok");
    return 0;
}
