#include "speer_internal.h"

#include <stdio.h>

#include "tls13_handshake.h"
#include "tls_msg.h"

#define FAIL(...)                     \
    do {                              \
        fprintf(stderr, __VA_ARGS__); \
        return 1;                     \
    } while (0)

int main(void) {
    speer_tls13_t h;
    uint8_t cert_priv[32] = {1};
    uint8_t cert_pub[32] = {2};
    uint8_t libp2p_priv[32] = {3};
    uint8_t libp2p_pub[32] = {4};
    uint8_t psk[32] = {9};
    if (speer_tls13_init_handshake(&h, SPEER_TLS_ROLE_SERVER, cert_priv, cert_pub,
                                   SPEER_LIBP2P_KEY_ED25519, libp2p_pub, sizeof(libp2p_pub),
                                   libp2p_priv, sizeof(libp2p_priv), NULL, NULL) != 0)
        FAIL("init\n");
    if (speer_tls13_set_psk(&h, psk, sizeof(psk)) != SPEER_TLS_OK) FAIL("set psk\n");
    if (h.psk_len != sizeof(psk)) FAIL("psk len\n");
    h.state = TLS_ST_DONE;

    uint8_t ticket[] = {1, 2, 3, 4};
    if (speer_tls13_send_new_session_ticket(&h, 60, ticket, sizeof(ticket)) != SPEER_TLS_NEED_OUT)
        FAIL("ticket\n");
    if (h.out_len < 18 || h.out_buf[0] != TLS_HS_NEW_SESSION_TICKET) FAIL("ticket msg\n");

    puts("tls13_psk_ticket: ok");
    return 0;
}
