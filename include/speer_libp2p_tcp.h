#ifndef SPEER_LIBP2P_TCP_H
#define SPEER_LIBP2P_TCP_H

#include <stddef.h>
#include <stdint.h>

#include "libp2p_noise.h"
#include "yamux.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SPEER_LIBP2P_TCP_DEFAULT_CRYPT_Q_CAP (256u * 1024u)

typedef int (*speer_libp2p_send_fn)(void *user, const uint8_t *data, size_t len);
typedef int (*speer_libp2p_recv_fn)(void *user, uint8_t *buf, size_t cap, size_t *out_n);

typedef struct {
    const uint8_t *static_pub;
    const uint8_t *static_priv;
    speer_libp2p_keytype_t keytype;
    const uint8_t *libp2p_pub;
    size_t libp2p_pub_len;
    const uint8_t *libp2p_priv;
    size_t libp2p_priv_len;
} speer_libp2p_identity_t;

typedef struct {
    int fd;
    int is_initiator;
    speer_libp2p_noise_t noise;
    speer_yamux_session_t mux;

    uint8_t crypt_q[SPEER_LIBP2P_TCP_DEFAULT_CRYPT_Q_CAP];
    size_t crypt_q_len;
    size_t crypt_q_off;

    char remote_peer_id_b58[64];
} speer_libp2p_tcp_session_t;

int speer_libp2p_tcp_session_init_dialer(speer_libp2p_tcp_session_t *session, int fd,
                                         const speer_libp2p_identity_t *identity);
int speer_libp2p_tcp_session_init_listener(speer_libp2p_tcp_session_t *session, int fd,
                                           const speer_libp2p_identity_t *identity);
void speer_libp2p_tcp_session_close(speer_libp2p_tcp_session_t *session);

int speer_libp2p_tcp_open_protocol_stream(speer_libp2p_tcp_session_t *session, const char *protocol,
                                          speer_yamux_stream_t **out_stream);
int speer_libp2p_tcp_accept_protocol_stream(speer_libp2p_tcp_session_t *session,
                                            const char *const *protocols, size_t num_protocols,
                                            size_t *selected_idx, speer_yamux_stream_t **out_stream,
                                            int timeout_ms, int pump_step_ms);

int speer_libp2p_uvar_frame_send(void *user, speer_libp2p_send_fn send_fn, const uint8_t *payload,
                                 size_t payload_len);
int speer_libp2p_uvar_frame_recv(void *user, speer_libp2p_recv_fn recv_fn, uint8_t *out,
                                 size_t out_cap, size_t *out_len);

int speer_libp2p_tcp_stream_send_frame(speer_libp2p_tcp_session_t *session,
                                       speer_yamux_stream_t *st, const uint8_t *payload,
                                       size_t payload_len);
int speer_libp2p_tcp_stream_recv_frame(speer_libp2p_tcp_session_t *session,
                                       speer_yamux_stream_t *st, uint8_t *out, size_t out_cap,
                                       size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif
