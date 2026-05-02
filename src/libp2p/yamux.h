#ifndef SPEER_YAMUX_H
#define SPEER_YAMUX_H

#include <stddef.h>
#include <stdint.h>

#define YAMUX_VERSION            0x00
#define YAMUX_TYPE_DATA          0x00
#define YAMUX_TYPE_WINDOW_UPDATE 0x01
#define YAMUX_TYPE_PING          0x02
#define YAMUX_TYPE_GO_AWAY       0x03

#define YAMUX_FLAG_SYN           0x0001
#define YAMUX_FLAG_ACK           0x0002
#define YAMUX_FLAG_FIN           0x0004
#define YAMUX_FLAG_RST           0x0008

#define YAMUX_INITIAL_WINDOW     262144
#define YAMUX_MAX_STREAMS        256
#define YAMUX_MAX_RECV_BUF       (4u * 1024u * 1024u)

typedef struct {
    uint8_t version;
    uint8_t type;
    uint16_t flags;
    uint32_t stream_id;
    uint32_t length;
} speer_yamux_hdr_t;

void speer_yamux_hdr_pack(uint8_t out[12], const speer_yamux_hdr_t *h);
int speer_yamux_hdr_unpack(speer_yamux_hdr_t *h, const uint8_t in[12]);

typedef struct speer_yamux_stream_s {
    uint32_t id;
    uint32_t recv_window;
    uint32_t send_window;
    int remote_closed;
    int local_closed;
    int reset;
    uint8_t *recv_buf;
    size_t recv_buf_len;
    size_t recv_buf_cap;
    struct speer_yamux_stream_s *next;
} speer_yamux_stream_t;

typedef struct speer_yamux_session_s {
    int is_initiator;
    uint32_t next_stream_id;
    speer_yamux_stream_t *streams;
    uint32_t stream_count;
    uint32_t max_streams;
    size_t max_recv_buf;

    int (*send_raw)(void *user, const uint8_t *data, size_t len);
    int (*recv_raw)(void *user, uint8_t *buf, size_t cap, size_t *out_n);
    void *user;
} speer_yamux_session_t;

void speer_yamux_init(speer_yamux_session_t *s, int is_initiator,
                      int (*send_raw)(void *, const uint8_t *, size_t),
                      int (*recv_raw)(void *, uint8_t *, size_t, size_t *), void *user);
void speer_yamux_close(speer_yamux_session_t *s);

speer_yamux_stream_t *speer_yamux_open_stream(speer_yamux_session_t *s);
int speer_yamux_stream_write(speer_yamux_session_t *s, speer_yamux_stream_t *st,
                             const uint8_t *data, size_t len);
int speer_yamux_stream_close(speer_yamux_session_t *s, speer_yamux_stream_t *st);
int speer_yamux_stream_reset(speer_yamux_session_t *s, speer_yamux_stream_t *st, uint32_t code);

int speer_yamux_pump(speer_yamux_session_t *s);
int speer_yamux_send_window_update(speer_yamux_session_t *s, speer_yamux_stream_t *st,
                                   uint32_t inc);
int speer_yamux_send_ping(speer_yamux_session_t *s, uint32_t opaque, int ack);
int speer_yamux_send_go_away(speer_yamux_session_t *s, uint32_t code);

#endif
