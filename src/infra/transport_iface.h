#ifndef SPEER_TRANSPORT_IFACE_H
#define SPEER_TRANSPORT_IFACE_H

#include <stdint.h>
#include <stddef.h>

typedef struct speer_transport_endpoint_s speer_transport_endpoint_t;
typedef struct speer_transport_conn_s speer_transport_conn_t;

typedef enum {
    SPEER_TR_OK = 0,
    SPEER_TR_AGAIN = 1,
    SPEER_TR_EOF = 2,
    SPEER_TR_FAIL = -1,
    SPEER_TR_INVALID = -2,
    SPEER_TR_REFUSED = -3,
} speer_tr_result_t;

typedef enum {
    SPEER_TR_DATAGRAM,
    SPEER_TR_STREAM,
} speer_tr_kind_t;

typedef struct {
    const char* name;
    speer_tr_kind_t kind;
    int (*listen)(speer_transport_endpoint_t** out_ep, const char* addr_str, void* config);
    int (*dial)(speer_transport_conn_t** out_conn, const char* addr_str, void* config);
    int (*accept)(speer_transport_endpoint_t* ep, speer_transport_conn_t** out_conn);
    int (*send)(speer_transport_conn_t* c, const uint8_t* data, size_t len, size_t* sent);
    int (*recv)(speer_transport_conn_t* c, uint8_t* buf, size_t cap, size_t* read_len);
    int (*close_conn)(speer_transport_conn_t* c);
    int (*close_endpoint)(speer_transport_endpoint_t* ep);
    int (*peer_addr)(speer_transport_conn_t* c, char* out, size_t cap);
    int (*local_addr)(speer_transport_endpoint_t* ep, char* out, size_t cap);
    int (*set_nonblocking)(speer_transport_conn_t* c, int yes);
} speer_transport_ops_t;

extern const speer_transport_ops_t speer_transport_tcp_ops;
extern const speer_transport_ops_t speer_transport_udp_ops;

#endif
