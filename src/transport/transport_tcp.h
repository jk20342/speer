#ifndef SPEER_TRANSPORT_TCP_H
#define SPEER_TRANSPORT_TCP_H

#include "transport_iface.h"

int speer_tcp_listen(int *out_listen_fd, const char *host, uint16_t port);
int speer_tcp_dial(int *out_fd, const char *host, uint16_t port);
int speer_tcp_accept(int listen_fd, int *out_fd, char *peer_addr_out, size_t peer_cap);
int speer_tcp_recv(int fd, uint8_t *buf, size_t cap, size_t *out_n);
int speer_tcp_send(int fd, const uint8_t *data, size_t len, size_t *out_sent);
void speer_tcp_close(int fd);
int speer_tcp_set_nonblocking(int fd, int yes);

int speer_tcp_recv_all(int fd, uint8_t *buf, size_t len);
int speer_tcp_send_all(int fd, const uint8_t *data, size_t len);

#endif
