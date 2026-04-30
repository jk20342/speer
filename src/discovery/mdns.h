#ifndef SPEER_MDNS_H
#define SPEER_MDNS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define MDNS_MULTICAST_ADDR_IPV4 "224.0.0.251"
#define MDNS_MULTICAST_ADDR_IPV6 "ff02::fb"
#define MDNS_PORT 5353
#define MDNS_MAX_PACKET_SIZE 9000
#define MDNS_MAX_NAME_LENGTH 256
#define MDNS_MAX_SERVICES 16
#define MDNS_TTL 120

typedef enum {
    MDNS_TYPE_A = 1,
    MDNS_TYPE_PTR = 12,
    MDNS_TYPE_TXT = 16,
    MDNS_TYPE_AAAA = 28,
    MDNS_TYPE_SRV = 33,
    MDNS_TYPE_ANY = 255,
} mdns_record_type_t;

typedef struct {
    char name[MDNS_MAX_NAME_LENGTH];
    uint16_t port;
    char target[MDNS_MAX_NAME_LENGTH];
    uint16_t priority;
    uint16_t weight;
} mdns_srv_record_t;

typedef struct {
    char key[64];
    char value[256];
} mdns_txt_field_t;

typedef struct {
    char name[MDNS_MAX_NAME_LENGTH];
    mdns_txt_field_t fields[16];
    uint32_t num_fields;
} mdns_txt_record_t;

typedef struct {
    char instance_name[MDNS_MAX_NAME_LENGTH];
    char service_type[MDNS_MAX_NAME_LENGTH];
    char domain[MDNS_MAX_NAME_LENGTH];
    mdns_srv_record_t srv;
    mdns_txt_record_t txt;
    uint8_t ipv4[4];
    uint8_t ipv6[16];
    bool has_ipv4;
    bool has_ipv6;
    uint32_t ttl;
} mdns_service_t;

typedef struct {
    int socket_ipv4;
    int socket_ipv6;
    mdns_service_t services[MDNS_MAX_SERVICES];
    uint32_t num_services;
    void (*on_peer_discovered)(void* user, const char* peer_id, const char* multiaddr);
    void* user;
    uint8_t recv_buffer[MDNS_MAX_PACKET_SIZE];
} mdns_ctx_t;

int mdns_init(mdns_ctx_t* ctx);
void mdns_free(mdns_ctx_t* ctx);

int mdns_register_service(mdns_ctx_t* ctx, const char* instance_name,
                          const char* service_type, uint16_t port,
                          const uint8_t* txt_data, size_t txt_len);
int mdns_unregister_service(mdns_ctx_t* ctx, const char* instance_name);

void mdns_set_discovery_callback(mdns_ctx_t* ctx,
                                  void (*callback)(void* user, const char* peer_id,
                                                  const char* multiaddr),
                                  void* user);

int mdns_poll(mdns_ctx_t* ctx, int timeout_ms);
int mdns_announce(mdns_ctx_t* ctx);

int mdns_build_probe(uint8_t* out, size_t* out_len, const char* service_name);
int mdns_build_announcement(uint8_t* out, size_t* out_len, const mdns_service_t* svc);
/* sender_ipv4_s_addr: sockaddr_in.sin_addr.s_addr from recvfrom (network byte order); use 0 if unknown */
int mdns_parse_packet(mdns_ctx_t* ctx, const uint8_t* data, size_t len,
                      char* out_peer_id, size_t peer_id_cap,
                      char* out_multiaddr, size_t multiaddr_cap,
                      uint32_t sender_ipv4_s_addr);

int mdns_build_libp2p_service_name(char* out, size_t cap, const uint8_t* peer_id);

#endif
