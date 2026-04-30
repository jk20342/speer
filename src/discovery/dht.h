#ifndef SPEER_DHT_H
#define SPEER_DHT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DHT_ID_BITS               256
#define DHT_ID_BYTES              32
#define DHT_K                     20
#define DHT_ALPHA                 3
#define DHT_MAX_BUCKETS           160
#define DHT_RPC_TIMEOUT_MS        5000
#define DHT_REFRESH_INTERVAL_MS   900000
#define DHT_REPUBLISH_INTERVAL_MS 86400000

#define DHT_RPC_PING              0x01
#define DHT_RPC_STORE             0x02
#define DHT_RPC_FIND_NODE         0x03
#define DHT_RPC_FIND_VALUE        0x04
#define DHT_RPC_ANNOUNCE          0x05

#define DHT_VALUE_MAX_SIZE        1024

typedef struct {
    uint8_t id[DHT_ID_BYTES];
    char address[64];
    uint64_t last_seen_ms;
    uint64_t last_query_ms;
    int pending_queries;
    bool good;
} dht_node_t;

typedef struct dht_bucket_s {
    dht_node_t nodes[DHT_K];
    uint32_t node_count;
    uint64_t last_changed_ms;
    struct dht_bucket_s *left;
    struct dht_bucket_s *right;
} dht_bucket_t;

typedef struct {
    uint8_t key[DHT_ID_BYTES];
    uint8_t value[DHT_VALUE_MAX_SIZE];
    size_t value_len;
    uint64_t stored_at_ms;
    uint64_t expires_at_ms;
    uint8_t original_publisher[DHT_ID_BYTES];
} dht_value_t;

typedef struct {
    uint8_t id[DHT_ID_BYTES];
    dht_bucket_t *root;
    int (*send_rpc)(void *user, const char *addr, const uint8_t *data, size_t len);
    void *user;
    uint32_t total_nodes;
    uint64_t start_time_ms;
    bool bootstrapped;
    uint64_t last_bootstrap_ms;
} dht_t;

typedef struct {
    char address[64];
    uint64_t last_attempt_ms;
    int failures;
} dht_bootstrap_t;

typedef struct {
    dht_bootstrap_t nodes[8];
    int num_nodes;
    int active_count;
} dht_bootstrap_list_t;

int dht_init(dht_t *dht, const uint8_t node_id[DHT_ID_BYTES]);
void dht_free(dht_t *dht);

int dht_handle_ping(dht_t *dht, const uint8_t *sender_id, const char *sender_addr,
                    uint8_t *response, size_t *response_len);
int dht_handle_find_node(dht_t *dht, const uint8_t *target_id, uint8_t *response,
                         size_t *response_len);
int dht_handle_find_value(dht_t *dht, const uint8_t *key, uint8_t *response, size_t *response_len,
                          dht_value_t *out_value);
int dht_handle_store(dht_t *dht, const uint8_t *key, const uint8_t *value, size_t value_len,
                     const uint8_t *publisher_id);

int dht_compute_store_token(dht_t *dht, const char *sender_addr, uint8_t token[16]);
int dht_verify_store_token(dht_t *dht, const char *sender_addr, const uint8_t token[16]);
int dht_handle_store_with_token(dht_t *dht, const char *sender_addr, const uint8_t token[16],
                                const uint8_t *key, const uint8_t *value, size_t value_len,
                                const uint8_t *publisher_id);

int dht_ping(dht_t *dht, const char *address);
int dht_find_node(dht_t *dht, const uint8_t *target_id);
int dht_find_value(dht_t *dht, const uint8_t *key);
int dht_store(dht_t *dht, const uint8_t *key, const uint8_t *value, size_t value_len);

int dht_add_node(dht_t *dht, const uint8_t *id, const char *address);
int dht_update_node(dht_t *dht, const uint8_t *id, const char *address);
void dht_remove_node(dht_t *dht, const uint8_t *id);
int dht_get_closest_nodes(dht_t *dht, const uint8_t *target_id, dht_node_t *out_nodes,
                          int max_nodes);

int dht_iterative_find_node(dht_t *dht, const uint8_t *target_id, dht_node_t *out_nodes,
                            int max_nodes);
int dht_iterative_find_value(dht_t *dht, const uint8_t *key, uint8_t *value, size_t *value_len);

void dht_refresh_buckets(dht_t *dht, uint64_t now_ms);
void dht_expire_values(dht_t *dht, uint64_t now_ms);

void dht_bootstrap_init(dht_bootstrap_list_t *list);
void dht_bootstrap_add(dht_bootstrap_list_t *list, const char *address);
int dht_bootstrap_run(dht_t *dht, dht_bootstrap_list_t *list, uint64_t now_ms);
int dht_is_bootstrapped(dht_t *dht);

void dht_distance(const uint8_t *a, const uint8_t *b, uint8_t *out);
int dht_distance_cmp(const uint8_t *a, const uint8_t *b, const uint8_t *target);
uint32_t dht_prefix_bits(const uint8_t *id1, const uint8_t *id2);

#endif
