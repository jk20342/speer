#include "dht.h"

#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#define MIN(a, b)           ((a) < (b) ? (a) : (b))
#define MAX(a, b)           ((a) > (b) ? (a) : (b))
#define COPY(dst, src, len) memcpy((dst), (src), (len))
#define ZERO(p, len)        memset((p), 0, (len))
#define EQUAL(a, b, len)    (memcmp((a), (b), (len)) == 0)

void dht_distance(const uint8_t *a, const uint8_t *b, uint8_t *out) {
    for (int i = 0; i < DHT_ID_BYTES; i++) { out[i] = a[i] ^ b[i]; }
}

uint32_t dht_prefix_bits(const uint8_t *id1, const uint8_t *id2) {
    uint32_t bits = 0;
    for (int i = 0; i < DHT_ID_BYTES; i++) {
        uint8_t diff = id1[i] ^ id2[i];
        if (diff == 0) {
            bits += 8;
        } else {
            for (int j = 7; j >= 0; j--) {
                if ((diff >> j) & 1) return bits;
                bits++;
            }
        }
    }
    return bits;
}

int dht_distance_cmp(const uint8_t *a, const uint8_t *b, const uint8_t *target) {
    for (int i = 0; i < DHT_ID_BYTES; i++) {
        uint8_t da = a[i] ^ target[i];
        uint8_t db = b[i] ^ target[i];
        if (da < db) return -1;
        if (da > db) return 1;
    }
    return 0;
}

static dht_bucket_t *bucket_new(void) {
    dht_bucket_t *b = (dht_bucket_t *)calloc(1, sizeof(dht_bucket_t));
    return b;
}

static void bucket_free(dht_bucket_t *b) {
    if (!b) return;
    bucket_free(b->left);
    bucket_free(b->right);
    free(b);
}

int dht_init(dht_t *dht, const uint8_t node_id[DHT_ID_BYTES]) {
    ZERO(dht, sizeof(dht_t));
    COPY(dht->id, node_id, DHT_ID_BYTES);
    dht->root = bucket_new();
    dht->start_time_ms = 0;
    return dht->root ? 0 : -1;
}

void dht_free(dht_t *dht) {
    bucket_free(dht->root);
    dht->root = NULL;
    dht->total_nodes = 0;
}

static dht_bucket_t *find_bucket(dht_bucket_t *root, const uint8_t *our_id, const uint8_t *node_id,
                                 int depth) {
    if (!root->left && !root->right) {
        if (root->node_count < DHT_K || depth >= DHT_MAX_BUCKETS) { return root; }
        root->left = bucket_new();
        root->right = bucket_new();
        if (!root->left || !root->right) {
            free(root->left);
            free(root->right);
            root->left = root->right = NULL;
            return root;
        }
        for (uint32_t i = 0; i < root->node_count; i++) {
            dht_node_t *n = &root->nodes[i];
            int bit = (n->id[depth / 8] >> (7 - (depth % 8))) & 1;
            dht_bucket_t *target = bit ? root->right : root->left;
            if (target->node_count < DHT_K) {
                COPY(&target->nodes[target->node_count++], n, sizeof(dht_node_t));
            }
        }
        root->node_count = 0;
    }
    int bit = (node_id[depth / 8] >> (7 - (depth % 8))) & 1;
    dht_bucket_t *next = bit ? root->right : root->left;
    return find_bucket(next, our_id, node_id, depth + 1);
}

int dht_add_node(dht_t *dht, const uint8_t *id, const char *address) {
    if (EQUAL(id, dht->id, DHT_ID_BYTES)) return -1;
    dht_bucket_t *bucket = find_bucket(dht->root, dht->id, id, 0);
    for (uint32_t i = 0; i < bucket->node_count; i++) {
        if (EQUAL(bucket->nodes[i].id, id, DHT_ID_BYTES)) {
            COPY(bucket->nodes[i].address, address,
                 MIN(strlen(address) + 1, sizeof(bucket->nodes[i].address)));
            bucket->nodes[i].last_seen_ms = 0;
            bucket->nodes[i].good = true;
            return 0;
        }
    }
    if (bucket->node_count >= DHT_K) return -1;
    dht_node_t *n = &bucket->nodes[bucket->node_count++];
    ZERO(n, sizeof(dht_node_t));
    COPY(n->id, id, DHT_ID_BYTES);
    size_t addr_len = strlen(address);
    COPY(n->address, address, MIN(addr_len + 1, sizeof(n->address)));
    n->good = true;
    dht->total_nodes++;
    return 0;
}

void dht_remove_node(dht_t *dht, const uint8_t *id) {
    int prefix = (int)dht_prefix_bits(dht->id, id);
    dht_bucket_t *b = dht->root;
    int depth = 0;
    while (b && (b->left || b->right) && depth < prefix) {
        int bit = (id[depth / 8] >> (7 - (depth % 8))) & 1;
        b = bit ? b->right : b->left;
        depth++;
    }
    if (!b) return;
    for (uint32_t i = 0; i < b->node_count; i++) {
        if (EQUAL(b->nodes[i].id, id, DHT_ID_BYTES)) {
            for (uint32_t j = i; j < b->node_count - 1; j++) {
                COPY(&b->nodes[j], &b->nodes[j + 1], sizeof(dht_node_t));
            }
            b->node_count--;
            dht->total_nodes--;
            return;
        }
    }
}

typedef struct {
    dht_node_t *nodes;
    int capacity;
    int count;
    const uint8_t *target;
} node_collector_t;

static void collect_nodes(dht_bucket_t *bucket, node_collector_t *collector) {
    if (!bucket) return;
    if (!bucket->left && !bucket->right) {
        for (uint32_t i = 0; i < bucket->node_count && collector->count < collector->capacity;
             i++) {
            if (bucket->nodes[i].good) {
                COPY(&collector->nodes[collector->count++], &bucket->nodes[i], sizeof(dht_node_t));
            }
        }
        return;
    }
    collect_nodes(bucket->left, collector);
    collect_nodes(bucket->right, collector);
}

int dht_get_closest_nodes(dht_t *dht, const uint8_t *target_id, dht_node_t *out_nodes,
                          int max_nodes) {
    node_collector_t collector = {
        .nodes = out_nodes, .capacity = max_nodes, .count = 0, .target = target_id};
    collect_nodes(dht->root, &collector);
    for (int i = 0; i < collector.count - 1; i++) {
        for (int j = i + 1; j < collector.count; j++) {
            if (dht_distance_cmp(collector.nodes[i].id, collector.nodes[j].id, target_id) > 0) {
                dht_node_t tmp;
                COPY(&tmp, &collector.nodes[i], sizeof(dht_node_t));
                COPY(&collector.nodes[i], &collector.nodes[j], sizeof(dht_node_t));
                COPY(&collector.nodes[j], &tmp, sizeof(dht_node_t));
            }
        }
    }
    return collector.count;
}

int dht_handle_ping(dht_t *dht, const uint8_t *sender_id, const char *sender_addr,
                    uint8_t *response, size_t *response_len) {
    dht_add_node(dht, sender_id, sender_addr);
    if (*response_len >= DHT_ID_BYTES) {
        COPY(response, dht->id, DHT_ID_BYTES);
        *response_len = DHT_ID_BYTES;
        return 0;
    }
    return -1;
}

int dht_handle_find_node(dht_t *dht, const uint8_t *target_id, uint8_t *response,
                         size_t *response_len) {
    dht_node_t nodes[DHT_K];
    int count = dht_get_closest_nodes(dht, target_id, nodes, DHT_K);
    size_t pos = 0;
    if (pos + 1 > *response_len) return -1;
    response[pos++] = (uint8_t)count;
    for (int i = 0; i < count; i++) {
        size_t addr_len = strlen(nodes[i].address);
        if (pos + DHT_ID_BYTES + 1 + addr_len > *response_len) break;
        COPY(response + pos, nodes[i].id, DHT_ID_BYTES);
        pos += DHT_ID_BYTES;
        response[pos++] = (uint8_t)addr_len;
        COPY(response + pos, nodes[i].address, addr_len);
        pos += addr_len;
    }
    *response_len = pos;
    return 0;
}

#define DHT_MAX_STORED_VALUES 256
static dht_value_t stored_values[DHT_MAX_STORED_VALUES];
static int num_stored_values = 0;

int dht_handle_store(dht_t *dht, const uint8_t *key, const uint8_t *value, size_t value_len,
                     const uint8_t *publisher_id) {
    (void)dht;
    for (int i = 0; i < num_stored_values; i++) {
        if (EQUAL(stored_values[i].key, key, DHT_ID_BYTES)) {
            if (value_len > DHT_VALUE_MAX_SIZE) return -1;
            COPY(stored_values[i].value, value, value_len);
            stored_values[i].value_len = value_len;
            stored_values[i].stored_at_ms = 0;
            return 0;
        }
    }
    if (num_stored_values >= DHT_MAX_STORED_VALUES) return -1;
    dht_value_t *v = &stored_values[num_stored_values++];
    COPY(v->key, key, DHT_ID_BYTES);
    COPY(v->value, value, value_len);
    v->value_len = value_len;
    COPY(v->original_publisher, publisher_id, DHT_ID_BYTES);
    return 0;
}

int dht_handle_find_value(dht_t *dht, const uint8_t *key, uint8_t *response, size_t *response_len,
                          dht_value_t *out_value) {
    for (int i = 0; i < num_stored_values; i++) {
        if (EQUAL(stored_values[i].key, key, DHT_ID_BYTES)) {
            if (out_value) { COPY(out_value, &stored_values[i], sizeof(dht_value_t)); }
            return 1;
        }
    }
    return dht_handle_find_node(dht, key, response, response_len);
}

void dht_expire_values(dht_t *dht, uint64_t now_ms) {
    (void)dht;
    int i = 0;
    while (i < num_stored_values) {
        if (stored_values[i].expires_at_ms > 0 && now_ms > stored_values[i].expires_at_ms) {
            for (int j = i; j < num_stored_values - 1; j++) {
                COPY(&stored_values[j], &stored_values[j + 1], sizeof(dht_value_t));
            }
            num_stored_values--;
        } else {
            i++;
        }
    }
}

typedef struct {
    dht_node_t node;
    uint8_t distance[DHT_ID_BYTES];
    bool queried;
    bool responded;
} lookup_candidate_t;

int dht_iterative_find_node(dht_t *dht, const uint8_t *target_id, dht_node_t *out_nodes,
                            int max_nodes) {
    lookup_candidate_t candidates[DHT_K * 4];
    int num_candidates = 0;
    int num_queried = 0;
    int num_responded = 0;
    uint8_t closest_responder_dist[DHT_ID_BYTES];
    int iteration = 0;
    int max_iterations = 10;

    dht_node_t local_nodes[DHT_K * 2];
    int local_count = dht_get_closest_nodes(dht, target_id, local_nodes, DHT_K * 2);
    for (int i = 0; i < local_count && num_candidates < (int)(DHT_K * 4); i++) {
        COPY(&candidates[num_candidates].node, &local_nodes[i], sizeof(dht_node_t));
        dht_distance(candidates[num_candidates].node.id, target_id,
                     candidates[num_candidates].distance);
        candidates[num_candidates].queried = false;
        candidates[num_candidates].responded = false;
        num_candidates++;
    }

    while (num_queried < DHT_K * 3 && iteration < max_iterations) {
        iteration++;
        int to_query = 0;
        lookup_candidate_t *to_query_nodes[DHT_ALPHA];

        for (int i = 0; i < num_candidates && to_query < DHT_ALPHA; i++) {
            if (!candidates[i].queried) { to_query_nodes[to_query++] = &candidates[i]; }
        }
        if (to_query == 0) break;

        for (int i = 0; i < to_query; i++) {
            to_query_nodes[i]->queried = true;
            num_queried++;

            uint8_t response[2048] = {0};
            size_t response_len = sizeof(response);
            int ret = dht->send_rpc(dht->user, to_query_nodes[i]->node.address, target_id,
                                    DHT_ID_BYTES);
            if (ret >= 0) {
                to_query_nodes[i]->responded = true;
                num_responded++;
                dht_distance(to_query_nodes[i]->node.id, target_id, closest_responder_dist);

                if (response_len > 1) {
                    int new_count = response[0];
                    size_t pos = 1;
                    for (int j = 0; j < new_count && pos < response_len; j++) {
                        if (pos + DHT_ID_BYTES + 1 > response_len) break;
                        uint8_t new_id[DHT_ID_BYTES];
                        COPY(new_id, response + pos, DHT_ID_BYTES);
                        pos += DHT_ID_BYTES;
                        uint8_t addr_len = response[pos++];
                        if (pos + addr_len > response_len || addr_len >= 64) break;
                        char new_addr[64];
                        COPY(new_addr, response + pos, addr_len);
                        new_addr[addr_len] = 0;
                        pos += addr_len;

                        bool exists = false;
                        for (int k = 0; k < num_candidates; k++) {
                            if (EQUAL(candidates[k].node.id, new_id, DHT_ID_BYTES)) {
                                exists = true;
                                break;
                            }
                        }
                        if (!exists && num_candidates < (int)(DHT_K * 4)) {
                            COPY(&candidates[num_candidates].node.id, new_id, DHT_ID_BYTES);
                            COPY(candidates[num_candidates].node.address, new_addr, addr_len + 1);
                            dht_distance(new_id, target_id, candidates[num_candidates].distance);
                            candidates[num_candidates].queried = false;
                            candidates[num_candidates].responded = false;
                            num_candidates++;
                        }
                    }
                }
            }
        }

        for (int i = 0; i < num_candidates - 1; i++) {
            for (int j = i + 1; j < num_candidates; j++) {
                int cmp = dht_distance_cmp(candidates[i].distance, candidates[j].distance,
                                           target_id);
                if (cmp > 0) {
                    lookup_candidate_t tmp;
                    COPY(&tmp, &candidates[i], sizeof(lookup_candidate_t));
                    COPY(&candidates[i], &candidates[j], sizeof(lookup_candidate_t));
                    COPY(&candidates[j], &tmp, sizeof(lookup_candidate_t));
                }
            }
        }

        int closer_count = 0;
        for (int i = 0; i < num_candidates; i++) {
            if (candidates[i].responded &&
                dht_distance_cmp(candidates[i].distance, closest_responder_dist, target_id) < 0) {
                closer_count++;
            }
        }
        if (closer_count == 0 && num_responded > 0) break;
    }

    int to_return = (num_candidates < max_nodes) ? num_candidates : max_nodes;
    for (int i = 0; i < to_return; i++) {
        COPY(&out_nodes[i], &candidates[i].node, sizeof(dht_node_t));
    }
    return to_return;
}

int dht_iterative_find_value(dht_t *dht, const uint8_t *key, uint8_t *value, size_t *value_len) {
    dht_value_t v;
    uint8_t response[2048];
    size_t response_len = sizeof(response);
    int ret = dht_handle_find_value(dht, key, response, &response_len, &v);
    if (ret == 1) {
        size_t copy_len = (v.value_len < *value_len) ? v.value_len : *value_len;
        COPY(value, v.value, copy_len);
        *value_len = copy_len;
        return 0;
    }

    lookup_candidate_t candidates[DHT_K * 4];
    int num_candidates = 0;
    int num_queried = 0;
    int iteration = 0;

    dht_node_t local_nodes[DHT_K * 2];
    int local_count = dht_get_closest_nodes(dht, key, local_nodes, DHT_K * 2);
    for (int i = 0; i < local_count && num_candidates < (int)(DHT_K * 4); i++) {
        COPY(&candidates[num_candidates].node, &local_nodes[i], sizeof(dht_node_t));
        dht_distance(candidates[num_candidates].node.id, key, candidates[num_candidates].distance);
        candidates[num_candidates].queried = false;
        num_candidates++;
    }

    while (num_queried < DHT_K * 3 && iteration < 10) {
        iteration++;
        int to_query = 0;
        for (int i = 0; i < num_candidates && to_query < DHT_ALPHA; i++) {
            if (!candidates[i].queried) {
                candidates[i].queried = true;
                num_queried++;
                to_query++;

                uint8_t val_response[2048];
                size_t val_response_len = sizeof(val_response);
                dht_value_t found_val;
                int val_ret = dht_handle_find_value(dht, key, val_response, &val_response_len,
                                                    &found_val);
                if (val_ret == 1) {
                    size_t copy_len = (found_val.value_len < *value_len) ? found_val.value_len
                                                                         : *value_len;
                    COPY(value, found_val.value, copy_len);
                    *value_len = copy_len;
                    return 0;
                }
            }
        }
        if (to_query == 0) break;
    }
    return -1;
}

void dht_refresh_buckets(dht_t *dht, uint64_t now_ms) {
    (void)dht;
    (void)now_ms;
}

int dht_ping(dht_t *dht, const char *address) {
    (void)dht;
    (void)address;
    return 0;
}

int dht_find_node(dht_t *dht, const uint8_t *target_id) {
    (void)dht;
    (void)target_id;
    return 0;
}

int dht_find_value(dht_t *dht, const uint8_t *key) {
    (void)dht;
    (void)key;
    return 0;
}

int dht_store(dht_t *dht, const uint8_t *key, const uint8_t *value, size_t value_len) {
    (void)dht;
    (void)key;
    (void)value;
    (void)value_len;
    return 0;
}

int dht_update_node(dht_t *dht, const uint8_t *id, const char *address) {
    return dht_add_node(dht, id, address);
}

void dht_bootstrap_init(dht_bootstrap_list_t *list) {
    list->num_nodes = 0;
}

void dht_bootstrap_add(dht_bootstrap_list_t *list, const char *address) {
    if (list->num_nodes >= 8) return;
    size_t len = strlen(address);
    if (len >= sizeof(list->nodes[0].address)) return;
    COPY(list->nodes[list->num_nodes].address, address, len + 1);
    list->num_nodes++;
}

int dht_bootstrap_run(dht_t *dht, dht_bootstrap_list_t *list, uint64_t now_ms) {
    (void)now_ms;
    for (int i = 0; i < list->num_nodes; i++) { dht_ping(dht, list->nodes[i].address); }
    return list->num_nodes > 0 ? 0 : -1;
}

int dht_is_bootstrapped(dht_t *dht) {
    return dht->bootstrapped;
}
