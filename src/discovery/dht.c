#include "dht.h"

#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include "../speer_internal.h"
#include "../util/ct_helpers.h"

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

static uint8_t g_dht_token_secret[32];
static int g_dht_token_secret_initialized = 0;

static int dht_token_init_if_needed(void) {
    if (g_dht_token_secret_initialized) return 0;
    if (speer_random_bytes_or_fail(g_dht_token_secret, sizeof(g_dht_token_secret)) != 0) {
        return -1;
    }
    g_dht_token_secret_initialized = 1;
    return 0;
}

int dht_compute_store_token(dht_t *dht, const char *sender_addr, uint8_t token[16]) {
    (void)dht;
    if (!sender_addr || !token) return -1;
    if (dht_token_init_if_needed() != 0) return -1;
    uint8_t k_ipad[64], k_opad[64];
    ZERO(k_ipad, sizeof(k_ipad));
    ZERO(k_opad, sizeof(k_opad));
    COPY(k_ipad, g_dht_token_secret, sizeof(g_dht_token_secret));
    COPY(k_opad, g_dht_token_secret, sizeof(g_dht_token_secret));
    for (size_t i = 0; i < sizeof(k_ipad); i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }
    sha256_ctx_t ctx;
    uint8_t inner[32];
    speer_sha256_init(&ctx);
    speer_sha256_update(&ctx, k_ipad, sizeof(k_ipad));
    speer_sha256_update(&ctx, (const uint8_t *)sender_addr, strlen(sender_addr));
    speer_sha256_final(&ctx, inner);
    uint8_t mac[32];
    speer_sha256_init(&ctx);
    speer_sha256_update(&ctx, k_opad, sizeof(k_opad));
    speer_sha256_update(&ctx, inner, sizeof(inner));
    speer_sha256_final(&ctx, mac);
    COPY(token, mac, 16);
    ZERO(k_ipad, sizeof(k_ipad));
    ZERO(k_opad, sizeof(k_opad));
    ZERO(inner, sizeof(inner));
    return 0;
}

int dht_verify_store_token(dht_t *dht, const char *sender_addr, const uint8_t token[16]) {
    uint8_t expect[16];
    if (dht_compute_store_token(dht, sender_addr, expect) != 0) return -1;
    return speer_ct_memeq(expect, token, 16) ? 0 : -1;
}

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
    (void)our_id;
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

int dht_handle_store_with_token(dht_t *dht, const char *sender_addr, const uint8_t token[16],
                                const uint8_t *key, const uint8_t *value, size_t value_len,
                                const uint8_t *publisher_id) {
    if (!sender_addr || !token) return -1;
    if (dht_verify_store_token(dht, sender_addr, token) != 0) return -1;
    return dht_handle_store(dht, key, value, value_len, publisher_id);
}

int dht_handle_store(dht_t *dht, const uint8_t *key, const uint8_t *value, size_t value_len,
                     const uint8_t *publisher_id) {
    if (!dht) return -1;
    if (!key || !value || !publisher_id) return -1;
    if (value_len == 0 || value_len > DHT_VALUE_MAX_SIZE) return -1;
    for (int i = 0; i < dht->num_values; i++) {
        if (EQUAL(dht->values[i].key, key, DHT_ID_BYTES)) {
            COPY(dht->values[i].value, value, value_len);
            dht->values[i].value_len = value_len;
            dht->values[i].stored_at_ms = dht->start_time_ms;
            dht->values[i].expires_at_ms = dht->start_time_ms + DHT_VALUE_TTL_MS;
            COPY(dht->values[i].original_publisher, publisher_id, DHT_ID_BYTES);
            return 0;
        }
    }
    if (dht->num_values >= DHT_MAX_STORED_VALUES) return -1;
    dht_value_t *v = &dht->values[dht->num_values++];
    COPY(v->key, key, DHT_ID_BYTES);
    COPY(v->value, value, value_len);
    v->value_len = value_len;
    v->stored_at_ms = dht->start_time_ms;
    v->expires_at_ms = dht->start_time_ms + DHT_VALUE_TTL_MS;
    COPY(v->original_publisher, publisher_id, DHT_ID_BYTES);
    return 0;
}

int dht_handle_find_value(dht_t *dht, const uint8_t *key, uint8_t *response, size_t *response_len,
                          dht_value_t *out_value) {
    if (!dht || !key) return -1;
    for (int i = 0; i < dht->num_values; i++) {
        if (EQUAL(dht->values[i].key, key, DHT_ID_BYTES)) {
            if (out_value) { COPY(out_value, &dht->values[i], sizeof(dht_value_t)); }
            if (response && response_len) {
                if (*response_len < 3 + dht->values[i].value_len) return -1;
                response[0] = 0xff;
                response[1] = (uint8_t)(dht->values[i].value_len >> 8);
                response[2] = (uint8_t)dht->values[i].value_len;
                COPY(response + 3, dht->values[i].value, dht->values[i].value_len);
                *response_len = 3 + dht->values[i].value_len;
            }
            return 1;
        }
    }
    return dht_handle_find_node(dht, key, response, response_len);
}

void dht_expire_values(dht_t *dht, uint64_t now_ms) {
    if (!dht) return;
    int i = 0;
    while (i < dht->num_values) {
        if (dht->values[i].expires_at_ms > 0 && now_ms > dht->values[i].expires_at_ms) {
            for (int j = i; j < dht->num_values - 1; j++) {
                COPY(&dht->values[j], &dht->values[j + 1], sizeof(dht_value_t));
            }
            dht->num_values--;
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

static void sort_candidates(lookup_candidate_t *candidates, int n) {
    for (int i = 0; i < n - 1; i++) {
        for (int j = i + 1; j < n; j++) {
            if (memcmp(candidates[i].distance, candidates[j].distance, DHT_ID_BYTES) > 0) {
                lookup_candidate_t tmp;
                COPY(&tmp, &candidates[i], sizeof(lookup_candidate_t));
                COPY(&candidates[i], &candidates[j], sizeof(lookup_candidate_t));
                COPY(&candidates[j], &tmp, sizeof(lookup_candidate_t));
            }
        }
    }
}

static int candidate_add(lookup_candidate_t *candidates, int *num_candidates, const uint8_t *target,
                         const uint8_t *id, const char *addr) {
    for (int i = 0; i < *num_candidates; i++)
        if (EQUAL(candidates[i].node.id, id, DHT_ID_BYTES)) return 0;
    if (*num_candidates >= (int)(DHT_K * 4)) return -1;
    lookup_candidate_t *c = &candidates[(*num_candidates)++];
    ZERO(c, sizeof(*c));
    COPY(c->node.id, id, DHT_ID_BYTES);
    COPY(c->node.address, addr, MIN(strlen(addr) + 1, sizeof(c->node.address)));
    c->node.good = true;
    dht_distance(id, target, c->distance);
    return 0;
}

static int parse_nodes_response(const uint8_t *response, size_t response_len,
                                lookup_candidate_t *candidates, int *num_candidates,
                                const uint8_t *target) {
    if (response_len < 1 || response[0] == 0xff) return -1;
    int new_count = response[0];
    size_t pos = 1;
    for (int j = 0; j < new_count && pos < response_len; j++) {
        if (pos + DHT_ID_BYTES + 1 > response_len) return -1;
        const uint8_t *new_id = response + pos;
        pos += DHT_ID_BYTES;
        uint8_t addr_len = response[pos++];
        if (pos + addr_len > response_len || addr_len >= 64) return -1;
        char new_addr[64];
        COPY(new_addr, response + pos, addr_len);
        new_addr[addr_len] = 0;
        pos += addr_len;
        candidate_add(candidates, num_candidates, target, new_id, new_addr);
    }
    return pos == response_len ? 0 : -1;
}

static int parse_value_response(const uint8_t *response, size_t response_len, uint8_t *value,
                                size_t *value_len) {
    if (response_len < 3 || response[0] != 0xff) return 0;
    size_t n = ((size_t)response[1] << 8) | response[2];
    if (3 + n != response_len || n > *value_len) return -1;
    COPY(value, response + 3, n);
    *value_len = n;
    return 1;
}

int dht_iterative_find_node(dht_t *dht, const uint8_t *target_id, dht_node_t *out_nodes,
                            int max_nodes) {
    lookup_candidate_t candidates[DHT_K * 4];
    int num_candidates = 0;
    int num_queried = 0;
    int iteration = 0;
    int max_iterations = 10;
    if (!dht || !target_id || !out_nodes || max_nodes <= 0) return -1;

    dht_node_t local_nodes[DHT_K * 2];
    int local_count = dht_get_closest_nodes(dht, target_id, local_nodes, DHT_K * 2);
    for (int i = 0; i < local_count && num_candidates < (int)(DHT_K * 4); i++) {
        candidate_add(candidates, &num_candidates, target_id, local_nodes[i].id,
                      local_nodes[i].address);
    }
    sort_candidates(candidates, num_candidates);

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

            if (!dht->send_rpc) continue;
            uint8_t response[2048];
            size_t response_len = sizeof(response);
            int ret = dht->send_rpc(dht->user, to_query_nodes[i]->node.address, DHT_RPC_FIND_NODE,
                                    target_id, DHT_ID_BYTES, response, &response_len);
            if (ret >= 0) {
                to_query_nodes[i]->responded = true;
                dht_add_node(dht, to_query_nodes[i]->node.id, to_query_nodes[i]->node.address);
                parse_nodes_response(response, response_len, candidates, &num_candidates,
                                     target_id);
            }
        }

        sort_candidates(candidates, num_candidates);
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
    if (!dht || !key || !value || !value_len) return -1;

    dht_node_t local_nodes[DHT_K * 2];
    int local_count = dht_get_closest_nodes(dht, key, local_nodes, DHT_K * 2);
    for (int i = 0; i < local_count && num_candidates < (int)(DHT_K * 4); i++) {
        candidate_add(candidates, &num_candidates, key, local_nodes[i].id, local_nodes[i].address);
    }
    sort_candidates(candidates, num_candidates);

    while (num_queried < DHT_K * 3 && iteration < 10) {
        iteration++;
        int to_query = 0;
        for (int i = 0; i < num_candidates && to_query < DHT_ALPHA; i++) {
            if (!candidates[i].queried) {
                candidates[i].queried = true;
                num_queried++;
                to_query++;

                if (!dht->send_rpc) continue;
                uint8_t val_response[2048];
                size_t val_response_len = sizeof(val_response);
                int val_ret = dht->send_rpc(dht->user, candidates[i].node.address,
                                            DHT_RPC_FIND_VALUE, key, DHT_ID_BYTES, val_response,
                                            &val_response_len);
                if (val_ret >= 0) {
                    int parsed = parse_value_response(val_response, val_response_len, value,
                                                      value_len);
                    if (parsed == 1) return 0;
                    if (parsed < 0) return -1;
                    parse_nodes_response(val_response, val_response_len, candidates,
                                         &num_candidates, key);
                }
            }
        }
        sort_candidates(candidates, num_candidates);
        if (to_query == 0) break;
    }
    return -1;
}

void dht_refresh_buckets(dht_t *dht, uint64_t now_ms) {
    if (!dht) return;
    dht_node_t nodes[DHT_K * 4];
    int count = dht_get_closest_nodes(dht, dht->id, nodes, DHT_K * 4);
    for (int i = 0; i < count; i++) {
        if (nodes[i].last_seen_ms > 0 && now_ms > nodes[i].last_seen_ms + DHT_REFRESH_INTERVAL_MS) {
            dht_remove_node(dht, nodes[i].id);
        }
    }
}

int dht_ping(dht_t *dht, const char *address) {
    if (!dht || !address || !dht->send_rpc) return -1;
    uint8_t response[DHT_ID_BYTES];
    size_t response_len = sizeof(response);
    if (dht->send_rpc(dht->user, address, DHT_RPC_PING, dht->id, DHT_ID_BYTES, response,
                      &response_len) != 0)
        return -1;
    if (response_len != DHT_ID_BYTES) return -1;
    if (dht_add_node(dht, response, address) != 0) return -1;
    return 0;
}

int dht_find_node(dht_t *dht, const uint8_t *target_id) {
    dht_node_t nodes[DHT_K];
    return dht_iterative_find_node(dht, target_id, nodes, DHT_K) >= 0 ? 0 : -1;
}

int dht_find_value(dht_t *dht, const uint8_t *key) {
    uint8_t value[DHT_VALUE_MAX_SIZE];
    size_t value_len = sizeof(value);
    return dht_iterative_find_value(dht, key, value, &value_len);
}

int dht_store(dht_t *dht, const uint8_t *key, const uint8_t *value, size_t value_len) {
    if (dht_handle_store(dht, key, value, value_len, dht->id) != 0) return -1;
    if (!dht->send_rpc) return 0;
    dht_node_t nodes[DHT_K];
    int n = dht_get_closest_nodes(dht, key, nodes, DHT_K);
    uint8_t req[DHT_ID_BYTES + DHT_VALUE_MAX_SIZE];
    COPY(req, key, DHT_ID_BYTES);
    COPY(req + DHT_ID_BYTES, value, value_len);
    for (int i = 0; i < n; i++) {
        uint8_t resp[1];
        size_t resp_len = sizeof(resp);
        dht->send_rpc(dht->user, nodes[i].address, DHT_RPC_STORE, req, DHT_ID_BYTES + value_len,
                      resp, &resp_len);
    }
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
    int ok = 0;
    for (int i = 0; i < list->num_nodes; i++) {
        if (dht_ping(dht, list->nodes[i].address) == 0) {
            list->nodes[i].failures = 0;
            ok++;
        } else {
            list->nodes[i].failures++;
        }
        list->nodes[i].last_attempt_ms = now_ms;
    }
    if (ok > 0) {
        dht->bootstrapped = true;
        dht->last_bootstrap_ms = now_ms;
        list->active_count = ok;
        return 0;
    }
    list->active_count = 0;
    return -1;
}

int dht_is_bootstrapped(dht_t *dht) {
    return dht->bootstrapped;
}
