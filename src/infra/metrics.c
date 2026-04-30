#include "metrics.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAX_LABELS 8
#define MAX_LABEL_LEN 32
#define MAX_NAME_LEN 64
#define HISTOGRAM_BUCKETS 10

typedef struct {
    char key[MAX_LABEL_LEN];
    char val[MAX_LABEL_LEN];
} label_t;

struct speer_metric_s {
    char name[MAX_NAME_LEN];
    speer_metric_type_t type;
    label_t labels[MAX_LABELS];
    size_t num_labels;
    int64_t value;
    int64_t count;
    int64_t sum;
    int64_t buckets[HISTOGRAM_BUCKETS];
    speer_metric_t* next;
};

static speer_metric_t* g_metrics = NULL;

static const int64_t bucket_bounds[HISTOGRAM_BUCKETS] = {
    1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, INT64_MAX
};

speer_metric_t* speer_metric_new(const char* name, speer_metric_type_t type) {
    speer_metric_t* m = calloc(1, sizeof(speer_metric_t));
    if (!m) return NULL;

    strncpy(m->name, name, MAX_NAME_LEN - 1);
    m->name[MAX_NAME_LEN - 1] = '\0';
    m->type = type;

    m->next = g_metrics;
    g_metrics = m;

    return m;
}

void speer_metric_free(speer_metric_t* m) {
    if (!m) return;

    speer_metric_t** p = &g_metrics;
    while (*p) {
        if (*p == m) {
            *p = m->next;
            break;
        }
        p = &(*p)->next;
    }

    free(m);
}

void speer_metric_label(speer_metric_t* m, const char* key, const char* val) {
    if (!m || m->num_labels >= MAX_LABELS) return;

    label_t* l = &m->labels[m->num_labels++];
    strncpy(l->key, key, MAX_LABEL_LEN - 1);
    l->key[MAX_LABEL_LEN - 1] = '\0';
    strncpy(l->val, val, MAX_LABEL_LEN - 1);
    l->val[MAX_LABEL_LEN - 1] = '\0';
}

void speer_metric_inc(speer_metric_t* m) {
    if (!m) return;
    m->value++;
    m->count++;
}

void speer_metric_dec(speer_metric_t* m) {
    if (!m) return;
    m->value--;
}

void speer_metric_add(speer_metric_t* m, int64_t delta) {
    if (!m) return;
    m->value += delta;
    m->count++;
}

void speer_metric_set(speer_metric_t* m, int64_t val) {
    if (!m) return;
    m->value = val;
}

void speer_metric_observe(speer_metric_t* m, int64_t val) {
    if (!m || m->type != SPEER_METRIC_HISTOGRAM) return;

    m->count++;
    m->sum += val;

    for (int i = 0; i < HISTOGRAM_BUCKETS; i++) {
        if (val <= bucket_bounds[i]) {
            m->buckets[i]++;
            break;
        }
    }
}

int64_t speer_metric_get(speer_metric_t* m) {
    return m ? m->value : 0;
}

void speer_metric_reset(speer_metric_t* m) {
    if (!m) return;
    m->value = 0;
    m->count = 0;
    m->sum = 0;
    memset(m->buckets, 0, sizeof(m->buckets));
}

static const char* type_str(speer_metric_type_t t) {
    switch (t) {
        case SPEER_METRIC_COUNTER: return "counter";
        case SPEER_METRIC_GAUGE: return "gauge";
        case SPEER_METRIC_HISTOGRAM: return "histogram";
        default: return "unknown";
    }
}

void speer_metrics_print(void) {
    for (speer_metric_t* m = g_metrics; m; m = m->next) {
        printf("# TYPE %s %s\n", m->name, type_str(m->type));
        printf("%s", m->name);

        for (size_t i = 0; i < m->num_labels; i++) {
            printf("%s%s=\"%s\"", i == 0 ? "{" : ",", m->labels[i].key, m->labels[i].val);
        }
        if (m->num_labels > 0) printf("}");

        if (m->type == SPEER_METRIC_HISTOGRAM) {
            printf(" %ld\n", (long)m->count);
            printf("%s_sum %ld\n", m->name, (long)m->sum);
            for (int i = 0; i < HISTOGRAM_BUCKETS; i++) {
                printf("%s_bucket{le=\"%ld\"} %ld\n",
                       m->name, (long)bucket_bounds[i], (long)m->buckets[i]);
            }
        } else {
            printf(" %ld\n", (long)m->value);
        }
    }
}
