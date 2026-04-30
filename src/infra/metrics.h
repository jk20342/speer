#ifndef SPEER_METRICS_H
#define SPEER_METRICS_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    SPEER_METRIC_COUNTER,
    SPEER_METRIC_GAUGE,
    SPEER_METRIC_HISTOGRAM,
} speer_metric_type_t;

typedef struct speer_metric_s speer_metric_t;

speer_metric_t *speer_metric_new(const char *name, speer_metric_type_t type);
void speer_metric_free(speer_metric_t *m);

void speer_metric_label(speer_metric_t *m, const char *key, const char *val);

void speer_metric_inc(speer_metric_t *m);
void speer_metric_dec(speer_metric_t *m);
void speer_metric_add(speer_metric_t *m, int64_t delta);
void speer_metric_set(speer_metric_t *m, int64_t val);
void speer_metric_observe(speer_metric_t *m, int64_t val);

int64_t speer_metric_get(speer_metric_t *m);

void speer_metric_reset(speer_metric_t *m);

void speer_metrics_print(void);

#endif
