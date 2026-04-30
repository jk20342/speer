#ifndef SPEER_QUIC_FLOW_H
#define SPEER_QUIC_FLOW_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct {
    uint64_t rx_offset;
    uint64_t rx_max;
    uint64_t rx_limit;

    uint64_t tx_offset;
    uint64_t tx_max;
    uint64_t tx_limit;

    uint64_t last_max_data_sent;
    uint64_t last_max_data_acked;

    uint32_t stream_count_bidi_local;
    uint32_t stream_count_bidi_remote;
    uint32_t stream_count_uni_local;
    uint32_t stream_count_uni_remote;

    uint32_t max_streams_bidi_local;
    uint32_t max_streams_bidi_remote;
    uint32_t max_streams_uni_local;
    uint32_t max_streams_uni_remote;
} speer_quic_flow_t;

#define QUIC_DEFAULT_WINDOW 65536
#define QUIC_WINDOW_INCREMENT 65536
#define QUIC_MAX_STREAMS_DEFAULT 100

void speer_quic_flow_init(speer_quic_flow_t* fc);

int speer_quic_flow_can_send(speer_quic_flow_t* fc, uint64_t bytes);
int speer_quic_flow_on_data_sent(speer_quic_flow_t* fc, uint64_t bytes);
int speer_quic_flow_on_data_acked(speer_quic_flow_t* fc, uint64_t offset);
int speer_quic_flow_on_data_received(speer_quic_flow_t* fc, uint64_t offset, uint64_t len);

uint64_t speer_quic_flow_get_max_data(speer_quic_flow_t* fc);
bool speer_quic_flow_should_update_max_data(speer_quic_flow_t* fc);

int speer_quic_flow_can_open_stream_bidi_local(speer_quic_flow_t* fc);
int speer_quic_flow_can_open_stream_uni_local(speer_quic_flow_t* fc);
void speer_quic_flow_on_stream_opened_bidi_local(speer_quic_flow_t* fc);
void speer_quic_flow_on_stream_opened_uni_local(speer_quic_flow_t* fc);

uint64_t speer_quic_flow_get_max_streams_bidi(speer_quic_flow_t* fc);
uint64_t speer_quic_flow_get_max_streams_uni(speer_quic_flow_t* fc);

int speer_quic_flow_on_max_data_received(speer_quic_flow_t* fc, uint64_t limit);
int speer_quic_flow_on_max_stream_data_received(speer_quic_flow_t* fc, uint64_t stream_id, uint64_t limit);
int speer_quic_flow_on_max_streams_received(speer_quic_flow_t* fc, uint64_t max_streams, int uni);

#endif
