#include "speer_internal.h"

#define INIT_CWND 1460
#define MIN_CWND 1460
#define MAX_CWND (10 * 1460)
#define INIT_SSTHRESH (64 * 1460)

#define PTO_MULTIPLIER 3
#define MAX_ACK_DELAY 25

void speer_conn_init(speer_conn_t* conn) {
    ZERO(conn, sizeof(*conn));
    conn->pkt_num = 0;
    conn->ack_num = 0;
    conn->rtt_ms = 100;
    conn->rtt_var_ms = 50;
    conn->timeout_ms = SPEER_INITIAL_TIMEOUT_MS;
    conn->mtu = SPEER_DEFAULT_MTU;
    conn->cwnd = INIT_CWND;
    conn->ssthresh = INIT_SSTHRESH;
    conn->last_send_ms = 0;
    conn->last_recv_ms = 0;
}

void speer_conn_update_rtt(speer_conn_t* conn, uint32_t rtt_sample) {
    if (conn->rtt_ms == 0) {
        conn->rtt_ms = rtt_sample;
        conn->rtt_var_ms = rtt_sample / 2;
    } else {
        int32_t delta = (int32_t)rtt_sample - (int32_t)conn->rtt_ms;
        conn->rtt_ms += delta / 8;
        conn->rtt_var_ms += ((int32_t)delta < 0 ? -delta : delta - (int32_t)conn->rtt_var_ms) / 4;
    }
    conn->timeout_ms = conn->rtt_ms + PTO_MULTIPLIER * conn->rtt_var_ms + MAX_ACK_DELAY;
    conn->timeout_ms = CLAMP(conn->timeout_ms, 100, SPEER_MAX_TIMEOUT_MS);
}

uint32_t speer_conn_get_timeout(speer_conn_t* conn) {
    return conn->timeout_ms;
}

static INLINE uint64_t pkt_num_encode(uint64_t full, uint64_t largest) {
    uint64_t win = 1;
    uint64_t h = largest + win;
    uint64_t l = h - (win << 1);
    
    uint64_t num = full;
    if (UNLIKELY(num < l)) num += (win << 1);
    
    return num;
}

static INLINE uint64_t pkt_num_decode(uint64_t truncated, uint64_t expected) {
    uint64_t win = 1;
    uint64_t h = expected + win;
    uint64_t l = h - (win << 1);
    
    uint64_t candidate = (expected & ~(win * 2 - 1)) | truncated;
    if (candidate < l) candidate += win * 2;
    else if (candidate > h) candidate -= win * 2;
    
    return candidate;
}

typedef struct {
    uint64_t pkt_num;
    uint64_t send_time_ms;
    uint8_t* data;
    size_t len;
    uint32_t in_flight:1;
    uint32_t ack_eliciting:1;
} sent_pkt_t;

#define MAX_SENT_PKTS 1024

typedef struct {
    sent_pkt_t pkts[MAX_SENT_PKTS];
    uint32_t head;
    uint32_t tail;
    uint64_t bytes_in_flight;
} sent_pkt_queue_t;

static void sent_queue_init(sent_pkt_queue_t* q) {
    ZERO(q, sizeof(*q));
}

static void sent_queue_add(sent_pkt_queue_t* q, uint64_t pkt_num,
                           const uint8_t* data, size_t len,
                           uint64_t now_ms) {
    uint32_t idx = q->tail % MAX_SENT_PKTS;
    if (q->tail - q->head >= MAX_SENT_PKTS) {
        sent_pkt_t* old = &q->pkts[q->head % MAX_SENT_PKTS];
        if (old->in_flight) q->bytes_in_flight -= old->len;
        if (old->data) free(old->data);
        q->head++;
    }
    
    sent_pkt_t* pkt = &q->pkts[idx];
    pkt->pkt_num = pkt_num;
    pkt->send_time_ms = now_ms;
    pkt->len = len;
    pkt->data = (uint8_t*)malloc(len);
    if (pkt->data) COPY(pkt->data, data, len);
    pkt->in_flight = 1;
    pkt->ack_eliciting = 1;
    
    q->bytes_in_flight += len;
    q->tail++;
}

static sent_pkt_t* sent_queue_find(sent_pkt_queue_t* q, uint64_t pkt_num) {
    for (uint32_t i = q->head; i < q->tail; i++) {
        sent_pkt_t* pkt = &q->pkts[i % MAX_SENT_PKTS];
        if (pkt->pkt_num == pkt_num) return pkt;
    }
    return NULL;
}

static void sent_queue_remove(sent_pkt_queue_t* q, sent_pkt_t* pkt) {
    if (pkt->in_flight) {
        q->bytes_in_flight -= pkt->len;
        pkt->in_flight = 0;
    }
}

static void sent_queue_cleanup(sent_pkt_queue_t* q) {
    while (q->head < q->tail) {
        sent_pkt_t* pkt = &q->pkts[q->head % MAX_SENT_PKTS];
        if (pkt->data) {
            free(pkt->data);
            pkt->data = NULL;
        }
        q->head++;
    }
}

#define MAX_ACK_RANGES 32

typedef struct {
    uint64_t ranges[MAX_ACK_RANGES * 2];
    uint32_t num_ranges;
    uint64_t largest_acked;
    uint64_t ack_delay;
} ack_frame_t;

static void ack_frame_init(ack_frame_t* af) {
    ZERO(af, sizeof(*af));
}

static void ack_frame_add(ack_frame_t* af, uint64_t pkt_num) {
    if (af->num_ranges == 0) {
        af->largest_acked = pkt_num;
        af->ranges[0] = 0;
        af->ranges[1] = 0;
        af->num_ranges = 1;
        return;
    }
    
    if (pkt_num == af->largest_acked - af->ranges[0] - af->ranges[1] - 1) {
        af->ranges[1]++;
    } else {
        if (af->num_ranges < MAX_ACK_RANGES) {
            af->num_ranges++;
            af->ranges[(af->num_ranges - 1) * 2] = af->largest_acked - pkt_num - 1;
            af->ranges[(af->num_ranges - 1) * 2 + 1] = 0;
        }
    }
}

typedef struct {
    uint64_t received[MAX_ACK_RANGES];
    uint32_t head;
    uint32_t count;
} recv_tracker_t;

static void recv_tracker_init(recv_tracker_t* rt) {
    ZERO(rt, sizeof(*rt));
}

static int recv_tracker_should_ack(recv_tracker_t* rt, uint64_t pkt_num, uint64_t now_ms) {
    (void)now_ms;
    for (uint32_t i = 0; i < rt->count; i++) {
        if (rt->received[(rt->head + i) % MAX_ACK_RANGES] == pkt_num) {
            return 0;
        }
    }
    
    rt->received[(rt->head + rt->count) % MAX_ACK_RANGES] = pkt_num;
    if (rt->count < MAX_ACK_RANGES) {
        rt->count++;
    } else {
        rt->head = (rt->head + 1) % MAX_ACK_RANGES;
    }
    
    return 1;
}

static void recv_tracker_clear_up_to(recv_tracker_t* rt, uint64_t largest_acked) {
    while (rt->count > 0 && rt->received[rt->head % MAX_ACK_RANGES] <= largest_acked) {
        rt->head = (rt->head + 1) % MAX_ACK_RANGES;
        rt->count--;
    }
}

typedef struct {
    speer_conn_t* conn;
    sent_pkt_queue_t sent;
    recv_tracker_t received;
    ack_frame_t pending_ack;
    uint64_t largest_acked_pkt;
    uint64_t last_ack_sent_pkt;
    uint64_t last_ack_sent_time;
    uint32_t ack_frequency;
    uint32_t max_ack_delay;
} recovery_ctx_t;

static void recovery_init(recovery_ctx_t* rcv, speer_conn_t* conn) {
    ZERO(rcv, sizeof(*rcv));
    rcv->conn = conn;
    rcv->ack_frequency = 2;
    rcv->max_ack_delay = MAX_ACK_DELAY;
    sent_queue_init(&rcv->sent);
    recv_tracker_init(&rcv->received);
    ack_frame_init(&rcv->pending_ack);
}

static void recovery_cleanup(recovery_ctx_t* rcv) {
    sent_queue_cleanup(&rcv->sent);
}

static void recovery_on_packet_sent(recovery_ctx_t* rcv, uint64_t pkt_num,
                                     const uint8_t* data, size_t len,
                                     uint64_t now_ms, int in_flight) {
    if (in_flight) {
        sent_queue_add(&rcv->sent, pkt_num, data, len, now_ms);
    }
    rcv->conn->last_send_ms = now_ms;
    rcv->conn->pkt_num++;
}

static void __attribute__((unused)) recovery_on_ack_received(recovery_ctx_t* rcv, const ack_frame_t* ack, uint64_t now_ms) {
    uint64_t largest_acked = ack->largest_acked;
    
    if (largest_acked > rcv->largest_acked_pkt) {
        rcv->largest_acked_pkt = largest_acked;
        
        sent_pkt_t* pkt = sent_queue_find(&rcv->sent, largest_acked);
        if (pkt && pkt->in_flight) {
            uint32_t rtt = (uint32_t)(now_ms - pkt->send_time_ms);
            speer_conn_update_rtt(rcv->conn, rtt);
            sent_queue_remove(&rcv->sent, pkt);
        }
    }
    
    for (uint32_t i = 0; i < ack->num_ranges; i++) {
        uint64_t gap = ack->ranges[i * 2];
        uint64_t ack_range_len = ack->ranges[i * 2 + 1];
        
        uint64_t acked = largest_acked - gap;
        for (uint64_t j = 0; j <= ack_range_len && acked > 0; j++) {
            sent_pkt_t* pkt = sent_queue_find(&rcv->sent, acked);
            if (pkt && pkt->in_flight) {
                sent_queue_remove(&rcv->sent, pkt);
            }
            if (j < ack_range_len) acked--;
        }
    }
    
    recv_tracker_clear_up_to(&rcv->received, largest_acked);
    
    if (rcv->sent.bytes_in_flight > 0) {
        if (rcv->conn->cwnd < rcv->conn->ssthresh) {
            rcv->conn->cwnd += 1460;
            if (rcv->conn->cwnd > MAX_CWND) rcv->conn->cwnd = MAX_CWND;
        } else {
            rcv->conn->cwnd += (1460 * 1460) / rcv->conn->cwnd;
        }
    }
}

static void __attribute__((unused)) recovery_on_packet_lost(recovery_ctx_t* rcv) {
    rcv->conn->ssthresh = MAX(rcv->sent.bytes_in_flight / 2, MIN_CWND);
    rcv->conn->cwnd = rcv->conn->ssthresh;
}

static void recovery_on_packet_received(recovery_ctx_t* rcv, uint64_t pkt_num, uint64_t now_ms) {
    if (recv_tracker_should_ack(&rcv->received, pkt_num, now_ms)) {
        ack_frame_add(&rcv->pending_ack, pkt_num);
        
        if (rcv->pending_ack.largest_acked - rcv->last_ack_sent_pkt >= rcv->ack_frequency ||
            now_ms - rcv->last_ack_sent_time >= rcv->max_ack_delay) {
        }
    }
    rcv->conn->last_recv_ms = now_ms;
}

static int __attribute__((unused)) recovery_get_loss_pn(recovery_ctx_t* rcv, uint64_t now_ms, uint64_t* lost_pn) {
    uint64_t loss_time = rcv->conn->rtt_ms + 4 * rcv->conn->rtt_var_ms;
    
    for (uint32_t i = rcv->sent.head; i < rcv->sent.tail; i++) {
        sent_pkt_t* pkt = &rcv->sent.pkts[i % MAX_SENT_PKTS];
        if (pkt->in_flight && now_ms - pkt->send_time_ms > loss_time) {
            *lost_pn = pkt->pkt_num;
            return 1;
        }
    }
    return 0;
}

static size_t __attribute__((unused)) recovery_get_retransmissions(recovery_ctx_t* rcv, uint64_t now_ms,
                                           uint8_t** packets, uint64_t* pkt_nums,
                                           size_t max_pkts) {
    size_t count = 0;
    uint64_t loss_time = rcv->conn->rtt_ms + 4 * rcv->conn->rtt_var_ms;
    
    for (uint32_t i = rcv->sent.head; i < rcv->sent.tail && count < max_pkts; i++) {
        sent_pkt_t* pkt = &rcv->sent.pkts[i % MAX_SENT_PKTS];
        if (pkt->in_flight && now_ms - pkt->send_time_ms > loss_time) {
            packets[count] = pkt->data;
            pkt_nums[count] = pkt->pkt_num;
            count++;
        }
    }
    
    return count;
}

int speer_transport_send(speer_peer_t* peer,
                         const uint8_t* data, size_t len,
                         uint8_t* out, size_t* out_len) {
    recovery_ctx_t* rcv = (recovery_ctx_t*)peer->user_data;
    speer_conn_t* conn = &peer->conn;
    
    if (len > (size_t)conn->mtu - 48) return SPEER_ERROR_BUFFER_TOO_SMALL;
    if (rcv->sent.bytes_in_flight + len > conn->cwnd) return SPEER_ERROR_BUFFER_TOO_SMALL;
    
    uint64_t now = speer_timestamp_ms();
    
    uint8_t plaintext[SPEER_MAX_PACKET_SIZE];
    size_t plaintext_len = 0;
    
    if (rcv->pending_ack.num_ranges > 0) {
        size_t ack_len = speer_frame_encode_ack(plaintext + plaintext_len,
                                                 rcv->pending_ack.largest_acked,
                                                 0,
                                                 (const uint8_t*)rcv->pending_ack.ranges,
                                                 rcv->pending_ack.num_ranges);
        plaintext_len += ack_len;
        rcv->last_ack_sent_pkt = rcv->pending_ack.largest_acked;
        rcv->last_ack_sent_time = now;
        ack_frame_init(&rcv->pending_ack);
    }
    
    if (len > 0) {
        size_t frame_len = speer_frame_encode_stream(plaintext + plaintext_len, 0, 0, data, len, 0);
        plaintext_len += frame_len;
    }
    
    size_t pkt_len;
    int ret = speer_packet_encode(out, &pkt_len,
                                   plaintext, plaintext_len,
                                   conn->cid, conn->cid_len,
                                   conn->pkt_num,
                                   peer->send_cipher.key);
    if (ret != 0) return ret;
    
    recovery_on_packet_sent(rcv, conn->pkt_num, out, pkt_len, now, 1);
    *out_len = pkt_len;
    
    return SPEER_OK;
}

int speer_transport_recv(speer_peer_t* peer,
                       const uint8_t* data, size_t len,
                       uint8_t* out, size_t* out_len) {
    (void)len;
    recovery_ctx_t* rcv = (recovery_ctx_t*)peer->user_data;
    
    uint8_t cid[SPEER_MAX_CID_LEN];
    uint8_t cid_len;
    uint64_t pkt_num;
    
    uint8_t plaintext[SPEER_MAX_PACKET_SIZE];
    size_t plaintext_len;
    
    int ret = speer_packet_decode(plaintext, &plaintext_len,
                                   data, len,
                                   cid, &cid_len, &pkt_num,
                                   peer->recv_cipher.key);
    if (ret != 0) return ret;
    
    uint64_t now = speer_timestamp_ms();
    
    recovery_on_packet_received(rcv, pkt_num, now);
    
    COPY(out, plaintext, plaintext_len);
    *out_len = plaintext_len;
    
    return SPEER_OK;
}

int speer_transport_init(speer_peer_t* peer) {
    recovery_ctx_t* rcv = (recovery_ctx_t*)malloc(sizeof(recovery_ctx_t));
    if (!rcv) return SPEER_ERROR_NO_MEMORY;
    
    recovery_init(rcv, &peer->conn);
    peer->user_data = rcv;
    
    return SPEER_OK;
}

void speer_transport_cleanup(speer_peer_t* peer) {
    recovery_ctx_t* rcv = (recovery_ctx_t*)peer->user_data;
    if (rcv) {
        recovery_cleanup(rcv);
        free(rcv);
        peer->user_data = NULL;
    }
}
