#pragma once
/* From jetkvm/microlink 80d0f8a (MIT, JetKVM). */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "cJSON.h"

/* Caller serializes map updates and packet checks. NULL denies all traffic. */
bool ml_packet_filter_update(cJSON **filters, const cJSON *map);
bool ml_packet_filter_accept(const cJSON *filters, const uint8_t *packet,
                             size_t length, uint32_t local_ip);

typedef struct {
    uint32_t remote_ip;
    uint16_t remote_port, local_port;
    uint64_t sent_ms;
    bool active;
} ml_udp_flow_t;
typedef struct {
    ml_udp_flow_t entries[64];
    unsigned next;
} ml_udp_flows_t;
/* Track return UDP traffic for locally initiated flows (for example ICE).
 * The caller holds the same lock as the packet filter. */
bool ml_packet_filter_udp_reply(ml_udp_flows_t *flows, const uint8_t *packet,
    size_t length, uint32_t local_ip, uint64_t now_ms, bool outgoing);
