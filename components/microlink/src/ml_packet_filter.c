/* Packet filter from the tailnet policy (PacketFilter / PacketFilters in the
 * map response). Taken from jetkvm/microlink 80d0f8a (MIT, JetKVM). */
#include "ml_packet_filter.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool address(const char *text, uint32_t *value)
{
    unsigned a, b, c, d;
    char extra;
    if (!text || sscanf(text, "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) != 4 ||
        a > 255 || b > 255 || c > 255 || d > 255) return false;
    *value = (a << 24) | (b << 16) | (c << 8) | d;
    return true;
}

static bool ip_matches(const cJSON *entry, const cJSON *bits, uint32_t ip)
{
    if (!cJSON_IsString(entry) || !entry->valuestring) return false;
    const char *text = entry->valuestring;
    if (!strcmp(text, "*")) return true;
    /* IPv6 and capability selectors do not match this IPv4-only interface. */
    if (strlen(text) >= 64) return false;
    char copy[64];
    strcpy(copy, text);
    char *separator = strchr(copy, '-');
    uint32_t first, last;
    if (separator) {
        *separator++ = '\0';
        return address(copy, &first) && address(separator, &last) &&
               first <= ip && ip <= last;
    }
    int prefix = 32;
    separator = strchr(copy, '/');
    if (separator) {
        *separator++ = '\0';
        char *end;
        long parsed = strtol(separator, &end, 10);
        if (!*separator || *end || parsed < 0 || parsed > 32) return false;
        prefix = (int)parsed;
    } else if (bits && !cJSON_IsNull(bits)) {
        if (!cJSON_IsNumber(bits) || bits->valuedouble != bits->valueint ||
            bits->valueint < 0 || bits->valueint > 32) return false;
        prefix = bits->valueint;
    }
    if (!address(copy, &first)) return false;
    uint32_t mask = prefix ? UINT32_MAX << (32 - prefix) : 0;
    return (ip & mask) == (first & mask);
}

bool ml_packet_filter_update(cJSON **filters, const cJSON *map)
{
    const cJSON *base = cJSON_GetObjectItemCaseSensitive(map, "PacketFilter");
    const cJSON *delta = cJSON_GetObjectItemCaseSensitive(map, "PacketFilters");
    if ((!base || cJSON_IsNull(base)) && (!delta || cJSON_IsNull(delta))) return true;
    cJSON *next = *filters ? cJSON_Duplicate(*filters, true) : cJSON_CreateObject();
    if (!next || (base && !cJSON_IsNull(base) && !cJSON_IsArray(base)) ||
        (delta && !cJSON_IsNull(delta) && !cJSON_IsObject(delta))) goto deny;
    /* The legacy base is applied before named updates. */
    if (base && !cJSON_IsNull(base)) {
        cJSON_DeleteItemFromObjectCaseSensitive(next, "base");
        cJSON *copy = cJSON_Duplicate(base, true);
        if (!copy || !cJSON_AddItemToObject(next, "base", copy)) {
            cJSON_Delete(copy);
            goto deny;
        }
    }
    const cJSON *reset = cJSON_GetObjectItemCaseSensitive(delta, "*");
    if (reset && cJSON_IsNull(reset)) {
        cJSON_Delete(next);
        next = cJSON_CreateObject();
        if (!next) goto deny;
    }
    const cJSON *item;
    cJSON_ArrayForEach(item, delta) {
        if (!item->string || !strcmp(item->string, "*")) continue;
        cJSON_DeleteItemFromObjectCaseSensitive(next, item->string);
        if (cJSON_IsNull(item)) continue;
        if (!cJSON_IsArray(item)) goto deny;
        cJSON *copy = cJSON_Duplicate(item, true);
        if (!copy || !cJSON_AddItemToObject(next, item->string, copy)) {
            cJSON_Delete(copy);
            goto deny;
        }
    }
    cJSON_Delete(*filters);
    *filters = next;
    return true;
deny:
    cJSON_Delete(next);
    cJSON_Delete(*filters);
    *filters = NULL;
    return false;
}

static uint32_t read32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

bool ml_packet_filter_udp_reply(ml_udp_flows_t *flows, const uint8_t *p,
    size_t length, uint32_t local_ip, uint64_t now_ms, bool outgoing)
{
    if (!flows || !p || length < 28 || (p[0] >> 4) != 4 || p[9] != 17) return false;
    unsigned header = (p[0] & 15) * 4;
    unsigned total = (unsigned)p[2] << 8 | p[3];
    if (header < 20 || total < header + 8 || total > length || (p[6] & 0x3f) || p[7])
        return false;
    uint32_t local = read32(p + (outgoing ? 12 : 16));
    uint32_t remote = read32(p + (outgoing ? 16 : 12));
    if (local != local_ip) return false;
    unsigned src_port = (unsigned)p[header] << 8 | p[header + 1];
    unsigned dst_port = (unsigned)p[header + 2] << 8 | p[header + 3];
    unsigned remote_port = outgoing ? dst_port : src_port;
    unsigned local_port = outgoing ? src_port : dst_port;
    for (unsigned i = 0; i < 64; ++i) {
        ml_udp_flow_t *flow = &flows->entries[i];
        if (flow->active && flow->remote_ip == remote && flow->remote_port == remote_port &&
            flow->local_port == local_port && now_ms - flow->sent_ms <= 60000) {
            if (outgoing) flow->sent_ms = now_ms;
            return true;
        }
    }
    if (outgoing) {
        flows->entries[flows->next++ % 64] = (ml_udp_flow_t){
            .remote_ip = remote, .remote_port = remote_port, .local_port = local_port,
            .sent_ms = now_ms, .active = true,
        };
    }
    return false;
}

bool ml_packet_filter_accept(const cJSON *filters, const uint8_t *p,
                             size_t length, uint32_t local_ip)
{
    if (!filters || !p || length < 20 || (p[0] >> 4) != 4) return false;
    unsigned header = (p[0] & 15) * 4;
    unsigned total = (unsigned)p[2] << 8 | p[3];
    if (header < 20 || total < header || total > length ||
        (p[6] & 0x3f) || p[7] || read32(p + 16) != local_ip) return false;
    uint8_t protocol = p[9];
    unsigned port = 0;
    if (protocol == 6) {
        if (total < header + 20 || (p[header + 12] >> 4) < 5 ||
            header + (p[header + 12] >> 4) * 4 > total) return false;
        /* Same TCP continuation rule as Tailscale's runIn4: only a new SYN
         * requires a grant. The local TCP stack validates continuation state. */
        if ((p[header + 13] & 0x12) != 0x02) return true;
        port = (unsigned)p[header + 2] << 8 | p[header + 3];
    } else if (protocol == 17) {
        if (total < header + 8) return false;
        port = (unsigned)p[header + 2] << 8 | p[header + 3];
    } else if (protocol == 1) {
        if (total < header + 8) return false;
        uint8_t type = p[header];
        if (type == 0 || type == 3 || type == 4 || type == 5 || type == 11 || type == 12)
            return true;
    } else return false;
    const cJSON *group, *rule, *source, *destination;
    cJSON_ArrayForEach(group, filters) cJSON_ArrayForEach(rule, group) {
        if (!cJSON_IsArray(group) || !cJSON_IsObject(rule)) continue;
        const cJSON *protocols = cJSON_GetObjectItemCaseSensitive(rule, "IPProto");
        if (protocols && !cJSON_IsNull(protocols) && !cJSON_IsArray(protocols)) continue;
        if (protocols && !cJSON_IsNull(protocols) && cJSON_GetArraySize(protocols)) {
            bool matches = false;
            const cJSON *proto;
            cJSON_ArrayForEach(proto, protocols)
                if (cJSON_IsNumber(proto) && proto->valuedouble == protocol) matches = true;
            if (!matches) continue;
        }
        bool matches = false;
        const cJSON *sources = cJSON_GetObjectItemCaseSensitive(rule, "SrcIPs");
        const cJSON *bits = cJSON_GetObjectItemCaseSensitive(rule, "SrcBits");
        if (!cJSON_IsArray(sources)) continue;
        int index = 0;
        cJSON_ArrayForEach(source, sources) {
            if (ip_matches(source, cJSON_GetArrayItem(bits, index++), read32(p + 12))) matches = true;
        }
        if (!matches) continue;
        cJSON_ArrayForEach(destination, cJSON_GetObjectItemCaseSensitive(rule, "DstPorts")) {
            if (!ip_matches(cJSON_GetObjectItemCaseSensitive(destination, "IP"),
                cJSON_GetObjectItemCaseSensitive(destination, "Bits"), local_ip)) continue;
            const cJSON *ports = cJSON_GetObjectItemCaseSensitive(destination, "Ports");
            const cJSON *first = cJSON_GetObjectItemCaseSensitive(ports, "First");
            const cJSON *last = cJSON_GetObjectItemCaseSensitive(ports, "Last");
            if (!cJSON_IsNumber(first) || !cJSON_IsNumber(last) ||
                first->valuedouble != first->valueint || last->valuedouble != last->valueint ||
                first->valueint < 0 || last->valueint > 65535 || first->valueint > last->valueint) continue;
            if (protocol == 1 || (port >= (unsigned)first->valueint && port <= (unsigned)last->valueint))
                return true;
        }
    }
    return false;
}
