/*
 * Conditional lwIP core lock.
 *
 * MicroLink calls a handful of raw lwIP APIs (udp_*, netif_*, wireguardif_*)
 * directly from its own tasks. Under the ESP-IDF "TCPIP core locking" model
 * (CONFIG_LWIP_TCPIP_CORE_LOCKING) that is only safe while holding the core
 * lock; without it those calls race the TCP/IP thread and corrupt lwIP state
 * (observed as a crash in tcp_output when a co-hosted TLS server runs).
 *
 * Some of the very same calls are also reached from inside lwIP callbacks
 * (e.g. the WireGuard netif output path, which already runs under the lock).
 * Re-taking a non-recursive lock there would dead-lock, so we lock only when
 * this thread is not already the holder. ml_lwip_lock() returns whether it
 * actually acquired the lock; pass that back to ml_lwip_unlock().
 *
 * With core locking disabled the helpers compile to no-ops (the build is
 * expected to enable it; see the ESP-KVM sdkconfig).
 */
#pragma once

#include <stdbool.h>

#include "lwip/opt.h"
#include "lwip/sys.h"
#include "lwip/tcpip.h"

static inline bool ml_lwip_lock(void)
{
#if LWIP_TCPIP_CORE_LOCKING
    if (sys_thread_tcpip(LWIP_CORE_LOCK_QUERY_HOLDER)) {
        return false; /* already held (called from within an lwIP callback) */
    }
    LOCK_TCPIP_CORE();
    return true;
#else
    return false;
#endif
}

static inline void ml_lwip_unlock(bool acquired)
{
#if LWIP_TCPIP_CORE_LOCKING
    if (acquired) {
        UNLOCK_TCPIP_CORE();
    }
#else
    (void)acquired;
#endif
}
