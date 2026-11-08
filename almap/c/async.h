#ifndef ALMAP_ASYNC_H
#define ALMAP_ASYNC_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * async.h - Step 20: asynchronous TCP connect scan with epoll.
 *
 * almap_async_connect_scan() scans every (host, port) combination in
 * deterministic host -> port order. hosts_be and ports are flat arrays
 * (lengths host_count and port_count); states_out must have
 * host_count * port_count bytes. Each output byte uses the same codes
 * as the connect worker pool:
 *   0 = open, 1 = closed/refused, 2 = timeout, 3 = error.
 *
 * The engine keeps up to max_concurrent non-blocking sockets in flight,
 * paced by an optional rate_per_sec token bucket (0 = unlimited). It
 * uses epoll on Linux: EPOLLOUT with SO_ERROR == 0 is open,
 * EPOLLERR/EPOLLHUP (and refused SO_ERROR values) are closed. Active
 * deadlines are kept in a launch-ordered list; because every connection
 * uses the same timeout_ms, that list is sorted by deadline, so timeout
 * processing is O(1) per expired connection without a per-event timer
 * scan.
 *
 * The function is reentrant: all engine state is allocated locally with
 * malloc/calloc and released before returning. It returns 0 when the
 * whole matrix was processed, and -1 for invalid arguments or an
 * allocation / epoll failure. A failed call may have written partial
 * states; callers should treat -1 as fatal for that batch.
 *
 * IPv4 only. Use only on networks you own or have permission to scan.
 */

#define ALMAP_ASYNC_DEFAULT_MAX_CONCURRENT 10000

#define ALMAP_ASYNC_STATE_OPEN 0
#define ALMAP_ASYNC_STATE_CLOSED 1
#define ALMAP_ASYNC_STATE_TIMEOUT 2
#define ALMAP_ASYNC_STATE_ERROR 3

int almap_async_connect_scan(const unsigned int *hosts_be, int host_count,
                             const int *ports, int port_count,
                             int timeout_ms, int max_concurrent,
                             int rate_per_sec, unsigned char *states_out);

/*
 * almap_async_errno_state(err) maps a connect()/SO_ERROR errno value to
 * the connect state codes above. 0 maps to open; ECONNREFUSED,
 * ECONNRESET, and ECONNABORTED map to closed; ETIMEDOUT maps to
 * timeout; everything else maps to error. Exposed for unit tests and
 * shared by the immediate-connect and EPOLLOUT/EPOLLERR paths.
 */
int almap_async_errno_state(int err);

#ifdef __cplusplus
}
#endif

#endif /* ALMAP_ASYNC_H */
