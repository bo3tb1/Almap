#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "pool.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "net.h"
#include "raw.h"
#include "icmp.h"
#include "os.h"

/*
 * pool.c - Steps 10,12,13,19: bounded pthread pool for connect scans,
 * SYN scans, and host discovery.
 * No libpcap, no Nmap code, no banner/service logic.
 * Connect and discovery TCP probes use the existing sockets from
 * c/net.c; SYN probes call the shared single-SYN helper in c/raw.c
 * (almap_syn_probe / almap_syn_probe_os), and optional discovery ICMP
 * uses c/icmp.c, so packet building and socket logic are not
 * duplicated here. Step 19 aggregates SYN+ACK fingerprint samples per
 * host; c/os.c owns the heuristic classification.
 * Bounded work queue: mutex + two condition variables, capacity
 * = number of workers, so at most `workers` threads are active.
 * Each queue index is processed by exactly one worker, which writes
 * states_out[index] (scans) or up_out[index] (discovery); no two
 * workers write the same byte, so the output arrays need no extra
 * locking.
 * Global rate: one mutex-protected next-allowed time shared by
 * all workers in one call (CLOCK_MONOTONIC + nanosleep with EINTR
 * loop). Discovery has no rate limiting and always passes 0.
 * Use only on networks you own and have permission to scan.
 */

typedef enum {
    POOL_MODE_CONNECT = 0,
    POOL_MODE_SYN = 1,
    POOL_MODE_DISCOVER = 2
} PoolMode;

typedef struct {
    pthread_mutex_t mu;
    pthread_cond_t not_full;
    pthread_cond_t not_empty;
    int *queue;
    int cap;
    int qhead;
    int qtail;
    int qcount;
    int done;
    PoolMode mode;
    int job_count;
    unsigned int src_be;
    unsigned int dst_be;
    const int *ports;
    const unsigned int *hosts_be;
    int icmp_available;
    int timeout_ms;
    int rate_per_sec;
    unsigned char *states_out;
    unsigned char *up_out;
    int collect_os;
    AlmapOsFingerprint fp;
    struct timespec next_allowed;
    int has_next;
} Pool;

static int scan_one_c(unsigned int addr_be, int port, int timeout_ms) {
    int fd;
    int code;
    fd = almap_sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        return 3;
    }
    code = almap_sock_connect_timeout(fd, addr_be, port, timeout_ms);
    almap_sock_close(fd);
    if (code < 0 || code > 3) {
        return 3;
    }
    return code;
}

/* Host discovery probe: TCP ping on 80 then 443 (open or closed/RST
 * both mean the host answered), then optional ICMP echo. Reuses
 * scan_one_c so the connect-socket logic is not duplicated. */
static int discover_one_c(unsigned int host_be, int timeout_ms, int icmp_available) {
    static const int ping_ports[2] = { 80, 443 };
    int i;
    int code;

    for (i = 0; i < 2; i++) {
        code = scan_one_c(host_be, ping_ports[i], timeout_ms);
        if (code == 0 || code == 1) {
            return 1;
        }
    }
    if (icmp_available != 0 && almap_icmp_ping(host_be, timeout_ms) == 1) {
        return 1;
    }
    return 0;
}

/* Probe one port according to the pool mode. The SYN path reuses
 * c/raw.c; code 4 (permission) is preserved for the Goose mapping.
 * When collect_os is set, a matching SYN+ACK also feeds the host
 * fingerprint. The pool mutex guards the aggregate; workers do not
 * hold it while sending/receiving. */
static int pool_probe(Pool *pool, int port) {
    int code;

    if (pool->mode == POOL_MODE_SYN) {
        if (pool->collect_os != 0) {
            AlmapOsSample sample;
            memset(&sample, 0, sizeof(sample));
            code = almap_syn_probe_os(pool->src_be, pool->dst_be, port,
                                      pool->timeout_ms, &sample);
            if (code == 0) {
                pthread_mutex_lock(&pool->mu);
                almap_os_note(&pool->fp, &sample);
                pthread_mutex_unlock(&pool->mu);
            }
        } else {
            code = almap_syn_probe(pool->src_be, pool->dst_be, port,
                                   pool->timeout_ms);
        }
        if (code < 0 || code > 4) {
            return 3;
        }
        return code;
    }
    return scan_one_c(pool->dst_be, port, pool->timeout_ms);
}

/* Execute one queued index and store its result. Each index is
 * owned by exactly one worker, so result writes need no locking. */
static void pool_do_job(Pool *pool, int idx) {
    if (pool->mode == POOL_MODE_DISCOVER) {
        pool->up_out[idx] = (unsigned char)discover_one_c(pool->hosts_be[idx], pool->timeout_ms, pool->icmp_available);
    } else {
        pool->states_out[idx] = (unsigned char)pool_probe(pool, pool->ports[idx]);
    }
}

static struct timespec almap_add_ns(struct timespec ts, long ns) {
    ts.tv_nsec += ns;
    while (ts.tv_nsec >= 1000000000L) {
        ts.tv_nsec -= 1000000000L;
        ts.tv_sec += 1;
    }
    return ts;
}

static int almap_ts_leq(struct timespec a, struct timespec b) {
    if (a.tv_sec != b.tv_sec) {
        return a.tv_sec < b.tv_sec;
    }
    return a.tv_nsec <= b.tv_nsec;
}

static int almap_ts_lt(struct timespec a, struct timespec b) {
    if (a.tv_sec != b.tv_sec) {
        return a.tv_sec < b.tv_sec;
    }
    return a.tv_nsec < b.tv_nsec;
}

static struct timespec almap_ts_diff(struct timespec end, struct timespec start) {
    struct timespec rem;
    rem.tv_sec = end.tv_sec - start.tv_sec;
    rem.tv_nsec = end.tv_nsec - start.tv_nsec;
    if (rem.tv_nsec < 0) {
        rem.tv_nsec += 1000000000L;
        rem.tv_sec -= 1;
    }
    return rem;
}

static void almap_rate_wait(Pool *pool) {
    long interval_ns;
    struct timespec slot;
    struct timespec now;

    if (pool->rate_per_sec <= 0) {
        return;
    }
    interval_ns = 1000000000L / (long)pool->rate_per_sec;
    if (interval_ns <= 0) {
        return;
    }
    pthread_mutex_lock(&pool->mu);
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        pthread_mutex_unlock(&pool->mu);
        return;
    }
    if (!pool->has_next) {
        slot = now;
        pool->next_allowed = almap_add_ns(now, interval_ns);
        pool->has_next = 1;
    } else if (almap_ts_leq(now, pool->next_allowed)) {
        slot = pool->next_allowed;
        pool->next_allowed = almap_add_ns(pool->next_allowed, interval_ns);
    } else {
        slot = now;
        pool->next_allowed = almap_add_ns(now, interval_ns);
    }
    pthread_mutex_unlock(&pool->mu);
    for (;;) {
        struct timespec cur;
        struct timespec rem;
        if (clock_gettime(CLOCK_MONOTONIC, &cur) != 0) {
            return;
        }
        if (!almap_ts_lt(cur, slot)) {
            return;
        }
        rem = almap_ts_diff(slot, cur);
        if (nanosleep(&rem, NULL) == 0) {
            return;
        }
        if (errno != EINTR) {
            return;
        }
    }
}

static void *almap_worker_main(void *arg) {
    Pool *pool = (Pool *)arg;
    for (;;) {
        int idx;
        pthread_mutex_lock(&pool->mu);
        while (pool->qcount == 0 && !pool->done) {
            pthread_cond_wait(&pool->not_empty, &pool->mu);
        }
        if (pool->done && pool->qcount == 0) {
            pthread_mutex_unlock(&pool->mu);
            break;
        }
        idx = pool->queue[pool->qhead];
        pool->qhead = (pool->qhead + 1) % pool->cap;
        pool->qcount--;
        pthread_cond_signal(&pool->not_full);
        pthread_mutex_unlock(&pool->mu);
        almap_rate_wait(pool);
        pool_do_job(pool, idx);
    }
    return NULL;
}

static void pool_cleanup(Pool *pool) {
    pthread_cond_destroy(&pool->not_empty);
    pthread_cond_destroy(&pool->not_full);
    pthread_mutex_destroy(&pool->mu);
}

/* Shared bounded-queue runner for every pool mode. The caller fills
 * every Pool field except the queue/mutex state and job_count. */
static int pool_run(Pool *pool, int workers) {
    int i;
    int nworkers;
    int cap;
    pthread_t *threads;
    int created = 0;
    int k;

    if (pool->job_count <= 0) {
        return 0;
    }
    if (pthread_mutex_init(&pool->mu, NULL) != 0) {
        return -1;
    }
    if (pthread_cond_init(&pool->not_full, NULL) != 0) {
        pthread_mutex_destroy(&pool->mu);
        return -1;
    }
    if (pthread_cond_init(&pool->not_empty, NULL) != 0) {
        pthread_cond_destroy(&pool->not_full);
        pthread_mutex_destroy(&pool->mu);
        return -1;
    }

    if (workers <= 1 || pool->job_count <= 1) {
        /* Sequential without spawning threads (still rate limited). */
        for (i = 0; i < pool->job_count; i++) {
            almap_rate_wait(pool);
            pool_do_job(pool, i);
        }
        pool_cleanup(pool);
        return 0;
    }

    nworkers = workers;
    cap = workers;
    if (nworkers > pool->job_count) {
        nworkers = pool->job_count;
    }
    if (cap > pool->job_count) {
        cap = pool->job_count;
    }
    if (cap < 1) {
        cap = 1;
    }
    pool->cap = cap;
    pool->qhead = 0;
    pool->qtail = 0;
    pool->qcount = 0;
    pool->done = 0;
    pool->queue = (int *)malloc((size_t)cap * sizeof(int));
    threads = (pthread_t *)malloc((size_t)nworkers * sizeof(pthread_t));
    if (pool->queue == NULL || threads == NULL) {
        free(pool->queue);
        free(threads);
        pool_cleanup(pool);
        return -1;
    }
    for (k = 0; k < nworkers; k++) {
        if (pthread_create(&threads[k], NULL, almap_worker_main, pool) != 0) {
            int j;
            pthread_mutex_lock(&pool->mu);
            pool->done = 1;
            pthread_cond_broadcast(&pool->not_empty);
            pthread_mutex_unlock(&pool->mu);
            for (j = 0; j < created; j++) {
                pthread_join(threads[j], NULL);
            }
            free(pool->queue);
            free(threads);
            pool_cleanup(pool);
            return -1;
        }
        created++;
    }
    for (i = 0; i < pool->job_count; i++) {
        pthread_mutex_lock(&pool->mu);
        while (pool->qcount == pool->cap) {
            pthread_cond_wait(&pool->not_full, &pool->mu);
        }
        pool->queue[pool->qtail] = i;
        pool->qtail = (pool->qtail + 1) % pool->cap;
        pool->qcount++;
        pthread_cond_signal(&pool->not_empty);
        pthread_mutex_unlock(&pool->mu);
    }
    pthread_mutex_lock(&pool->mu);
    pool->done = 1;
    pthread_cond_broadcast(&pool->not_empty);
    pthread_mutex_unlock(&pool->mu);
    for (k = 0; k < nworkers; k++) {
        pthread_join(threads[k], NULL);
    }
    free(pool->queue);
    free(threads);
    pool_cleanup(pool);
    return 0;
}

int almap_connect_scan_host(unsigned int addr_be, const int *ports, int port_count, int timeout_ms, int workers, int rate_per_sec, unsigned char *states_out) {
    Pool pool;
    int i;

    if (ports == NULL || states_out == NULL || port_count < 0) {
        return -1;
    }
    if (port_count == 0) {
        return 0;
    }
    if (addr_be == 0 || timeout_ms <= 0) {
        for (i = 0; i < port_count; i++) {
            states_out[i] = 3;
        }
        return 0;
    }

    memset(&pool, 0, sizeof(pool));
    pool.mode = POOL_MODE_CONNECT;
    pool.job_count = port_count;
    pool.src_be = 0;
    pool.dst_be = addr_be;
    pool.ports = ports;
    pool.timeout_ms = timeout_ms;
    pool.rate_per_sec = rate_per_sec;
    pool.states_out = states_out;
    pool.has_next = 0;
    return pool_run(&pool, workers);
}

/* Shared SYN-host runner for the plain and Step 19 fingerprint paths.
 * fp_out is NULL for the plain path, or five ints for the OS path:
 * [os_class, ttl, window, option_bits, ip_id_behavior]. */
static int syn_scan_host_impl(unsigned int src_be, unsigned int dst_be, const int *ports, int port_count, int timeout_ms, int workers, int rate_per_sec, unsigned char *states_out, int *fp_out) {
    Pool pool;
    int i;
    int rc;

    if (ports == NULL || states_out == NULL || port_count < 0) {
        return -1;
    }
    if (port_count == 0) {
        return 0;
    }
    if (src_be == 0 || dst_be == 0 || timeout_ms <= 0) {
        /* Documented choice: report errors instead of sending probes
         * with an unusable source/destination. */
        for (i = 0; i < port_count; i++) {
            states_out[i] = 3;
        }
        if (fp_out != NULL) {
            for (i = 0; i < 5; i++) {
                fp_out[i] = 0;
            }
        }
        return 0;
    }

    memset(&pool, 0, sizeof(pool));
    pool.mode = POOL_MODE_SYN;
    pool.job_count = port_count;
    pool.src_be = src_be;
    pool.dst_be = dst_be;
    pool.ports = ports;
    pool.timeout_ms = timeout_ms;
    pool.rate_per_sec = rate_per_sec;
    pool.states_out = states_out;
    pool.collect_os = (fp_out != NULL) ? 1 : 0;
    almap_os_init(&pool.fp);
    pool.has_next = 0;
    rc = pool_run(&pool, workers);
    if (fp_out != NULL) {
        int os_class = ALMAP_OS_UNKNOWN;
        if (rc == 0) {
            os_class = almap_os_finalize(&pool.fp);
        }
        fp_out[0] = os_class;
        fp_out[1] = pool.fp.ttl;
        fp_out[2] = pool.fp.window;
        fp_out[3] = pool.fp.options;
        fp_out[4] = pool.fp.ip_id_behavior;
    }
    return rc;
}

int almap_syn_scan_host(unsigned int src_be, unsigned int dst_be, const int *ports, int port_count, int timeout_ms, int workers, int rate_per_sec, unsigned char *states_out) {
    return syn_scan_host_impl(src_be, dst_be, ports, port_count, timeout_ms,
                              workers, rate_per_sec, states_out, NULL);
}

int almap_syn_scan_host_os(unsigned int src_be, unsigned int dst_be, const int *ports, int port_count, int timeout_ms, int workers, int rate_per_sec, unsigned char *states_out, int *fp_out) {
    return syn_scan_host_impl(src_be, dst_be, ports, port_count, timeout_ms,
                              workers, rate_per_sec, states_out, fp_out);
}

int almap_discover_hosts(const unsigned int *hosts_be, int host_count, int timeout_ms, int workers, int icmp_available, unsigned char *up_out) {
    Pool pool;
    int i;

    if (hosts_be == NULL || up_out == NULL || host_count < 0) {
        return -1;
    }
    if (host_count == 0) {
        return 0;
    }
    if (timeout_ms <= 0) {
        /* Defensive fallback: no usable timeout means no host is up. */
        for (i = 0; i < host_count; i++) {
            up_out[i] = 0;
        }
        return 0;
    }

    memset(&pool, 0, sizeof(pool));
    pool.mode = POOL_MODE_DISCOVER;
    pool.job_count = host_count;
    pool.hosts_be = hosts_be;
    pool.icmp_available = icmp_available;
    pool.timeout_ms = timeout_ms;
    pool.rate_per_sec = 0; /* Discovery never uses --rate. */
    pool.up_out = up_out;
    pool.has_next = 0;
    return pool_run(&pool, workers);
}
