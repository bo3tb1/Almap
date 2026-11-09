#ifndef _WIN32
#define _GNU_SOURCE
#endif

#include "async.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>

/*
 * async.c - Step 20: asynchronous TCP connect scan (Linux epoll).
 *
 * One epoll instance owns every in-flight non-blocking connect. Sockets
 * are created non-blocking, connect() is started immediately, and each
 * pending fd is registered with EPOLLOUT | EPOLLERR | EPOLLHUP. Ready
 * events finish a connection; deadlines finish stalled ones.
 *
 * Timeout structure: all connections use the same timeout_ms and are
 * launched in nondecreasing clock order, so a FIFO list of active slots
 * is also sorted by deadline. Expiring the head (and any following
 * entries whose deadline has passed) is O(1) per connection; no timer
 * wheel or full-array scan is needed. This is the "sorting" option in
 * the Step 20 requirements.
 *
 * Rate limiting: an integer token bucket paced by interval_ns =
 * 1e9 / rate_per_sec. Tokens are capped at max_concurrent so a burst
 * cannot exceed the engine's socket budget. rate_per_sec == 0 launches
 * as fast as free slots allow.
 *
 * Work is addressed by a single int64 job index:
 *   job = host_index * port_count + port_index
 * states_out[job] is written exactly once, in deterministic
 * host -> port order regardless of completion order.
 *
 * No global mutable state. All engine memory is malloc/calloc'd in the
 * call and freed before returning. IPv4 only.
 *
 * Use only on networks you own or have permission to scan.
 */

#define ALMAP_ASYNC_EVENT_BATCH 256
#define ALMAP_ASYNC_NS_PER_MS 1000000LL
#define ALMAP_ASYNC_NS_PER_SEC 1000000000LL

typedef struct {
    int fd;
    int prev;                 /* deadline-list link, -1 at an end */
    int next;                 /* deadline-list link or free-list link */
    int active;
    int pad;
    int64_t job;
    int64_t deadline_ns;
} AlmapAsyncConn;

typedef struct {
    AlmapAsyncConn *conns;
    int cap;
    int free_head;
    int timeout_head;
    int timeout_tail;
    int active_count;
} AlmapAsyncEngine;

static int64_t almap_async_now_ns(void) {
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (int64_t)ts.tv_sec * ALMAP_ASYNC_NS_PER_SEC + (int64_t)ts.tv_nsec;
}

int almap_async_errno_state(int err) {
    if (err == 0) {
        return ALMAP_ASYNC_STATE_OPEN;
    }
    if (err == ECONNREFUSED || err == ECONNRESET || err == ECONNABORTED) {
        return ALMAP_ASYNC_STATE_CLOSED;
    }
    if (err == ETIMEDOUT) {
        return ALMAP_ASYNC_STATE_TIMEOUT;
    }
    return ALMAP_ASYNC_STATE_ERROR;
}

static void almap_async_engine_init(AlmapAsyncEngine *eng, AlmapAsyncConn *conns, int cap) {
    int i;

    eng->conns = conns;
    eng->cap = cap;
    eng->free_head = cap > 0 ? 0 : -1;
    eng->timeout_head = -1;
    eng->timeout_tail = -1;
    eng->active_count = 0;
    for (i = 0; i < cap; i++) {
        conns[i].fd = -1;
        conns[i].prev = -1;
        conns[i].next = (i + 1 < cap) ? (i + 1) : -1;
        conns[i].active = 0;
        conns[i].pad = 0;
        conns[i].job = -1;
        conns[i].deadline_ns = 0;
    }
}

static int almap_async_slot_alloc(AlmapAsyncEngine *eng) {
    int slot;

    slot = eng->free_head;
    if (slot < 0) {
        return -1;
    }
    eng->free_head = eng->conns[slot].next;
    eng->conns[slot].next = -1;
    return slot;
}

static void almap_async_slot_free(AlmapAsyncEngine *eng, int slot) {
    AlmapAsyncConn *c = &eng->conns[slot];

    c->fd = -1;
    c->active = 0;
    c->prev = -1;
    c->next = eng->free_head;
    eng->free_head = slot;
}

static void almap_async_deadline_append(AlmapAsyncEngine *eng, int slot) {
    AlmapAsyncConn *c = &eng->conns[slot];

    c->prev = eng->timeout_tail;
    c->next = -1;
    if (eng->timeout_tail >= 0) {
        eng->conns[eng->timeout_tail].next = slot;
    } else {
        eng->timeout_head = slot;
    }
    eng->timeout_tail = slot;
}

static void almap_async_deadline_unlink(AlmapAsyncEngine *eng, int slot) {
    AlmapAsyncConn *c = &eng->conns[slot];

    if (c->prev >= 0) {
        eng->conns[c->prev].next = c->next;
    } else {
        eng->timeout_head = c->next;
    }
    if (c->next >= 0) {
        eng->conns[c->next].prev = c->prev;
    } else {
        eng->timeout_tail = c->prev;
    }
    c->prev = -1;
    c->next = -1;
}

/*
 * Start one non-blocking connect.
 * Returns 1 when the socket is pending in epoll (fd_out owns it), or 0
 * when the job finished immediately (state_out is set and fd_out is
 * -1). Never returns -1: socket/setup failures become state 3 so the
 * scan still fills every output slot.
 */
static int almap_async_launch_one(const unsigned int *hosts_be, int port_count,
                                  const int *ports, int64_t job,
                                  int *fd_out, int *state_out) {
    int host_index;
    int port_index;
    int fd;
    int flags;
    int rc;
    struct sockaddr_in addr;

    *fd_out = -1;
    *state_out = ALMAP_ASYNC_STATE_ERROR;

    host_index = (int)(job / (int64_t)port_count);
    port_index = (int)(job % (int64_t)port_count);

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        return 0;
    }
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(fd);
        return 0;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)ports[port_index]);
    addr.sin_addr.s_addr = htonl(hosts_be[host_index]);

    rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc == 0) {
        close(fd);
        *state_out = ALMAP_ASYNC_STATE_OPEN;
        return 0;
    }
    if (errno == EINPROGRESS || errno == EINTR) {
        *fd_out = fd;
        return 1;
    }

    *state_out = almap_async_errno_state(errno);
    close(fd);
    return 0;
}

static void almap_async_finish(AlmapAsyncEngine *eng, int slot, int state,
                               unsigned char *states_out, int *completed) {
    AlmapAsyncConn *c = &eng->conns[slot];

    (void)eng;
    close(c->fd);
    c->fd = -1;
    states_out[c->job] = (unsigned char)state;
    (*completed)++;
}

int almap_async_connect_scan(const unsigned int *hosts_be, int host_count,
                             const int *ports, int port_count,
                             int timeout_ms, int max_concurrent, int retries,
                             int rate_per_sec, unsigned char *states_out) {
    AlmapAsyncEngine eng;
    AlmapAsyncConn *conns;
    unsigned char *attempts;
    struct epoll_event *events;
    struct epoll_event ev;
    int64_t total;
    int64_t next_job;
    int64_t interval_ns;
    int64_t last_refill_ns;
    int64_t now_ns;
    int tokens;
    int epfd;
    int cap;
    int completed;
    int rc;
    int i;

    if (host_count < 0 || port_count < 0) {
        return -1;
    }
    if (host_count == 0 || port_count == 0) {
        return 0;
    }
    if (hosts_be == NULL || ports == NULL || states_out == NULL) {
        return -1;
    }
    if (timeout_ms <= 0 || max_concurrent <= 0 || retries < 0 ||
        retries > 100 || rate_per_sec < 0) {
        return -1;
    }

    total = (int64_t)host_count * (int64_t)port_count;
    if (total <= 0 || total > (int64_t)INT_MAX) {
        return -1;
    }

    cap = max_concurrent;
    if ((int64_t)cap > total) {
        cap = (int)total;
    }
    if (cap < 1) {
        return -1;
    }

    conns = (AlmapAsyncConn *)calloc((size_t)cap, sizeof(*conns));
    attempts = (unsigned char *)calloc((size_t)total, sizeof(*attempts));
    events = (struct epoll_event *)malloc((size_t)ALMAP_ASYNC_EVENT_BATCH * sizeof(*events));
    if (conns == NULL || attempts == NULL || events == NULL) {
        free(conns);
        free(attempts);
        free(events);
        return -1;
    }
    epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) {
        free(conns);
        free(attempts);
        free(events);
        return -1;
    }

    almap_async_engine_init(&eng, conns, cap);

    /* Every slot must be written; error is the safe default if an
     * unexpected path ever skips a completion. */
    memset(states_out, ALMAP_ASYNC_STATE_ERROR, (size_t)total);

    interval_ns = 0;
    last_refill_ns = 0;
    tokens = 0;
    if (rate_per_sec > 0) {
        interval_ns = ALMAP_ASYNC_NS_PER_SEC / (int64_t)rate_per_sec;
        if (interval_ns < 1) {
            interval_ns = 1;
        }
        last_refill_ns = almap_async_now_ns();
        tokens = 1; /* allow the first attempt immediately */
    }

    next_job = 0;
    completed = 0;
    rc = 0;

    while (completed < (int)total) {
        now_ns = almap_async_now_ns();

        /* Expire stalled connects from the sorted deadline list. A
         * timed-out connect is retried (with a fresh deadline) up to
         * retries times before its final timeout state is recorded. */
        while (eng.timeout_head >= 0 &&
               eng.conns[eng.timeout_head].deadline_ns <= now_ns) {
            int slot = eng.timeout_head;
            int job;
            int fd = -1;
            int state = ALMAP_ASYNC_STATE_TIMEOUT;
            int launched = 0;

            almap_async_deadline_unlink(&eng, slot);
            job = eng.conns[slot].job;
            close(eng.conns[slot].fd);
            eng.conns[slot].fd = -1;
            eng.conns[slot].active = 0;
            eng.active_count--;
            almap_async_slot_free(&eng, slot);

            attempts[job]++;
            if (retries > 0 && (int)attempts[job] <= retries) {
                launched = almap_async_launch_one(hosts_be, port_count, ports,
                                                  job, &fd, &state);
                if (launched == 0) {
                    states_out[job] = (unsigned char)state;
                    completed++;
                } else {
                    int newslot = almap_async_slot_alloc(&eng);
                    if (newslot < 0) {
                        close(fd);
                        states_out[job] = ALMAP_ASYNC_STATE_ERROR;
                        completed++;
                    } else {
                        eng.conns[newslot].fd = fd;
                        eng.conns[newslot].job = job;
                        eng.conns[newslot].deadline_ns =
                            almap_async_now_ns() +
                            (int64_t)timeout_ms * ALMAP_ASYNC_NS_PER_MS;
                        eng.conns[newslot].active = 1;

                        memset(&ev, 0, sizeof(ev));
                        ev.events = EPOLLOUT | EPOLLERR | EPOLLHUP;
                        ev.data.u32 = (uint32_t)newslot;
                        if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) != 0) {
                            close(fd);
                            eng.conns[newslot].fd = -1;
                            eng.conns[newslot].active = 0;
                            states_out[job] = ALMAP_ASYNC_STATE_ERROR;
                            completed++;
                            almap_async_slot_free(&eng, newslot);
                        } else {
                            almap_async_deadline_append(&eng, newslot);
                            eng.active_count++;
                        }
                    }
                }
            } else {
                states_out[job] = ALMAP_ASYNC_STATE_TIMEOUT;
                completed++;
            }
        }

        /* Refill the rate bucket and start as much work as allowed. */
        while (next_job < total && eng.free_head >= 0) {
            int fd;
            int state;
            int launched;
            int slot;

            if (interval_ns > 0) {
                now_ns = almap_async_now_ns();
                if (now_ns > last_refill_ns) {
                    int64_t elapsed = now_ns - last_refill_ns;
                    int64_t gained = elapsed / interval_ns;
                    if (gained > 0) {
                        if (gained > (int64_t)cap) {
                            tokens = cap;
                        } else if ((int64_t)tokens + gained > (int64_t)cap) {
                            tokens = cap;
                        } else {
                            tokens += (int)gained;
                        }
                        last_refill_ns += gained * interval_ns;
                    }
                }
                if (tokens <= 0) {
                    break;
                }
                tokens--;
            }

            launched = almap_async_launch_one(hosts_be, port_count, ports,
                                              next_job, &fd, &state);
            if (launched == 0) {
                states_out[next_job] = (unsigned char)state;
                next_job++;
                completed++;
                continue;
            }

            slot = almap_async_slot_alloc(&eng);
            if (slot < 0) {
                /* Cannot happen: free_head was checked. Defensive. */
                close(fd);
                states_out[next_job] = ALMAP_ASYNC_STATE_ERROR;
                next_job++;
                completed++;
                continue;
            }

            eng.conns[slot].fd = fd;
            eng.conns[slot].job = next_job;
            /* Sample the clock at registration, not at the top of the
             * fill loop: launching 10,000 sockets can take milliseconds,
             * and each socket deserves the full timeout. CLOCK_MONOTONIC
             * keeps these deadlines nondecreasing, preserving the
             * launch-ordered deadline list. */
            eng.conns[slot].deadline_ns =
                almap_async_now_ns() +
                (int64_t)timeout_ms * ALMAP_ASYNC_NS_PER_MS;
            eng.conns[slot].active = 1;

            memset(&ev, 0, sizeof(ev));
            ev.events = EPOLLOUT | EPOLLERR | EPOLLHUP;
            ev.data.u32 = (uint32_t)slot;
            if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) != 0) {
                close(fd);
                eng.conns[slot].fd = -1;
                eng.conns[slot].active = 0;
                states_out[next_job] = ALMAP_ASYNC_STATE_ERROR;
                next_job++;
                completed++;
                almap_async_slot_free(&eng, slot);
                continue;
            }

            almap_async_deadline_append(&eng, slot);
            eng.active_count++;
            next_job++;
        }

        if (completed >= (int)total) {
            break;
        }

        /* Sleep until the nearest deadline, the next rate token, or an
         * epoll event. Round up to whole milliseconds. */
        {
            int wait_ms;
            int64_t best_ns;
            int64_t now2;

            now2 = almap_async_now_ns();
            best_ns = -1;
            if (eng.timeout_head >= 0) {
                best_ns = eng.conns[eng.timeout_head].deadline_ns - now2;
                if (best_ns < 0) {
                    best_ns = 0;
                }
            }
            if (interval_ns > 0 && tokens <= 0 &&
                next_job < total && eng.free_head >= 0) {
                int64_t rate_ns = last_refill_ns + interval_ns - now2;
                if (rate_ns < 0) {
                    rate_ns = 0;
                }
                if (best_ns < 0 || rate_ns < best_ns) {
                    best_ns = rate_ns;
                }
            }
            if (best_ns < 0) {
                /* No deadline and no rate wait: only outstanding epoll
                 * events can make progress. Use a short safety poll. */
                wait_ms = 1;
            } else {
                int64_t wait_ns = best_ns;
                wait_ms = (int)((wait_ns + ALMAP_ASYNC_NS_PER_MS - 1) /
                                ALMAP_ASYNC_NS_PER_MS);
                if (wait_ms < 0) {
                    wait_ms = 0;
                }
            }

            i = epoll_wait(epfd, events, ALMAP_ASYNC_EVENT_BATCH, wait_ms);
        }
        if (i < 0) {
            if (errno == EINTR) {
                continue;
            }
            rc = -1;
            break;
        }

        for (int k = 0; k < i; k++) {
            int slot = (int)events[k].data.u32;
            int state;
            int err;
            socklen_t errlen;

            if (slot < 0 || slot >= cap || !eng.conns[slot].active) {
                continue;
            }

            err = 0;
            errlen = sizeof(err);
            if (getsockopt(eng.conns[slot].fd, SOL_SOCKET, SO_ERROR,
                           &err, &errlen) != 0) {
                state = ALMAP_ASYNC_STATE_ERROR;
            } else if (err != 0) {
                state = almap_async_errno_state(err);
            } else if ((events[k].events & (EPOLLERR | EPOLLHUP)) != 0) {
                /* The requirement treats EPOLLERR/EPOLLHUP as
                 * refused/closed even when SO_ERROR is already clear. */
                state = ALMAP_ASYNC_STATE_CLOSED;
            } else if ((events[k].events & EPOLLOUT) != 0) {
                state = ALMAP_ASYNC_STATE_OPEN;
            } else {
                state = ALMAP_ASYNC_STATE_ERROR;
            }

            almap_async_deadline_unlink(&eng, slot);
            almap_async_finish(&eng, slot, state, states_out, &completed);
            eng.active_count--;
            almap_async_slot_free(&eng, slot);
        }
    }

    /* On a fatal epoll error, close every still-active socket. States
     * left unset stay at the error default from the memset above. */
    if (rc != 0) {
        for (i = 0; i < cap; i++) {
            if (eng.conns[i].active) {
                close(eng.conns[i].fd);
                eng.conns[i].fd = -1;
                eng.conns[i].active = 0;
            }
        }
    }

    close(epfd);
    free(conns);
    free(attempts);
    free(events);
    (void)eng.active_count;
    return rc;
}
