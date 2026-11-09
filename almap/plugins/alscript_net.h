/*
 * plugins/alscript_net.h - shared helpers for the Step 33 AlScript
 * arsenal. Raw POSIX TCP only, no heap, fixed buffers.
 *
 * Buffers used by the plugins stay below 4096 bytes. This header is
 * included by the plugin .c files and is not built on its own.
 * Use only on networks you own or have permission to scan.
 */
#ifndef ALSCRIPT_NET_H
#define ALSCRIPT_NET_H

#include "../c/alscript.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>

static int as_connect(AlScriptContext *ctx) {
    int fd;
    struct sockaddr_in addr;
    int flags;
    int rc;
    struct pollfd pfd;
    int pr;

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        return -1;
    }
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(fd);
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)ctx->port);
    addr.sin_addr.s_addr = htonl(ctx->target_ip);
    rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc != 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    if (rc != 0) {
        pfd.fd = fd;
        pfd.events = POLLOUT;
        pfd.revents = 0;
        pr = poll(&pfd, 1, ctx->timeout_ms);
        if (pr <= 0 || (pfd.revents & POLLOUT) == 0) {
            close(fd);
            return -1;
        }
        {
            int err = 0;
            socklen_t errlen = sizeof(err);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) != 0 || err != 0) {
                close(fd);
                return -1;
            }
        }
    }
    return fd;
}

static int as_send_all(int fd, const void *data, size_t len, int timeout_ms) {
    const char *p = (const char *)data;
    size_t sent = 0;

    while (sent < len) {
        ssize_t n = send(fd, p + sent, len - sent, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd pfd;
                int pr;
                pfd.fd = fd;
                pfd.events = POLLOUT;
                pfd.revents = 0;
                pr = poll(&pfd, 1, timeout_ms);
                if (pr <= 0) {
                    return -1;
                }
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

static int as_recv_exact(int fd, void *data, size_t len, int timeout_ms) {
    unsigned char *p = (unsigned char *)data;
    size_t got = 0;

    while (got < len) {
        struct pollfd pfd;
        int pr;
        ssize_t n;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        pr = poll(&pfd, 1, timeout_ms);
        if (pr <= 0) {
            return -1;
        }
        if ((pfd.revents & (POLLIN | POLLHUP | POLLERR)) == 0) {
            return -1;
        }
        if (pfd.revents & POLLERR) {
            return -1;
        }
        n = recv(fd, p + got, len - got, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        got += (size_t)n;
    }
    return 0;
}

static int as_recv_all(int fd, char *buf, size_t cap, int timeout_ms) {
    size_t total = 0;

    if (buf == NULL || cap < 2) {
        return 0;
    }
    while (total + 1 < cap) {
        struct pollfd pfd;
        int pr;
        ssize_t n;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        pr = poll(&pfd, 1, timeout_ms);
        if (pr == 0) {
            break;
        }
        if (pr < 0 || (pfd.revents & (POLLIN | POLLHUP | POLLERR)) == 0) {
            break;
        }
        if (pfd.revents & POLLERR) {
            break;
        }
        n = recv(fd, buf + total, cap - 1 - total, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (n == 0) {
            break;
        }
        total += (size_t)n;
    }
    buf[total] = '\0';
    return (int)total;
}

static int as_recv_line(int fd, char *buf, size_t cap, int timeout_ms) {
    size_t total = 0;

    if (buf == NULL || cap < 2) {
        return 0;
    }
    while (total + 1 < cap) {
        struct pollfd pfd;
        int pr;
        ssize_t n;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        pr = poll(&pfd, 1, timeout_ms);
        if (pr == 0) {
            break;
        }
        if (pr < 0 || (pfd.revents & (POLLIN | POLLHUP | POLLERR)) == 0) {
            break;
        }
        if (pfd.revents & POLLERR) {
            break;
        }
        n = recv(fd, buf + total, 1, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (n == 0) {
            break;
        }
        total++;
        if (buf[total - 1] == '\n') {
            break;
        }
    }
    buf[total] = '\0';
    return (int)total;
}

static void as_trim(char *s) {
    size_t start = 0;
    size_t end;

    if (s == NULL) {
        return;
    }
    end = strlen(s);
    while (start < end && (s[start] == ' ' || s[start] == '\t' ||
                           s[start] == '\r' || s[start] == '\n')) {
        start++;
    }
    while (end > start && (s[end - 1] == ' ' || s[end - 1] == '\t' ||
                           s[end - 1] == '\r' || s[end - 1] == '\n')) {
        end--;
    }
    if (start > 0 && end > start) {
        memmove(s, s + start, end - start);
    }
    s[end - start > 0 ? end - start : 0] = '\0';
}

static void as_clean_field(char *s) {
    size_t i;

    if (s == NULL) {
        return;
    }
    as_trim(s);
    for (i = 0; s[i] != '\0'; i++) {
        if ((unsigned char)s[i] < 32) {
            s[i] = '.';
        }
    }
}

static int as_caseeq_n(const char *a, const char *b, size_t n) {
    size_t i;

    for (i = 0; i < n; i++) {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'A' && ca <= 'Z') {
            ca = (char)(ca - 'A' + 'a');
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (char)(cb - 'A' + 'a');
        }
        if (ca != cb) {
            return 0;
        }
    }
    return 1;
}

/* Extract a header value (case-insensitive name, line-anchored). */
static int as_find_header(const char *resp, const char *name,
                          char *out, size_t outcap) {
    const char *p;
    size_t nlen;

    if (out == NULL || outcap < 2) {
        return 0;
    }
    out[0] = '\0';
    if (resp == NULL || name == NULL) {
        return 0;
    }
    nlen = strlen(name);
    p = resp;
    while (*p != '\0') {
        const char *e = strchr(p, '\n');
        size_t llen = (e != NULL) ? (size_t)(e - p) : strlen(p);
        if (llen > 0 && p[llen - 1] == '\r') {
            llen--;
        }
        if (llen > nlen && p[nlen] == ':' &&
            as_caseeq_n(p, name, nlen)) {
            const char *v = p + nlen + 1;
            size_t vlen = llen - (nlen + 1);
            while (vlen > 0 && (*v == ' ' || *v == '\t')) {
                v++;
                vlen--;
            }
            while (vlen > 0 && (v[vlen - 1] == ' ' || v[vlen - 1] == '\t')) {
                vlen--;
            }
            if (vlen >= outcap) {
                vlen = outcap - 1;
            }
            memcpy(out, v, vlen);
            out[vlen] = '\0';
            as_clean_field(out);
            return 1;
        }
        if (e == NULL) {
            break;
        }
        p = e + 1;
    }
    return 0;
}

static const char *as_http_body(const char *resp) {
    const char *p;

    if (resp == NULL) {
        return NULL;
    }
    p = strstr(resp, "\r\n\r\n");
    if (p != NULL) {
        return p + 4;
    }
    p = strstr(resp, "\n\n");
    if (p != NULL) {
        return p + 2;
    }
    return NULL;
}

static void as_ip_text(unsigned int ip, char *out, size_t cap) {
    struct in_addr a;

    a.s_addr = htonl(ip);
    if (inet_ntop(AF_INET, &a, out, (socklen_t)cap) == NULL) {
        snprintf(out, cap, "%u.%u.%u.%u",
                 (ip >> 24) & 255u, (ip >> 16) & 255u,
                 (ip >> 8) & 255u, ip & 255u);
    }
}

/* Send one UDP datagram to (ctx->target_ip, ctx->port) and return the
 * first reply. Returns the reply length or -1 on send/timeout error.
 * resp is always NUL-terminated when cap >= 1. */
static int as_udp_exchange(AlScriptContext *ctx, const void *req, size_t reqlen,
                           char *resp, size_t cap, int timeout_ms) {
    int fd;
    int n;
    struct sockaddr_in addr;
    struct pollfd pfd;

    if (ctx == NULL || req == NULL || resp == NULL || cap < 1 || reqlen == 0) {
        return -1;
    }
    resp[0] = '\0';
    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)ctx->port);
    addr.sin_addr.s_addr = htonl(ctx->target_ip);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    if (send(fd, req, reqlen, 0) != (ssize_t)reqlen) {
        close(fd);
        return -1;
    }
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    if (poll(&pfd, 1, timeout_ms) <= 0 ||
        (pfd.revents & (POLLIN | POLLERR)) == 0) {
        close(fd);
        return -1;
    }
    n = (int)recv(fd, resp, cap - 1, 0);
    close(fd);
    if (n < 0) {
        resp[0] = '\0';
        return -1;
    }
    resp[n] = '\0';
    return n;
}

#endif /* ALSCRIPT_NET_H */
