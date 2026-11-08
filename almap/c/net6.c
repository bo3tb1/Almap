#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "net6.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * net6.c - Step 18: limited IPv6 TCP connect probe (POSIX, Linux).
 *
 * Uses AF_INET6, struct sockaddr_in6, and inet_pton (in the text entry
 * point) without touching the existing IPv4 helpers in net.c. The byte
 * entry point receives exactly the 16 bytes an inet_pton result would
 * hold, so both entry points share one connect implementation.
 *
 * No SYN, raw sockets, UDP, service detection, or banner grabbing over
 * IPv6 in this step. Use only on networks you own or have permission to
 * scan.
 */

static int almap6_connect_bytes(const unsigned char addr16[16], int port, int timeout_ms) {
    struct sockaddr_in6 addr;
    struct pollfd pfd;
    int fd;
    int flags;
    int err;
    socklen_t errlen;
    int pr;

    if (addr16 == NULL || port < 1 || port > 65535 || timeout_ms <= 0) {
        return 3;
    }

    fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        return 3;
    }
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(fd);
        return 3;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons((uint16_t)port);
    memcpy(&addr.sin6_addr, addr16, 16);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        close(fd);
        return 0;
    }
    if (errno != EINPROGRESS) {
        int code = 3;
        if (errno == ECONNREFUSED) {
            code = 1;
        } else if (errno == ETIMEDOUT) {
            code = 2;
        }
        close(fd);
        return code;
    }

    pfd.fd = fd;
    pfd.events = POLLOUT;
    pfd.revents = 0;
    pr = poll(&pfd, 1, timeout_ms);
    if (pr == 0) {
        close(fd);
        return 2;
    }
    if (pr < 0) {
        close(fd);
        return 3;
    }
    if ((pfd.revents & (POLLOUT | POLLERR | POLLHUP)) == 0) {
        close(fd);
        return 3;
    }

    err = 0;
    errlen = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) != 0) {
        close(fd);
        return 3;
    }
    close(fd);
    if (err == 0) {
        return 0;
    }
    if (err == ECONNREFUSED) {
        return 1;
    }
    if (err == ETIMEDOUT) {
        return 2;
    }
    return 3;
}

int almap6_sock_connect_timeout(const unsigned char *addr16, int port, int timeout_ms) {
    return almap6_connect_bytes(addr16, port, timeout_ms);
}

int almap6_sock_connect_text(const unsigned char *text, int text_len, int port, int timeout_ms) {
    char buf[64];
    struct in6_addr parsed;

    if (text == NULL || text_len <= 0 || text_len >= (int)sizeof(buf)) {
        return 3;
    }
    memcpy(buf, text, (size_t)text_len);
    buf[text_len] = '\0';
    if (inet_pton(AF_INET6, buf, &parsed) != 1) {
        return 3;
    }
    return almap6_connect_bytes((const unsigned char *)&parsed, port, timeout_ms);
}
