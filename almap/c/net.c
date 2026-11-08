#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "net.h"

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
 * net.c - Step 3: TCP connect-scan sockets (POSIX, Linux).
 * Step 8 adds banner grabbing; Step 16 adds the fixed HTTP HEAD probe
 * used by service detection. No SYN, raw sockets, or evasion here.
 * Use only on networks you own or have permission to scan.
 */

int almap_sock_create(int domain, int type, int protocol) {
    int fd;
    int flags;

    fd = socket(domain, type, protocol);
    if (fd < 0) {
        return -1;
    }
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int almap_sock_connect_timeout(int fd, unsigned int addr_be, int port, int timeout_ms) {
    struct sockaddr_in addr;
    struct pollfd pfd;
    int err;
    socklen_t errlen;
    int pr;

    if (fd < 0 || port < 1 || port > 65535 || timeout_ms <= 0) {
        return 3;
    }

    /* Ensure the fd is non-blocking (almap_sock_create already does this). */
    {
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0) {
            return 3;
        }
        if ((flags & O_NONBLOCK) == 0) {
            if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
                return 3;
            }
        }
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(addr_be);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        return 0;
    }
    if (errno != EINPROGRESS) {
        if (errno == ECONNREFUSED) {
            return 1;
        }
        if (errno == ETIMEDOUT) {
            return 2;
        }
        return 3;
    }

    pfd.fd = fd;
    pfd.events = POLLOUT;
    pfd.revents = 0;
    pr = poll(&pfd, 1, timeout_ms);
    if (pr == 0) {
        return 2;
    }
    if (pr < 0) {
        return 3;
    }
    if ((pfd.revents & (POLLOUT | POLLERR | POLLHUP)) == 0) {
        return 3;
    }

    err = 0;
    errlen = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) != 0) {
        return 3;
    }
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

int almap_sock_close(int fd) {
    if (fd < 0) {
        return -1;
    }
    if (close(fd) != 0) {
        return -1;
    }
    return 0;
}

/*
 * Shared probe helper: connect, optionally send a fixed request, then
 * wait for readable data and read up to out_cap-1 bytes. The socket
 * creation/connect logic is the same almap_sock_create /
 * almap_sock_connect_timeout pair used by the connect scan, so banner
 * grabbing and service probing do not duplicate it.
 */
static int almap_sock_probe(unsigned int addr_be, int port, int timeout_ms, const char *request, int request_len, unsigned char *out, int out_cap) {
    int fd;
    int code;
    struct pollfd pfd;
    int pr;
    ssize_t n;

    if (out == NULL || out_cap < 2) {
        return -1;
    }
    if (addr_be == 0 || port < 1 || port > 65535 || timeout_ms <= 0) {
        return -1;
    }

    fd = almap_sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        return -1;
    }
    code = almap_sock_connect_timeout(fd, addr_be, port, timeout_ms);
    if (code != 0) {
        close(fd);
        return -1;
    }

    if (request != NULL && request_len > 0) {
        int sent = 0;
        while (sent < request_len) {
            pfd.fd = fd;
            pfd.events = POLLOUT;
            pfd.revents = 0;
            pr = poll(&pfd, 1, timeout_ms);
            if (pr <= 0) {
                break;
            }
            if ((pfd.revents & POLLOUT) == 0) {
                break;
            }
            n = send(fd, request + sent, (size_t)(request_len - sent), 0);
            if (n <= 0) {
                break;
            }
            sent += (int)n;
        }
    }

    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    pr = poll(&pfd, 1, timeout_ms);
    if (pr == 0) {
        out[0] = '\0';
        close(fd);
        return 0;
    }
    if (pr < 0) {
        close(fd);
        return -1;
    }
    if ((pfd.revents & POLLIN) == 0) {
        out[0] = '\0';
        close(fd);
        return 0;
    }
    n = recv(fd, out, (size_t)(out_cap - 1), 0);
    if (n < 0) {
        close(fd);
        return -1;
    }
    if (n == 0) {
        out[0] = '\0';
        close(fd);
        return 0;
    }
    out[n] = '\0';
    close(fd);
    return (int)n;
}

int almap_sock_grab_banner(unsigned int addr_be, int port, int timeout_ms, unsigned char *out, int out_cap) {
    return almap_sock_probe(addr_be, port, timeout_ms, NULL, 0, out, out_cap);
}

int almap_sock_http_probe(unsigned int addr_be, int port, int timeout_ms, unsigned char *out, int out_cap) {
    static const char request[] = "HEAD / HTTP/1.0\r\n\r\n";
    return almap_sock_probe(addr_be, port, timeout_ms, request, (int)(sizeof(request) - 1), out, out_cap);
}

