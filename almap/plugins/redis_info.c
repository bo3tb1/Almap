/*
 * plugins/redis_info.c - Step 30 AlScript (NSE redis-info analog).
 *
 * Build:
 *   gcc -shared -fPIC -o plugins/redis_info.so plugins/redis_info.c
 * Run:
 *   ./almap -t 127.0.0.1 -p 6379 --scan connect --script ./plugins/redis_info.so
 *
 * Sends INFO and extracts the redis_version field. Output is
 * redis_version:<version> (empty when the server is not Redis or
 * the field is absent). Returns 0 on connected success, 1 on
 * connection failure. No heap, no external libs: raw POSIX sockets.
 * Use only on networks you own or have permission to scan.
 */
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

#define REDIS_PREFIX "redis_version:"

static int connect_tcp(AlScriptContext *ctx) {
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

static int send_all(int fd, const char *data, size_t len, int timeout_ms) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, data + sent, len - sent, 0);
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

static int read_all(int fd, char *buf, size_t cap, int timeout_ms) {
    size_t total = 0;
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
    if (total < cap) {
        buf[total] = '\0';
    } else {
        buf[cap - 1] = '\0';
        total = cap - 1;
    }
    return (int)total;
}

static void clean_value(char *s) {
    size_t i;
    size_t len = strlen(s);
    while (len > 0) {
        char c = s[len - 1];
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') {
            s[len - 1] = '\0';
            len--;
        } else {
            break;
        }
    }
    for (i = 0; s[i]; i++) {
        if ((unsigned char)s[i] < 32) {
            s[i] = '.';
        }
    }
}

int almap_script_run(AlScriptContext *ctx) {
    int fd;
    static const char cmd[] = "INFO\r\n";
    char resp[16384];
    const char *hit;
    char version[128];
    size_t i;

    if (ctx == NULL || ctx->output_buf == NULL || ctx->output_max < 2) {
        return 1;
    }
    ctx->output_buf[0] = '\0';
    if (ctx->port < 1 || ctx->port > 65535 || ctx->timeout_ms <= 0) {
        return 1;
    }
    if (ctx->target_ip == 0) {
        return 1;
    }

    fd = connect_tcp(ctx);
    if (fd < 0) {
        return 1;
    }
    if (send_all(fd, cmd, strlen(cmd), ctx->timeout_ms) != 0) {
        close(fd);
        return 1;
    }
    if (read_all(fd, resp, sizeof(resp), ctx->timeout_ms) <= 0) {
        close(fd);
        ctx->output_buf[0] = '\0';
        return 0;
    }
    close(fd);

    hit = strstr(resp, REDIS_PREFIX);
    if (hit == NULL) {
        ctx->output_buf[0] = '\0';
        return 0;
    }
    hit += strlen(REDIS_PREFIX);
    for (i = 0; hit[i] && hit[i] != '\r' && hit[i] != '\n' && i < sizeof(version) - 1; i++) {
        version[i] = hit[i];
    }
    version[i] = '\0';
    clean_value(version);
    if (version[0] == '\0') {
        ctx->output_buf[0] = '\0';
        return 0;
    }
    snprintf(ctx->output_buf, (size_t)ctx->output_max, "redis_version:%s", version);
    return 0;
}
