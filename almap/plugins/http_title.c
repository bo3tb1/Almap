/*
 * plugins/http_title.c - Step 30 AlScript (NSE http-title analog).
 *
 * Build:
 *   gcc -shared -fPIC -o plugins/http_title.so plugins/http_title.c
 * Run:
 *   ./almap -t 127.0.0.1 -p 80 --scan connect --script ./plugins/http_title.so
 *
 * Sends GET / HTTP/1.0 and extracts the <title> element and the
 * Server: response header. Output is title="<title>" server="<ver>"
 * (omitting a part when absent). Returns 0 on connected success
 * (empty output when neither field exists), 1 on connection failure.
 * No heap, no external libs: raw POSIX sockets only.
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

static int ci_char(const char *a, const char *b) {
    while (*a && *b) {
        char ca = *a;
        char cb = *b;
        if (ca >= 'A' && ca <= 'Z') {
            ca = (char)(ca - 'A' + 'a');
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (char)(cb - 'A' + 'a');
        }
        if (ca != cb) {
            return 0;
        }
        a++;
        b++;
    }
    return *b == '\0';
}

static const char *find_ci(const char *hay, const char *needle) {
    size_t nlen = strlen(needle);
    const char *p = hay;
    if (nlen == 0) {
        return hay;
    }
    while (*p) {
        const char *h = p;
        size_t i = 0;
        while (i < nlen && h[i]) {
            char ca = h[i];
            char cb = needle[i];
            if (ca >= 'A' && ca <= 'Z') {
                ca = (char)(ca - 'A' + 'a');
            }
            if (cb >= 'A' && cb <= 'Z') {
                cb = (char)(cb - 'A' + 'a');
            }
            if (ca != cb) {
                break;
            }
            i++;
        }
        if (i == nlen) {
            return p;
        }
        p++;
    }
    return NULL;
}

static void clean_field(char *s) {
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
    {
        size_t start = 0;
        while (s[start] == ' ' || s[start] == '\t') {
            start++;
        }
        if (start > 0) {
            memmove(s, s + start, strlen(s + start) + 1);
        }
    }
    for (i = 0; s[i]; i++) {
        if ((unsigned char)s[i] < 32) {
            s[i] = '.';
        }
    }
    (void)ci_char;
}

int almap_script_run(AlScriptContext *ctx) {
    int fd;
    static const char req[] = "GET / HTTP/1.0\r\n\r\n";
    char resp[8192];
    char server[512];
    char title[1024];
    int have_server = 0;
    int have_title = 0;
    const char *p;

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
    server[0] = '\0';
    title[0] = '\0';

    fd = connect_tcp(ctx);
    if (fd < 0) {
        return 1;
    }
    if (send_all(fd, req, strlen(req), ctx->timeout_ms) != 0) {
        close(fd);
        return 1;
    }
    if (read_all(fd, resp, sizeof(resp), ctx->timeout_ms) <= 0) {
        close(fd);
        ctx->output_buf[0] = '\0';
        return 0;
    }
    close(fd);

    /* Server: header (case-insensitive, line-anchored II). */
    p = resp;
    while (*p) {
        const char *line_end = strchr(p, '\n');
        size_t llen;
        if (line_end == NULL) {
            llen = strlen(p);
        } else {
            llen = (size_t)(line_end - p);
        }
        {
            char line[600];
            size_t k;
            for (k = 0; k < llen && k < sizeof(line) - 1; k++) {
                line[k] = p[k];
            }
            line[k] = '\0';
            {
                char *colon = strchr(line, ':');
                if (colon != NULL) {
                    size_t hlen = (size_t)(colon - line);
                    /* Compare header name case-insensitively to Server. */
                    if (hlen == 6) {
                        const char *want = "server";
                        size_t i;
                        int ok = 1;
                        for (i = 0; i < 6; i++) {
                            char ca = line[i];
                            if (ca >= 'A' && ca <= 'Z') {
                                ca = (char)(ca - 'A' + 'a');
                            }
                            if (ca != want[i]) {
                                ok = 0;
                                break;
                            }
                        }
                        if (ok) {
                            const char *val = colon + 1;
                            size_t vi;
                            for (vi = 0; val[vi] && vi < sizeof(server) - 1; vi++) {
                                server[vi] = val[vi];
                            }
                            server[vi] = '\0';
                            clean_field(server);
                            have_server = 1;
                        }
                    }
                }
            }
        }
        if (line_end == NULL) {
            break;
        }
        p = line_end + 1;
    }

    /* <title>...</title> (case-insensitive). */
    {
        const char *open = find_ci(resp, "<title>");
        if (open != NULL) {
            const char *close = find_ci(open + 7, "</title>");
            if (close != NULL) {
                size_t raw = (size_t)(close - (open + 7));
                size_t take = raw;
                size_t i;
                if (take >= sizeof(title)) {
                    take = sizeof(title) - 1;
                }
                for (i = 0; i < take; i++) {
                    title[i] = open[7 + i];
                }
                title[take] = '\0';
                clean_field(title);
                have_title = 1;
            }
        }
    }

    if (have_title && have_server) {
        snprintf(ctx->output_buf, (size_t)ctx->output_max,
                 "title=\"%s\" server=\"%s\"", title, server);
    } else if (have_title) {
        snprintf(ctx->output_buf, (size_t)ctx->output_max, "title=\"%s\"", title);
    } else if (have_server) {
        snprintf(ctx->output_buf, (size_t)ctx->output_max, "server=\"%s\"", server);
    } else {
        ctx->output_buf[0] = '\0';
    }
    return 0;
}
