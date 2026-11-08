/*
 * plugins/ftp_anon.c - Step 30 AlScript (NSE ftp-anon analog).
 *
 * Build:
 *   gcc -shared -fPIC -o plugins/ftp_anon.so plugins/ftp_anon.c
 * Run:
 *   ./almap -t 127.0.0.1 -p 21 --scan connect --script ./plugins/ftp_anon.so
 *
 * Connects to FTP, reads the greeting, sends USER/PASS anonymous,
 * and checks for 230 (Login successful). On 230 the output is
 * "230 Login successful"; otherwise "Anonymous login failed: <reply>".
 * Returns 0 on connected success, 1 on connection failure. No heap,
 * no external libs: raw POSIX sockets only.
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

/* Read one FTP line (up to LF) into buf. Returns line length (without
 * trailing CRLF handling folded in) or 0 on timeout/EOF. */
static int read_line(int fd, char *buf, size_t cap, int timeout_ms) {
    size_t total = 0;
    while (total + 1 < cap) {
        struct pollfd pfd;
        int pr;
        ssize_t n;
        size_t k;
        int done = 0;
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
        for (k = 0; k < total; k++) {
            if (buf[k] == '\n') {
                done = 1;
                break;
            }
        }
        if (done) {
            break;
        }
    }
    if (total < cap) {
        buf[total] = '\0';
    } else {
        buf[cap - 1] = '\0';
        total = cap - 1;
    }
    return (int)total;
}

static void clean_line(char *s) {
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
    static const char user_cmd[] = "USER anonymous\r\n";
    static const char pass_cmd[] = "PASS anonymous\r\n";
    char greeting[1024];
    char reply[1024];
    int glen;
    int rlen;

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
    glen = read_line(fd, greeting, sizeof(greeting), ctx->timeout_ms);
    if (glen <= 0) {
        close(fd);
        ctx->output_buf[0] = '\0';
        return 0;
    }
    clean_line(greeting);
    if (strncmp(greeting, "220", 3) != 0) {
        /* Not an FTP greeting; report nothing (still a plugin success). */
        close(fd);
        ctx->output_buf[0] = '\0';
        return 0;
    }
    if (send_all(fd, user_cmd, strlen(user_cmd), ctx->timeout_ms) != 0) {
        close(fd);
        return 1;
    }
    rlen = read_line(fd, reply, sizeof(reply), ctx->timeout_ms);
    if (rlen <= 0) {
        close(fd);
        ctx->output_buf[0] = '\0';
        return 0;
    }
    clean_line(reply);
    /* If USER already logged in (230), no PASS needed; some servers
     * answer 230 directly to USER. */
    if (strncmp(reply, "230", 3) == 0) {
        snprintf(ctx->output_buf, (size_t)ctx->output_max, "%s", reply);
        close(fd);
        return 0;
    }
    if (send_all(fd, pass_cmd, strlen(pass_cmd), ctx->timeout_ms) != 0) {
        close(fd);
        return 1;
    }
    rlen = read_line(fd, reply, sizeof(reply), ctx->timeout_ms);
    close(fd);
    if (rlen <= 0) {
        ctx->output_buf[0] = '\0';
        return 0;
    }
    clean_line(reply);
    if (strncmp(reply, "230", 3) == 0) {
        snprintf(ctx->output_buf, (size_t)ctx->output_max, "%s", reply);
        return 0;
    }
    /* Failed anonymous login: include the server's reply for context
     * (capped to output_max). */
    snprintf(ctx->output_buf, (size_t)ctx->output_max,
             "Anonymous login failed: %s", reply);
    return 0;
}
