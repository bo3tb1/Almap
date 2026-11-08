/*
 * plugins/ssh_version.c - Step 30 AlScript (NSE ssh-hostkey analog).
 *
 * Build:
 *   gcc -shared -fPIC -o plugins/ssh_version.so plugins/ssh_version.c
 * Run:
 *   ./almap -t 127.0.0.1 -p 22 --scan connect --script ./plugins/ssh_version.so
 *
 * Reads the server's SSH banner line and writes the exact protocol
 * version (e.g. SSH-2.0-OpenSSH_8.9). Returns 0 on connected success
 * (empty output when no SSH banner is seen), 1 on connection failure.
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

int almap_script_run(AlScriptContext *ctx) {
    int fd;
    char buf[1024];
    size_t total = 0;
    size_t i;
    size_t line_end;
    size_t n;
    char version[512];

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
    /* Read until first LF (banner line) or timeout/buffer full. */
    while (total + 1 < sizeof(buf)) {
        struct pollfd pfd;
        int pr;
        ssize_t r;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        pr = poll(&pfd, 1, ctx->timeout_ms);
        if (pr == 0) {
            break;
        }
        if (pr < 0 || (pfd.revents & (POLLIN | POLLHUP | POLLERR)) == 0) {
            break;
        }
        if (pfd.revents & POLLERR) {
            break;
        }
        r = recv(fd, buf + total, sizeof(buf) - 1 - total, 0);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (r == 0) {
            break;
        }
        total += (size_t)r;
        /* Banner ends at first LF; keep reading only if no LF yet. */
        {
            size_t k;
            int found = 0;
            for (k = 0; k < total; k++) {
                if (buf[k] == '\n') {
                    found = 1;
                    break;
                }
            }
            if (found) {
                break;
            }
        }
    }
    close(fd);
    if (total == 0) {
        ctx->output_buf[0] = '\0';
        return 0;
    }
    buf[total] = '\0';

    /* Extract first line up to LF/CRLF. */
    line_end = total;
    for (i = 0; i < total; i++) {
        if (buf[i] == '\n') {
            line_end = i;
            break;
        }
    }
    if (line_end == total) {
        line_end = total;
    }
    /* Trim trailing CR. */
    while (line_end > 0 && buf[line_end - 1] == '\r') {
        line_end--;
    }
    n = line_end;
    if (n >= sizeof(version)) {
        n = sizeof(version) - 1;
    }
    for (i = 0; i < n; i++) {
        version[i] = buf[i];
    }
    version[n] = '\0';
    /* Clean control bytes and trim surrounding spaces. */
    for (i = 0; version[i]; i++) {
        if ((unsigned char)version[i] < 32) {
            version[i] = '.';
        }
    }
    {
        size_t start = 0;
        size_t end = strlen(version);
        while (version[start] == ' ' || version[start] == '\t') {
            start++;
        }
        while (end > start && (version[end - 1] == ' ' || version[end - 1] == '\t')) {
            end--;
        }
        if (start > 0 || end < strlen(version)) {
            size_t len = end - start;
            memmove(version, version + start, len);
            version[len] = '\0';
        }
    }
    /* Only emit when it looks like SSH-; otherwise empty (not SSH). */
    if (strncmp(version, "SSH-", 4) != 0) {
        ctx->output_buf[0] = '\0';
        return 0;
    }
    snprintf(ctx->output_buf, (size_t)ctx->output_max, "%s", version);
    return 0;
}
