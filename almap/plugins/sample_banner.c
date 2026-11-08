/*
 * plugins/sample_banner.c - Step 22 sample AlScript plugin.
 * Build:
 *   gcc -shared -fPIC -o sample_banner.so plugins/sample_banner.c
 * Run:
 *   ./almap -t 127.0.0.1 -p 12345 --scan connect --script ./sample_banner.so
 *
 * The plugin exports int almap_script_run(AlScriptContext *ctx):
 * it opens a TCP connection to (target_ip, port) with ctx->timeout_ms,
 * reads up to output_max - 1 banner bytes, cleans trailing CR/LF and
 * control bytes, and writes the text to ctx->output_buf. Returns 0 on
 * success (empty output is still success), 1 on failure.
 * No heap, no sandbox: install only scripts you trust.
 */
#include "../c/alscript.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>

int almap_script_run(AlScriptContext *ctx) {
    int fd = -1;
    struct sockaddr_in addr;
    int flags;
    int rc;
    struct pollfd pfd;
    int pr;
    ssize_t n;
    size_t to_read;
    size_t i;
    size_t end;

    if (ctx == NULL || ctx->output_buf == NULL || ctx->output_max < 2) {
        return 1;
    }
    ctx->output_buf[0] = '\0';
    if (ctx->port < 1 || ctx->port > 65535 || ctx->timeout_ms <= 0) {
        return 1;
    }
    /* target_ip is host-order u32 (first octet high). Any nonzero
     * address is accepted; 0 is rejected as invalid. */
    if (ctx->target_ip == 0) {
        return 1;
    }

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        return 1;
    }
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(fd);
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)ctx->port);
    addr.sin_addr.s_addr = htonl(ctx->target_ip);
    rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc != 0 && errno != EINPROGRESS) {
        close(fd);
        return 1;
    }
    if (rc != 0) {
        pfd.fd = fd;
        pfd.events = POLLOUT;
        pfd.revents = 0;
        pr = poll(&pfd, 1, ctx->timeout_ms);
        if (pr <= 0) {
            close(fd);
            return 1;
        }
        if ((pfd.revents & POLLOUT) == 0) {
            close(fd);
            return 1;
        }
        /* Confirm the connect really succeeded (not just POLLOUT). */
        {
            int err = 0;
            socklen_t errlen = sizeof(err);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) != 0 || err != 0) {
                close(fd);
                return 1;
            }
        }
    }

    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    pr = poll(&pfd, 1, ctx->timeout_ms);
    if (pr == 0) {
        /* Open but silent: empty output is success. */
        close(fd);
        ctx->output_buf[0] = '\0';
        return 0;
    }
    if (pr < 0 || (pfd.revents & POLLIN) == 0) {
        close(fd);
        return 1;
    }

    to_read = (size_t)(ctx->output_max - 1);
    if (to_read == 0) {
        to_read = 1;
    }
    n = recv(fd, ctx->output_buf, to_read, 0);
    close(fd);
    if (n < 0) {
        ctx->output_buf[0] = '\0';
        return 1;
    }
    if (n == 0) {
        ctx->output_buf[0] = '\0';
        return 0;
    }
    /* Trim trailing CR/LF and replace leftover control bytes with '.'. */
    end = (size_t)n;
    while (end > 0 && (ctx->output_buf[end - 1] == '\r' || ctx->output_buf[end - 1] == '\n')) {
        end--;
    }
    for (i = 0; i < end; i++) {
        if ((unsigned char)ctx->output_buf[i] < 32) {
            ctx->output_buf[i] = '.';
        }
    }
    ctx->output_buf[end] = '\0';
    return 0;
}
