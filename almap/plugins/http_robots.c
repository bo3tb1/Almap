/*
 * plugins/http_robots.c - NSE http-robots.txt analog.
 *
 * Build:
 *   gcc -shared -fPIC -o plugins/http_robots.so plugins/http_robots.c
 * Run:
 *   ./almap -t 127.0.0.1 -p 80 --scan connect --script ./plugins/http_robots.so
 *
 * Fetches /robots.txt and writes the first five body lines.
 * No heap, no external libs: raw POSIX sockets only.
 * Use only on networks you own or have permission to scan.
 */
#include "alscript_net.h"

int almap_script_run(AlScriptContext *ctx) {
    int fd;
    char ip[64];
    char req[512];
    char resp[3584];
    const char *body;
    size_t used = 0;
    size_t out_cap;
    int lines = 0;
    int n;

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

    as_ip_text(ctx->target_ip, ip, sizeof(ip));
    snprintf(req, sizeof(req),
             "GET /robots.txt HTTP/1.0\r\nHost: %s\r\nUser-Agent: ALmap\r\n"
             "Connection: close\r\n\r\n", ip);

    fd = as_connect(ctx);
    if (fd < 0) {
        return 1;
    }
    if (as_send_all(fd, req, strlen(req), ctx->timeout_ms) != 0) {
        close(fd);
        return 1;
    }
    n = as_recv_all(fd, resp, sizeof(resp), ctx->timeout_ms);
    close(fd);
    if (n <= 0) {
        return 0;
    }

    body = as_http_body(resp);
    if (body == NULL) {
        return 0;
    }
    while (*body == '\r' || *body == '\n') {
        body++;
    }
    out_cap = (size_t)ctx->output_max;
    while (lines < 5 && *body != '\0' && used + 2 < out_cap) {
        const char *e = strchr(body, '\n');
        size_t len = (e != NULL) ? (size_t)(e - body) : strlen(body);
        if (len > 0 && body[len - 1] == '\r') {
            len--;
        }
        if (used + len + 2 > out_cap) {
            len = out_cap - used - 2;
        }
        memcpy(ctx->output_buf + used, body, len);
        used += len;
        if (e != NULL && used + 1 < out_cap) {
            ctx->output_buf[used++] = '\n';
        }
        lines++;
        if (e == NULL) {
            break;
        }
        body = e + 1;
    }
    ctx->output_buf[used] = '\0';
    return 0;
}
