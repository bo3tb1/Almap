/*
 * plugins/http_webdav.c - NSE http-webdav analog.
 *
 * Build:
 *   gcc -shared -fPIC -o plugins/http_webdav.so plugins/http_webdav.c
 * Run:
 *   ./almap -t 127.0.0.1 -p 80 --scan connect --script ./plugins/http_webdav.so
 *
 * Sends an OPTIONS request and checks for the DAV response header.
 * Output: "DAV: <value>" when WebDAV is advertised, otherwise
 * "WebDAV: disabled".
 * No heap, no external libs: raw POSIX sockets only.
 * Use only on networks you own or have permission to scan.
 */
#include "alscript_net.h"

int almap_script_run(AlScriptContext *ctx) {
    int fd;
    char ip[64];
    char req[512];
    char resp[3072];
    char dav[1024];
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
             "OPTIONS / HTTP/1.0\r\nHost: %s\r\nUser-Agent: ALmap\r\n"
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

    if (as_find_header(resp, "DAV", dav, sizeof(dav))) {
        snprintf(ctx->output_buf, (size_t)ctx->output_max,
                 "DAV: %s", dav);
    } else {
        snprintf(ctx->output_buf, (size_t)ctx->output_max,
                 "WebDAV: disabled");
    }
    return 0;
}
