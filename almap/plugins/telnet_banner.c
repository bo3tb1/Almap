/*
 * plugins/telnet_banner.c - NSE telnet-banner analog.
 *
 * Build:
 *   gcc -shared -fPIC -o plugins/telnet_banner.so plugins/telnet_banner.c
 * Run:
 *   ./almap -t 127.0.0.1 -p 23 --scan connect --script ./plugins/telnet_banner.so
 *
 * Reads the raw Telnet banner until EOF, timeout, or buffer full.
 * CR/LF/TAB are preserved; other control bytes and NUL are replaced
 * with '.' so the output stays printable.
 * No heap, no external libs: raw POSIX sockets only.
 * Use only on networks you own or have permission to scan.
 */
#include "alscript_net.h"

int almap_script_run(AlScriptContext *ctx) {
    int fd;
    char buf[3000];
    int n;
    int i;
    size_t out_cap;
    size_t copy;

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

    fd = as_connect(ctx);
    if (fd < 0) {
        return 1;
    }
    n = as_recv_all(fd, buf, sizeof(buf), ctx->timeout_ms);
    close(fd);
    if (n <= 0) {
        return 0;
    }

    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)buf[i];
        if (c == 0 || (c < 32 && c != '\r' && c != '\n' && c != '\t') ||
            c == 127 || c == 255) {
            buf[i] = '.';
        }
    }

    out_cap = (size_t)ctx->output_max;
    copy = ((size_t)n < out_cap - 1) ? (size_t)n : out_cap - 1;
    memcpy(ctx->output_buf, buf, copy);
    ctx->output_buf[copy] = '\0';
    return 0;
}
