/*
 * plugins/smtp_commands.c - NSE smtp-commands analog.
 *
 * Build:
 *   gcc -shared -fPIC -o plugins/smtp_commands.so plugins/smtp_commands.c
 * Run:
 *   ./almap -t 127.0.0.1 -p 25 --scan connect --script ./plugins/smtp_commands.so
 *
 * Reads the SMTP greeting, sends EHLO, and collects the extension
 * lines from the multiline 250 reply.
 * Output: "EHLO: <comma-separated extensions>" (empty when EHLO fails).
 * No heap, no external libs: raw POSIX sockets only.
 * Use only on networks you own or have permission to scan.
 */
#include "alscript_net.h"

static void append_ext(char *dst, size_t cap, const char *text) {
    size_t used;
    size_t len;

    if (dst == NULL || text == NULL || cap < 2) {
        return;
    }
    used = strlen(dst);
    len = strlen(text);
    if (used + len + 3 > cap) {
        return;
    }
    if (used > 0) {
        dst[used++] = ',';
        dst[used++] = ' ';
    }
    memcpy(dst + used, text, len);
    used += len;
    dst[used] = '\0';
}

int almap_script_run(AlScriptContext *ctx) {
    int fd;
    char line[1024];
    char text[768];
    char exts[2600];
    int n;
    int first = 1;
    int guard;

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

    n = as_recv_line(fd, line, sizeof(line), ctx->timeout_ms);
    guard = 0;
    while (n > 0 && strncmp(line, "220-", 4) == 0 && guard++ < 8) {
        n = as_recv_line(fd, line, sizeof(line), ctx->timeout_ms);
    }
    if (n <= 0 || strncmp(line, "220", 3) != 0) {
        close(fd);
        return 0;
    }

    if (as_send_all(fd, "EHLO almap.local\r\n", 18, ctx->timeout_ms) != 0) {
        close(fd);
        return 1;
    }

    exts[0] = '\0';
    guard = 0;
    while (guard++ < 64) {
        n = as_recv_line(fd, line, sizeof(line), ctx->timeout_ms);
        if (n <= 0 || strncmp(line, "250", 3) != 0) {
            break;
        }
        if (line[3] != '-' && line[3] != ' ') {
            break;
        }
        snprintf(text, sizeof(text), "%s", line + 4);
        as_clean_field(text);
        if (!(first && line[3] == '-') && text[0] != '\0') {
            append_ext(exts, sizeof(exts), text);
        }
        first = 0;
        if (line[3] == ' ') {
            break;
        }
    }
    close(fd);

    if (exts[0] != '\0') {
        snprintf(ctx->output_buf, (size_t)ctx->output_max,
                 "EHLO: %s", exts);
    }
    return 0;
}
