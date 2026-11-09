/*
 * plugins/ftp_syst.c - NSE ftp-syst analog.
 *
 * Build:
 *   gcc -shared -fPIC -o plugins/ftp_syst.so plugins/ftp_syst.c
 * Run:
 *   ./almap -t 127.0.0.1 -p 21 --scan connect --script ./plugins/ftp_syst.so
 *
 * Reads the FTP greeting, sends SYST, and extracts the 215 reply text
 * (the server OS type, for example "UNIX Type: L8").
 * Output: "SYST: <value>" (empty when SYST is not supported).
 * No heap, no external libs: raw POSIX sockets only.
 * Use only on networks you own or have permission to scan.
 */
#include "alscript_net.h"

int almap_script_run(AlScriptContext *ctx) {
    int fd;
    char line[1024];
    char syst[768];
    int n;
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

    /* Read the greeting; skip 220- continuation lines. */
    n = as_recv_line(fd, line, sizeof(line), ctx->timeout_ms);
    guard = 0;
    while (n > 0 && strncmp(line, "220-", 4) == 0 && guard++ < 8) {
        n = as_recv_line(fd, line, sizeof(line), ctx->timeout_ms);
    }
    if (n <= 0 || strncmp(line, "220", 3) != 0) {
        close(fd);
        return 0;
    }

    if (as_send_all(fd, "SYST\r\n", 6, ctx->timeout_ms) != 0) {
        close(fd);
        return 1;
    }

    syst[0] = '\0';
    n = as_recv_line(fd, line, sizeof(line), ctx->timeout_ms);
    guard = 0;
    while (n > 0 && strncmp(line, "215", 3) == 0 && guard++ < 8) {
        const char *text = line + 3;
        if (*text == ' ' || *text == '-') {
            text++;
        }
        snprintf(syst, sizeof(syst), "%s", text);
        if (line[3] == ' ') {
            break;
        }
        n = as_recv_line(fd, line, sizeof(line), ctx->timeout_ms);
    }
    close(fd);

    as_clean_field(syst);
    if (syst[0] != '\0') {
        snprintf(ctx->output_buf, (size_t)ctx->output_max,
                 "SYST: %s", syst);
    }
    return 0;
}
