/*
 * plugins/mysql_version.c - NSE mysql-info analog (version only).
 *
 * Build:
 *   gcc -shared -fPIC -o plugins/mysql_version.so plugins/mysql_version.c
 * Run:
 *   ./almap -t 127.0.0.1 -p 3306 --scan connect --script ./plugins/mysql_version.so
 *
 * Reads the MySQL initial handshake packet and extracts the
 * NUL-terminated server version string.
 * Output: "mysql_version:<version>" (empty when not MySQL).
 * No heap, no external libs: raw POSIX sockets only.
 * Use only on networks you own or have permission to scan.
 */
#include "alscript_net.h"

int almap_script_run(AlScriptContext *ctx) {
    int fd;
    unsigned char hdr[4];
    unsigned char pkt[3072];
    unsigned int plen;
    char version[256];
    size_t i;
    size_t max;

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
    if (as_recv_exact(fd, hdr, 4, ctx->timeout_ms) != 0) {
        close(fd);
        return 0;
    }
    plen = (unsigned int)hdr[0] | ((unsigned int)hdr[1] << 8) |
           ((unsigned int)hdr[2] << 16);
    if (plen < 2 || plen > sizeof(pkt)) {
        close(fd);
        return 0;
    }
    if (as_recv_exact(fd, pkt, plen, ctx->timeout_ms) != 0) {
        close(fd);
        return 0;
    }
    close(fd);

    /* payload[0] is the protocol version, then the server version. */
    max = (size_t)plen - 1;
    for (i = 0; i < max && pkt[1 + i] != '\0' && i < sizeof(version) - 1; i++) {
        version[i] = (char)pkt[1 + i];
    }
    version[i] = '\0';
    as_clean_field(version);
    if (version[0] != '\0') {
        snprintf(ctx->output_buf, (size_t)ctx->output_max,
                 "mysql_version:%s", version);
    }
    return 0;
}
