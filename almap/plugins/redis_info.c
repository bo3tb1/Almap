/*
 * plugins/redis_info.c - NSE redis-info analog.
 *
 * Build:
 *   gcc -shared -fPIC -o plugins/redis_info.so plugins/redis_info.c
 * Run:
 *   ./almap -t 127.0.0.1 -p 6379 --scan connect --script ./plugins/redis_info.so
 *
 * Sends INFO and extracts the redis_version field.
 * Output: "redis_version:<version>" (empty when not Redis or when the
 * field is absent). Buffers stay below 4096 bytes.
 * No heap, no external libs: raw POSIX sockets only.
 * Use only on networks you own or have permission to scan.
 */
#include "alscript_net.h"

int almap_script_run(AlScriptContext *ctx) {
    int fd;
    char resp[3072];
    char version[128];
    size_t total = 0;
    size_t i;
    const char *hit;

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
    if (as_send_all(fd, "INFO\r\n", 6, ctx->timeout_ms) != 0) {
        close(fd);
        return 1;
    }

    resp[0] = '\0';
    while (total + 1 < sizeof(resp)) {
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
        r = recv(fd, resp + total, sizeof(resp) - 1 - total, 0);
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
        resp[total] = '\0';
        if (strstr(resp, "redis_version:") != NULL) {
            break;
        }
    }
    close(fd);

    hit = strstr(resp, "redis_version:");
    if (hit == NULL) {
        return 0;
    }
    hit += strlen("redis_version:");
    for (i = 0; hit[i] != '\0' && hit[i] != '\r' && hit[i] != '\n' &&
                hit[i] != ' ' && i < sizeof(version) - 1; i++) {
        version[i] = hit[i];
    }
    version[i] = '\0';
    as_clean_field(version);
    if (version[0] != '\0') {
        snprintf(ctx->output_buf, (size_t)ctx->output_max,
                 "redis_version:%s", version);
    }
    return 0;
}
