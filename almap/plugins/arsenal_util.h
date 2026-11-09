/*
 * plugins/arsenal_util.h - shared helpers for the Step 33 AlScript
 * NSE-compatible arsenal. Raw POSIX sockets, fixed buffers, no heap.
 *
 * Use only on networks you own or have permission to scan.
 */
#ifndef ARSENAL_UTIL_H
#define ARSENAL_UTIL_H

#define _POSIX_C_SOURCE 200809L

#include "alscript_net.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#ifndef AR_BUF
#define AR_BUF 8192
#endif

static int ar_check(AlScriptContext *ctx) {
    if (ctx == NULL || ctx->output_buf == NULL || ctx->output_max < 2) {
        return 0;
    }
    if (ctx->port < 1 || ctx->port > 65535 || ctx->timeout_ms <= 0) {
        return 0;
    }
    return ctx->target_ip != 0;
}

static int ar_valid(AlScriptContext *ctx) {
    if (!ar_check(ctx)) {
        return 0;
    }
    ctx->output_buf[0] = '\0';
    return 1;
}

static void ar_out(AlScriptContext *ctx, const char *fmt, ...) {
    va_list ap;

    if (ctx == NULL || ctx->output_buf == NULL || ctx->output_max < 2) {
        return;
    }
    va_start(ap, fmt);
    (void)vsnprintf(ctx->output_buf, (size_t)ctx->output_max, fmt, ap);
    va_end(ap);
    ctx->output_buf[ctx->output_max - 1] = '\0';
}

static void ar_append(AlScriptContext *ctx, const char *fmt, ...) {
    size_t used;
    va_list ap;

    if (ctx == NULL || ctx->output_buf == NULL || ctx->output_max < 2) {
        return;
    }
    used = strlen(ctx->output_buf);
    if (used + 1 >= (size_t)ctx->output_max) {
        return;
    }
    va_start(ap, fmt);
    (void)vsnprintf(ctx->output_buf + used, (size_t)ctx->output_max - used,
                    fmt, ap);
    va_end(ap);
    ctx->output_buf[ctx->output_max - 1] = '\0';
}

static int ar_lower(int c) {
    if (c >= 'A' && c <= 'Z') {
        return c - 'A' + 'a';
    }
    return c;
}

static const char *ar_stristr(const char *hay, const char *needle) {
    size_t nlen;

    if (hay == NULL || needle == NULL) {
        return NULL;
    }
    nlen = strlen(needle);
    if (nlen == 0) {
        return hay;
    }
    while (*hay != '\0') {
        size_t i = 0;
        while (i < nlen && hay[i] != '\0' &&
               ar_lower((unsigned char)hay[i]) ==
               ar_lower((unsigned char)needle[i])) {
            i++;
        }
        if (i == nlen) {
            return hay;
        }
        hay++;
    }
    return NULL;
}

static int ar_contains_ci(const char *hay, const char *needle) {
    return ar_stristr(hay, needle) != NULL;
}

static int ar_starts_ci(const char *s, const char *prefix) {
    size_t i;

    if (s == NULL || prefix == NULL) {
        return 0;
    }
    for (i = 0; prefix[i] != '\0'; i++) {
        if (s[i] == '\0' ||
            ar_lower((unsigned char)s[i]) !=
            ar_lower((unsigned char)prefix[i])) {
            return 0;
        }
    }
    return 1;
}

static void ar_clean(char *s) {
    size_t i;

    if (s == NULL) {
        return;
    }
    as_trim(s);
    for (i = 0; s[i] != '\0'; i++) {
        if ((unsigned char)s[i] < 32 || (unsigned char)s[i] == 127) {
            s[i] = ' ';
        }
    }
}

static int ar_http_request(AlScriptContext *ctx, const char *method,
                           const char *path, const char *host,
                           const char *extra, const char *body,
                           const char *ctype, char *resp, size_t cap) {
    char req[4096];
    char ip[32];
    const char *h = host;
    size_t body_len = (body != NULL) ? strlen(body) : 0;
    int n;
    int fd;
    int got;

    if (!ar_check(ctx) || method == NULL || path == NULL || resp == NULL ||
        cap < 2) {
        return -1;
    }
    resp[0] = '\0';
    if (h == NULL || h[0] == '\0') {
        as_ip_text(ctx->target_ip, ip, sizeof(ip));
        h = ip;
    }
    if (path[0] != '/') {
        path = "/";
    }
    if (extra == NULL) {
        extra = "";
    }
    if (ctype != NULL && ctype[0] != '\0') {
        n = snprintf(req, sizeof(req),
                     "%s %s HTTP/1.0\r\nHost: %s\r\n"
                     "User-Agent: ALmap/5.0\r\nAccept: */*\r\n"
                     "Connection: close\r\nContent-Type: %s\r\n"
                     "Content-Length: %lu\r\n%s%s\r\n",
                     method, path, h, ctype, (unsigned long)body_len,
                     extra, (body != NULL) ? body : "");
    } else {
        n = snprintf(req, sizeof(req),
                     "%s %s HTTP/1.0\r\nHost: %s\r\n"
                     "User-Agent: ALmap/5.0\r\nAccept: */*\r\n"
                     "Connection: close\r\n%s%s\r\n",
                     method, path, h, extra, (body != NULL) ? body : "");
    }
    if (n < 0 || (size_t)n >= sizeof(req)) {
        return -1;
    }
    fd = as_connect(ctx);
    if (fd < 0) {
        return -1;
    }
    if (as_send_all(fd, req, (size_t)n, ctx->timeout_ms) != 0) {
        close(fd);
        return -1;
    }
    got = as_recv_all(fd, resp, cap, ctx->timeout_ms);
    close(fd);
    return got;
}

static int ar_http_get(AlScriptContext *ctx, const char *path,
                       char *resp, size_t cap) {
    return ar_http_request(ctx, "GET", path, NULL, NULL, NULL, NULL,
                           resp, cap);
}

static int ar_http_head(AlScriptContext *ctx, const char *path,
                        char *resp, size_t cap) {
    return ar_http_request(ctx, "HEAD", path, NULL, NULL, NULL, NULL,
                           resp, cap);
}

static int ar_http_post(AlScriptContext *ctx, const char *path,
                        const char *body, const char *ctype,
                        char *resp, size_t cap) {
    return ar_http_request(ctx, "POST", path, NULL, NULL, body, ctype,
                           resp, cap);
}

static int ar_http_status(const char *resp) {
    int code = 0;

    if (resp == NULL) {
        return 0;
    }
    if (sscanf(resp, "HTTP/%*d.%*d %d", &code) == 1) {
        return code;
    }
    return 0;
}

static const char *ar_http_body(const char *resp) {
    const char *p = as_http_body(resp);

    return (p != NULL) ? p : "";
}

static int ar_http_ok(const char *resp) {
    int code = ar_http_status(resp);

    return code >= 200 && code < 400;
}

static int ar_http_header(const char *resp, const char *name,
                          char *out, size_t cap) {
    return as_find_header(resp, name, out, cap);
}

static void ar_b64(const unsigned char *in, size_t len, char *out,
                   size_t cap) {
    static const char tab[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i;
    size_t o = 0;

    if (out == NULL || cap == 0) {
        return;
    }
    for (i = 0; i + 2 < len && o + 4 < cap; i += 3) {
        unsigned int v = ((unsigned int)in[i] << 16) |
                         ((unsigned int)in[i + 1] << 8) |
                         (unsigned int)in[i + 2];
        out[o++] = tab[(v >> 18) & 63];
        out[o++] = tab[(v >> 12) & 63];
        out[o++] = tab[(v >> 6) & 63];
        out[o++] = tab[v & 63];
    }
    if (i < len && o + 4 < cap) {
        unsigned int v = (unsigned int)in[i] << 16;
        if (i + 1 < len) {
            v |= (unsigned int)in[i + 1] << 8;
        }
        out[o++] = tab[(v >> 18) & 63];
        out[o++] = tab[(v >> 12) & 63];
        out[o++] = (i + 1 < len) ? tab[(v >> 6) & 63] : '=';
        out[o++] = '=';
    }
    out[o] = '\0';
}

static void ar_basic_auth(const char *user, const char *pass,
                          char *out, size_t cap) {
    char raw[256];
    char enc[512];

    if (out == NULL || cap < 2) {
        return;
    }
    (void)snprintf(raw, sizeof(raw), "%s:%s", user, pass);
    ar_b64((const unsigned char *)raw, strlen(raw), enc, sizeof(enc));
    (void)snprintf(out, cap, "Authorization: Basic %s\r\n", enc);
}

static int ar_ftp_reply(int fd, char *out, size_t cap, int timeout_ms) {
    char line[512];
    int code = -1;
    size_t used = 0;

    if (out == NULL || cap < 2) {
        return -1;
    }
    out[0] = '\0';
    for (;;) {
        int n = as_recv_line(fd, line, sizeof(line), timeout_ms);
        if (n <= 0) {
            return code;
        }
        if (used + (size_t)n + 1 < cap) {
            memcpy(out + used, line, (size_t)n);
            used += (size_t)n;
            out[used] = '\0';
        }
        if (n >= 3 && isdigit((unsigned char)line[0]) &&
            isdigit((unsigned char)line[1]) && isdigit((unsigned char)line[2])) {
            int c = (line[0] - '0') * 100 + (line[1] - '0') * 10 +
                    (line[2] - '0');
            if (code < 0) {
                code = c;
            }
            if (n < 4 || line[3] == ' ' || line[3] == '\r' ||
                line[3] == '\n') {
                break;
            }
        } else {
            break;
        }
    }
    return code;
}

static int ar_ftp_open(AlScriptContext *ctx, char *banner, size_t cap) {
    int fd = as_connect(ctx);

    if (fd < 0) {
        return -1;
    }
    if (ar_ftp_reply(fd, banner, cap, ctx->timeout_ms) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int ar_ftp_cmd(int fd, const char *cmd, char *out, size_t cap,
                      int timeout_ms) {
    char line[512];

    if (cmd == NULL) {
        return -1;
    }
    (void)snprintf(line, sizeof(line), "%s\r\n", cmd);
    if (as_send_all(fd, line, strlen(line), timeout_ms) != 0) {
        return -1;
    }
    return ar_ftp_reply(fd, out, cap, timeout_ms);
}

static int ar_ftp_login(int fd, const char *user, const char *pass,
                        char *out, size_t cap, int timeout_ms) {
    char cmd[256];
    int code;

    (void)snprintf(cmd, sizeof(cmd), "USER %s", user);
    code = ar_ftp_cmd(fd, cmd, out, cap, timeout_ms);
    if (code == 230) {
        return 230;
    }
    if (code != 331 && code != 332) {
        return code;
    }
    (void)snprintf(cmd, sizeof(cmd), "PASS %s", pass);
    return ar_ftp_cmd(fd, cmd, out, cap, timeout_ms);
}

static const char *ar_brute_words[10] = {
    "admin", "root", "password", "123456", "admin123",
    "root123", "toor", "letmein", "qwerty", "test"
};

static int ar_parse_uint(const char *s) {
    if (s == NULL) {
        return -1;
    }
    return (int)strtol(s, NULL, 10);
}

#endif /* ARSENAL_UTIL_H */
