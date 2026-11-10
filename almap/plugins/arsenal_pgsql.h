/*
 * plugins/arsenal_pgsql.h - minimal PostgreSQL v3 startup/auth helpers
 * for the Step 33 AlScript arsenal. Raw TCP, fixed buffers, no heap.
 */
#ifndef ARSENAL_PGSQL_H
#define ARSENAL_PGSQL_H

#include "arsenal_util.h"

static void ar_pg_put32(unsigned char *p, unsigned int v) {
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)(v & 255u);
}

static int ar_pg_start(AlScriptContext *ctx, const char *user,
                       const char *db, int *ssl_out) {
    static const unsigned char sslreq[8] = {
        0, 0, 0, 8, 0x04, 0xD2, 0x16, 0x2F
    };
    char b;
    int fd;

    if (ssl_out != NULL) {
        *ssl_out = 0;
    }
    fd = as_connect(ctx);
    if (fd < 0) {
        return -1;
    }
    if (as_send_all(fd, sslreq, sizeof(sslreq), ctx->timeout_ms) != 0) {
        close(fd);
        return -1;
    }
    if (as_recv_exact(fd, &b, 1, ctx->timeout_ms) != 0) {
        close(fd);
        return -1;
    }
    if (b == 'S') {
        if (ssl_out != NULL) {
            *ssl_out = 1;
        }
        close(fd);
        return -2;
    }
    if (b != 'N') {
        close(fd);
        return -1;
    }
    {
        unsigned char pkt[512];
        size_t o = 8;
        const char *u = (user != NULL) ? user : "postgres";
        const char *d = (db != NULL) ? db : "postgres";

        memset(pkt, 0, sizeof(pkt));
        memcpy(pkt + o, "user", 5);
        o += 5;
        memcpy(pkt + o, u, strlen(u) + 1);
        o += strlen(u) + 1;
        memcpy(pkt + o, "database", 9);
        o += 9;
        memcpy(pkt + o, d, strlen(d) + 1);
        o += strlen(d) + 1;
        pkt[o++] = 0;
        ar_pg_put32(pkt, (unsigned int)o);
        ar_pg_put32(pkt + 4, 196608u);
        if (as_send_all(fd, pkt, o, ctx->timeout_ms) != 0) {
            close(fd);
            return -1;
        }
    }
    return fd;
}

static int ar_pg_login(AlScriptContext *ctx, const char *user,
                       const char *pass, char *msg, size_t cap) {
    unsigned char hdr[5];
    unsigned char buf[512];
    unsigned int len;
    unsigned int code;
    int ssl = 0;
    int fd;
    int n;

    if (msg == NULL || cap < 2) {
        return -1;
    }
    msg[0] = '\0';
    fd = ar_pg_start(ctx, user, "postgres", &ssl);
    if (fd == -2) {
        (void)snprintf(msg, cap, "SSL required");
        return 0;
    }
    if (fd < 0) {
        return -1;
    }
    if (as_recv_exact(fd, hdr, 5, ctx->timeout_ms) != 0) {
        close(fd);
        return -1;
    }
    len = ((unsigned int)hdr[1] << 24) | ((unsigned int)hdr[2] << 16) |
          ((unsigned int)hdr[3] << 8) | hdr[4];
    if (len < 4 || len - 4 > sizeof(buf)) {
        close(fd);
        return -1;
    }
    if (as_recv_exact(fd, buf, len - 4, ctx->timeout_ms) != 0) {
        close(fd);
        return -1;
    }
    if (hdr[0] != 'R') {
        (void)snprintf(msg, cap, "auth type %c", hdr[0]);
        close(fd);
        return 0;
    }
    code = ((unsigned int)buf[0] << 24) | ((unsigned int)buf[1] << 16) |
           ((unsigned int)buf[2] << 8) | buf[3];
    if (code == 0) {
        (void)snprintf(msg, cap, "OK");
        close(fd);
        return 1;
    }
    if (code != 3) {
        (void)snprintf(msg, cap, "auth code %u", code);
        close(fd);
        return 0;
    }
    {
        unsigned char pkt[512];
        size_t o = 5;
        size_t plen = (pass != NULL) ? strlen(pass) : 0;

        memset(pkt, 0, sizeof(pkt));
        pkt[0] = 'p';
        memcpy(pkt + o, pass != NULL ? pass : "", plen);
        o += plen;
        pkt[o++] = 0;
        ar_pg_put32(pkt + 1, (unsigned int)o);
        if (as_send_all(fd, pkt, o, ctx->timeout_ms) != 0) {
            close(fd);
            return -1;
        }
    }
    if (as_recv_exact(fd, hdr, 5, ctx->timeout_ms) != 0) {
        close(fd);
        return -1;
    }
    len = ((unsigned int)hdr[1] << 24) | ((unsigned int)hdr[2] << 16) |
          ((unsigned int)hdr[3] << 8) | hdr[4];
    if (len < 4 || len - 4 > sizeof(buf)) {
        close(fd);
        return -1;
    }
    if (as_recv_exact(fd, buf, len - 4, ctx->timeout_ms) != 0) {
        close(fd);
        return -1;
    }
    n = (hdr[0] == 'R' && len >= 8 && buf[0] == 0 && buf[1] == 0 &&
         buf[2] == 0 && buf[3] == 0);
    (void)snprintf(msg, cap, "%s", n ? "OK" : "denied");
    close(fd);
    return n ? 1 : 0;
}

#endif /* ARSENAL_PGSQL_H */
