/*
 * plugins/arsenal_mysql.h - minimal MySQL protocol helpers for the
 * Step 33 AlScript arsenal. Raw TCP, fixed buffers, no heap.
 */
#ifndef ARSENAL_MYSQL_H
#define ARSENAL_MYSQL_H

#include "arsenal_util.h"

static int ar_mysql_read_packet(int fd, unsigned char *out, size_t cap,
                                int timeout_ms, unsigned char *seq) {
    unsigned char hdr[4];
    unsigned int len;

    if (out == NULL || cap < 2) {
        return -1;
    }
    if (as_recv_exact(fd, hdr, 4, timeout_ms) != 0) {
        return -1;
    }
    len = (unsigned int)hdr[0] | ((unsigned int)hdr[1] << 8) |
          ((unsigned int)hdr[2] << 16);
    if (seq != NULL) {
        *seq = hdr[3];
    }
    if (len + 1 > cap) {
        return -1;
    }
    if (len > 0 && as_recv_exact(fd, out, len, timeout_ms) != 0) {
        return -1;
    }
    out[len] = '\0';
    return (int)len;
}

static int ar_mysql_send_packet(int fd, const unsigned char *payload,
                                size_t len, unsigned char seq,
                                int timeout_ms) {
    unsigned char hdr[4];

    if (payload == NULL || len > 0xFFFFFF) {
        return -1;
    }
    hdr[0] = (unsigned char)(len & 255u);
    hdr[1] = (unsigned char)((len >> 8) & 255u);
    hdr[2] = (unsigned char)((len >> 16) & 255u);
    hdr[3] = seq;
    if (as_send_all(fd, hdr, 4, timeout_ms) != 0) {
        return -1;
    }
    return as_send_all(fd, payload, len, timeout_ms);
}

static int ar_mysql_open(AlScriptContext *ctx, char *version, size_t vcap,
                         unsigned char *salt, size_t saltcap) {
    unsigned char pkt[2048];
    int fd;
    int n;
    size_t off;
    size_t i;

    (void)saltcap;
    if (version == NULL || vcap < 2 || salt == NULL) {
        return -1;
    }
    version[0] = '\0';
    salt[0] = '\0';
    fd = as_connect(ctx);
    if (fd < 0) {
        return -1;
    }
    n = ar_mysql_read_packet(fd, pkt, sizeof(pkt), ctx->timeout_ms, NULL);
    if (n < 2 || pkt[0] != 10) {
        close(fd);
        return -1;
    }
    off = 1;
    for (i = 0; off + i < (size_t)n && pkt[off + i] != 0 && i + 1 < vcap; i++) {
        version[i] = (char)pkt[off + i];
    }
    version[i] = '\0';
    ar_clean(version);
    off += i + 1;
    off += 4; /* connection id */
    if (off + 8 <= (size_t)n) {
        memcpy(salt, pkt + off, 8);
        salt[8] = '\0';
    }
    return fd;
}

static int ar_mysql_login(int fd, const char *user, const char *pass,
                          int empty, int timeout_ms, char *msg,
                          size_t msgcap) {
    unsigned char pkt[512];
    unsigned char resp[2048];
    size_t o = 0;
    size_t ulen;
    size_t plen;
    unsigned int caps = 0x000AA201u;
    int n;

    if (user == NULL || msg == NULL || msgcap < 2) {
        return -1;
    }
    msg[0] = '\0';
    ulen = strlen(user);
    plen = (empty || pass == NULL) ? 0 : strlen(pass);
    if (ulen > 200) {
        return -1;
    }
    if (!empty && plen > 20) {
        plen = 20;
    }
    pkt[o++] = (unsigned char)(caps & 255u);
    pkt[o++] = (unsigned char)((caps >> 8) & 255u);
    pkt[o++] = (unsigned char)((caps >> 16) & 255u);
    pkt[o++] = (unsigned char)((caps >> 24) & 255u);
    pkt[o++] = 0;
    pkt[o++] = 0;
    pkt[o++] = 0;
    pkt[o++] = 1;
    pkt[o++] = 33;
    memset(pkt + o, 0, 23);
    o += 23;
    memcpy(pkt + o, user, ulen);
    o += ulen;
    pkt[o++] = 0;
    pkt[o++] = (unsigned char)(empty ? 0 : 20);
    if (!empty) {
        /* A deterministic non-matching scramble. This is a probe, not a
         * credential; CVE-2012-2122 detection relies on the server's
         * faulty memcmp, not on knowing the password. */
        memset(pkt + o, 0x41, 20);
        o += 20;
    }
    memcpy(pkt + o, "mysql_native_password", 22);
    o += 22;
    pkt[o++] = 0;
    if (ar_mysql_send_packet(fd, pkt, o, 1, timeout_ms) != 0) {
        return -1;
    }
    n = ar_mysql_read_packet(fd, resp, sizeof(resp), timeout_ms, NULL);
    if (n <= 0) {
        return -1;
    }
    if (resp[0] == 0x00) {
        (void)snprintf(msg, msgcap, "OK");
        return 0;
    }
    if (resp[0] == 0xFF) {
        int code = 0;
        size_t i;
        if (n >= 3) {
            code = (int)resp[1] | ((int)resp[2] << 8);
        }
        for (i = 3; i < (size_t)n && i + 1 < msgcap; i++) {
            msg[i - 3] = (char)resp[i];
        }
        msg[(n > 3) ? (size_t)(n - 3) : 0] = '\0';
        ar_clean(msg);
        return code;
    }
    (void)snprintf(msg, msgcap, "unexpected response 0x%02x", resp[0]);
    return -1;
}

#endif /* ARSENAL_MYSQL_H */
