/*
 * plugins/arsenal_mssql.h - minimal TDS 7.x helpers for the Step 33
 * AlScript arsenal. Raw TCP, fixed buffers, no heap.
 */
#ifndef ARSENAL_MSSQL_H
#define ARSENAL_MSSQL_H

#include "arsenal_util.h"

static void ar_mssql_set16(unsigned char *p, unsigned int v) {
    p[0] = (unsigned char)(v & 255u);
    p[1] = (unsigned char)((v >> 8) & 255u);
}

static void ar_mssql_set32(unsigned char *p, unsigned int v) {
    p[0] = (unsigned char)(v & 255u);
    p[1] = (unsigned char)((v >> 8) & 255u);
    p[2] = (unsigned char)((v >> 16) & 255u);
    p[3] = (unsigned char)((v >> 24) & 255u);
}

static int ar_mssql_read_packet(int fd, unsigned char *out, size_t cap,
                                int timeout_ms, unsigned char *type) {
    unsigned char hdr[8];
    unsigned int len;
    unsigned int body;

    if (out == NULL || cap < 2) {
        return -1;
    }
    if (as_recv_exact(fd, hdr, 8, timeout_ms) != 0) {
        return -1;
    }
    if (type != NULL) {
        *type = hdr[0];
    }
    len = ((unsigned int)hdr[2] << 8) | hdr[3];
    if (len < 8) {
        return -1;
    }
    body = len - 8;
    if (body + 1 > cap) {
        return -1;
    }
    if (body > 0 && as_recv_exact(fd, out, body, timeout_ms) != 0) {
        return -1;
    }
    out[body] = '\0';
    return (int)body;
}

static int ar_mssql_prelogin(AlScriptContext *ctx, char *version,
                             size_t vcap, char *instance, size_t icap) {
    unsigned char pkt[128];
    unsigned char resp[512];
    unsigned int plen = 18;
    unsigned int total = 8 + plen;
    int fd;
    int n;
    unsigned char type = 0;
    int off = 0;

    if (version == NULL || vcap < 2 || instance == NULL || icap < 2) {
        return -1;
    }
    version[0] = '\0';
    instance[0] = '\0';
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x12;
    pkt[1] = 0x01;
    pkt[2] = (unsigned char)(total >> 8);
    pkt[3] = (unsigned char)(total & 255u);
    pkt[4] = 0;
    pkt[5] = 0;
    pkt[6] = 1;
    pkt[7] = 0;
    pkt[8] = 0x00;
    pkt[9] = 0x00;
    pkt[10] = 0x0B;
    pkt[11] = 0x00;
    pkt[12] = 0x06;
    pkt[13] = 0x01;
    pkt[14] = 0x00;
    pkt[15] = 0x11;
    pkt[16] = 0x00;
    pkt[17] = 0x01;
    pkt[18] = 0xFF;
    pkt[19] = 0x0F;
    pkt[20] = 0x00;
    pkt[21] = 0x07;
    pkt[22] = 0xD0;
    pkt[23] = 0x00;
    pkt[24] = 0x00;
    pkt[25] = 0x00;
    fd = as_connect(ctx);
    if (fd < 0) {
        return -1;
    }
    if (as_send_all(fd, pkt, total, ctx->timeout_ms) != 0) {
        close(fd);
        return -1;
    }
    n = ar_mssql_read_packet(fd, resp, sizeof(resp), ctx->timeout_ms, &type);
    close(fd);
    if (n <= 0 || type != 0x04) {
        return -1;
    }
    while (off + 5 <= n && resp[off] != 0xFF) {
        unsigned char opt = resp[off];
        unsigned int o = ((unsigned int)resp[off + 1] << 8) | resp[off + 2];
        unsigned int l = ((unsigned int)resp[off + 3] << 8) | resp[off + 4];
        off += 5;
        if (o + l > (unsigned int)n) {
            continue;
        }
        if (opt == 0x00 && l >= 6) {
            unsigned int major = resp[o];
            unsigned int minor = resp[o + 1];
            unsigned int build = ((unsigned int)resp[o + 2] << 8) | resp[o + 3];
            unsigned int sub = ((unsigned int)resp[o + 4] << 8) | resp[o + 5];
            (void)snprintf(version, vcap, "%u.%u.%u.%u",
                           major, minor, build, sub);
        } else if (opt == 0x02 && l > 0) {
            size_t i;
            for (i = 0; i < l && i + 1 < icap; i++) {
                instance[i] = (char)resp[o + i];
            }
            instance[i] = '\0';
            ar_clean(instance);
        }
    }
    return 0;
}

static int ar_mssql_ucs2(const char *s, unsigned char *out, size_t cap) {
    size_t i;
    size_t n;

    if (s == NULL || out == NULL) {
        return 0;
    }
    n = strlen(s);
    if (n * 2 + 2 > cap) {
        return -1;
    }
    for (i = 0; i < n; i++) {
        out[i * 2] = (unsigned char)s[i];
        out[i * 2 + 1] = 0;
    }
    out[n * 2] = 0;
    out[n * 2 + 1] = 0;
    return (int)(n * 2);
}

#define AR_MSSQL_FIXED 100

static void ar_mssql_field(unsigned char *p, int pair, const char *s,
                           unsigned char *var, size_t *voff) {
    size_t len = strlen(s);
    int base = 42 + pair * 4;

    if (len == 0) {
        ar_mssql_set16(p + base, 0);
        ar_mssql_set16(p + base + 2, 0);
        return;
    }
    ar_mssql_set16(p + base, (unsigned int)*voff);
    ar_mssql_set16(p + base + 2, (unsigned int)len);
    (void)ar_mssql_ucs2(s, var + *voff, 512 - *voff);
    *voff += len * 2;
}

static int ar_mssql_empty_login(AlScriptContext *ctx, char *msg,
                                size_t msgcap) {
    unsigned char login[1024];
    unsigned char pkt[1200];
    unsigned char resp[2048];
    char ip[32];
    size_t voff = AR_MSSQL_FIXED;
    unsigned int total;
    int fd;
    int n;
    unsigned char type = 0;
    int i;

    if (msg == NULL || msgcap < 2) {
        return -1;
    }
    msg[0] = '\0';
    as_ip_text(ctx->target_ip, ip, sizeof(ip));
    memset(login, 0, sizeof(login));
    ar_mssql_field(login, 0, "ALMAP", login, &voff);
    ar_mssql_field(login, 1, "sa", login, &voff);
    ar_mssql_field(login, 2, "", login, &voff);
    ar_mssql_field(login, 3, "ALmap", login, &voff);
    ar_mssql_field(login, 4, ip, login, &voff);
    ar_mssql_field(login, 5, "", login, &voff);
    ar_mssql_field(login, 6, "ALmap", login, &voff);
    ar_mssql_field(login, 7, "", login, &voff);
    ar_mssql_field(login, 8, "", login, &voff);
    /* ClientID, SSPI, attach DB, change password, SSPI long. */
    memset(login + 78, 0, 6);
    ar_mssql_set16(login + 84, 0);
    ar_mssql_set16(login + 86, 0);
    ar_mssql_set16(login + 88, 0);
    ar_mssql_set16(login + 90, 0);
    ar_mssql_set16(login + 92, 0);
    ar_mssql_set16(login + 94, 0);
    ar_mssql_set32(login + 96, 0);
    ar_mssql_set32(login + 4, 0x74000004u);
    ar_mssql_set32(login + 8, 4096);
    login[24] = 0xE0;
    login[25] = 0x00;
    login[26] = 0x00;
    login[27] = 0x00;
    login[28] = 0x03;
    login[29] = 0x00;
    login[30] = 0x00;
    login[31] = 0x00;
    total = (unsigned int)voff;
    ar_mssql_set32(login, total);
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x10;
    pkt[1] = 0x01;
    total += 8;
    pkt[2] = (unsigned char)(total >> 8);
    pkt[3] = (unsigned char)(total & 255u);
    pkt[4] = 0;
    pkt[5] = 0;
    pkt[6] = 1;
    pkt[7] = 0;
    memcpy(pkt + 8, login, voff);
    fd = as_connect(ctx);
    if (fd < 0) {
        return -1;
    }
    if (as_send_all(fd, pkt, total, ctx->timeout_ms) != 0) {
        close(fd);
        return -1;
    }
    n = ar_mssql_read_packet(fd, resp, sizeof(resp), ctx->timeout_ms, &type);
    close(fd);
    if (n <= 0) {
        return -1;
    }
    if (type == 0x04) {
        (void)snprintf(msg, msgcap, "login accepted");
        return 0;
    }
    for (i = 0; i + 9 < n; i++) {
        if (resp[i] == 0xAA) {
            unsigned int mlen = ((unsigned int)resp[i + 7] << 8) | resp[i + 8];
            size_t k;
            if (i + 9 + mlen > (unsigned int)n) {
                mlen = (unsigned int)(n - i - 9);
            }
            for (k = 0; k < mlen && k / 2 + 1 < msgcap; k += 2) {
                msg[k / 2] = (char)resp[i + 9 + k];
            }
            msg[mlen / 2] = '\0';
            ar_clean(msg);
            return 1;
        }
    }
    (void)snprintf(msg, msgcap, "login failed (TDS type 0x%02x)", type);
    return 1;
}

#endif /* ARSENAL_MSSQL_H */
