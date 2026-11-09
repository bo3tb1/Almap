/*
 * plugins/arsenal_tls.h - minimal TLS record/handshake helpers for the
 * Step 33 AlScript arsenal. Raw TCP, fixed buffers, no OpenSSL.
 *
 * The helpers send a ClientHello and parse ServerHello/ServerKeyExchange
 * records. They are deliberately read-only probes; no application data
 * is decrypted and no private key material is used.
 */
#ifndef ARSENAL_TLS_H
#define ARSENAL_TLS_H

#include "arsenal_util.h"

#define AR_TLS_CCS 20
#define AR_TLS_ALERT 21
#define AR_TLS_HANDSHAKE 22
#define AR_TLS_HEARTBEAT 24

static const unsigned short ar_tls_ciphers[] = {
    0xC02F, 0xC030, 0xC02B, 0xC02C, 0xCCA8, 0xCCA9,
    0x009E, 0x009F, 0x002F, 0x0035, 0x003C, 0x003D,
    0x000A, 0x0005, 0x0004, 0x0067, 0x006B, 0x0033,
    0x0039, 0x0016, 0x0023, 0x0009, 0x0006, 0x0003
};

static const unsigned short ar_tls_cbc_ciphers[] = {
    0x002F, 0x0035, 0x003C, 0x003D, 0x000A, 0x0005,
    0x0004, 0x0067, 0x006B, 0x0033, 0x0039, 0x0016,
    0x0023, 0x0009, 0x0006, 0x0003
};

static int ar_tls_is_cbc(unsigned int cipher) {
    size_t i;

    for (i = 0; i < sizeof(ar_tls_cbc_ciphers) / sizeof(ar_tls_cbc_ciphers[0]);
         i++) {
        if (ar_tls_cbc_ciphers[i] == cipher) {
            return 1;
        }
    }
    return 0;
}

static const char *ar_tls_cipher_name(unsigned int c) {
    switch (c) {
        case 0xC02F: return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        case 0xC030: return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
        case 0xC02B: return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
        case 0xC02C: return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
        case 0xCCA8: return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305";
        case 0xCCA9: return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305";
        case 0x009E: return "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256";
        case 0x009F: return "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384";
        case 0x002F: return "TLS_RSA_WITH_AES_128_CBC_SHA";
        case 0x0035: return "TLS_RSA_WITH_AES_256_CBC_SHA";
        case 0x003C: return "TLS_RSA_WITH_AES_128_CBC_SHA256";
        case 0x003D: return "TLS_RSA_WITH_AES_256_CBC_SHA256";
        case 0x000A: return "TLS_RSA_WITH_3DES_EDE_CBC_SHA";
        case 0x0005: return "TLS_RSA_WITH_RC4_128_SHA";
        case 0x0004: return "TLS_RSA_WITH_RC4_128_MD5";
        case 0x0067: return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256";
        case 0x006B: return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256";
        case 0x0033: return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA";
        case 0x0039: return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA";
        case 0x0016: return "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA";
        case 0x0023: return "TLS_DHE_DSS_WITH_AES_128_CBC_SHA";
        case 0x0009: return "TLS_RSA_WITH_DES_CBC_SHA";
        case 0x0006: return "TLS_RSA_EXPORT_WITH_RC4_40_MD5";
        case 0x0003: return "TLS_RSA_EXPORT_WITH_RC4_40_MD5";
        default: return "unknown";
    }
}

static const char *ar_tls_version_name(unsigned int v) {
    switch (v) {
        case 0x0300: return "SSLv3";
        case 0x0301: return "TLSv1.0";
        case 0x0302: return "TLSv1.1";
        case 0x0303: return "TLSv1.2";
        case 0x0304: return "TLSv1.3";
        default: return "unknown";
    }
}

static int ar_tls_client_hello(unsigned char *out, size_t cap,
                               unsigned int version,
                               const unsigned short *ciphers, int nc,
                               int heartbeat) {
    unsigned char body[1024];
    size_t b = 0;
    size_t ext_len_pos;
    size_t ext_start;
    int i;

    if (out == NULL || cap < 128 || ciphers == NULL || nc < 1) {
        return -1;
    }
    memset(body, 0, sizeof(body));
    body[b++] = (unsigned char)(version >> 8);
    body[b++] = (unsigned char)(version & 255u);
    for (i = 0; i < 32; i++) {
        body[b++] = (unsigned char)(0x30 + i);
    }
    body[b++] = 0; /* session id length */
    body[b++] = (unsigned char)((nc * 2) >> 8);
    body[b++] = (unsigned char)((nc * 2) & 255u);
    for (i = 0; i < nc; i++) {
        body[b++] = (unsigned char)(ciphers[i] >> 8);
        body[b++] = (unsigned char)(ciphers[i] & 255u);
    }
    body[b++] = 1;
    body[b++] = 0;
    ext_len_pos = b;
    b += 2;
    ext_start = b;
    if (version >= 0x0301) {
        /* supported_groups: x25519, secp256r1, secp384r1 */
        body[b++] = 0x00; body[b++] = 0x0A;
        body[b++] = 0x00; body[b++] = 0x08;
        body[b++] = 0x00; body[b++] = 0x06;
        body[b++] = 0x00; body[b++] = 0x1D;
        body[b++] = 0x00; body[b++] = 0x17;
        body[b++] = 0x00; body[b++] = 0x18;
        /* ec_point_formats: uncompressed */
        body[b++] = 0x00; body[b++] = 0x0B;
        body[b++] = 0x00; body[b++] = 0x02;
        body[b++] = 0x01; body[b++] = 0x00;
        /* signature_algorithms */
        body[b++] = 0x00; body[b++] = 0x0D;
        body[b++] = 0x00; body[b++] = 0x0A;
        body[b++] = 0x00; body[b++] = 0x08;
        body[b++] = 0x04; body[b++] = 0x03;
        body[b++] = 0x08; body[b++] = 0x04;
        body[b++] = 0x04; body[b++] = 0x01;
        body[b++] = 0x05; body[b++] = 0x01;
        /* renegotiation_info */
        body[b++] = 0xFF; body[b++] = 0x01;
        body[b++] = 0x00; body[b++] = 0x01;
        body[b++] = 0x00;
        if (heartbeat) {
            body[b++] = 0x00; body[b++] = 0x0F;
            body[b++] = 0x00; body[b++] = 0x01;
            body[b++] = 0x01;
        }
    }
    if (b + 64 > sizeof(body)) {
        return -1;
    }
    body[ext_len_pos] = (unsigned char)((b - ext_start) >> 8);
    body[ext_len_pos + 1] = (unsigned char)((b - ext_start) & 255u);
    if (9 + b > cap) {
        return -1;
    }
    out[0] = AR_TLS_HANDSHAKE;
    out[1] = (unsigned char)(version >> 8);
    out[2] = (unsigned char)(version & 255u);
    out[3] = (unsigned char)((b + 4) >> 8);
    out[4] = (unsigned char)((b + 4) & 255u);
    out[5] = 1;
    out[6] = (unsigned char)(b >> 16);
    out[7] = (unsigned char)(b >> 8);
    out[8] = (unsigned char)(b & 255u);
    memcpy(out + 9, body, b);
    return (int)(9 + b);
}

static int ar_tls_read_record(int fd, unsigned char *out, size_t cap,
                              int timeout_ms) {
    unsigned char hdr[5];
    unsigned int len;

    if (out == NULL || cap < 2) {
        return -1;
    }
    if (as_recv_exact(fd, hdr, 5, timeout_ms) != 0) {
        return -1;
    }
    len = ((unsigned int)hdr[3] << 8) | hdr[4];
    if (len + 1 > cap) {
        return -1;
    }
    if (len > 0 && as_recv_exact(fd, out, len, timeout_ms) != 0) {
        return -1;
    }
    out[len] = '\0';
    return (int)len;
}

static int ar_tls_exchange(AlScriptContext *ctx, const unsigned char *hello,
                           int hlen, unsigned char *resp, size_t cap) {
    int fd;
    int n;

    fd = as_connect(ctx);
    if (fd < 0) {
        return -1;
    }
    if (as_send_all(fd, hello, (size_t)hlen, ctx->timeout_ms) != 0) {
        close(fd);
        return -1;
    }
    n = ar_tls_read_record(fd, resp, cap, ctx->timeout_ms);
    close(fd);
    return n;
}

static int ar_tls_parse_server_hello(const unsigned char *p, int len,
                                     unsigned int *version,
                                     unsigned int *cipher,
                                     int *sid_len) {
    int off;

    if (p == NULL || len < 40 || p[0] != 2) {
        return -1;
    }
    *version = ((unsigned int)p[4] << 8) | p[5];
    off = 6 + 32;
    if (off >= len) {
        return -1;
    }
    *sid_len = p[off];
    off += 1 + *sid_len;
    if (off + 2 > len) {
        return -1;
    }
    *cipher = ((unsigned int)p[off] << 8) | p[off + 1];
    return 0;
}

static int ar_tls_probe(AlScriptContext *ctx, unsigned int version,
                        const unsigned short *ciphers, int nc,
                        unsigned int *selver, unsigned int *selcipher,
                        int heartbeat, unsigned char *resp, size_t cap) {
    unsigned char hello[1200];
    int hlen;
    int n;
    int sid = 0;

    hlen = ar_tls_client_hello(hello, sizeof(hello), version, ciphers, nc,
                               heartbeat);
    if (hlen < 0) {
        return -1;
    }
    n = ar_tls_exchange(ctx, hello, hlen, resp, cap);
    if (n < 0) {
        return -1;
    }
    if (resp[0] == AR_TLS_ALERT) {
        return 0;
    }
    if (ar_tls_parse_server_hello(resp, n, selver, selcipher, &sid) != 0) {
        return -1;
    }
    return 1;
}

static int ar_tls_heartbleed(AlScriptContext *ctx, unsigned char *resp,
                             size_t cap) {
    unsigned char hello[1200];
    unsigned char hb[16];
    unsigned int ver = 0;
    unsigned int cipher = 0;
    int sid = 0;
    int hlen;
    int fd;
    int n;

    hlen = ar_tls_client_hello(hello, sizeof(hello), 0x0301,
                               ar_tls_ciphers,
                               (int)(sizeof(ar_tls_ciphers) /
                                     sizeof(ar_tls_ciphers[0])), 1);
    if (hlen < 0) {
        return -1;
    }
    fd = as_connect(ctx);
    if (fd < 0) {
        return -1;
    }
    if (as_send_all(fd, hello, (size_t)hlen, ctx->timeout_ms) != 0) {
        close(fd);
        return -1;
    }
    n = ar_tls_read_record(fd, resp, cap, ctx->timeout_ms);
    if (n <= 0 || resp[0] == AR_TLS_ALERT ||
        ar_tls_parse_server_hello(resp, n, &ver, &cipher, &sid) != 0) {
        close(fd);
        return 0;
    }
    /* Malformed heartbeat: claims a 16 KiB payload but sends none. */
    hb[0] = AR_TLS_HEARTBEAT;
    hb[1] = (unsigned char)(ver >> 8);
    hb[2] = (unsigned char)(ver & 255u);
    hb[3] = 0;
    hb[4] = 3;
    hb[5] = 1;
    hb[6] = 0x40;
    hb[7] = 0x00;
    if (as_send_all(fd, hb, 8, ctx->timeout_ms) != 0) {
        close(fd);
        return 0;
    }
    n = ar_tls_read_record(fd, resp, cap, 500);
    close(fd);
    if (n > 3 && resp[0] == AR_TLS_HEARTBEAT) {
        return 1;
    }
    return 0;
}

static int ar_tls_ccs_test(AlScriptContext *ctx, unsigned char *resp,
                           size_t cap, unsigned int *selver,
                           unsigned int *selcipher) {
    unsigned char hello[1200];
    unsigned char ccs[6] = { AR_TLS_CCS, 0x03, 0x01, 0x00, 0x01, 0x01 };
    unsigned int ver = 0;
    unsigned int cipher = 0;
    int sid = 0;
    int hlen;
    int fd;
    int n;

    hlen = ar_tls_client_hello(hello, sizeof(hello), 0x0303,
                               ar_tls_ciphers,
                               (int)(sizeof(ar_tls_ciphers) /
                                     sizeof(ar_tls_ciphers[0])), 0);
    if (hlen < 0) {
        return -1;
    }
    fd = as_connect(ctx);
    if (fd < 0) {
        return -1;
    }
    if (as_send_all(fd, hello, (size_t)hlen, ctx->timeout_ms) != 0) {
        close(fd);
        return -1;
    }
    n = ar_tls_read_record(fd, resp, cap, ctx->timeout_ms);
    if (n <= 0 || ar_tls_parse_server_hello(resp, n, &ver, &cipher, &sid) != 0) {
        close(fd);
        return -1;
    }
    *selver = ver;
    *selcipher = cipher;
    /* Drain the server flight through ServerHelloDone before injecting
     * the early CCS, so a queued Certificate/ServerKeyExchange record is
     * not mistaken for acceptance. */
    {
        int i;
        for (i = 0; i < 6; i++) {
            if (resp[0] == AR_TLS_ALERT) {
                close(fd);
                return 0;
            }
            if (n >= 4 && resp[0] == 14) {
                break;
            }
            n = ar_tls_read_record(fd, resp, cap, ctx->timeout_ms);
            if (n <= 0) {
                break;
            }
        }
    }
    if (as_send_all(fd, ccs, sizeof(ccs), ctx->timeout_ms) != 0) {
        close(fd);
        return -1;
    }
    n = ar_tls_read_record(fd, resp, cap, 500);
    close(fd);
    if (n <= 0) {
        return 0;
    }
    if (resp[0] == AR_TLS_ALERT) {
        return 0;
    }
    return 1;
}

static int ar_tls_dh_bits(AlScriptContext *ctx, int *bits,
                          unsigned int *group_len) {
    static const unsigned short dhe_ciphers[] = {
        0x009E, 0x009F, 0x0067, 0x006B, 0x0033, 0x0039, 0x0016
    };
    unsigned char hello[1200];
    unsigned char rec[4096];
    unsigned int ver = 0;
    unsigned int cipher = 0;
    int sid = 0;
    int hlen;
    int fd;
    int n;
    int i;

    *bits = 0;
    *group_len = 0;
    hlen = ar_tls_client_hello(hello, sizeof(hello), 0x0303,
                               dhe_ciphers,
                               (int)(sizeof(dhe_ciphers) /
                                     sizeof(dhe_ciphers[0])), 0);
    if (hlen < 0) {
        return -1;
    }
    fd = as_connect(ctx);
    if (fd < 0) {
        return -1;
    }
    if (as_send_all(fd, hello, (size_t)hlen, ctx->timeout_ms) != 0) {
        close(fd);
        return -1;
    }
    n = ar_tls_read_record(fd, rec, sizeof(rec), ctx->timeout_ms);
    if (n <= 0 || ar_tls_parse_server_hello(rec, n, &ver, &cipher, &sid) != 0) {
        close(fd);
        return -1;
    }
    for (i = 0; i < 4; i++) {
        int off;
        n = ar_tls_read_record(fd, rec, sizeof(rec), ctx->timeout_ms);
        if (n <= 0) {
            break;
        }
        if (rec[0] != 12) {
            continue;
        }
        off = 4;
        if (off + 2 > n) {
            break;
        }
        if (off < n && rec[off] == 3) {
            /* ECDHE ServerKeyExchange: named curve + point. */
            *bits = 0;
            *group_len = 0;
            break;
        }
        {
            unsigned int plen = ((unsigned int)rec[off] << 8) | rec[off + 1];
            off += 2;
            if (plen > 1024 || plen > (unsigned int)(n - off) || plen < 64) {
                *bits = 0;
                *group_len = 0;
                break;
            }
            if (plen >= 2) {
                unsigned int pbits = ((unsigned int)rec[off] << 8) |
                                     rec[off + 1];
                if (pbits >= 512 && pbits <= 8192) {
                    *bits = (int)pbits;
                    *group_len = pbits / 8;
                }
            }
        }
        break;
    }
    close(fd);
    return 0;
}

#endif /* ARSENAL_TLS_H */
