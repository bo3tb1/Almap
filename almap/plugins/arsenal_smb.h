/*
 * plugins/arsenal_smb.h - minimal SMB1/SMB2 negotiation helpers for
 * the Step 33 AlScript arsenal. Raw TCP, fixed buffers, no heap.
 */
#ifndef ARSENAL_SMB_H
#define ARSENAL_SMB_H

#include "arsenal_util.h"

static int ar_smb_recv_nb(int fd, unsigned char *out, size_t cap,
                          int timeout_ms) {
    unsigned char hdr[4];
    unsigned int len;

    if (out == NULL || cap < 5) {
        return -1;
    }
    if (as_recv_exact(fd, hdr, 4, timeout_ms) != 0) {
        return -1;
    }
    if (hdr[0] != 0) {
        return -1;
    }
    len = ((unsigned int)hdr[1] << 16) | ((unsigned int)hdr[2] << 8) | hdr[3];
    if (len + 1 > cap) {
        return -1;
    }
    if (as_recv_exact(fd, out, len, timeout_ms) != 0) {
        return -1;
    }
    out[len] = '\0';
    return (int)len;
}

static int ar_smb1_negotiate(AlScriptContext *ctx, unsigned char *resp,
                             size_t cap) {
    static const char dialects[] =
        "\x02PC NETWORK PROGRAM 1.0\x00"
        "\x02LANMAN1.0\x00"
        "\x02Windows for Workgroups 3.1a\x00"
        "\x02LM1.2X002\x00"
        "\x02LANMAN2.1\x00"
        "\x02NT LM 0.12\x00"
        "\x02SMB 2.002\x00"
        "\x02SMB 2.???\x00";
    unsigned char req[512];
    unsigned char body[256];
    unsigned char *smb = body;
    size_t dlen = sizeof(dialects) - 1;
    size_t msglen;
    int fd;
    int n;

    if (resp == NULL || cap < 64 || dlen + 35 > sizeof(body)) {
        return -1;
    }
    memset(body, 0, sizeof(body));
    msglen = 35 + dlen;
    smb[0] = 0xFF;
    smb[1] = 'S';
    smb[2] = 'M';
    smb[3] = 'B';
    smb[4] = 0x72;
    smb[9] = 0x18;
    smb[10] = 0x53;
    smb[11] = 0xC8;
    smb[26] = 0xFE;
    smb[27] = 0xFF;
    smb[32] = 0;
    smb[33] = (unsigned char)(dlen & 255u);
    smb[34] = (unsigned char)((dlen >> 8) & 255u);
    memcpy(body + 39, dialects, dlen);
    req[0] = 0;
    req[1] = (unsigned char)((msglen >> 16) & 255u);
    req[2] = (unsigned char)((msglen >> 8) & 255u);
    req[3] = (unsigned char)(msglen & 255u);
    memcpy(req + 4, body, msglen);
    fd = as_connect(ctx);
    if (fd < 0) {
        return -1;
    }
    if (as_send_all(fd, req, msglen + 4, ctx->timeout_ms) != 0) {
        close(fd);
        return -1;
    }
    n = ar_smb_recv_nb(fd, resp + 4, cap - 4, ctx->timeout_ms);
    close(fd);
    if (n < 0) {
        return -1;
    }
    resp[0] = 0;
    resp[1] = (unsigned char)((n >> 16) & 255u);
    resp[2] = (unsigned char)((n >> 8) & 255u);
    resp[3] = (unsigned char)(n & 255u);
    return n + 4;
}

static int ar_smb2_negotiate(AlScriptContext *ctx, unsigned char *resp,
                             size_t cap) {
    unsigned char req[160];
    static const unsigned short dialects[] = {
        0x0202, 0x0210, 0x0300, 0x0302, 0x0311
    };
    size_t len;
    int fd;
    int n;
    int i;

    if (resp == NULL || cap < 80) {
        return -1;
    }
    memset(req, 0, sizeof(req));
    req[0] = 0;
    len = 4 + 64 + 36 + sizeof(dialects);
    req[1] = (unsigned char)((len >> 16) & 255u);
    req[2] = (unsigned char)((len >> 8) & 255u);
    req[3] = (unsigned char)(len & 255u);
    req[4] = 0xFE;
    req[5] = 'S';
    req[6] = 'M';
    req[7] = 'B';
    req[8] = 64;
    req[10] = 0;
    req[68] = 36;
    req[70] = (unsigned char)(sizeof(dialects) / sizeof(dialects[0]));
    req[72] = 1;
    for (i = 0; i < (int)(sizeof(dialects) / sizeof(dialects[0])); i++) {
        req[104 + i * 2] = (unsigned char)(dialects[i] & 255u);
        req[105 + i * 2] = (unsigned char)(dialects[i] >> 8);
    }
    fd = as_connect(ctx);
    if (fd < 0) {
        return -1;
    }
    if (as_send_all(fd, req, len, ctx->timeout_ms) != 0) {
        close(fd);
        return -1;
    }
    n = ar_smb_recv_nb(fd, resp + 4, cap - 4, ctx->timeout_ms);
    close(fd);
    if (n < 0) {
        return -1;
    }
    resp[0] = 0;
    resp[1] = (unsigned char)((n >> 16) & 255u);
    resp[2] = (unsigned char)((n >> 8) & 255u);
    resp[3] = (unsigned char)(n & 255u);
    return n + 4;
}

static unsigned int ar_smb1_dialect(const unsigned char *resp, int len) {
    if (resp == NULL || len < 4 + 35) {
        return 0xFFFF;
    }
    return (unsigned int)resp[4 + 33] | ((unsigned int)resp[4 + 34] << 8);
}

static unsigned int ar_smb2_dialect(const unsigned char *resp, int len) {
    if (resp == NULL || len < 4 + 74) {
        return 0xFFFF;
    }
    if (resp[4] != 0xFE || resp[5] != 'S' || resp[6] != 'M' ||
        resp[7] != 'B') {
        return 0xFFFF;
    }
    return (unsigned int)resp[72] | ((unsigned int)resp[73] << 8);
}

static const char *ar_smb1_dialect_name(unsigned int d) {
    switch (d) {
        case 0: return "PC NETWORK PROGRAM 1.0";
        case 1: return "LANMAN1.0";
        case 2: return "Windows for Workgroups 3.1a";
        case 3: return "LM1.2X002";
        case 4: return "LANMAN2.1";
        case 5: return "NT LM 0.12";
        case 6: return "SMB 2.002";
        case 7: return "SMB 2.???";
        default: return "unknown";
    }
}

static const char *ar_smb2_dialect_name(unsigned int d) {
    switch (d) {
        case 0x0202: return "SMB 2.0.2";
        case 0x0210: return "SMB 2.1";
        case 0x0300: return "SMB 3.0";
        case 0x0302: return "SMB 3.0.2";
        case 0x0311: return "SMB 3.1.1";
        default: return "SMB 2/3";
    }
}

static int ar_smb1_security_mode(const unsigned char *resp, int len) {
    if (resp == NULL || len < 4 + 36) {
        return -1;
    }
    return (int)resp[4 + 35];
}

static int ar_smb2_security_mode(const unsigned char *resp, int len) {
    if (resp == NULL || len < 4 + 72) {
        return -1;
    }
    return ((int)resp[70] << 8) | resp[71];
}

static int ar_smb1_session_setup(int fd, unsigned int *uid,
                                 char *os, size_t os_cap,
                                 char *lan, size_t lan_cap,
                                 int timeout_ms) {
    unsigned char req[256];
    unsigned char resp[2048];
    unsigned char *smb = req + 4;
    size_t bodylen = 32 + 1 + 24 + 2;
    int n;
    unsigned int status;

    if (uid == NULL || os == NULL || lan == NULL) {
        return -1;
    }
    *uid = 0;
    os[0] = '\0';
    lan[0] = '\0';
    memset(req, 0, sizeof(req));
    req[0] = 0;
    req[1] = 0;
    req[2] = 0;
    req[3] = (unsigned char)bodylen;
    smb[0] = 0xFF;
    smb[1] = 'S';
    smb[2] = 'M';
    smb[3] = 'B';
    smb[4] = 0x73;
    smb[9] = 0x18;
    smb[10] = 0x53;
    smb[11] = 0xC8;
    smb[26] = 0xFE;
    smb[27] = 0xFF;
    smb[32] = 12;
    smb[33] = 0xFF;
    smb[34] = 0;
    smb[35] = 0;
    smb[36] = 0;
    smb[37] = 0xFF;
    smb[38] = 0xFF;
    smb[39] = 2;
    smb[40] = 0;
    smb[41] = 0;
    smb[42] = 0;
    smb[43] = 0;
    smb[44] = 0;
    smb[45] = 0;
    smb[46] = 0;
    smb[47] = 0;
    smb[48] = 0;
    smb[49] = 0;
    smb[50] = 0;
    smb[51] = 0;
    smb[52] = 0;
    smb[53] = 0;
    smb[54] = 0;
    smb[55] = 0;
    smb[56] = 0;
    smb[57] = 0;
    if (as_send_all(fd, req, 4 + bodylen, timeout_ms) != 0) {
        return -1;
    }
    n = ar_smb_recv_nb(fd, resp, sizeof(resp), timeout_ms);
    if (n < 32) {
        return -1;
    }
    status = ((unsigned int)resp[5] << 24) | ((unsigned int)resp[6] << 16) |
             ((unsigned int)resp[7] << 8) | resp[8];
    if (status == 0) {
        *uid = ((unsigned int)resp[28] << 8) | resp[29];
        if (n >= 35) {
            int wc = resp[32];
            int boff = 33 + wc * 2;
            if (boff + 2 <= n) {
                int blen = ((int)resp[boff] << 8) | resp[boff + 1];
                int bdata = boff + 2;
                int end = bdata + blen;
                if (end > n) {
                    end = n;
                }
                if (bdata < end) {
                    size_t l = 0;
                    while (bdata + (int)l < end && resp[bdata + l] != 0 &&
                           l + 1 < os_cap) {
                        os[l] = (char)resp[bdata + l];
                        l++;
                    }
                    os[l] = '\0';
                    bdata += (int)l + 1;
                    l = 0;
                    while (bdata + (int)l < end && resp[bdata + l] != 0 &&
                           l + 1 < lan_cap) {
                        lan[l] = (char)resp[bdata + l];
                        l++;
                    }
                    lan[l] = '\0';
                    ar_clean(os);
                    ar_clean(lan);
                }
            }
        }
    }
    return (int)status;
}

static int ar_smb1_tree_connect(int fd, unsigned int uid, const char *server,
                                const char *share, const char *service,
                                unsigned int *tid, int timeout_ms) {
    unsigned char req[512];
    unsigned char resp[1024];
    unsigned char *smb = req + 4;
    char path[256];
    size_t pathlen;
    size_t servicelen;
    size_t bodylen;
    int n;
    unsigned int status;

    if (server == NULL || share == NULL || service == NULL || tid == NULL) {
        return -1;
    }
    *tid = 0;
    memset(req, 0, sizeof(req));
    (void)snprintf(path, sizeof(path), "\\\\%s\\%s", server, share);
    pathlen = strlen(path) + 1;
    servicelen = strlen(service) + 1;
    bodylen = 32 + 1 + 8 + 2 + pathlen + servicelen;
    if (bodylen > sizeof(req) - 4) {
        return -1;
    }
    req[3] = (unsigned char)bodylen;
    smb[0] = 0xFF;
    smb[1] = 'S';
    smb[2] = 'M';
    smb[3] = 'B';
    smb[4] = 0x75;
    smb[9] = 0x18;
    smb[10] = 0x53;
    smb[11] = 0xC8;
    smb[26] = 0xFE;
    smb[27] = 0xFF;
    smb[28] = (unsigned char)(uid >> 8);
    smb[29] = (unsigned char)(uid & 255u);
    smb[32] = 4;
    smb[33] = 0xFF;
    smb[34] = 0;
    smb[35] = 0;
    smb[36] = 0;
    smb[37] = 0;
    smb[38] = 0;
    smb[39] = 0;
    smb[40] = 0;
    smb[41] = 0;
    smb[41] = (unsigned char)((pathlen + servicelen) & 255u);
    smb[42] = (unsigned char)(((pathlen + servicelen) >> 8) & 255u);
    memcpy(smb + 43, path, pathlen);
    memcpy(smb + 43 + pathlen, service, servicelen);
    if (as_send_all(fd, req, 4 + bodylen, timeout_ms) != 0) {
        return -1;
    }
    n = ar_smb_recv_nb(fd, resp, sizeof(resp), timeout_ms);
    if (n < 32) {
        return -1;
    }
    status = ((unsigned int)resp[5] << 24) | ((unsigned int)resp[6] << 16) |
             ((unsigned int)resp[7] << 8) | resp[8];
    if (status == 0) {
        *tid = ((unsigned int)resp[24] << 8) | resp[25];
    }
    return (int)status;
}

static int ar_smb1_open_session(AlScriptContext *ctx, int *outfd,
                                unsigned int *uid, char *os, size_t os_cap,
                                char *lan, size_t lan_cap) {
    unsigned char resp[2048];
    int fd;
    int n;

    if (outfd == NULL || uid == NULL || os == NULL || lan == NULL) {
        return -1;
    }
    *outfd = -1;
    *uid = 0;
    os[0] = '\0';
    lan[0] = '\0';
    fd = as_connect(ctx);
    if (fd < 0) {
        return -1;
    }
    {
        /* Reuse the negotiate helper's wire format on this connection. */
        static const char dialects[] =
            "\x02PC NETWORK PROGRAM 1.0\x00"
            "\x02LANMAN1.0\x00"
            "\x02Windows for Workgroups 3.1a\x00"
            "\x02LM1.2X002\x00"
            "\x02LANMAN2.1\x00"
            "\x02NT LM 0.12\x00"
            "\x02SMB 2.002\x00"
            "\x02SMB 2.???\x00";
        unsigned char req[512];
        unsigned char body[256];
        size_t dlen = sizeof(dialects) - 1;
        size_t msglen = 35 + dlen;
        memset(body, 0, sizeof(body));
        body[0] = 0xFF;
        body[1] = 'S';
        body[2] = 'M';
        body[3] = 'B';
        body[4] = 0x72;
        body[9] = 0x18;
        body[10] = 0x53;
        body[11] = 0xC8;
        body[26] = 0xFE;
        body[27] = 0xFF;
        body[32] = 0;
        body[33] = (unsigned char)(dlen & 255u);
        body[34] = (unsigned char)((dlen >> 8) & 255u);
        memcpy(body + 39, dialects, dlen);
        req[0] = 0;
        req[1] = (unsigned char)((msglen >> 16) & 255u);
        req[2] = (unsigned char)((msglen >> 8) & 255u);
        req[3] = (unsigned char)(msglen & 255u);
        memcpy(req + 4, body, msglen);
        if (as_send_all(fd, req, msglen + 4, ctx->timeout_ms) != 0) {
            close(fd);
            return -1;
        }
        n = ar_smb_recv_nb(fd, resp, sizeof(resp), ctx->timeout_ms);
        if (n < 32) {
            close(fd);
            return -1;
        }
    }
    (void)ar_smb1_session_setup(fd, uid, os, os_cap, lan, lan_cap,
                                ctx->timeout_ms);
    *outfd = fd;
    return 0;
}

#endif /* ARSENAL_SMB_H */
