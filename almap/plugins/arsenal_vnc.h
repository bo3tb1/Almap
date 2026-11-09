/*
 * plugins/arsenal_vnc.h - minimal RFB/VNC authentication helpers for
 * the Step 33 AlScript arsenal. Raw TCP, fixed buffers, no heap.
 */
#ifndef ARSENAL_VNC_H
#define ARSENAL_VNC_H

#include "arsenal_util.h"
#include "arsenal_des.h"

static int ar_vnc_open(AlScriptContext *ctx, int *outfd, int *sectype,
                       unsigned char challenge[16]) {
    unsigned char ver[12];
    unsigned char buf[256];
    int fd;
    int n;
    int i;

    if (outfd == NULL || sectype == NULL || challenge == NULL) {
        return -1;
    }
    *outfd = -1;
    *sectype = 0;
    fd = as_connect(ctx);
    if (fd < 0) {
        return -1;
    }
    if (as_recv_exact(fd, ver, 12, ctx->timeout_ms) != 0) {
        close(fd);
        return -1;
    }
    if (memcmp(ver, "RFB ", 4) != 0) {
        close(fd);
        return -1;
    }
    if (as_send_all(fd, "RFB 003.008\n", 12, ctx->timeout_ms) != 0) {
        close(fd);
        return -1;
    }
    if (ver[4] == '0' && ver[5] == '0' && ver[6] == '3' &&
        ver[8] == '0' && ver[9] == '0' && ver[10] < '8') {
        if (as_recv_exact(fd, buf, 4, ctx->timeout_ms) != 0) {
            close(fd);
            return -1;
        }
        *sectype = ((int)buf[0] << 24) | ((int)buf[1] << 16) |
                   ((int)buf[2] << 8) | buf[3];
    } else {
        if (as_recv_exact(fd, buf, 1, ctx->timeout_ms) != 0) {
            close(fd);
            return -1;
        }
        n = buf[0];
        if (n == 0) {
            close(fd);
            return -1;
        }
        if (n > (int)sizeof(buf)) {
            n = (int)sizeof(buf);
        }
        if (as_recv_exact(fd, buf, (size_t)n, ctx->timeout_ms) != 0) {
            close(fd);
            return -1;
        }
        *sectype = 0;
        for (i = 0; i < n; i++) {
            if (buf[i] == 2) {
                *sectype = 2;
                break;
            }
            if (buf[i] == 1 && *sectype == 0) {
                *sectype = 1;
            }
        }
        if (*sectype == 0) {
            close(fd);
            return -1;
        }
        buf[0] = (unsigned char)*sectype;
        if (as_send_all(fd, buf, 1, ctx->timeout_ms) != 0) {
            close(fd);
            return -1;
        }
    }
    if (*sectype == 2) {
        if (as_recv_exact(fd, challenge, 16, ctx->timeout_ms) != 0) {
            close(fd);
            return -1;
        }
    }
    *outfd = fd;
    return 0;
}

static int ar_vnc_result(int fd, int timeout_ms) {
    unsigned char res[4];

    if (as_recv_exact(fd, res, 4, timeout_ms) != 0) {
        return -1;
    }
    return ((int)res[0] << 24) | ((int)res[1] << 16) |
           ((int)res[2] << 8) | res[3];
}

static int ar_vnc_try_password(AlScriptContext *ctx, const char *pass,
                               int *sectype_out) {
    unsigned char challenge[16];
    unsigned char key[8];
    unsigned char resp[16];
    int fd = -1;
    int sectype = 0;
    int i;

    if (pass == NULL) {
        return -1;
    }
    if (ar_vnc_open(ctx, &fd, &sectype, challenge) != 0) {
        return -1;
    }
    if (sectype_out != NULL) {
        *sectype_out = sectype;
    }
    if (sectype == 1) {
        close(fd);
        return 2;
    }
    memset(key, 0, sizeof(key));
    for (i = 0; i < 8 && pass[i] != '\0'; i++) {
        key[i] = ar_des_reverse8((unsigned char)pass[i]);
    }
    ar_des_encrypt_block(key, challenge, resp);
    ar_des_encrypt_block(key, challenge + 8, resp + 8);
    if (as_send_all(fd, resp, 16, ctx->timeout_ms) != 0) {
        close(fd);
        return -1;
    }
    i = ar_vnc_result(fd, ctx->timeout_ms);
    close(fd);
    if (i == 0) {
        return 1;
    }
    return 0;
}

#endif /* ARSENAL_VNC_H */
