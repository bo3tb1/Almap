/*
 * plugins/arsenal_oracle.h - minimal Oracle TNS CONNECT helper for the
 * Step 33 AlScript arsenal. Raw TCP, fixed buffers, no heap.
 */
#ifndef ARSENAL_ORACLE_H
#define ARSENAL_ORACLE_H

#include "arsenal_util.h"

static int ar_oracle_tns(AlScriptContext *ctx, const char *connect_data,
                         char *resp, size_t cap) {
    char ip[32];
    char desc[512];
    unsigned char pkt[1024];
    size_t dlen;
    size_t total;
    int fd;
    int n;

    if (ctx == NULL || connect_data == NULL || resp == NULL || cap < 2) {
        return -1;
    }
    resp[0] = '\0';
    as_ip_text(ctx->target_ip, ip, sizeof(ip));
    (void)snprintf(desc, sizeof(desc),
                   "(DESCRIPTION=(CONNECT_DATA=%s)"
                   "(ADDRESS=(PROTOCOL=TCP)(HOST=%s)(PORT=%d)))",
                   connect_data, ip, ctx->port);
    dlen = strlen(desc);
    total = 58 + dlen;
    if (total > sizeof(pkt)) {
        return -1;
    }
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = (unsigned char)(total >> 8);
    pkt[1] = (unsigned char)(total & 255u);
    pkt[4] = 1; /* TNS CONNECT */
    pkt[8] = 0x01;
    pkt[9] = 0x36;
    pkt[10] = 0x01;
    pkt[11] = 0x2C;
    pkt[18] = 0x00;
    pkt[19] = 0x01;
    pkt[20] = (unsigned char)(dlen >> 8);
    pkt[21] = (unsigned char)(dlen & 255u);
    pkt[22] = 0x00;
    pkt[23] = 0x3A;
    pkt[26] = 0x00;
    pkt[27] = 0x01;
    memcpy(pkt + 58, desc, dlen);
    fd = as_connect(ctx);
    if (fd < 0) {
        return -1;
    }
    if (as_send_all(fd, pkt, total, ctx->timeout_ms) != 0) {
        close(fd);
        return -1;
    }
    n = as_recv_all(fd, resp, cap, ctx->timeout_ms);
    close(fd);
    if (n > 0) {
        ar_clean(resp);
    }
    return n;
}

#endif /* ARSENAL_ORACLE_H */
