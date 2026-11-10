/*
 * plugins/arsenal_mongo.h - minimal MongoDB OP_QUERY helper for the
 * Step 33 AlScript arsenal. Raw TCP, fixed buffers, no heap.
 */
#ifndef ARSENAL_MONGO_H
#define ARSENAL_MONGO_H

#include "arsenal_util.h"

static void ar_mongo_put32(unsigned char *p, unsigned int v) {
    p[0] = (unsigned char)(v & 255u);
    p[1] = (unsigned char)((v >> 8) & 255u);
    p[2] = (unsigned char)((v >> 16) & 255u);
    p[3] = (unsigned char)((v >> 24) & 255u);
}

static int ar_mongo_cmd(AlScriptContext *ctx, const char *cmd,
                        char *resp, size_t cap) {
    unsigned char pkt[512];
    size_t clen;
    size_t dlen;
    size_t o;
    size_t b;
    int fd;
    int n;

    if (ctx == NULL || cmd == NULL || resp == NULL || cap < 2) {
        return -1;
    }
    resp[0] = '\0';
    clen = strlen(cmd) + 1;
    dlen = 10 + clen;
    if (16 + 4 + 11 + 8 + dlen > sizeof(pkt)) {
        return -1;
    }
    memset(pkt, 0, sizeof(pkt));
    pkt[12] = 0xD4; /* OP_QUERY = 2004, little-endian */
    pkt[13] = 0x07;
    o = 16;
    o += 4; /* flags */
    memcpy(pkt + o, "admin.$cmd", 11);
    o += 11;
    o += 8; /* numberToSkip / numberToReturn */
    b = o;
    ar_mongo_put32(pkt + b, (unsigned int)dlen);
    pkt[b + 4] = 0x10; /* int32 */
    memcpy(pkt + b + 5, cmd, clen);
    ar_mongo_put32(pkt + b + 5 + clen, 1u);
    pkt[b + dlen - 1] = 0;
    o += dlen;
    ar_mongo_put32(pkt, (unsigned int)o);
    fd = as_connect(ctx);
    if (fd < 0) {
        return -1;
    }
    if (as_send_all(fd, pkt, o, ctx->timeout_ms) != 0) {
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

#endif /* ARSENAL_MONGO_H */
