/*
 * plugins/mongodb_info.c - NSE mongodb-info analog (version only).
 *
 * Build:
 *   gcc -shared -fPIC -o plugins/mongodb_info.so plugins/mongodb_info.c
 * Run:
 *   ./almap -t 127.0.0.1 -p 27017 --scan connect --script ./plugins/mongodb_info.so
 *
 * Sends a MongoDB OP_MSG buildInfo command to admin and extracts the
 * BSON "version" string from the reply.
 * Output: "mongodb_version:<version>" (empty when unavailable).
 * No heap, no external libs: raw POSIX sockets only.
 * Use only on networks you own or have permission to scan.
 */
#include "alscript_net.h"

static void put_le32(unsigned char *p, unsigned int v) {
    p[0] = (unsigned char)(v & 255u);
    p[1] = (unsigned char)((v >> 8) & 255u);
    p[2] = (unsigned char)((v >> 16) & 255u);
    p[3] = (unsigned char)((v >> 24) & 255u);
}

static unsigned int get_le32(const unsigned char *p) {
    return (unsigned int)p[0] | ((unsigned int)p[1] << 8) |
           ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
}

static int bson_skip_value(const unsigned char *doc, size_t doclen,
                           size_t *pos, unsigned char type) {
    size_t p = *pos;
    unsigned int n;

    switch (type) {
        case 0x01: /* double */
        case 0x09: /* datetime */
        case 0x11: /* timestamp */
        case 0x12: /* int64 */
            if (p + 8 > doclen) {
                return 0;
            }
            *pos = p + 8;
            return 1;
        case 0x02: /* string */
        case 0x0D: /* javascript code */
        case 0x0E: /* symbol */
            if (p + 4 > doclen) {
                return 0;
            }
            n = get_le32(doc + p);
            if (p + 4 + n > doclen) {
                return 0;
            }
            *pos = p + 4 + n;
            return 1;
        case 0x03: /* embedded document */
        case 0x04: /* array */
            if (p + 4 > doclen) {
                return 0;
            }
            n = get_le32(doc + p);
            if (n < 5 || p + n > doclen) {
                return 0;
            }
            *pos = p + n;
            return 1;
        case 0x05: /* binary */
            if (p + 5 > doclen) {
                return 0;
            }
            n = get_le32(doc + p);
            if (p + 5 + n > doclen) {
                return 0;
            }
            *pos = p + 5 + n;
            return 1;
        case 0x06: /* undefined */
        case 0x0A: /* null */
        case 0x7F: /* max key */
        case 0xFF: /* min key */
            *pos = p;
            return 1;
        case 0x07: /* object id */
            if (p + 12 > doclen) {
                return 0;
            }
            *pos = p + 12;
            return 1;
        case 0x08: /* bool */
            if (p + 1 > doclen) {
                return 0;
            }
            *pos = p + 1;
            return 1;
        case 0x0B: { /* regex: two cstrings */
            size_t a = p;
            while (a < doclen && doc[a] != 0) {
                a++;
            }
            if (a >= doclen) {
                return 0;
            }
            a++;
            while (a < doclen && doc[a] != 0) {
                a++;
            }
            if (a >= doclen) {
                return 0;
            }
            *pos = a + 1;
            return 1;
        }
        case 0x0C: /* dbpointer: string + 12-byte id */
            if (p + 4 > doclen) {
                return 0;
            }
            n = get_le32(doc + p);
            if (p + 4 + n + 12 > doclen) {
                return 0;
            }
            *pos = p + 4 + n + 12;
            return 1;
        case 0x0F: /* code with scope: total size includes the length */
            if (p + 4 > doclen) {
                return 0;
            }
            n = get_le32(doc + p);
            if (n < 4 || p + n > doclen) {
                return 0;
            }
            *pos = p + n;
            return 1;
        case 0x13: /* decimal128 */
            if (p + 16 > doclen) {
                return 0;
            }
            *pos = p + 16;
            return 1;
        default:
            return 0;
    }
}

static int bson_find_string(const unsigned char *doc, size_t avail,
                            const char *name, char *out, size_t outcap) {
    size_t doclen;
    size_t pos;

    if (doc == NULL || name == NULL || out == NULL || outcap < 2 ||
        avail < 5) {
        return 0;
    }
    out[0] = '\0';
    doclen = get_le32(doc);
    if (doclen < 5 || doclen > avail) {
        return 0;
    }
    pos = 4;
    while (pos < doclen) {
        unsigned char type = doc[pos++];
        const char *key;
        size_t nlen;

        if (type == 0) {
            break;
        }
        key = (const char *)(doc + pos);
        nlen = strnlen(key, doclen - pos);
        if (pos + nlen >= doclen) {
            return 0;
        }
        pos += nlen + 1;
        if (strcmp(key, name) == 0) {
            if (type == 0x02 && pos + 4 <= doclen) {
                unsigned int slen = get_le32(doc + pos);
                size_t copy;
                pos += 4;
                if (slen < 1 || pos + slen > doclen) {
                    return 0;
                }
                copy = (slen - 1 < outcap - 1) ? (size_t)(slen - 1) : outcap - 1;
                memcpy(out, doc + pos, copy);
                out[copy] = '\0';
                as_clean_field(out);
                return out[0] != '\0';
            }
            return 0;
        }
        if (!bson_skip_value(doc, doclen, &pos, type)) {
            return 0;
        }
    }
    return 0;
}

static size_t build_buildinfo(unsigned char *doc, size_t cap) {
    size_t off = 4; /* reserve the int32 document length */

    if (cap < 64) {
        return 0;
    }
    doc[off++] = 0x10; /* int32 */
    memcpy(doc + off, "buildInfo", 10);
    off += 10;
    put_le32(doc + off, 1);
    off += 4;
    doc[off++] = 0x02; /* string */
    memcpy(doc + off, "$db", 4);
    off += 4;
    put_le32(doc + off, 6); /* "admin" including NUL */
    off += 4;
    memcpy(doc + off, "admin", 6);
    off += 6;
    doc[off++] = 0; /* document terminator */
    put_le32(doc, (unsigned int)off);
    return off;
}

int almap_script_run(AlScriptContext *ctx) {
    int fd;
    unsigned char doc[256];
    unsigned char msg[512];
    unsigned char hdr[16];
    unsigned char resp[4000];
    unsigned char version[256];
    size_t doclen;
    size_t msglen;
    unsigned int rlen;
    unsigned int opcode;
    const unsigned char *rdoc;
    size_t avail;

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

    doclen = build_buildinfo(doc, sizeof(doc));
    if (doclen == 0) {
        return 1;
    }
    msglen = 21 + doclen;
    put_le32(msg, (unsigned int)msglen);
    put_le32(msg + 4, 1);  /* requestID */
    put_le32(msg + 8, 0);  /* responseTo */
    put_le32(msg + 12, 2013); /* OP_MSG */
    put_le32(msg + 16, 0); /* flagBits */
    msg[20] = 0;           /* section kind 0 */
    memcpy(msg + 21, doc, doclen);

    fd = as_connect(ctx);
    if (fd < 0) {
        return 1;
    }
    if (as_send_all(fd, msg, msglen, ctx->timeout_ms) != 0) {
        close(fd);
        return 1;
    }
    if (as_recv_exact(fd, hdr, 16, ctx->timeout_ms) != 0) {
        close(fd);
        return 0;
    }
    rlen = get_le32(hdr);
    opcode = get_le32(hdr + 12);
    if (rlen < 21 || rlen - 16 > sizeof(resp)) {
        close(fd);
        return 0;
    }
    if (as_recv_exact(fd, resp, rlen - 16, ctx->timeout_ms) != 0) {
        close(fd);
        return 0;
    }
    close(fd);

    if (opcode == 2013) {
        if (resp[4] != 0) { /* only section kind 0 is expected */
            return 0;
        }
        rdoc = resp + 5;
        avail = (size_t)(rlen - 16) - 5;
    } else if (opcode == 1) { /* legacy OP_REPLY */
        if (rlen - 16 < 20) {
            return 0;
        }
        rdoc = resp + 20;
        avail = (size_t)(rlen - 16) - 20;
    } else {
        return 0;
    }

    if (bson_find_string(rdoc, avail, "version",
                         (char *)version, sizeof(version))) {
        snprintf(ctx->output_buf, (size_t)ctx->output_max,
                 "mongodb_version:%s", (char *)version);
    }
    return 0;
}
