/*
 * plugins/arsenal_dns.h - minimal DNS wire helpers for the Step 33
 * AlScript arsenal. Raw UDP/TCP, fixed buffers, no external resolver.
 */
#ifndef ARSENAL_DNS_H
#define ARSENAL_DNS_H

#include "arsenal_util.h"

#define AR_DNS_A 1
#define AR_DNS_NS 2
#define AR_DNS_CNAME 5
#define AR_DNS_SOA 6
#define AR_DNS_PTR 12
#define AR_DNS_MX 15
#define AR_DNS_TXT 16
#define AR_DNS_AAAA 28
#define AR_DNS_AXFR 252
#define AR_DNS_ANY 255

static int ar_dns_encode_name(const char *name, unsigned char *out,
                              size_t cap) {
    size_t o = 0;
    const char *p = name;

    if (name == NULL || out == NULL || cap < 2) {
        return -1;
    }
    while (*p != '\0') {
        const char *dot = strchr(p, '.');
        size_t len = (dot != NULL) ? (size_t)(dot - p) : strlen(p);
        if (len == 0) {
            p++;
            continue;
        }
        if (len > 63 || o + len + 1 >= cap) {
            return -1;
        }
        out[o++] = (unsigned char)len;
        memcpy(out + o, p, len);
        o += len;
        if (dot == NULL) {
            break;
        }
        p = dot + 1;
    }
    if (o + 1 > cap) {
        return -1;
    }
    out[o++] = 0;
    return (int)o;
}

static int ar_dns_make_query(const char *name, unsigned int qtype,
                             unsigned int flags, unsigned char *buf,
                             size_t cap) {
    int nlen;
    unsigned int id = (unsigned int)(time(NULL) & 0xFFFFu);

    if (buf == NULL || cap < 18) {
        return -1;
    }
    memset(buf, 0, 12);
    buf[0] = (unsigned char)(id >> 8);
    buf[1] = (unsigned char)(id & 255u);
    buf[2] = (unsigned char)(flags >> 8);
    buf[3] = (unsigned char)(flags & 255u);
    buf[5] = 1; /* QDCOUNT */
    nlen = ar_dns_encode_name(name, buf + 12, cap - 12);
    if (nlen < 0 || 12 + (size_t)nlen + 4 > cap) {
        return -1;
    }
    buf[12 + nlen] = (unsigned char)(qtype >> 8);
    buf[13 + nlen] = (unsigned char)(qtype & 255u);
    buf[14 + nlen] = 0;
    buf[15 + nlen] = 1; /* IN */
    return 12 + nlen + 4;
}

static int ar_dns_udp(AlScriptContext *ctx, const char *name,
                      unsigned int qtype, unsigned int flags,
                      char *resp, size_t cap) {
    unsigned char req[512];
    int n;

    n = ar_dns_make_query(name, qtype, flags, req, sizeof(req));
    if (n < 0) {
        return -1;
    }
    return as_udp_exchange(ctx, req, (size_t)n, resp, cap, ctx->timeout_ms);
}

static int ar_dns_tcp_send(int fd, const unsigned char *pkt, int len,
                           int timeout_ms) {
    unsigned char hdr[2];

    if (pkt == NULL || len < 0 || len > 65535) {
        return -1;
    }
    hdr[0] = (unsigned char)(len >> 8);
    hdr[1] = (unsigned char)(len & 255);
    if (as_send_all(fd, hdr, 2, timeout_ms) != 0) {
        return -1;
    }
    return as_send_all(fd, pkt, (size_t)len, timeout_ms);
}

static int ar_dns_tcp_recv(int fd, char *out, size_t cap, int timeout_ms) {
    unsigned char hdr[2];
    unsigned int len;

    if (out == NULL || cap < 2) {
        return -1;
    }
    if (as_recv_exact(fd, hdr, 2, timeout_ms) != 0) {
        return -1;
    }
    len = ((unsigned int)hdr[0] << 8) | (unsigned int)hdr[1];
    if (len + 1 > cap) {
        return -1;
    }
    if (as_recv_exact(fd, out, len, timeout_ms) != 0) {
        return -1;
    }
    out[len] = '\0';
    return (int)len;
}

static int ar_dns_tcp_query(AlScriptContext *ctx, const char *name,
                            unsigned int qtype, unsigned int flags,
                            char *resp, size_t cap) {
    unsigned char req[512];
    int n;
    int fd;
    int got;

    n = ar_dns_make_query(name, qtype, flags, req, sizeof(req));
    if (n < 0) {
        return -1;
    }
    fd = as_connect(ctx);
    if (fd < 0) {
        return -1;
    }
    if (ar_dns_tcp_send(fd, req, n, ctx->timeout_ms) != 0) {
        close(fd);
        return -1;
    }
    got = ar_dns_tcp_recv(fd, resp, cap, ctx->timeout_ms);
    close(fd);
    return got;
}

static int ar_dns_rcode(const char *resp, int len) {
    const unsigned char *p = (const unsigned char *)resp;

    if (p == NULL || len < 4) {
        return -1;
    }
    return p[3] & 15;
}

static int ar_dns_qdcount(const char *resp, int len) {
    const unsigned char *p = (const unsigned char *)resp;

    if (p == NULL || len < 6) {
        return 0;
    }
    return ((int)p[4] << 8) | (int)p[5];
}

static int ar_dns_ancount(const char *resp, int len) {
    const unsigned char *p = (const unsigned char *)resp;

    if (p == NULL || len < 8) {
        return 0;
    }
    return ((int)p[6] << 8) | (int)p[7];
}

/* Safe name skipper: returns consumed bytes from p, or -1. */
static int ar_dns_name_len(const unsigned char *p, const unsigned char *end) {
    const unsigned char *start = p;

    while (p < end) {
        if ((*p & 0xC0) == 0xC0) {
            return (p + 2 <= end) ? (int)((p + 2) - start) : -1;
        }
        if (*p == 0) {
            return (int)((p + 1) - start);
        }
        if (p + 1 + *p > end) {
            return -1;
        }
        p += 1 + *p;
    }
    return -1;
}

/* Decode a name with compression relative to a DNS message base. */
static int ar_dns_name_at(const unsigned char *base, int len, int off,
                          char *out, size_t cap) {
    size_t o = 0;
    int guard = 0;

    if (base == NULL || out == NULL || cap < 2 || off < 0 || off >= len) {
        return -1;
    }
    out[0] = '\0';
    while (off < len && guard++ < 64) {
        const unsigned char *p = base + off;
        if ((*p & 0xC0) == 0xC0) {
            if (off + 1 >= len) {
                return -1;
            }
            off = ((int)(p[0] & 0x3F) << 8) | p[1];
            continue;
        }
        if (*p == 0) {
            break;
        }
        if (off + 1 + *p > len) {
            return -1;
        }
        if (o > 0 && o + 1 < cap) {
            out[o++] = '.';
        }
        if (o + *p >= cap) {
            return -1;
        }
        memcpy(out + o, p + 1, *p);
        o += *p;
        out[o] = '\0';
        off += 1 + *p;
    }
    if (o == 0) {
        (void)snprintf(out, cap, ".");
    }
    return (int)o;
}

/* Dump up to max answers as "name TYPE value" lines. */
static int ar_dns_dump_answers(AlScriptContext *ctx, const char *resp,
                               int len, int max) {
    const unsigned char *base = (const unsigned char *)resp;
    int qd;
    int an;
    int off = 12;
    int i;
    int printed = 0;

    if (base == NULL || len < 12) {
        return 0;
    }
    qd = ar_dns_qdcount(resp, len);
    an = ar_dns_ancount(resp, len);
    for (i = 0; i < qd; i++) {
        int nl = ar_dns_name_len(base + off, base + len);
        if (nl < 0 || off + nl + 4 > len) {
            return printed;
        }
        off += nl + 4;
    }
    for (i = 0; i < an && printed < max; i++) {
        char name[256];
        char val[256];
        int nl = ar_dns_name_len(base + off, base + len);
        unsigned int type;
        unsigned int rdlen;

        if (nl < 0 || off + nl + 10 > len) {
            break;
        }
        if (ar_dns_name_at(base, len, off, name, sizeof(name)) < 0) {
            (void)snprintf(name, sizeof(name), "?");
        }
        off += nl;
        type = ((unsigned int)base[off] << 8) | base[off + 1];
        rdlen = ((unsigned int)base[off + 8] << 8) | base[off + 9];
        off += 10;
        if (off + (int)rdlen > len) {
            break;
        }
        val[0] = '\0';
        if (type == AR_DNS_A && rdlen == 4) {
            (void)snprintf(val, sizeof(val), "%u.%u.%u.%u",
                           base[off], base[off + 1], base[off + 2],
                           base[off + 3]);
        } else if (type == AR_DNS_AAAA && rdlen == 16) {
            (void)snprintf(val, sizeof(val),
                           "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                           "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                           base[off], base[off + 1], base[off + 2],
                           base[off + 3], base[off + 4], base[off + 5],
                           base[off + 6], base[off + 7], base[off + 8],
                           base[off + 9], base[off + 10], base[off + 11],
                           base[off + 12], base[off + 13], base[off + 14],
                           base[off + 15]);
        } else if (type == AR_DNS_CNAME || type == AR_DNS_NS ||
                   type == AR_DNS_PTR) {
            (void)ar_dns_name_at(base, len, off, val, sizeof(val));
        } else if (type == AR_DNS_TXT && rdlen > 0) {
            unsigned int tl = base[off];
            if (tl > rdlen - 1) {
                tl = rdlen - 1;
            }
            if (tl >= sizeof(val)) {
                tl = sizeof(val) - 1;
            }
            memcpy(val, base + off + 1, tl);
            val[tl] = '\0';
            ar_clean(val);
        } else if (type == AR_DNS_SOA) {
            (void)snprintf(val, sizeof(val), "SOA");
        } else if (type == AR_DNS_MX && rdlen >= 3) {
            char mx[200];
            if (ar_dns_name_at(base, len, off + 2, mx, sizeof(mx)) >= 0) {
                (void)snprintf(val, sizeof(val), "%u %s",
                               ((unsigned int)base[off] << 8) | base[off + 1],
                               mx);
            }
        } else {
            (void)snprintf(val, sizeof(val), "%u bytes", rdlen);
        }
        if (printed > 0) {
            ar_append(ctx, "\n");
        }
        ar_append(ctx, "%s %s %s", name, type == AR_DNS_A ? "A" :
                  type == AR_DNS_AAAA ? "AAAA" :
                  type == AR_DNS_CNAME ? "CNAME" :
                  type == AR_DNS_NS ? "NS" :
                  type == AR_DNS_PTR ? "PTR" :
                  type == AR_DNS_MX ? "MX" :
                  type == AR_DNS_TXT ? "TXT" :
                  type == AR_DNS_SOA ? "SOA" : "TYPE", val);
        printed++;
        off += (int)rdlen;
    }
    return printed;
}

#endif /* ARSENAL_DNS_H */
