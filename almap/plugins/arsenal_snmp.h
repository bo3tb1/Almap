/*
 * plugins/arsenal_snmp.h - minimal BER/SNMPv2c helpers for the Step 33
 * AlScript arsenal. Raw UDP, fixed buffers, no external ASN.1 library.
 */
#ifndef ARSENAL_SNMP_H
#define ARSENAL_SNMP_H

#include "arsenal_util.h"

static int ar_ber_len(unsigned char *out, size_t len) {
    if (len < 128) {
        out[0] = (unsigned char)len;
        return 1;
    }
    if (len < 256) {
        out[0] = 0x81;
        out[1] = (unsigned char)len;
        return 2;
    }
    out[0] = 0x82;
    out[1] = (unsigned char)(len >> 8);
    out[2] = (unsigned char)(len & 255u);
    return 3;
}

static int ar_ber_tlv(unsigned char tag, const unsigned char *val,
                      size_t len, unsigned char *out, size_t cap) {
    int l;
    int n;

    if (out == NULL || cap < 2 || (val == NULL && len > 0)) {
        return -1;
    }
    l = ar_ber_len(out + 1, len);
    n = 1 + l;
    if (n + (int)len > (int)cap) {
        return -1;
    }
    out[0] = tag;
    if (len > 0) {
        memmove(out + n, val, len);
    }
    return n + (int)len;
}

static int ar_ber_int(unsigned int v, unsigned char *out, size_t cap) {
    unsigned char tmp[5];
    unsigned char rev[5];
    int n = 0;
    int i;

    if (v == 0) {
        tmp[n++] = 0;
    } else {
        while (v > 0 && n < 5) {
            tmp[n++] = (unsigned char)(v & 255u);
            v >>= 8;
        }
    }
    if (n > 1 && (tmp[n - 1] & 0x80) != 0) {
        tmp[n++] = 0;
    }
    for (i = 0; i < n; i++) {
        rev[i] = tmp[n - 1 - i];
    }
    return ar_ber_tlv(0x02, rev, (size_t)n, out, cap);
}

static int ar_ber_oid(const char *oid, unsigned char *out, size_t cap) {
    unsigned char tmp[128];
    size_t n = 0;
    unsigned int parts[32];
    int np = 0;
    const char *p = oid;

    if (oid == NULL || out == NULL || cap < 2) {
        return -1;
    }
    while (*p != '\0' && np < 32) {
        unsigned int v = 0;
        int any = 0;
        while (*p >= '0' && *p <= '9') {
            v = v * 10 + (unsigned int)(*p - '0');
            p++;
            any = 1;
        }
        if (!any) {
            return -1;
        }
        parts[np++] = v;
        if (*p == '.') {
            p++;
        }
    }
    if (np < 2) {
        return -1;
    }
    tmp[n++] = (unsigned char)(parts[0] * 40 + parts[1]);
    {
        int i;
        for (i = 2; i < np; i++) {
            unsigned int v = parts[i];
            unsigned char stack[5];
            int sn = 0;
            do {
                stack[sn++] = (unsigned char)(v & 0x7F);
                v >>= 7;
            } while (v > 0);
            while (sn > 0) {
                unsigned char b = stack[--sn];
                if (sn > 0) {
                    b |= 0x80;
                }
                if (n < sizeof(tmp)) {
                    tmp[n++] = b;
                }
            }
        }
    }
    return ar_ber_tlv(0x06, tmp, n, out, cap);
}

static int ar_snmp_make_get(const char *community, const char *oid,
                            unsigned char *out, size_t cap) {
    unsigned char oidbuf[128];
    unsigned char nullbuf[8];
    unsigned char vbcontent[256];
    unsigned char varbind[256];
    unsigned char vblist[256];
    unsigned char pducontent[512];
    unsigned char pdu[512];
    unsigned char msgcontent[768];
    unsigned char msg[768];
    int n_oid;
    int n_null;
    int a;
    int n;
    int total;

    n_oid = ar_ber_oid(oid, oidbuf, sizeof(oidbuf));
    if (n_oid < 0) {
        return -1;
    }
    n_null = ar_ber_tlv(0x05, NULL, 0, nullbuf, sizeof(nullbuf));
    if (n_null < 0) {
        return -1;
    }
    if ((size_t)(n_oid + n_null) > sizeof(vbcontent)) {
        return -1;
    }
    memcpy(vbcontent, oidbuf, (size_t)n_oid);
    memcpy(vbcontent + n_oid, nullbuf, (size_t)n_null);
    a = n_oid + n_null;
    n = ar_ber_tlv(0x30, vbcontent, (size_t)a, varbind, sizeof(varbind));
    if (n < 0) {
        return -1;
    }
    n = ar_ber_tlv(0x30, varbind, (size_t)n, vblist, sizeof(vblist));
    if (n < 0) {
        return -1;
    }
    total = n;

    a = ar_ber_int(1, pducontent, sizeof(pducontent));
    if (a < 0) {
        return -1;
    }
    n = ar_ber_int(0, pducontent + a, sizeof(pducontent) - (size_t)a);
    if (n < 0) {
        return -1;
    }
    a += n;
    n = ar_ber_int(0, pducontent + a, sizeof(pducontent) - (size_t)a);
    if (n < 0) {
        return -1;
    }
    a += n;
    if ((size_t)(a + total) > sizeof(pducontent)) {
        return -1;
    }
    memcpy(pducontent + a, vblist, (size_t)total);
    a += total;
    n = ar_ber_tlv(0xA0, pducontent, (size_t)a, pdu, sizeof(pdu));
    if (n < 0) {
        return -1;
    }
    total = n;

    a = ar_ber_int(1, msgcontent, sizeof(msgcontent));
    if (a < 0) {
        return -1;
    }
    n = ar_ber_tlv(0x04, (const unsigned char *)community,
                   strlen(community), msgcontent + a,
                   sizeof(msgcontent) - (size_t)a);
    if (n < 0) {
        return -1;
    }
    a += n;
    if ((size_t)(a + total) > sizeof(msgcontent)) {
        return -1;
    }
    memcpy(msgcontent + a, pdu, (size_t)total);
    a += total;
    n = ar_ber_tlv(0x30, msgcontent, (size_t)a, msg, sizeof(msg));
    if (n < 0) {
        return -1;
    }
    if ((size_t)n > cap) {
        return -1;
    }
    memcpy(out, msg, (size_t)n);
    return n;
}

static int ar_ber_read_tlv(const unsigned char *p, int len, int *tag,
                           const unsigned char **val, int *vlen,
                           int *consumed) {
    int l;
    int o = 1;

    if (p == NULL || len < 2 || tag == NULL || val == NULL || vlen == NULL ||
        consumed == NULL) {
        return -1;
    }
    *tag = p[0];
    if ((p[1] & 0x80) == 0) {
        l = p[1];
        o = 2;
    } else {
        int n = p[1] & 0x7F;
        int i;
        if (n < 1 || n > 3 || len < 2 + n) {
            return -1;
        }
        l = 0;
        for (i = 0; i < n; i++) {
            l = (l << 8) | p[2 + i];
        }
        o = 2 + n;
    }
    if (l < 0 || o + l > len) {
        return -1;
    }
    *val = p + o;
    *vlen = l;
    *consumed = o + l;
    return 0;
}

static int ar_snmp_format_value(int tag, const unsigned char *v, int vl,
                                char *out, size_t cap) {
    size_t i;

    if (out == NULL || cap < 2 || v == NULL || vl < 0) {
        return -1;
    }
    out[0] = '\0';
    if (tag == 0x04) {
        size_t n = (size_t)vl;
        if (n >= cap) {
            n = cap - 1;
        }
        memcpy(out, v, n);
        out[n] = '\0';
    } else if (tag == 0x06) {
        size_t o = 0;
        unsigned int x = 0;
        int first = 1;
        for (i = 0; i < (size_t)vl && o + 8 < cap; i++) {
            x = (x << 7) | (v[i] & 0x7F);
            if ((v[i] & 0x80) == 0) {
                if (first) {
                    o += (size_t)snprintf(out + o, cap - o, "%u.%u",
                                          x / 40, x % 40);
                    first = 0;
                } else {
                    o += (size_t)snprintf(out + o, cap - o, ".%u", x);
                }
                x = 0;
            }
        }
    } else if (tag == 0x02 || tag == 0x41 || tag == 0x42 || tag == 0x43) {
        unsigned int x = 0;
        for (i = 0; i < (size_t)vl; i++) {
            x = (x << 8) | v[i];
        }
        (void)snprintf(out, cap, "%u", x);
    } else {
        (void)snprintf(out, cap, "tag 0x%02x len %d", tag, vl);
    }
    ar_clean(out);
    return 0;
}

static int ar_snmp_get(AlScriptContext *ctx, const char *community,
                       const char *oid, char *out, size_t cap) {
    unsigned char req[1024];
    char resp[2048];
    int n;
    int tag;
    const unsigned char *v;
    int vl;
    int used;
    int off;
    int i;

    if (out == NULL || cap < 2) {
        return -1;
    }
    out[0] = '\0';
    n = ar_snmp_make_get(community, oid, req, sizeof(req));
    if (n < 0) {
        return -1;
    }
    n = as_udp_exchange(ctx, req, (size_t)n, resp, sizeof(resp),
                        ctx->timeout_ms);
    if (n <= 0) {
        return -1;
    }
    if (ar_ber_read_tlv((const unsigned char *)resp, n, &tag, &v, &vl,
                        &used) != 0 || tag != 0x30) {
        return -1;
    }
    off = 0;
    for (i = 0; i < 3 && off < vl; i++) {
        int t;
        const unsigned char *vv;
        int l;
        int c;
        if (ar_ber_read_tlv(v + off, vl - off, &t, &vv, &l, &c) != 0) {
            return -1;
        }
        off += c;
        if (i == 2 && t == 0xA2) {
            int po = 0;
            int j;
            for (j = 0; j < 4 && po < l; j++) {
                int pt;
                const unsigned char *pv;
                int pl;
                int pc;
                if (ar_ber_read_tlv(vv + po, l - po, &pt, &pv, &pl, &pc) != 0) {
                    return -1;
                }
                po += pc;
                if (j == 3 && pt == 0x30) {
                    int vo = 0;
                    int vt;
                    const unsigned char *vvv;
                    int vll;
                    int vc;
                    if (ar_ber_read_tlv(pv, pl, &vt, &vvv, &vll, &vc) != 0) {
                        return -1;
                    }
                    vo = 0;
                    if (ar_ber_read_tlv(vvv + vo, vll - vo, &vt, &pv, &pl,
                                        &vc) != 0) {
                        return -1;
                    }
                    vo += vc;
                    if (ar_ber_read_tlv(vvv + vo, vll - vo, &vt, &pv, &pl,
                                        &vc) != 0) {
                        return -1;
                    }
                    return ar_snmp_format_value(vt, pv, pl, out, cap);
                }
            }
        }
    }
    return -1;
}

#endif /* ARSENAL_SNMP_H */
