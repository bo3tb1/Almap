/*
 * plugins/snmp_sysdescr.c - NSE snmp-sysdescr analog.
 *
 * Build:
 *   gcc -shared -fPIC -o plugins/snmp_sysdescr.so plugins/snmp_sysdescr.c
 * Run:
 *   ./almap -t 127.0.0.1 -p 161 --scan connect --script ./plugins/snmp_sysdescr.so
 *
 * Sends an SNMPv2c GET for 1.3.6.1.2.1.1.1.0 (sysDescr) with the
 * "public" community and extracts the returned OCTET STRING.
 * Output: "sysDescr: <text>" (empty when no reply or no value).
 * No heap, no external libs: raw POSIX UDP sockets only.
 * Use only on networks you own or have permission to scan.
 */
#include "alscript_net.h"

static int snmp_ber_next(const unsigned char *buf, size_t end, size_t *pos,
                         unsigned char *tag, size_t *vstart, size_t *vlen) {
    size_t p = *pos;
    unsigned char t;
    unsigned char first;
    size_t len;
    int i;

    if (p >= end) {
        return 0;
    }
    t = buf[p++];
    if (p >= end) {
        return 0;
    }
    first = buf[p++];
    if (first & 0x80) {
        int nb = first & 0x7F;
        if (nb < 1 || nb > 3 || p + (size_t)nb > end) {
            return 0;
        }
        len = 0;
        for (i = 0; i < nb; i++) {
            len = (len << 8) | (size_t)buf[p++];
        }
    } else {
        len = first;
    }
    if (p + len > end) {
        return 0;
    }
    *tag = t;
    *vstart = p;
    *vlen = len;
    *pos = p + len;
    return 1;
}

int almap_script_run(AlScriptContext *ctx) {
    static const unsigned char oid[] = {
        0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00
    };
    static const unsigned char nullv[] = { 0x05, 0x00 };
    unsigned char req[128];
    unsigned char resp[2048];
    unsigned char varbind[32];
    size_t vb = 0;
    size_t off = 0;
    size_t p;
    size_t end;
    size_t s;
    size_t l;
    unsigned char tag;
    char value[1024];
    int n;

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

    memcpy(varbind + vb, oid, sizeof(oid));
    vb += sizeof(oid);
    memcpy(varbind + vb, nullv, sizeof(nullv));
    vb += sizeof(nullv);

    /* SNMPv2c GET, community "public", one varbind. */
    req[off++] = 0x30;
    req[off++] = 0x29;
    req[off++] = 0x02;
    req[off++] = 0x01;
    req[off++] = 0x01;
    req[off++] = 0x04;
    req[off++] = 0x06;
    memcpy(req + off, "public", 6);
    off += 6;
    req[off++] = 0xA0;
    req[off++] = 0x1C;
    req[off++] = 0x02;
    req[off++] = 0x04;
    req[off++] = 0x12;
    req[off++] = 0x34;
    req[off++] = 0x56;
    req[off++] = 0x78;
    req[off++] = 0x02;
    req[off++] = 0x01;
    req[off++] = 0x00;
    req[off++] = 0x02;
    req[off++] = 0x01;
    req[off++] = 0x00;
    req[off++] = 0x30;
    req[off++] = 0x0E;
    req[off++] = 0x30;
    req[off++] = 0x0C;
    memcpy(req + off, varbind, vb);
    off += vb;

    n = as_udp_exchange(ctx, req, off, (char *)resp, sizeof(resp),
                        ctx->timeout_ms);
    if (n < 16) {
        return 0;
    }

    p = 0;
    end = (size_t)n;
    if (!snmp_ber_next(resp, end, &p, &tag, &s, &l) || tag != 0x30) {
        return 0;
    }
    end = s + l;
    p = s;
    if (!snmp_ber_next(resp, end, &p, &tag, &s, &l) || tag != 0x02) {
        return 0;
    }
    if (!snmp_ber_next(resp, end, &p, &tag, &s, &l) || tag != 0x04) {
        return 0;
    }
    if (!snmp_ber_next(resp, end, &p, &tag, &s, &l) || tag != 0xA2) {
        return 0;
    }
    end = s + l;
    p = s;
    /* request-id, error-status, error-index */
    if (!snmp_ber_next(resp, end, &p, &tag, &s, &l) || tag != 0x02) {
        return 0;
    }
    if (!snmp_ber_next(resp, end, &p, &tag, &s, &l) || tag != 0x02) {
        return 0;
    }
    if (!snmp_ber_next(resp, end, &p, &tag, &s, &l) || tag != 0x02) {
        return 0;
    }
    if (!snmp_ber_next(resp, end, &p, &tag, &s, &l) || tag != 0x30) {
        return 0;
    }
    end = s + l;
    p = s;
    if (!snmp_ber_next(resp, end, &p, &tag, &s, &l) || tag != 0x30) {
        return 0;
    }
    end = s + l;
    p = s;
    if (!snmp_ber_next(resp, end, &p, &tag, &s, &l) || tag != 0x06) {
        return 0;
    }
    if (!snmp_ber_next(resp, end, &p, &tag, &s, &l) || tag != 0x04) {
        return 0;
    }
    if (l >= sizeof(value)) {
        l = sizeof(value) - 1;
    }
    memcpy(value, resp + s, l);
    value[l] = '\0';
    as_clean_field(value);
    if (value[0] != '\0') {
        snprintf(ctx->output_buf, (size_t)ctx->output_max,
                 "sysDescr: %s", value);
    }
    return 0;
}
