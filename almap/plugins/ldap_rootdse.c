/*
 * plugins/ldap_rootdse.c - NSE ldap-rootdse analog.
 *
 * Build:
 *   gcc -shared -fPIC -o plugins/ldap_rootdse.so plugins/ldap_rootdse.c
 * Run:
 *   ./almap -t 127.0.0.1 -p 389 --scan connect --script ./plugins/ldap_rootdse.so
 *
 * Performs an anonymous LDAPv3 bind, searches the Root DSE for the
 * defaultNamingContext attribute, and writes its value.
 * Output: "defaultNamingContext: <dn>" (empty when unavailable).
 * No heap, no external libs: raw POSIX sockets only.
 * Use only on networks you own or have permission to scan.
 */
#include "alscript_net.h"

static int ldap_ber_next(const unsigned char *buf, size_t end, size_t *pos,
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

static int ldap_recv_message(int fd, unsigned char *buf, size_t cap,
                             int timeout_ms) {
    unsigned char hdr[8];
    unsigned char first;
    size_t len;
    size_t hlen;
    int i;

    if (as_recv_exact(fd, hdr, 2, timeout_ms) != 0) {
        return -1;
    }
    if (hdr[0] != 0x30) {
        return -1;
    }
    first = hdr[1];
    hlen = 2;
    if (first & 0x80) {
        int nb = first & 0x7F;
        if (nb < 1 || nb > 3) {
            return -1;
        }
        if (as_recv_exact(fd, hdr + 2, (size_t)nb, timeout_ms) != 0) {
            return -1;
        }
        len = 0;
        for (i = 0; i < nb; i++) {
            len = (len << 8) | (size_t)hdr[2 + i];
        }
        hlen += (size_t)nb;
    } else {
        len = first;
    }
    if (len > cap - hlen) {
        return -1;
    }
    buf[0] = 0x30;
    buf[1] = first;
    if (hlen > 2) {
        memcpy(buf + 2, hdr + 2, hlen - 2);
    }
    if (as_recv_exact(fd, buf + hlen, len, timeout_ms) != 0) {
        return -1;
    }
    return (int)(hlen + len);
}

static int ldap_extract_default_naming_context(const unsigned char *msg,
                                               size_t n,
                                               char *out, size_t outcap) {
    static const char attr[] = "defaultNamingContext";
    size_t pos = 0;
    size_t s;
    size_t l;
    size_t end;
    size_t p;
    unsigned char tag;

    if (msg == NULL || out == NULL || outcap < 2 || n < 2) {
        return 0;
    }
    out[0] = '\0';
    if (!ldap_ber_next(msg, n, &pos, &tag, &s, &l) || tag != 0x30) {
        return 0;
    }
    end = s + l;
    p = s;
    if (!ldap_ber_next(msg, end, &p, &tag, &s, &l) || tag != 0x02) {
        return 0;
    }
    if (!ldap_ber_next(msg, end, &p, &tag, &s, &l) || tag != 0x64) {
        return 0;
    }
    end = s + l;
    p = s;
    if (!ldap_ber_next(msg, end, &p, &tag, &s, &l) || tag != 0x04) {
        return 0;
    }
    if (!ldap_ber_next(msg, end, &p, &tag, &s, &l) || tag != 0x30) {
        return 0;
    }
    end = s + l;
    p = s;
    while (p < end) {
        size_t aend;
        size_t ap;
        size_t ts;
        size_t tl;
        size_t vs;
        size_t vl;

        if (!ldap_ber_next(msg, end, &p, &tag, &s, &l) || tag != 0x30) {
            return 0;
        }
        aend = s + l;
        ap = s;
        if (!ldap_ber_next(msg, aend, &ap, &tag, &ts, &tl) || tag != 0x04) {
            return 0;
        }
        if (!ldap_ber_next(msg, aend, &ap, &tag, &vs, &vl) || tag != 0x31) {
            return 0;
        }
        if (tl == sizeof(attr) - 1 && memcmp(msg + ts, attr, tl) == 0) {
            size_t vp = vs;
            size_t vend = vs + vl;
            size_t ds;
            size_t dl;
            if (ldap_ber_next(msg, vend, &vp, &tag, &ds, &dl) && tag == 0x04) {
                size_t copy = (dl < outcap - 1) ? dl : outcap - 1;
                memcpy(out, msg + ds, copy);
                out[copy] = '\0';
                as_clean_field(out);
                return out[0] != '\0';
            }
            return 0;
        }
    }
    return 0;
}

int almap_script_run(AlScriptContext *ctx) {
    static const unsigned char bind_req[14] = {
        0x30, 0x0C, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02,
        0x01, 0x03, 0x04, 0x00, 0x80, 0x00
    };
    static const unsigned char search_req[61] = {
        0x30, 0x3B, 0x02, 0x01, 0x02, 0x63, 0x36,
        0x04, 0x00,
        0x0A, 0x01, 0x00,
        0x0A, 0x01, 0x00,
        0x02, 0x01, 0x00,
        0x02, 0x01, 0x00,
        0x01, 0x01, 0x00,
        0x87, 0x0B, 'o', 'b', 'j', 'e', 'c', 't', 'C', 'l', 'a', 's', 's',
        0x30, 0x16, 0x04, 0x14,
        'd', 'e', 'f', 'a', 'u', 'l', 't', 'N', 'a', 'm', 'i', 'n', 'g',
        'C', 'o', 'n', 't', 'e', 'x', 't'
    };
    unsigned char msg[3584];
    char value[1024];
    int fd;
    int n;
    int i;

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

    fd = as_connect(ctx);
    if (fd < 0) {
        return 1;
    }

    if (as_send_all(fd, bind_req, sizeof(bind_req), ctx->timeout_ms) != 0) {
        close(fd);
        return 1;
    }
    (void)ldap_recv_message(fd, msg, sizeof(msg), ctx->timeout_ms);

    if (as_send_all(fd, search_req, sizeof(search_req), ctx->timeout_ms) != 0) {
        close(fd);
        return 1;
    }

    value[0] = '\0';
    for (i = 0; i < 8; i++) {
        n = ldap_recv_message(fd, msg, sizeof(msg), ctx->timeout_ms);
        if (n <= 0) {
            break;
        }
        if (ldap_extract_default_naming_context(msg, (size_t)n,
                                                value, sizeof(value))) {
            break;
        }
    }
    close(fd);

    if (value[0] != '\0') {
        snprintf(ctx->output_buf, (size_t)ctx->output_max,
                 "defaultNamingContext: %s", value);
    }
    return 0;
}
