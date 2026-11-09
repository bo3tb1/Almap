/*
 * plugins/dns_version.c - NSE dns-version analog.
 *
 * Build:
 *   gcc -shared -fPIC -o plugins/dns_version.so plugins/dns_version.c
 * Run:
 *   ./almap -t 127.0.0.1 -p 53 --scan connect --script ./plugins/dns_version.so
 *
 * Sends a CHAOS class TXT query for "version.bind" over UDP and falls
 * back to DNS-over-TCP when the UDP query is unanswered. The first TXT
 * character-string in the answer section is written to the output.
 * Output: "version.bind: <text>" (empty when no answer).
 * No heap, no external libs: raw POSIX sockets only.
 * Use only on networks you own or have permission to scan.
 */
#include "alscript_net.h"

#define DNS_QUERY_ID 0x414Cu

static int dns_skip_name(const unsigned char *msg, size_t n, size_t *pos) {
    size_t p = *pos;
    int guard = 0;

    while (p < n && guard++ < 128) {
        unsigned char l = msg[p];
        if ((l & 0xC0) == 0xC0) {
            if (p + 1 >= n) {
                return 0;
            }
            *pos = p + 2;
            return 1;
        }
        if (l == 0) {
            *pos = p + 1;
            return 1;
        }
        if (p + 1 + (size_t)l > n) {
            return 0;
        }
        p += 1 + (size_t)l;
    }
    return 0;
}

static int dns_parse_txt(const unsigned char *msg, size_t n,
                         char *out, size_t outcap) {
    unsigned int ancount;
    size_t p;
    unsigned int i;

    if (msg == NULL || out == NULL || outcap < 2 || n < 12) {
        return 0;
    }
    out[0] = '\0';
    ancount = ((unsigned int)msg[6] << 8) | (unsigned int)msg[7];
    if (ancount == 0) {
        return 0;
    }
    p = 12;
    if (!dns_skip_name(msg, n, &p) || p + 4 > n) {
        return 0;
    }
    p += 4;
    for (i = 0; i < ancount && i < 16; i++) {
        unsigned int type;
        unsigned int rdlen;
        size_t used = 0;
        size_t end;

        if (!dns_skip_name(msg, n, &p) || p + 10 > n) {
            return 0;
        }
        type = ((unsigned int)msg[p] << 8) | (unsigned int)msg[p + 1];
        rdlen = ((unsigned int)msg[p + 8] << 8) | (unsigned int)msg[p + 9];
        p += 10;
        if (p + rdlen > n) {
            return 0;
        }
        if (type == 16 && rdlen > 0) {
            end = p + rdlen;
            while (p < end) {
                unsigned int slen = msg[p++];
                size_t copy;
                if (p + slen > end) {
                    break;
                }
                copy = (size_t)slen;
                if (used + copy + 1 >= outcap) {
                    copy = outcap - 1 - used;
                }
                memcpy(out + used, msg + p, copy);
                used += copy;
                p += slen;
                if (p < end && used + 1 < outcap) {
                    out[used++] = ' ';
                }
            }
            out[used] = '\0';
            as_clean_field(out);
            return out[0] != '\0';
        }
        p += rdlen;
    }
    return 0;
}

static size_t dns_build_query(unsigned char *req, size_t cap) {
    size_t off = 0;

    if (cap < 64) {
        return 0;
    }
    req[off++] = (unsigned char)((DNS_QUERY_ID >> 8) & 255u);
    req[off++] = (unsigned char)(DNS_QUERY_ID & 255u);
    req[off++] = 0x01; /* recursion desired */
    req[off++] = 0x00;
    req[off++] = 0x00; /* QDCOUNT */
    req[off++] = 0x01;
    req[off++] = 0x00; /* ANCOUNT */
    req[off++] = 0x00;
    req[off++] = 0x00; /* NSCOUNT */
    req[off++] = 0x00;
    req[off++] = 0x00; /* ARCOUNT */
    req[off++] = 0x00;
    req[off++] = 7; /* version */
    memcpy(req + off, "version", 7);
    off += 7;
    req[off++] = 4; /* bind */
    memcpy(req + off, "bind", 4);
    off += 4;
    req[off++] = 0;
    req[off++] = 0x00; /* QTYPE TXT */
    req[off++] = 0x10;
    req[off++] = 0x00; /* QCLASS CH */
    req[off++] = 0x03;
    return off;
}

int almap_script_run(AlScriptContext *ctx) {
    unsigned char req[128];
    unsigned char resp[2048];
    char text[1024];
    size_t qlen;
    int n;
    int fd;

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

    qlen = dns_build_query(req, sizeof(req));
    if (qlen == 0) {
        return 1;
    }

    n = as_udp_exchange(ctx, req, qlen, (char *)resp, sizeof(resp),
                        ctx->timeout_ms);
    if (n >= 12) {
        if (dns_parse_txt(resp, (size_t)n, text, sizeof(text))) {
            snprintf(ctx->output_buf, (size_t)ctx->output_max,
                     "version.bind: %s", text);
            return 0;
        }
    }

    /* DNS over TCP fallback: two-byte length prefix. */
    fd = as_connect(ctx);
    if (fd < 0) {
        return 0;
    }
    {
        unsigned char frame[130];
        frame[0] = (unsigned char)((qlen >> 8) & 255u);
        frame[1] = (unsigned char)(qlen & 255u);
        memcpy(frame + 2, req, qlen);
        if (as_send_all(fd, frame, qlen + 2, ctx->timeout_ms) != 0) {
            close(fd);
            return 0;
        }
    }
    {
        unsigned char hdr[2];
        unsigned int mlen;
        if (as_recv_exact(fd, hdr, 2, ctx->timeout_ms) != 0) {
            close(fd);
            return 0;
        }
        mlen = ((unsigned int)hdr[0] << 8) | (unsigned int)hdr[1];
        if (mlen < 12 || mlen > sizeof(resp)) {
            close(fd);
            return 0;
        }
        if (as_recv_exact(fd, resp, mlen, ctx->timeout_ms) != 0) {
            close(fd);
            return 0;
        }
        close(fd);
        if (dns_parse_txt(resp, mlen, text, sizeof(text))) {
            snprintf(ctx->output_buf, (size_t)ctx->output_max,
                     "version.bind: %s", text);
        }
    }
    return 0;
}
