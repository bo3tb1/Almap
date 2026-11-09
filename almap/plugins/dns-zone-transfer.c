/* dns-zone-transfer - attempt AXFR for likely zones. */
#include "arsenal_dns.h"

static int ar_axfr_try(AlScriptContext *ctx, const char *zone) {
    unsigned char req[512];
    char resp[4096];
    int n;
    int fd;
    int total = 0;
    int i;
    int first = 1;

    n = ar_dns_make_query(zone, AR_DNS_AXFR, 0x0000, req, sizeof(req));
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
    for (i = 0; i < 8; i++) {
        int got = ar_dns_tcp_recv(fd, resp, sizeof(resp), 500);
        if (got <= 0) {
            break;
        }
        if (ar_dns_rcode(resp, got) != 0) {
            break;
        }
        if (first) {
            ar_append(ctx, "DNS zone transfer: %s\n", zone);
            first = 0;
        }
        total += ar_dns_dump_answers(ctx, resp, got, 12);
    }
    close(fd);
    return total;
}

int almap_script_run(AlScriptContext *ctx) {
    char ip[32];
    char reverse[128];
    size_t o = 0;
    const char *p;
    static const char *fallback[] = { "example.com", "test", "local" };
    size_t i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    as_ip_text(ctx->target_ip, ip, sizeof(ip));
    p = ip;
    while (*p != '\0' && o + 8 < sizeof(reverse)) {
        const char *dot = strchr(p, '.');
        size_t len = (dot != NULL) ? (size_t)(dot - p) : strlen(p);
        memcpy(reverse + o, p, len);
        o += len;
        reverse[o++] = '.';
        if (dot == NULL) {
            break;
        }
        p = dot + 1;
    }
    (void)snprintf(reverse + o, sizeof(reverse) - o, "in-addr.arpa");
    if (ar_axfr_try(ctx, reverse) > 0) {
        return 0;
    }
    for (i = 0; i < sizeof(fallback) / sizeof(fallback[0]); i++) {
        int n = ar_axfr_try(ctx, fallback[i]);
        if (n > 0) {
            return 0;
        }
    }
    ar_out(ctx, "DNS zone transfer: refused or no records");
    return 0;
}
