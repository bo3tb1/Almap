/* dns-brute-2 - five fixed subdomain lookups under example.com. */
#include "arsenal_dns.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *names[] = { "www", "mail", "ftp", "admin", "test" };
    char resp[4096];
    char fqdn[128];
    int found = 0;
    size_t i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        int n;
        (void)snprintf(fqdn, sizeof(fqdn), "%s.example.com", names[i]);
        n = ar_dns_udp(ctx, fqdn, AR_DNS_A, 0x0100, resp, sizeof(resp));
        if (n > 0 && ar_dns_rcode(resp, n) == 0 &&
            ar_dns_ancount(resp, n) > 0) {
            ar_append(ctx, "%s%s ", (found == 0) ? "DNS brute: " : "",
                      fqdn);
            ar_dns_dump_answers(ctx, resp, n, 2);
            found++;
        }
    }
    if (found == 0) {
        ar_out(ctx, "DNS brute: no names resolved under example.com");
    }
    return 0;
}
