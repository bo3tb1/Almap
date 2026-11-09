/* dns-zone-transfer-2 - attempt AXFR for three likely zones. */
#include "arsenal_dns.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *zones[] = { "example.com", "test", "local" };
    char resp[4096];
    int found = 0;
    size_t i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < sizeof(zones) / sizeof(zones[0]); i++) {
        int n = ar_dns_tcp_query(ctx, zones[i], AR_DNS_AXFR, 0,
                                 resp, sizeof(resp));
        if (n > 0 && ar_dns_rcode(resp, n) == 0 &&
            ar_dns_ancount(resp, n) > 0) {
            ar_append(ctx, "%s%s\n", (found == 0) ?
                      "DNS zone transfer: " : "", zones[i]);
            ar_dns_dump_answers(ctx, resp, n, 6);
            found++;
        }
    }
    if (found == 0) {
        ar_out(ctx, "DNS zone transfer: refused or no records");
    }
    return 0;
}
