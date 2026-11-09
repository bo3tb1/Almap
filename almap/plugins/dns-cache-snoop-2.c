/* dns-cache-snoop-2 - test for cached DNS answers. */
#include "arsenal_dns.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *names[] = {
        "example.com", "www.example.com", "localhost"
    };
    char resp[4096];
    int found = 0;
    size_t i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        int n = ar_dns_udp(ctx, names[i], AR_DNS_A, 0x0100,
                           resp, sizeof(resp));
        if (n > 0 && ar_dns_rcode(resp, n) == 0 &&
            ar_dns_ancount(resp, n) > 0) {
            ar_append(ctx, "%s%s", (found == 0) ?
                      "DNS cache snoop: " : ", ", names[i]);
            found++;
        }
    }
    if (found == 0) {
        ar_out(ctx, "DNS cache snoop: no cached answers");
    }
    return 0;
}
