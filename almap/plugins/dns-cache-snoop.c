/* dns-cache-snoop - check for cached answers and open recursion. */
#include "arsenal_dns.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *domains[] = {
        "example.com", "google.com", "cloudflare.com", "github.com",
        "microsoft.com", "amazon.com", "facebook.com", "wikipedia.org",
        "openai.com", "localhost"
    };
    char resp[4096];
    int found = 0;
    int recursion = 0;
    size_t i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < sizeof(domains) / sizeof(domains[0]); i++) {
        int n = ar_dns_udp(ctx, domains[i], AR_DNS_A, 0x0000,
                           resp, sizeof(resp));
        if (n > 0 && ar_dns_rcode(resp, n) == 0 &&
            ar_dns_ancount(resp, n) > 0) {
            if (found > 0) {
                ar_append(ctx, "; ");
            } else {
                ar_append(ctx, "DNS cache: ");
            }
            ar_append(ctx, "%s ", domains[i]);
            ar_dns_dump_answers(ctx, resp, n, 1);
            found++;
        }
    }
    {
        int n = ar_dns_udp(ctx, "example.com", AR_DNS_A, 0x0100,
                           resp, sizeof(resp));
        if (n > 0 && ar_dns_rcode(resp, n) == 0 &&
            ar_dns_ancount(resp, n) > 0) {
            recursion = 1;
        }
    }
    if (found == 0) {
        ar_out(ctx, "DNS cache: no cached answers; recursion %s",
               recursion ? "available" : "not confirmed");
    } else {
        ar_append(ctx, "; recursion %s", recursion ? "available" :
                  "not confirmed");
    }
    return 0;
}
