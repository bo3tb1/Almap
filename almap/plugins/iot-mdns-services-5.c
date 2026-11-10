/* iot-mdns-services-5 - mDNS service enumeration probe
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_dns.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[2048];
    int n;
    int an;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_dns_udp(ctx, "_services._dns-sd._udp.local", 12, 0x0000, resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "iot-mdns-services-5: no DNS reply");
        return 0;
    }
    an = ar_dns_ancount(resp, n);
    ar_out(ctx, "iot-mdns-services-5: %d answer(s)", an);
    (void)ar_dns_dump_answers(ctx, resp, n, 5);
    return 0;
}
