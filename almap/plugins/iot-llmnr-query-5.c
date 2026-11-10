/* iot-llmnr-query-5 - LLMNR name-resolution probe
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
    n = ar_dns_udp(ctx, "almap", 1, 0x0000, resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "iot-llmnr-query-5: no DNS reply");
        return 0;
    }
    an = ar_dns_ancount(resp, n);
    ar_out(ctx, "iot-llmnr-query-5: %d answer(s)", an);
    (void)ar_dns_dump_answers(ctx, resp, n, 5);
    return 0;
}
