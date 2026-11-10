/* upnp-ssdp-4 - UPnP SSDP M-SEARCH discovery (UDP)
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char msearch[] =
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n";
    char resp[2048];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = as_udp_exchange(ctx, msearch, sizeof(msearch) - 1, resp, sizeof(resp),
                        ctx->timeout_ms);
    if (n <= 0) {
        ar_out(ctx, "upnp-ssdp: no SSDP reply on UDP %d", ctx->port);
        return 0;
    }
    ar_clean(resp);
    ar_out(ctx, "upnp-ssdp: %.220s", resp);
    return 0;
}
