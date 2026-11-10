/* coap-wellknown-4 - CoAP well-known resource listing
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const unsigned char req[21] = {
        0x40, 0x01, 0x12, 0x34, 0xbb, 0x2e, 0x77, 0x65, 0x6c, 0x6c,
        0x2d, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x44, 0x63, 0x6f, 0x72,
        0x65
    };
    char resp[1500] = {0};
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = as_udp_exchange(ctx, req, sizeof(req), resp, sizeof(resp), ctx->timeout_ms);
    if (n <= 4) {
        ar_out(ctx, "coap-wellknown-4: short/invalid CoAP reply (%d bytes)", n);
        return 0;
    }
    ar_clean(resp);
    ar_out(ctx, "coap-wellknown-4: %d bytes from /.well-known/core: %.*s", n,
           (n - 4 > 180) ? 180 : n - 4, resp + 4);
    return 0;
}
