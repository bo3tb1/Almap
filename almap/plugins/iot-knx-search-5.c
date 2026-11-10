/* iot-knx-search-5 - KNXnet/IP search request probe
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const unsigned char req[] = {
        0x06, 0x10, 0x02, 0x01, 0x00, 0x0e, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    };
    char resp[2048];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = as_udp_exchange(ctx, req, sizeof(req), resp, sizeof(resp),
                        ctx->timeout_ms);
    if (n <= 0) {
        ar_out(ctx, "iot-knx-search-5: no UDP reply");
        return 0;
    }
    if (n >= 6 && (unsigned char)resp[2] == 0x02) {
        ar_out(ctx, "iot-knx-search-5: expected reply seen (%d bytes)", n);
    } else {
        ar_out(ctx, "iot-knx-search-5: unexpected reply (%d bytes)", n);
    }
    return 0;
}
