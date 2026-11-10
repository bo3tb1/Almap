/* iot-ipmi-rmcp-5 - IPMI RMCP presence probe
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const unsigned char req[] = {
        0x06, 0x00, 0xff, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    char resp[2048];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = as_udp_exchange(ctx, req, sizeof(req), resp, sizeof(resp),
                        ctx->timeout_ms);
    if (n <= 0) {
        ar_out(ctx, "iot-ipmi-rmcp-5: no UDP reply");
        return 0;
    }
    if (n >= 4 && resp[0] == 0x06 && resp[1] == 0x00 && resp[2] == 0xff && resp[3] == 0x07) {
        ar_out(ctx, "iot-ipmi-rmcp-5: expected reply seen (%d bytes)", n);
    } else {
        ar_out(ctx, "iot-ipmi-rmcp-5: unexpected reply (%d bytes)", n);
    }
    return 0;
}
