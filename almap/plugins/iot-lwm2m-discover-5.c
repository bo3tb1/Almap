/* iot-lwm2m-discover-5 - LwM2M CoAP discovery probe
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const unsigned char req[] = {
        0x40, 0x01, 0x12, 0x34, 0xbb, 0x2e, 0x77, 0x65, 0x6c, 0x6c, 0x2d, 0x6b,
        0x6e, 0x6f, 0x77, 0x6e, 0x44, 0x63, 0x6f, 0x72, 0x65,
    };
    char resp[2048];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = as_udp_exchange(ctx, req, sizeof(req), resp, sizeof(resp),
                        ctx->timeout_ms);
    if (n <= 0) {
        ar_out(ctx, "iot-lwm2m-discover-5: no UDP reply");
        return 0;
    }
    ar_clean(resp);
    if (ar_contains_ci(resp, "core")) {
        ar_out(ctx, "iot-lwm2m-discover-5: detected");
    } else {
        ar_out(ctx, "iot-lwm2m-discover-5: not detected");
    }
    return 0;
}
