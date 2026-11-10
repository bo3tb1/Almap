/* svc-radius-5 - RADIUS access-request probe
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const unsigned char req[] = {
        0x01, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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
        ar_out(ctx, "svc-radius-5: no UDP reply");
        return 0;
    }
    if (n >= 1 && ((unsigned char)resp[0] == 2 || (unsigned char)resp[0] == 3 || (unsigned char)resp[0] == 11)) {
        ar_out(ctx, "svc-radius-5: expected reply seen (%d bytes)", n);
    } else {
        ar_out(ctx, "svc-radius-5: unexpected reply (%d bytes)", n);
    }
    return 0;
}
