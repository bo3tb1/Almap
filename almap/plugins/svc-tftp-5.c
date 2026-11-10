/* svc-tftp-5 - TFTP read-request probe
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const unsigned char req[] = {
        0x00, 0x01, 0x61, 0x6c, 0x6d, 0x61, 0x70, 0x00, 0x6f, 0x63, 0x74, 0x65,
        0x74, 0x00,
    };
    char resp[2048];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = as_udp_exchange(ctx, req, sizeof(req), resp, sizeof(resp),
                        ctx->timeout_ms);
    if (n <= 0) {
        ar_out(ctx, "svc-tftp-5: no UDP reply");
        return 0;
    }
    if (n >= 4 && ((unsigned char)resp[1] == 0x03 || (unsigned char)resp[1] == 0x05)) {
        ar_out(ctx, "svc-tftp-5: expected reply seen (%d bytes)", n);
    } else {
        ar_out(ctx, "svc-tftp-5: unexpected reply (%d bytes)", n);
    }
    return 0;
}
