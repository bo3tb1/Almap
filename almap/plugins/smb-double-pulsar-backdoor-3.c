/* smb-double-pulsar-backdoor-3 - DoublePulsar exposure probe. */
#include "arsenal_smb.h"

int almap_script_run(AlScriptContext *ctx) {
    unsigned char resp[2048];
    unsigned int d1 = 0xFFFF;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_smb1_negotiate(ctx, resp, sizeof(resp));
    if (n > 0) {
        d1 = ar_smb1_dialect(resp, n);
    }
    if (d1 <= 5) {
        ar_out(ctx, "SMBv1 offered (%s); DoublePulsar not confirmed",
               ar_smb1_dialect_name(d1));
    } else {
        ar_out(ctx, "SMBv1 not offered; DoublePulsar not detected");
    }
    return 0;
}
