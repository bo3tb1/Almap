/* ssl-dh-params-2 - report DHE parameter size. */
#include "arsenal_tls.h"

int almap_script_run(AlScriptContext *ctx) {
    int bits = 0;
    unsigned int group_len = 0;

    if (!ar_valid(ctx)) {
        return 1;
    }
    if (ar_tls_dh_bits(ctx, &bits, &group_len) != 0) {
        ar_out(ctx, "TLS DH params: no handshake");
        return 0;
    }
    if (bits <= 0) {
        ar_out(ctx, "TLS DH params: no DHE parameters offered");
    } else if (bits < 2048) {
        ar_out(ctx, "VULNERABLE: weak %d-bit DH parameters", bits);
    } else {
        ar_out(ctx, "TLS DH params: %d-bit (%u bytes)", bits, group_len);
    }
    return 0;
}
