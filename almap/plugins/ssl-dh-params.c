/* ssl-dh-params - inspect DHE ServerKeyExchange group size. */
#include "arsenal_tls.h"

int almap_script_run(AlScriptContext *ctx) {
    int bits = 0;
    unsigned int group_len = 0;
    int rc;

    if (!ar_valid(ctx)) {
        return 1;
    }
    rc = ar_tls_dh_bits(ctx, &bits, &group_len);
    if (rc != 0) {
        ar_out(ctx, "DH params: TLS handshake failed");
    } else if (bits == 0) {
        ar_out(ctx, "DH params: server selected ECDHE or no DHE suite");
    } else if (bits <= 1024) {
        ar_out(ctx, "VULNERABLE: weak DH group %d bits (%u bytes)",
               bits, group_len);
    } else {
        ar_out(ctx, "DH params: %d-bit group (%u bytes)", bits, group_len);
    }
    return 0;
}
