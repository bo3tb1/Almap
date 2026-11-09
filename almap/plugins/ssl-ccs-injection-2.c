/* ssl-ccs-injection-2 - TLS ChangeCipherSpec injection probe. */
#include "arsenal_tls.h"

int almap_script_run(AlScriptContext *ctx) {
    unsigned char resp[4096];
    unsigned int ver = 0;
    unsigned int cipher = 0;
    int rc;

    if (!ar_valid(ctx)) {
        return 1;
    }
    rc = ar_tls_ccs_test(ctx, resp, sizeof(resp), &ver, &cipher);
    if (rc == 1) {
        ar_out(ctx, "VULNERABLE: TLS CCS injection (%s, %s)",
               ar_tls_version_name(ver), ar_tls_cipher_name(cipher));
    } else if (rc == 0) {
        ar_out(ctx, "not vulnerable: TLS CCS injection");
    } else {
        ar_out(ctx, "TLS CCS injection: no handshake");
    }
    return 0;
}
