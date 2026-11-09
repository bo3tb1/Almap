/* ssl-ccs-injection - early ChangeCipherSpec injection probe. */
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
    if (rc < 0) {
        ar_out(ctx, "CCS injection: TLS handshake failed");
    } else if (rc == 1) {
        ar_out(ctx, "VULNERABLE: CVE-2014-0224 early CCS accepted (%s/%s)",
               ar_tls_version_name(ver), ar_tls_cipher_name(cipher));
    } else {
        ar_out(ctx, "not vulnerable: early CCS rejected (%s/%s)",
               ar_tls_version_name(ver), ar_tls_cipher_name(cipher));
    }
    return 0;
}
