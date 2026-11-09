/* ssl-poodle - SSLv3 CBC POODLE exposure check. */
#include "arsenal_tls.h"

int almap_script_run(AlScriptContext *ctx) {
    unsigned char resp[4096];
    unsigned int selver = 0;
    unsigned int selcipher = 0;
    int rc;

    if (!ar_valid(ctx)) {
        return 1;
    }
    rc = ar_tls_probe(ctx, 0x0300, ar_tls_cbc_ciphers,
                      (int)(sizeof(ar_tls_cbc_ciphers) /
                            sizeof(ar_tls_cbc_ciphers[0])),
                      &selver, &selcipher, 0, resp, sizeof(resp));
    if (rc == 1 && selver == 0x0300 && ar_tls_is_cbc(selcipher)) {
        ar_out(ctx, "VULNERABLE: POODLE (SSLv3 CBC %s)",
               ar_tls_cipher_name(selcipher));
    } else if (rc == 1) {
        ar_out(ctx, "not vulnerable: POODLE (selected %s/%s)",
               ar_tls_version_name(selver), ar_tls_cipher_name(selcipher));
    } else {
        ar_out(ctx, "not vulnerable: SSLv3 not negotiated");
    }
    return 0;
}
