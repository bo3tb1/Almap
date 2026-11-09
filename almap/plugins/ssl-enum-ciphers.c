/* ssl-enum-ciphers - enumerate negotiated TLS versions and ciphers. */
#include "arsenal_tls.h"

int almap_script_run(AlScriptContext *ctx) {
    static const unsigned int versions[] = { 0x0300, 0x0301, 0x0302, 0x0303 };
    unsigned char resp[4096];
    unsigned int selver = 0;
    unsigned int selcipher = 0;
    int found = 0;
    size_t i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < sizeof(versions) / sizeof(versions[0]); i++) {
        int rc = ar_tls_probe(ctx, versions[i], ar_tls_ciphers,
                              (int)(sizeof(ar_tls_ciphers) /
                                    sizeof(ar_tls_ciphers[0])),
                              &selver, &selcipher, 0, resp, sizeof(resp));
        if (rc == 1) {
            ar_append(ctx, "%s%s: %s", (found == 0) ?
                      "TLS ciphers: " : "; ",
                      ar_tls_version_name(versions[i]),
                      ar_tls_cipher_name(selcipher));
            found++;
        }
    }
    if (found == 0) {
        ar_out(ctx, "TLS ciphers: no supported handshake");
    }
    return 0;
}
