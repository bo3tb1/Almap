/* ssl-heartbleed - Heartbleed CVE-2014-0160 heartbeat probe. */
#include "arsenal_tls.h"

int almap_script_run(AlScriptContext *ctx) {
    unsigned char resp[4096];
    int rc;

    if (!ar_valid(ctx)) {
        return 1;
    }
    rc = ar_tls_heartbleed(ctx, resp, sizeof(resp));
    if (rc == 1) {
        ar_out(ctx, "VULNERABLE: Heartbleed CVE-2014-0160 (heartbeat reply)");
    } else if (rc == 0) {
        ar_out(ctx, "not vulnerable: Heartbleed CVE-2014-0160 not confirmed");
    } else {
        ar_out(ctx, "Heartbleed: TLS handshake failed");
    }
    return 0;
}
