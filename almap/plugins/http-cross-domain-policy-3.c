/* http-cross-domain-policy-3 - check for a permissive crossdomain.xml. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    const char *body;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_get(ctx, "/crossdomain.xml", resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-cross-domain-policy-3: no response");
        return 0;
    }
    body = ar_http_body(resp);
    if (ar_contains_ci(body, "allow-access-from domain=\"*\"")) {
        ar_out(ctx, "VULNERABLE: permissive cross-domain policy");
    } else {
        ar_out(ctx, "not vulnerable: permissive cross-domain policy (HTTP %d)", ar_http_status(resp));
    }
    return 0;
}
