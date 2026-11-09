/* http-trace-2 - test whether the TRACE method is enabled. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[4096];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "TRACE", "/", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n > 0 && ar_http_status(resp) == 200 &&
        ar_contains_ci(resp, "TRACE")) {
        ar_out(ctx, "VULNERABLE: HTTP TRACE method enabled");
    } else {
        ar_out(ctx, "not vulnerable: HTTP TRACE (HTTP %d)",
               ar_http_status(resp));
    }
    return 0;
}
