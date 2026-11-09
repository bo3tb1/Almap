/* http-trace - check whether the HTTP TRACE method is enabled. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "TRACE", "/", NULL,
                        "X-Almap-Trace: trace-test\r\n", NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "TRACE: no response");
        return 0;
    }
    if (ar_http_status(resp) == 200 &&
        (ar_contains_ci(resp, "TRACE /") ||
         ar_contains_ci(resp, "X-Almap-Trace"))) {
        ar_out(ctx, "TRACE enabled (HTTP %d)", ar_http_status(resp));
    } else if (ar_http_status(resp) == 405 ||
               ar_http_status(resp) == 501) {
        ar_out(ctx, "TRACE disabled (HTTP %d)", ar_http_status(resp));
    } else {
        ar_out(ctx, "TRACE not confirmed (HTTP %d)", ar_http_status(resp));
    }
    return 0;
}
