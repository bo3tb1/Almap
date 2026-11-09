/* http-robots-3 - fetch and display robots.txt. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    const char *body;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_get(ctx, "/robots.txt", resp, sizeof(resp));
    if (n <= 0 || ar_http_status(resp) >= 400) {
        ar_out(ctx, "robots.txt: not found (HTTP %d)", ar_http_status(resp));
        return 0;
    }
    body = ar_http_body(resp);
    ar_out(ctx, "robots.txt: %.500s", body);
    return 0;
}
