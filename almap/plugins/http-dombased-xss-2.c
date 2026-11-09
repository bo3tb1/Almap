/* http-dombased-xss-2 - look for DOM XSS sinks in the landing page. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    const char *body;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_get(ctx, "/", resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "DOM XSS: no response");
        return 0;
    }
    body = ar_http_body(resp);
    if (ar_contains_ci(body, "document.write") ||
        ar_contains_ci(body, "innerhtml") ||
        ar_contains_ci(body, "location.hash")) {
        ar_out(ctx, "potentially vulnerable: DOM XSS sink detected");
    } else {
        ar_out(ctx, "not vulnerable: no DOM XSS sink found");
    }
    return 0;
}
