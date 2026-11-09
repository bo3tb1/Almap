/* http-stored-xss-2 - test whether a script payload is reflected. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char payload[] = "<script>alert(1)</script>";
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "POST", "/", NULL, "\r\n", payload,
                        "text/plain", resp, sizeof(resp));
    if (n > 0 && strstr(ar_http_body(resp), payload) != NULL) {
        ar_out(ctx, "potentially vulnerable: stored XSS payload reflected");
    } else {
        ar_out(ctx, "not vulnerable: XSS payload not reflected (HTTP %d)",
               ar_http_status(resp));
    }
    return 0;
}
