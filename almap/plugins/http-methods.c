/* http-methods - enumerate allowed methods and test TRACE. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    char allow[1024];
    int have_allow = 0;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "OPTIONS", "/", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n > 0) {
        have_allow = ar_http_header(resp, "Allow", allow, sizeof(allow));
        if (have_allow) {
            ar_out(ctx, "Allow: %s", allow);
        }
    }
    n = ar_http_request(ctx, "TRACE", "/", NULL,
                        "X-Almap-Trace: yes\r\n", NULL, NULL,
                        resp, sizeof(resp));
    if (n > 0 && ar_http_status(resp) == 200 &&
        ar_contains_ci(resp, "TRACE /")) {
        ar_append(ctx, "%sTRACE enabled", (ctx->output_buf[0] != '\0') ?
                  "; " : "");
    } else if (ctx->output_buf[0] == '\0') {
        ar_out(ctx, "methods: OPTIONS returned no Allow header");
    }
    return 0;
}
