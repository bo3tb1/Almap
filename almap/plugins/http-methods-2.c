/* http-methods-2 - report the Allow header from an OPTIONS request. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    char allow[512];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "OPTIONS", "/", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "HTTP methods: no response");
        return 0;
    }
    if (ar_http_header(resp, "Allow", allow, sizeof(allow))) {
        ar_out(ctx, "HTTP methods: %s", allow);
    } else {
        ar_out(ctx, "HTTP methods: Allow not disclosed (HTTP %d)",
               ar_http_status(resp));
    }
    return 0;
}
