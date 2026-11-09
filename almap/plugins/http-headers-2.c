/* http-headers-2 - report common security-relevant HTTP headers. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    char val[512];
    int n;
    int found = 0;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_get(ctx, "/", resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "HTTP headers: no response");
        return 0;
    }
    if (ar_http_header(resp, "Server", val, sizeof(val))) {
        ar_out(ctx, "Server: %s", val);
        found++;
    }
    if (ar_http_header(resp, "X-Powered-By", val, sizeof(val))) {
        ar_append(ctx, "%sX-Powered-By: %s", found ? "; " : "", val);
        found++;
    }
    if (ar_http_header(resp, "Content-Type", val, sizeof(val))) {
        ar_append(ctx, "%sContent-Type: %s", found ? "; " : "", val);
        found++;
    }
    if (ar_http_header(resp, "X-Frame-Options", val, sizeof(val))) {
        ar_append(ctx, "%sX-Frame-Options: %s", found ? "; " : "", val);
        found++;
    }
    if (found == 0) {
        ar_out(ctx, "HTTP headers: none disclosed");
    }
    return 0;
}
