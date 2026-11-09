/* http-favicon-2 - fetch the site favicon. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_get(ctx, "/favicon.ico", resp, sizeof(resp));
    if (n > 0 && ar_http_status(resp) == 200) {
        ar_out(ctx, "favicon: present (%d response bytes)", n);
    } else {
        ar_out(ctx, "favicon: not found (HTTP %d)", ar_http_status(resp));
    }
    return 0;
}
