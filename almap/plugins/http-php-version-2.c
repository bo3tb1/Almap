/* http-php-version-2 - disclose the PHP version. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    char val[256];
    const char *body;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_get(ctx,
                    "/?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000",
                    resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "PHP version: no response");
        return 0;
    }
    if (ar_http_header(resp, "X-Powered-By", val, sizeof(val))) {
        ar_out(ctx, "PHP version: %s", val);
        return 0;
    }
    body = ar_http_body(resp);
    if (ar_contains_ci(body, "PHP Version")) {
        ar_out(ctx, "PHP version: phpinfo banner disclosed");
    } else {
        ar_out(ctx, "PHP version: not disclosed (HTTP %d)",
               ar_http_status(resp));
    }
    return 0;
}
