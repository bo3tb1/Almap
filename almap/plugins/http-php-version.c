/* http-php-version - detect PHP version from headers and probes. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    char val[256];
    const char *body;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_get(ctx, "/", resp, sizeof(resp));
    if (n > 0 && ar_http_header(resp, "X-Powered-By", val, sizeof(val))) {
        if (ar_contains_ci(val, "PHP")) {
            ar_out(ctx, "PHP version: %s", val);
            return 0;
        }
    }
    n = ar_http_get(ctx, "/?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000",
                    resp, sizeof(resp));
    if (n > 0 && ar_contains_ci(ar_http_body(resp), "PHP")) {
        body = ar_http_body(resp);
        if (sscanf(body, "PHP Version %255s", val) == 1 ||
            sscanf(body, "%*[^P]PHP Version %255s", val) == 1) {
            ar_out(ctx, "PHP version: %s", val);
            return 0;
        }
    }
    n = ar_http_get(ctx, "/phpinfo.php", resp, sizeof(resp));
    if (n > 0 && ar_contains_ci(resp, "PHP Version")) {
        body = ar_http_body(resp);
        {
            const char *p = ar_stristr(body, "PHP Version");
            if (p != NULL) {
                p += 11;
                while (*p == ' ' || *p == ':' || *p == '<' || *p == '>') {
                    p++;
                }
                if (sscanf(p, "%255s", val) == 1) {
                    ar_out(ctx, "PHP version: %s", val);
                    return 0;
                }
            }
        }
    }
    ar_out(ctx, "PHP version: not disclosed");
    return 0;
}
