/* http-cookie-flags-3 - check cookie HttpOnly and Secure flags. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_get(ctx, "/", resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "HTTP cookie flags: no response");
        return 0;
    }
    if (ar_stristr(resp, "set-cookie:") == NULL) {
        ar_out(ctx, "HTTP cookie flags: no cookies set");
        return 0;
    }
    ar_out(ctx, "HTTP cookie flags: HttpOnly=%s Secure=%s",
           ar_stristr(resp, "httponly") ? "yes" : "no",
           ar_stristr(resp, "secure") ? "yes" : "no");
    return 0;
}
