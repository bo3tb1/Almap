/* http-traceroute-3 - count proxy hops from response headers. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    const char *p;
    int hops = 0;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_get(ctx, "/", resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "HTTP traceroute: no response");
        return 0;
    }
    p = resp;
    while ((p = ar_stristr(p, "\nVia:")) != NULL) {
        hops++;
        p++;
    }
    if (ar_stristr(resp, "X-Forwarded-For") != NULL) {
        hops++;
    }
    ar_out(ctx, "HTTP traceroute: %d proxy hop(s) indicated", hops);
    return 0;
}
