/* http-google-mobile - detect Google mobile redirect/endpoint behaviour. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    char loc[512];
    const char *body;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/", NULL,
                        "User-Agent: Mozilla/5.0 (Linux; Android 10; Mobile)\r\n",
                        NULL, NULL, resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "google-mobile: no response");
        return 0;
    }
    body = ar_http_body(resp);
    if (ar_http_header(resp, "Location", loc, sizeof(loc)) &&
        (ar_contains_ci(loc, "google") || ar_contains_ci(loc, "/m/") ||
         ar_contains_ci(loc, "mobile"))) {
        ar_out(ctx, "google-mobile: mobile redirect %s", loc);
    } else if (ar_contains_ci(body, "google") &&
               ar_contains_ci(body, "mobile")) {
        ar_out(ctx, "google-mobile: mobile Google page detected");
    } else {
        ar_out(ctx, "google-mobile: no mobile Google behaviour detected");
    }
    return 0;
}
