/* http-title-3 - extract the HTML page title. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    char title[256];
    const char *p;
    const char *e;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_get(ctx, "/", resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "title: no response");
        return 0;
    }
    p = ar_stristr(resp, "<title");
    if (p != NULL && (p = strchr(p, '>')) != NULL) {
        p++;
        e = strchr(p, '<');
        if (e != NULL) {
            size_t len = (size_t)(e - p);
            if (len >= sizeof(title)) {
                len = sizeof(title) - 1;
            }
            memcpy(title, p, len);
            title[len] = '\0';
            ar_clean(title);
            ar_out(ctx, "title: %s", title);
            return 0;
        }
    }
    ar_out(ctx, "title: not found (HTTP %d)", ar_http_status(resp));
    return 0;
}
