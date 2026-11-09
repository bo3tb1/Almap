/* http-robots - parse robots.txt and probe disallowed paths. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    char robots[4096];
    char path[512];
    const char *p;
    int found = 0;
    int probes = 0;

    if (!ar_valid(ctx)) {
        return 1;
    }
    if (ar_http_get(ctx, "/robots.txt", resp, sizeof(resp)) <= 0 ||
        ar_http_status(resp) == 404) {
        ar_out(ctx, "robots.txt: not found");
        return 0;
    }
    (void)snprintf(robots, sizeof(robots), "%s", ar_http_body(resp));
    p = robots;
    while (*p != '\0' && probes < 10) {
        const char *e = strchr(p, '\n');
        size_t len = (e != NULL) ? (size_t)(e - p) : strlen(p);
        if (len > 0 && p[len - 1] == '\r') {
            len--;
        }
        if (len > 10 && ar_starts_ci(p, "Disallow:")) {
            const char *v = p + 9;
            size_t vlen;
            while (*v == ' ' || *v == '\t') {
                v++;
            }
            vlen = len - (size_t)(v - p);
            if (vlen > 0 && vlen < sizeof(path) - 1) {
                size_t i;
                int n;
                for (i = 0; i < vlen; i++) {
                    path[i] = v[i];
                }
                path[vlen] = '\0';
                ar_clean(path);
                n = ar_http_get(ctx, path, resp, sizeof(resp));
                if (n > 0 && ar_http_status(resp) != 404 &&
                    ar_http_status(resp) != 403) {
                    ar_append(ctx, "%s%s [%d]", (found == 0) ?
                              "robots disallowed: " : ", ",
                              path, ar_http_status(resp));
                    found++;
                }
                probes++;
            }
        }
        if (e == NULL) {
            break;
        }
        p = e + 1;
    }
    if (found == 0) {
        ar_out(ctx, "robots.txt: no accessible Disallow entries found");
    }
    return 0;
}
