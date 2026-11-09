/* http-vhosts-2 - compare three Host header values. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *hosts[] = { "admin", "test", "localhost" };
    char resp[4096];
    int found = 0;
    size_t i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < sizeof(hosts) / sizeof(hosts[0]); i++) {
        int n = ar_http_request(ctx, "GET", "/", hosts[i], NULL, NULL,
                                NULL, resp, sizeof(resp));
        if (n > 0) {
            ar_append(ctx, "%s%s=%d", (found == 0) ? "vhosts: " : ", ",
                      hosts[i], ar_http_status(resp));
            found++;
        }
    }
    if (found == 0) {
        ar_out(ctx, "vhosts: no responses");
    }
    return 0;
}
