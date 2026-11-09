/* http-sql-injection-2 - error-based SQL injection probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *paths[] = {
        "/?id=1%27", "/index.php?id=1%27", "/search?q=1%27"
    };
    char resp[8192];
    int found = 0;
    size_t i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        int n = ar_http_get(ctx, paths[i], resp, sizeof(resp));
        const char *body = ar_http_body(resp);
        if (n > 0 &&
            (ar_contains_ci(body, "SQL syntax") ||
             ar_contains_ci(body, "mysql_fetch") ||
             ar_contains_ci(body, "ORA-"))) {
            ar_append(ctx, "%s%s", (found == 0) ? "VULNERABLE: " : ", ",
                      paths[i]);
            found++;
        }
    }
    if (found == 0) {
        ar_out(ctx, "not vulnerable: no SQL error signature");
    }
    return 0;
}
