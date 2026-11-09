/* http-svn-enum - detect exposed Subversion metadata. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *paths[] = {
        "/.svn/entries", "/.svn/wc.db", "/.svn/all-wcprops",
        "/.svn/prop-base/", "/.svn/text-base/", "/.svn/format"
    };
    char resp[8192];
    int found = 0;
    size_t i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        int n = ar_http_get(ctx, paths[i], resp, sizeof(resp));
        int code = ar_http_status(resp);
        const char *body = ar_http_body(resp);
        if (n > 0 && code == 200 &&
            (strstr(body, "svn") != NULL || strstr(body, "dir") != NULL ||
             strstr(body, "SQLite") != NULL || strstr(body, "12") != NULL)) {
            ar_append(ctx, "%s%s", (found == 0) ? "svn exposed: " : ", ",
                      paths[i]);
            found++;
        }
    }
    if (found == 0) {
        ar_out(ctx, "svn exposed: no");
    }
    return 0;
}
