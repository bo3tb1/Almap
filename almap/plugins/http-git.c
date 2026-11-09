/* http-git - detect an exposed .git directory and read HEAD. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *paths[] = {
        "/.git/HEAD", "/.git/config", "/.git/index", "/.git/logs/HEAD",
        "/.git/refs/heads/master", "/.git/refs/heads/main"
    };
    char resp[8192];
    char head[256];
    int found = 0;
    size_t i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    head[0] = '\0';
    for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        int n = ar_http_get(ctx, paths[i], resp, sizeof(resp));
        int code = ar_http_status(resp);
        const char *body = ar_http_body(resp);
        if (n > 0 && code == 200 &&
            (strstr(body, "ref:") != NULL || strstr(body, "[core]") != NULL ||
             strstr(body, "DIRC") != NULL || strstr(body, "commit ") != NULL)) {
            ar_append(ctx, "%s%s", (found == 0) ? "git exposed: " : ", ",
                      paths[i]);
            found++;
            if (i == 0) {
                (void)snprintf(head, sizeof(head), "%s", body);
                ar_clean(head);
            }
        }
    }
    if (found > 0 && head[0] != '\0') {
        ar_append(ctx, " HEAD=%s", head);
    } else if (found == 0) {
        ar_out(ctx, "git exposed: no");
    }
    return 0;
}
