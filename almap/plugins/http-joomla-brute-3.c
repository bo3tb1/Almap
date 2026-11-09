/* http-joomla-brute-3 - five fixed Joomla admin logins. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *users[] = {
        "admin", "root", "admin", "root", "password"
    };
    static const char *passes[] = {
        "admin", "root", "password", "password", "password"
    };
    char body[512];
    char resp[4096];
    int found = 0;
    int i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < 5; i++) {
        int n;
        (void)snprintf(body, sizeof(body),
                       "username=%s&passwd=%s&option=com_login&task=login",
                       users[i], passes[i]);
        n = ar_http_request(ctx, "POST", "/administrator/index.php", NULL,
                            "\r\n", body,
                            "application/x-www-form-urlencoded",
                            resp, sizeof(resp));
        if (n > 0 && ar_http_status(resp) != 401 &&
            !ar_contains_ci(resp, "Invalid")) {
            ar_append(ctx, "%s%s:%s", (found == 0) ?
                      "Joomla valid credentials: " : ", ",
                      users[i], passes[i]);
            found++;
        }
    }
    if (found == 0) {
        ar_out(ctx, "Joomla brute: no valid credentials in 5 attempts");
    }
    return 0;
}
