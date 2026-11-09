/* http-default-accounts-3 - five common HTTP Basic credentials. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *users[] = {
        "admin", "root", "admin", "root", "password"
    };
    static const char *passes[] = {
        "admin", "root", "password", "password", "password"
    };
    char resp[4096];
    char auth[512];
    int found = 0;
    int i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < 5; i++) {
        ar_basic_auth(users[i], passes[i], auth, sizeof(auth));
        if (ar_http_request(ctx, "GET", "/", NULL, auth, NULL, NULL,
                            resp, sizeof(resp)) > 0 &&
            ar_http_status(resp) != 401) {
            ar_append(ctx, "%s%s:%s", (found == 0) ?
                      "HTTP default accounts: " : ", ",
                      users[i], passes[i]);
            found++;
        }
    }
    if (found == 0) {
        ar_out(ctx, "HTTP default accounts: none accepted");
    }
    return 0;
}
