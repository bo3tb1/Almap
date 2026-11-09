/* vnc-brute-3 - five fixed VNC password attempts. */
#include "arsenal_vnc.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *passwords[] = {
        "admin", "root", "password", "123456", "vnc"
    };
    int found = 0;
    size_t i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < sizeof(passwords) / sizeof(passwords[0]); i++) {
        int sectype = 0;
        int rc = ar_vnc_try_password(ctx, passwords[i], &sectype);
        if (rc == 1) {
            ar_append(ctx, "%s%s", (found == 0) ?
                      "VNC valid password: " : ", ", passwords[i]);
            found++;
        } else if (rc == 2) {
            ar_out(ctx, "VNC: no authentication required");
            return 0;
        }
    }
    if (found == 0) {
        ar_out(ctx, "VNC brute: no valid password in 5 attempts");
    }
    return 0;
}
