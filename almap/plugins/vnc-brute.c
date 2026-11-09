/* vnc-brute - small fixed dictionary check for VNC authentication. */
#include "arsenal_vnc.h"

int almap_script_run(AlScriptContext *ctx) {
    int sectype = 0;
    int found = 0;
    int noauth = 0;
    int i;
    int rc;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < 10; i++) {
        rc = ar_vnc_try_password(ctx, ar_brute_words[i], &sectype);
        if (rc == 2) {
            noauth = 1;
            break;
        }
        if (rc == 1) {
            ar_append(ctx, "%s%s", (found == 0) ?
                      "VNC valid password: " : ", ", ar_brute_words[i]);
            found++;
            break;
        }
    }
    if (noauth) {
        ar_out(ctx, "VNC: no authentication required (security type None)");
    } else if (found == 0) {
        ar_out(ctx, "VNC brute: no valid password in 10-word dictionary");
    }
    return 0;
}
