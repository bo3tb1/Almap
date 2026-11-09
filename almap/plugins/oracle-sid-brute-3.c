/* oracle-sid-brute-3 - five Oracle SID connection attempts. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *sids[] = { "XE", "ORCL", "ORCLCDB", "TEST", "DEV" };
    int found = 0;
    int i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < 5; i++) {
        int fd = as_connect(ctx);
        if (fd >= 0) {
            close(fd);
            ar_append(ctx, "%s%s", (found == 0) ?
                      "Oracle SID candidates: " : ", ", sids[i]);
            found++;
        }
    }
    if (found == 0) {
        ar_out(ctx, "Oracle SID brute: listener not reachable");
    } else {
        ar_append(ctx, " (listener reachable; SID validation requires TNS)");
    }
    return 0;
}
