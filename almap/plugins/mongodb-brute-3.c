/* mongodb-brute-3 - five MongoDB connection attempts. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    int found = 0;
    int i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < 5; i++) {
        int fd = as_connect(ctx);
        if (fd >= 0) {
            close(fd);
            found++;
        }
    }
    if (found > 0) {
        ar_out(ctx, "MongoDB brute: %d/5 connections accepted; "
               "authentication required", found);
    } else {
        ar_out(ctx, "MongoDB brute: no connections");
    }
    return 0;
}
