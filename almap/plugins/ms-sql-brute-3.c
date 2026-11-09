/* ms-sql-brute-3 - five blank-password sa login attempts. */
#include "arsenal_mssql.h"

int almap_script_run(AlScriptContext *ctx) {
    char msg[1024];
    int found = 0;
    int i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < 5; i++) {
        int rc = ar_mssql_empty_login(ctx, msg, sizeof(msg));
        if (rc == 0) {
            ar_out(ctx, "MSSQL brute: sa blank password accepted");
            found = 1;
            break;
        }
        if (rc < 0) {
            break;
        }
    }
    if (!found) {
        ar_out(ctx, "MSSQL brute: sa blank password rejected in 5 attempts");
    }
    return 0;
}
