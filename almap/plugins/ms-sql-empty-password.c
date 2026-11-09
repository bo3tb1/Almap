/* ms-sql-empty-password - test the sa account with a blank password. */
#include "arsenal_mssql.h"

int almap_script_run(AlScriptContext *ctx) {
    char msg[1024];
    int rc;

    if (!ar_valid(ctx)) {
        return 1;
    }
    rc = ar_mssql_empty_login(ctx, msg, sizeof(msg));
    if (rc == 0) {
        ar_out(ctx, "MSSQL empty password: sa login accepted");
    } else if (rc > 0) {
        ar_out(ctx, "MSSQL empty password: sa login rejected (%s)", msg);
    } else {
        ar_out(ctx, "MSSQL empty password: no TDS response");
    }
    return 0;
}
