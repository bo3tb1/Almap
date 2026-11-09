/* ms-sql-info - TDS prelogin version and instance discovery. */
#include "arsenal_mssql.h"

int almap_script_run(AlScriptContext *ctx) {
    char version[64];
    char instance[128];
    int rc;

    if (!ar_valid(ctx)) {
        return 1;
    }
    rc = ar_mssql_prelogin(ctx, version, sizeof(version),
                           instance, sizeof(instance));
    if (rc != 0) {
        ar_out(ctx, "MSSQL info: no TDS prelogin response");
        return 0;
    }
    ar_out(ctx, "MSSQL version: %s", version[0] != '\0' ? version : "unknown");
    if (instance[0] != '\0') {
        ar_append(ctx, " instance: %s", instance);
    }
    return 0;
}
