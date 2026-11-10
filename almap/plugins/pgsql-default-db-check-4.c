/* pgsql-default-db-check-4 - PostgreSQL default database reachability
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_pgsql.h"

int almap_script_run(AlScriptContext *ctx) {
    int ssl = 0;
    int rc;

    if (!ar_valid(ctx)) {
        return 1;
    }
    rc = ar_pg_start(ctx, "postgres", "template1", &ssl);
    if (rc < 0) {
        ar_out(ctx, "pgsql-default-db-check-4: PostgreSQL not reachable");
        return 0;
    }
    ar_out(ctx, "pgsql-default-db-check-4: startup ok (ssl=%s, user=postgres, db=template1)",
           ssl ? "offered" : "disabled");
    return 0;
}
