/* pgsql-ssl-posture-4 - report PostgreSQL SSL negotiation posture.
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_pgsql.h"

int almap_script_run(AlScriptContext *ctx) {
    int ssl = 0;

    if (!ar_valid(ctx)) {
        return 1;
    }
    if (ar_pg_start(ctx, "postgres", "postgres", &ssl) < 0) {
        ar_out(ctx, "pgsql-ssl-posture: not reachable");
        return 0;
    }
    ar_out(ctx, "PostgreSQL SSL: server %s SSL on startup",
           ssl ? "OFFERS" : "DOES NOT offer");
    return 0;
}
