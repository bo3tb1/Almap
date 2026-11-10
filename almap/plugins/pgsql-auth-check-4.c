/* pgsql-auth-check-4 - PostgreSQL default-credential check (5-entry dict).
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_pgsql.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *words[5] = { "admin", "password", "root", "test", "guest" };
    char msg[256];
    int i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < 5; i++) {
        if (ar_pg_login(ctx, "postgres", words[i], msg, sizeof(msg)) == 0) {
            ar_out(ctx, "pgsql-auth-check: postgres:%s ACCEPTED (verify)", words[i]);
            return 0;
        }
    }
    ar_out(ctx, "pgsql-auth-check: all 5 default passwords rejected");
    return 0;
}
