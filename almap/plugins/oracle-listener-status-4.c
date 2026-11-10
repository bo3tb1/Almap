/* oracle-listener-status-4 - Oracle TNS listener status probe
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_oracle.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[512];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_oracle_tns(ctx, "(CONNECT_DATA=(COMMAND=status))", resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "oracle-listener-status-4: Oracle TNS listener not responding");
        return 0;
    }
    ar_clean(resp);
    ar_out(ctx, "oracle-listener-status-4: TNS reply [%d bytes] %.200s", n, resp);
    return 0;
}
