/* kerberos-userenum-4 - Kerberos AS-REQ user-enumeration surface probe
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    int fd;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = as_connect(ctx);
    if (fd < 0) {
        ar_out(ctx, "kerberos-userenum-4: KDC not reachable on port %d", ctx->port);
        return 0;
    }
    close(fd);
    ar_out(ctx, "kerberos-userenum-4: KDC reachable on TCP %d (AS-REQ probing requires a realm)", ctx->port);
    return 0;
}
