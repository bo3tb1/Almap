/* nfs-check-4 - NFS service (TCP 2049) reachability probe
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
        ar_out(ctx, "nfs-check-4: not reachable on port %d", ctx->port);
        return 0;
    }
    close(fd);
    ar_out(ctx, "nfs-check-4: service reachable on port %d (2049 surface)", ctx->port);
    return 0;
}
