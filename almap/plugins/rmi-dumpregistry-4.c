/* rmi-dumpregistry-4 - Java RMI registry endpoint probe
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    /* JRMI magic + version 2 + StreamProtocol (0x4b) */
    static const unsigned char hs[7] = { 0x4a, 0x52, 0x4d, 0x49, 0x00, 0x02, 0x4b };
    unsigned char resp[256];
    int fd;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = as_connect(ctx);
    if (fd < 0 || as_send_all(fd, hs, sizeof(hs), ctx->timeout_ms) != 0 ||
        (n = as_recv_all(fd, (char *)resp, sizeof(resp), ctx->timeout_ms)) < 1) {
        if (fd >= 0) close(fd);
        ar_out(ctx, "rmi-dumpregistry-4: no JRMP response");
        return 0;
    }
    close(fd);
    ar_out(ctx, "rmi-dumpregistry-4: JRMP ack=0x%02x%s", resp[0],
           (resp[0] == 0x4e) ? " (RMI registry live; verify)" : "");
    return 0;
}
