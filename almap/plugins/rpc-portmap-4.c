/* rpc-portmap-4 - ONC-RPC portmapper NULL call
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    /* record-marked RPC CALL: prog=100000 v2 proc=0 (NULL), AUTH_NULL */
    static const unsigned char call[44] = {
        0x80, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x86, 0xa0,
        0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    unsigned char resp[1024];
    int fd;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = as_connect(ctx);
    if (fd < 0 || as_send_all(fd, call, sizeof(call), ctx->timeout_ms) != 0 ||
        (n = as_recv_all(fd, (char *)resp, sizeof(resp), ctx->timeout_ms)) < 12) {
        if (fd >= 0) close(fd);
        ar_out(ctx, "rpc-portmap: no RPC reply on port %d", ctx->port);
        return 0;
    }
    close(fd);
    /* reply: [4 rm][4 xid][4 mtype==1] accept state at offset 20 */
    ar_out(ctx, "rpc-portmap: RPC reply %d bytes (portmapper responding)", n);
    return 0;
}
