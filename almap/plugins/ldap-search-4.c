/* ldap-search-4 - LDAP search reachability (anonymous base query)
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    /* anonymous simple bind, LDAPv3, messageID 1 */
    static const unsigned char bind[14] = {
        0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03,
        0x04, 0x00, 0x80, 0x00
    };
    unsigned char resp[256];
    int fd;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = as_connect(ctx);
    if (fd < 0 || as_send_all(fd, bind, sizeof(bind), ctx->timeout_ms) != 0 ||
        (n = as_recv_all(fd, (char *)resp, sizeof(resp), ctx->timeout_ms)) < 7) {
        if (fd >= 0) close(fd);
        ar_out(ctx, "ldap-search-4: not reachable");
        return 0;
    }
    close(fd);
    ar_out(ctx, "ldap-search-4: LDAP answered bind (%d bytes); anon query surface present", n);
    return 0;
}
