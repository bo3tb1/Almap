/* ldap-anon-bind-4 - LDAP anonymous simple-bind check
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
        ar_out(ctx, "ldap-anon-bind: no BindResponse");
        return 0;
    }
    close(fd);
    /* BindResponse (0x61); resultCode is the ENUMERATED after 0x0a 0x01 */
    ar_out(ctx, "ldap-anon-bind: resultCode=%d%s", resp[n > 9 ? 9 : n - 1],
           (resp[5] == 0x61 && resp[9] == 0x00) ? " (anonymous bind ALLOWED; verify)" : "");
    return 0;
}
