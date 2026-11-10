/* smb-security-mode-check-4 - report SMB signing / security mode posture.
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_smb.h"

int almap_script_run(AlScriptContext *ctx) {
    unsigned char resp[1024];
    int n;
    int mode;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_smb2_negotiate(ctx, resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "SMB security mode: no SMB2 response");
        return 0;
    }
    mode = ar_smb2_security_mode(resp, n);
    ar_out(ctx, "SMB2 security mode 0x%02x (signing %s)",
           mode, (mode & 0x02) ? "required" : "enabled/optional");
    return 0;
}
