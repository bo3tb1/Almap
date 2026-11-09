/* smb-security-mode-3 - report SMB signing and authentication mode. */
#include "arsenal_smb.h"

int almap_script_run(AlScriptContext *ctx) {
    unsigned char resp[2048];
    int mode = -1;
    int smb2 = 0;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_smb2_negotiate(ctx, resp, sizeof(resp));
    if (n > 0 && ar_smb2_dialect(resp, n) != 0xFFFF) {
        mode = ar_smb2_security_mode(resp, n);
        smb2 = 1;
    } else {
        n = ar_smb1_negotiate(ctx, resp, sizeof(resp));
        if (n > 0) {
            mode = ar_smb1_security_mode(resp, n);
        }
    }
    if (mode < 0) {
        ar_out(ctx, "SMB security mode: not detected");
        return 0;
    }
    ar_out(ctx, "SMB security mode: 0x%02x (%s)", mode,
           (mode & 0x01) ? "user-level" : "share-level");
    ar_append(ctx, ", %s", (mode & 0x02) ? "encrypted passwords" :
              "plaintext passwords");
    ar_append(ctx, ", signing %s", (mode & 0x08) ? "required" :
              ((mode & 0x04) ? "enabled" : "disabled"));
    ar_append(ctx, " (%s)", smb2 ? "SMB2" : "SMB1");
    return 0;
}
