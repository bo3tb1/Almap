/* smb-protocols-check-4 - enumerate supported SMB dialects (posture).
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_smb.h"

int almap_script_run(AlScriptContext *ctx) {
    unsigned char resp[1024];
    int n1;
    int n2;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n1 = ar_smb1_negotiate(ctx, resp, sizeof(resp));
    ar_append(ctx, "SMBv1: %s",
              (n1 > 0) ? ar_smb1_dialect_name(ar_smb1_dialect(resp, n1)) : "no");
    n2 = ar_smb2_negotiate(ctx, resp, sizeof(resp));
    ar_append(ctx, ", SMB2/3: %s",
              (n2 > 0) ? ar_smb2_dialect_name(ar_smb2_dialect(resp, n2)) : "no");
    return 0;
}
