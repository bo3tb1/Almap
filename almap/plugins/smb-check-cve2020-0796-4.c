/* smb-check-cve2020-0796-4 - SMBGhost (SMBv3.1.1 compression) exposure check.
 * Benign: negotiates SMB2 and reports the top dialect offered.
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_smb.h"

int almap_script_run(AlScriptContext *ctx) {
    unsigned char resp[1024];
    unsigned int d;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_smb2_negotiate(ctx, resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "SMB2 not answering (CVE-2020-0796 unlikely)");
        return 0;
    }
    d = ar_smb2_dialect(resp, n);
    ar_out(ctx, "SMB2 dialect %s (CVE-2020-0796 affects 3.1.1; verify compression)",
           ar_smb2_dialect_name(d));
    return 0;
}
