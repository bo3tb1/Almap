/* smb-check-cve2017-0144-4 - EternalBlue (MS17-010) SMBv1 exposure check.
 * Benign: negotiates SMBv1 and reports whether the legacy dialect answers.
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_smb.h"

int almap_script_run(AlScriptContext *ctx) {
    unsigned char resp[1024];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_smb1_negotiate(ctx, resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "SMBv1 not answering (CVE-2017-0144 unlikely)");
        return 0;
    }
    ar_out(ctx, "SMBv1 negotiated: %s (CVE-2017-0144/MS17-010 surface; verify)",
           ar_smb1_dialect_name(ar_smb1_dialect(resp, n)));
    return 0;
}
