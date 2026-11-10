/* smb-vuln-cve2021-44142-5 - Samba CVE-2021-44142 SMB negotiate probe
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_smb.h"

int almap_script_run(AlScriptContext *ctx) {
    unsigned char resp[4096];
    int n;
    unsigned int d;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_smb2_negotiate(ctx, resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "smb-vuln-cve2021-44142-5: no SMB2 negotiate reply");
        return 0;
    }
    d = ar_smb2_dialect(resp, n);
    ar_out(ctx, "smb-vuln-cve2021-44142-5: SMB dialect 0x%04x (%s); verify patch level",
           d, ar_smb2_dialect_name(d));
    return 0;
}
