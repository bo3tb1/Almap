/* smb-check-vulns-3 - combined SMBv1 vulnerability exposure check. */
#include "arsenal_smb.h"

int almap_script_run(AlScriptContext *ctx) {
    unsigned char resp[2048];
    unsigned int d1 = 0xFFFF;
    unsigned int d2 = 0xFFFF;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_smb1_negotiate(ctx, resp, sizeof(resp));
    if (n > 0) {
        d1 = ar_smb1_dialect(resp, n);
    }
    n = ar_smb2_negotiate(ctx, resp, sizeof(resp));
    if (n > 0) {
        d2 = ar_smb2_dialect(resp, n);
    }
    if (d1 <= 5) {
        ar_out(ctx, "potentially vulnerable: SMBv1 offered (%s); "
               "check MS08-067 and MS17-010", ar_smb1_dialect_name(d1));
    } else {
        ar_out(ctx, "SMBv1 not offered; MS08-067/MS17-010 not indicated");
    }
    if (d2 != 0xFFFF) {
        ar_append(ctx, "; SMB2 dialect %s", ar_smb2_dialect_name(d2));
    }
    return 0;
}
