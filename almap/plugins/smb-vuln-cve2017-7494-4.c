/* smb-vuln-cve2017-7494-4 - SambaCry SMB RCE probe. */
#include "arsenal_smb.h"

int almap_script_run(AlScriptContext *ctx) {
    unsigned char resp[2048];
    char os[128];
    char lan[128];
    unsigned int dialect;
    unsigned int uid;
    int fd = -1;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_smb2_negotiate(ctx, resp, sizeof(resp));
    if (n > 0) {
        dialect = ar_smb2_dialect(resp, n);
        ar_out(ctx, "smb-vuln-cve2017-7494-4: SMB2 dialect=%s security=0x%x; verify CVE-2017-7494",
               ar_smb2_dialect_name(dialect),
               ar_smb2_security_mode(resp, n));
        return 0;
    }
    n = ar_smb1_open_session(ctx, &fd, &uid, os, sizeof(os), lan, sizeof(lan));
    if (n == 0) {
        ar_out(ctx, "smb-vuln-cve2017-7494-4: SMB1 os=%s lan=%s; verify CVE-2017-7494", os, lan);
        close(fd);
    } else {
        ar_out(ctx, "smb-vuln-cve2017-7494-4: no SMB response; verify CVE-2017-7494");
    }
    return 0;
}
