/* smb-mbenum-3 - SMB2 dialect and security-mode summary. */
#include "arsenal_smb.h"

int almap_script_run(AlScriptContext *ctx) {
    unsigned char resp[2048];
    unsigned int dialect = 0xFFFF;
    int mode = -1;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_smb2_negotiate(ctx, resp, sizeof(resp));
    if (n > 0) {
        dialect = ar_smb2_dialect(resp, n);
        mode = ar_smb2_security_mode(resp, n);
    }
    if (dialect == 0xFFFF) {
        ar_out(ctx, "SMB mbenum: SMB2 not offered");
        return 0;
    }
    ar_out(ctx, "SMB mbenum: %s security 0x%02x",
           ar_smb2_dialect_name(dialect), mode);
    return 0;
}
