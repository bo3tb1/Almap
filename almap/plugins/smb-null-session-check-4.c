/* smb-null-session-check-4 - test for anonymous (null) SMB session.
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_smb.h"

int almap_script_run(AlScriptContext *ctx) {
    char os[256];
    char lan[256];
    unsigned int uid = 0;
    int fd = -1;

    if (!ar_valid(ctx)) {
        return 1;
    }
    (void)ar_smb1_open_session(ctx, &fd, &uid, os, sizeof(os), lan, sizeof(lan));
    if (fd >= 0) {
        close(fd);
        ar_out(ctx, "SMB null session ALLOWED (os=%s)", os);
        return 0;
    }
    ar_out(ctx, "SMB null session refused");
    return 0;
}
