/* ssh-vuln-cve2024-6387-5 - OpenSSH regreSSHion CVE-2024-6387 banner probe
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char line[512];
    int fd;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = as_connect(ctx);
    if (fd < 0) {
        ar_out(ctx, "ssh-vuln-cve2024-6387-5: TCP %d not reachable", ctx->port);
        return 0;
    }
    n = as_recv_line(fd, line, sizeof(line), ctx->timeout_ms);
    close(fd);
    if (n <= 0) {
        ar_out(ctx, "ssh-vuln-cve2024-6387-5: no SSH banner");
        return 0;
    }
    as_clean_field(line);
    if (ar_contains_ci(line, "OpenSSH")) {
        ar_out(ctx, "ssh-vuln-cve2024-6387-5: banner '%s' (verify patch level)", line);
    } else {
        ar_out(ctx, "ssh-vuln-cve2024-6387-5: banner '%s'", line);
    }
    return 0;
}
