/* cloud-aws-imdsv2-token-4 - AWS EC2 IMDSv2 token endpoint
 * Probes a well-known cloud metadata endpoint; benign GET/PUT.
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "PUT", "/latest/api/token", "169.254.169.254", "X-aws-ec2-metadata-token-ttl-seconds: 21600\\r\\n", NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "cloud-aws-imdsv2-token-4: no response from metadata endpoint");
        return 0;
    }
    ar_out(ctx, "cloud-aws-imdsv2-token-4: PUT /latest/api/token [%d]%s", ar_http_status(resp),
           (ar_http_status(resp) == 200) ? " (metadata EXPOSED; verify)" : "");
    return 0;
}
