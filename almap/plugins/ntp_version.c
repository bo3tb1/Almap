/*
 * plugins/ntp_version.c - NSE ntp-info analog.
 *
 * Build:
 *   gcc -shared -fPIC -o plugins/ntp_version.so plugins/ntp_version.c
 * Run:
 *   ./almap -t 127.0.0.1 -p 123 --scan connect --script ./plugins/ntp_version.so
 *
 * Sends a client-mode NTP v4 request and extracts the response version
 * and stratum fields.
 * Output: "NTP version:<n> stratum:<n>" (empty when no reply).
 * No heap, no external libs: raw POSIX UDP sockets only.
 * Use only on networks you own or have permission to scan.
 */
#include "alscript_net.h"

int almap_script_run(AlScriptContext *ctx) {
    unsigned char req[48];
    char resp[512];
    int n;
    unsigned int version;
    unsigned int stratum;

    if (ctx == NULL || ctx->output_buf == NULL || ctx->output_max < 2) {
        return 1;
    }
    ctx->output_buf[0] = '\0';
    if (ctx->port < 1 || ctx->port > 65535 || ctx->timeout_ms <= 0) {
        return 1;
    }
    if (ctx->target_ip == 0) {
        return 1;
    }

    memset(req, 0, sizeof(req));
    req[0] = 0x23; /* LI=0, version=4, mode=3 (client) */
    n = as_udp_exchange(ctx, req, sizeof(req), resp, sizeof(resp),
                        ctx->timeout_ms);
    if (n < 2) {
        return 0;
    }
    version = ((unsigned char)resp[0] >> 3) & 7u;
    stratum = (unsigned char)resp[1];
    snprintf(ctx->output_buf, (size_t)ctx->output_max,
             "NTP version:%u stratum:%u", version, stratum);
    return 0;
}
