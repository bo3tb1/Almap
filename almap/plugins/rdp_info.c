/*
 * plugins/rdp_info.c - NSE rdp-ntlm-info analog (negotiation only).
 *
 * Build:
 *   gcc -shared -fPIC -o plugins/rdp_info.so plugins/rdp_info.c
 * Run:
 *   ./almap -t 127.0.0.1 -p 3389 --scan connect --script ./plugins/rdp_info.so
 *
 * Sends an RDP X.224 Connection Request with an RDP Negotiation
 * Request (TLS | CredSSP) and parses the Negotiation Response. It
 * reports the selected security protocol and, when the reply carries a
 * printable dotted version string, that OS/version text as well.
 * Output: "RDP selected protocol: <name> (<n>) [OS: <text>]".
 * No heap, no external libs: raw POSIX sockets only.
 * Use only on networks you own or have permission to scan.
 */
#include "alscript_net.h"

static const char *rdp_protocol_name(unsigned int p) {
    switch (p) {
        case 0: return "RDP";
        case 1: return "TLS";
        case 2: return "CredSSP";
        case 3: return "CredSSP (early user auth)";
        case 4: return "RDSTLS";
        case 8: return "CredSSP (extended)";
        default: return "unknown";
    }
}

static int rdp_find_version_string(const unsigned char *buf, size_t n,
                                   char *out, size_t outcap) {
    size_t i = 0;

    if (out == NULL || outcap < 2) {
        return 0;
    }
    out[0] = '\0';
    while (i < n) {
        size_t start;
        size_t len;
        int has_dot = 0;
        int has_digit = 0;
        size_t k;

        while (i < n && (buf[i] < 32 || buf[i] > 126)) {
            i++;
        }
        start = i;
        while (i < n && buf[i] >= 32 && buf[i] <= 126) {
            i++;
        }
        len = i - start;
        if (len < 4 || len >= outcap) {
            continue;
        }
        for (k = 0; k < len; k++) {
            if (buf[start + k] == '.') {
                has_dot = 1;
            }
            if (buf[start + k] >= '0' && buf[start + k] <= '9') {
                has_digit = 1;
            }
        }
        if (has_dot && has_digit) {
            memcpy(out, buf + start, len);
            out[len] = '\0';
            as_clean_field(out);
            return out[0] != '\0';
        }
    }
    return 0;
}

int almap_script_run(AlScriptContext *ctx) {
    static const unsigned char req[19] = {
        0x03, 0x00, 0x00, 0x13,
        0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00
    };
    unsigned char resp[2048];
    char os[256];
    unsigned int tpkt_len;
    unsigned int selected;
    size_t body_len;
    int fd;

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

    fd = as_connect(ctx);
    if (fd < 0) {
        return 1;
    }
    if (as_send_all(fd, req, sizeof(req), ctx->timeout_ms) != 0) {
        close(fd);
        return 1;
    }
    if (as_recv_exact(fd, resp, 4, ctx->timeout_ms) != 0) {
        close(fd);
        return 0;
    }
    if (resp[0] != 0x03) {
        close(fd);
        return 0;
    }
    tpkt_len = ((unsigned int)resp[2] << 8) | (unsigned int)resp[3];
    if (tpkt_len < 11) {
        close(fd);
        return 0;
    }
    body_len = (size_t)tpkt_len - 4;
    if (body_len > sizeof(resp) - 4) {
        body_len = sizeof(resp) - 4;
    }
    if (as_recv_exact(fd, resp + 4, body_len, ctx->timeout_ms) != 0) {
        close(fd);
        return 0;
    }
    close(fd);

    os[0] = '\0';
    (void)rdp_find_version_string(resp, body_len + 4, os, sizeof(os));

    if (body_len >= 15 && resp[11] == 0x02) {
        selected = (unsigned int)resp[15] | ((unsigned int)resp[16] << 8) |
                   ((unsigned int)resp[17] << 16) |
                   ((unsigned int)resp[18] << 24);
        if (os[0] != '\0') {
            snprintf(ctx->output_buf, (size_t)ctx->output_max,
                     "RDP selected protocol: %s (%u) OS: %s",
                     rdp_protocol_name(selected), selected, os);
        } else {
            snprintf(ctx->output_buf, (size_t)ctx->output_max,
                     "RDP selected protocol: %s (%u)",
                     rdp_protocol_name(selected), selected);
        }
        return 0;
    }
    if (body_len >= 15 && resp[11] == 0x03) {
        unsigned int failure = (unsigned int)resp[15] |
                               ((unsigned int)resp[16] << 8) |
                               ((unsigned int)resp[17] << 16) |
                               ((unsigned int)resp[18] << 24);
        snprintf(ctx->output_buf, (size_t)ctx->output_max,
                 "RDP negotiation failure: %u", failure);
        return 0;
    }
    if (os[0] != '\0') {
        snprintf(ctx->output_buf, (size_t)ctx->output_max,
                 "RDP OS: %s", os);
    }
    return 0;
}
