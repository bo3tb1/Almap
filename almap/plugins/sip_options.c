/*
 * plugins/sip_options.c - NSE sip-options analog.
 *
 * Build:
 *   gcc -shared -fPIC -o plugins/sip_options.so plugins/sip_options.c
 * Run:
 *   ./almap -t 127.0.0.1 -p 5060 --scan connect --script ./plugins/sip_options.so
 *
 * Sends a SIP OPTIONS request over UDP (with a TCP fallback) and
 * extracts the Server response header.
 * Output: "Server: <value>" (empty when no reply or header).
 * No heap, no external libs: raw POSIX sockets only.
 * Use only on networks you own or have permission to scan.
 */
#include "alscript_net.h"

static void build_request(char *req, size_t cap, const char *ip,
                          unsigned int target_ip, int port) {
    unsigned int tag = (target_ip * 2654435761u) ^ (unsigned int)port;
    snprintf(req, cap,
             "OPTIONS sip:%s SIP/2.0\r\n"
             "Via: SIP/2.0/UDP %s:%d;branch=z9hG4bK%08x\r\n"
             "Max-Forwards: 70\r\n"
             "From: <sip:almap@%s>;tag=%08x\r\n"
             "To: <sip:%s>\r\n"
             "Call-ID: %08x@almap\r\n"
             "CSeq: 1 OPTIONS\r\n"
             "Contact: <sip:almap@%s>\r\n"
             "Content-Length: 0\r\n\r\n",
             ip, ip, port, tag, ip, tag, ip, tag, ip);
}

int almap_script_run(AlScriptContext *ctx) {
    int fd;
    int n;
    char ip[64];
    char req[1024];
    char resp[3072];
    char server[1024];

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

    as_ip_text(ctx->target_ip, ip, sizeof(ip));
    build_request(req, sizeof(req), ip, ctx->target_ip, ctx->port);

    n = as_udp_exchange(ctx, req, strlen(req), resp, sizeof(resp),
                        ctx->timeout_ms);
    if (n <= 0) {
        fd = as_connect(ctx);
        if (fd < 0) {
            return 1;
        }
        if (as_send_all(fd, req, strlen(req), ctx->timeout_ms) != 0) {
            close(fd);
            return 1;
        }
        n = as_recv_all(fd, resp, sizeof(resp), ctx->timeout_ms);
        close(fd);
        if (n <= 0) {
            return 0;
        }
    }

    if (as_find_header(resp, "Server", server, sizeof(server))) {
        snprintf(ctx->output_buf, (size_t)ctx->output_max,
                 "Server: %s", server);
    }
    return 0;
}
