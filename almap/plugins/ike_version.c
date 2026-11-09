/*
 * plugins/ike_version.c - NSE ike-version analog.
 *
 * Build:
 *   gcc -shared -fPIC -o plugins/ike_version.so plugins/ike_version.c
 * Run:
 *   ./almap -t 127.0.0.1 -p 500 --scan connect --script ./plugins/ike_version.so
 *
 * Sends an IKEv2 IKE_SA_INIT request (AES-CBC-128, HMAC-SHA2-256,
 * DH group 14) and extracts the IKE version from the response header
 * plus any printable Vendor ID payloads.
 * Output: "IKE version: <major>.<minor> [vendor: <id>, ...]".
 * No heap, no external libs: raw POSIX UDP sockets only.
 * Use only on networks you own or have permission to scan.
 */
#include "alscript_net.h"

static void ike_put16(unsigned char *p, unsigned int v) {
    p[0] = (unsigned char)((v >> 8) & 255u);
    p[1] = (unsigned char)(v & 255u);
}

static void ike_put32(unsigned char *p, unsigned int v) {
    p[0] = (unsigned char)((v >> 24) & 255u);
    p[1] = (unsigned char)((v >> 16) & 255u);
    p[2] = (unsigned char)((v >> 8) & 255u);
    p[3] = (unsigned char)(v & 255u);
}

static int ike_printable(const unsigned char *p, size_t n) {
    size_t i;

    if (n < 3) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        if (p[i] < 32 || p[i] > 126) {
            return 0;
        }
    }
    return 1;
}

static void ike_append_vendor(char *dst, size_t cap, const char *text) {
    size_t used;

    if (dst == NULL || text == NULL || cap < 2) {
        return;
    }
    used = strlen(dst);
    if (used + strlen(text) + 3 > cap) {
        return;
    }
    if (used > 0) {
        dst[used++] = ',';
        dst[used++] = ' ';
        dst[used++] = '\0';
    }
    memcpy(dst + used, text, strlen(text) + 1);
}

int almap_script_run(AlScriptContext *ctx) {
    unsigned char req[512];
    unsigned char resp[2048];
    char vendors[1024];
    char version[64];
    size_t off;
    size_t sa;
    size_t sa_len_at;
    size_t prop;
    size_t prop_len_at;
    size_t ke;
    size_t ke_len_at;
    unsigned int major;
    unsigned int minor;
    unsigned int next;
    size_t pos;
    size_t n;
    int guard;
    int nread;

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
    req[0] = 0x10;
    req[1] = 0x11;
    req[2] = 0x12;
    req[3] = 0x13;
    req[4] = 0x14;
    req[5] = 0x15;
    req[6] = 0x16;
    req[7] = 0x17;
    req[16] = 33;   /* next payload: SA */
    req[17] = 0x20; /* IKEv2, minor 0 */
    req[18] = 34;   /* IKE_SA_INIT */
    req[19] = 0x08; /* initiator */
    off = 28;

    /* SA payload with one proposal and four transforms. */
    sa = off;
    req[off++] = 34; /* next payload: KE */
    req[off++] = 0;
    sa_len_at = off;
    off += 2;
    prop = off;
    req[off++] = 2; /* last proposal */
    req[off++] = 0;
    prop_len_at = off;
    off += 2;
    req[off++] = 1; /* proposal number */
    req[off++] = 1; /* protocol ID: IKE */
    req[off++] = 0; /* SPI size */
    req[off++] = 4; /* transforms */

    /* ENCR AES-CBC-128 (type 1, id 12, key length 128). */
    req[off++] = 0;
    req[off++] = 0;
    ike_put16(req + off, 12);
    off += 2;
    req[off++] = 1;
    req[off++] = 0;
    ike_put16(req + off, 12);
    off += 2;
    ike_put16(req + off, 0x800E);
    off += 2;
    ike_put16(req + off, 128);
    off += 2;

    /* PRF HMAC-SHA2-256 (type 2, id 5). */
    req[off++] = 0;
    req[off++] = 0;
    ike_put16(req + off, 8);
    off += 2;
    req[off++] = 2;
    req[off++] = 0;
    ike_put16(req + off, 5);
    off += 2;

    /* Integrity HMAC-SHA2-256-128 (type 3, id 12). */
    req[off++] = 0;
    req[off++] = 0;
    ike_put16(req + off, 8);
    off += 2;
    req[off++] = 3;
    req[off++] = 0;
    ike_put16(req + off, 12);
    off += 2;

    /* DH group 14 (type 4, id 14), last transform. */
    req[off++] = 3;
    req[off++] = 0;
    ike_put16(req + off, 8);
    off += 2;
    req[off++] = 4;
    req[off++] = 0;
    ike_put16(req + off, 14);
    off += 2;

    ike_put16(req + prop_len_at, (unsigned int)(off - prop));
    ike_put16(req + sa_len_at, (unsigned int)(off - sa));

    /* KE payload: DH group 14 with the public value 2. */
    ke = off;
    req[off++] = 0;
    req[off++] = 0;
    ke_len_at = off;
    off += 2;
    ike_put16(req + off, 14);
    off += 2;
    ike_put16(req + off, 0);
    off += 2;
    memset(req + off, 0, 256);
    req[off + 255] = 0x02;
    off += 256;
    ike_put16(req + ke_len_at, (unsigned int)(off - ke));

    ike_put32(req + 24, (unsigned int)off);

    nread = as_udp_exchange(ctx, req, off, (char *)resp, sizeof(resp),
                            ctx->timeout_ms);
    if (nread < 28) {
        return 0;
    }
    n = (size_t)nread;

    major = ((unsigned int)resp[17] >> 4) & 15u;
    minor = (unsigned int)resp[17] & 15u;
    snprintf(version, sizeof(version), "%u.%u", major, minor);

    vendors[0] = '\0';
    next = resp[16];
    pos = 28;
    for (guard = 0; guard < 32 && next != 0; guard++) {
        unsigned int plen;
        if (pos + 4 > n) {
            break;
        }
        plen = ((unsigned int)resp[pos + 2] << 8) |
               (unsigned int)resp[pos + 3];
        if (plen < 4 || pos + plen > n) {
            break;
        }
        if (next == 43 && ike_printable(resp + pos + 4, plen - 4)) {
            char vendor[512];
            size_t copy = (size_t)(plen - 4);
            if (copy >= sizeof(vendor)) {
                copy = sizeof(vendor) - 1;
            }
            memcpy(vendor, resp + pos + 4, copy);
            vendor[copy] = '\0';
            as_clean_field(vendor);
            ike_append_vendor(vendors, sizeof(vendors), vendor);
        }
        next = resp[pos];
        pos += plen;
    }

    if (vendors[0] != '\0') {
        snprintf(ctx->output_buf, (size_t)ctx->output_max,
                 "IKE version: %s vendor: %s", version, vendors);
    } else {
        snprintf(ctx->output_buf, (size_t)ctx->output_max,
                 "IKE version: %s", version);
    }
    return 0;
}
