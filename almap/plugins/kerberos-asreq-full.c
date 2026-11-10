/*
 * kerberos-asreq-full - full Kerberos AS-REQ probe (RFC 4120).
 *
 * Builds a complete, DER-encoded AS-REQ (no pre-authentication, as used
 * by AS-REP roasting) for a client principal in a realm, sends it to the
 * KDC over TCP/88 with the 4-byte length prefix, and decodes the reply:
 *   - AS-REP            -> the account requires no pre-auth (roastable)
 *   - KRB-ERROR         -> the error code is decoded (PREAUTH_REQUIRED,
 *                          C_PRINCIPAL_UNKNOWN, WRONG_REALM, ...)
 *
 * The AlScript context only carries an IP/port, so the client principal
 * and realm are sensible defaults; a matching realm yields the most
 * informative reply. Read-only: no credentials are sent and no ticket
 * material is used.
 *
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

/* --- Defaults (no realm/username is available from the context). --- */
#define KRB_DEF_CNAME "administrator"
#define KRB_DEF_REALM "EXAMPLE.COM"

/* ASN.1 / DER tags. */
#define DER_INT 0x02
#define DER_BITSTR 0x03
#define DER_GENSTR 0x1B
#define DER_GENTIME 0x18
#define DER_SEQ 0x30

/* Encode a DER length into out (1..3 bytes). Returns the byte count. */
static size_t der_len(size_t len, unsigned char *out) {
    if (len < 0x80) {
        out[0] = (unsigned char)len;
        return 1;
    }
    if (len < 0x100) {
        out[0] = 0x81;
        out[1] = (unsigned char)len;
        return 2;
    }
    out[0] = 0x82;
    out[1] = (unsigned char)(len >> 8);
    out[2] = (unsigned char)(len & 0xFF);
    return 3;
}

/* Wrap content[0..clen) in a DER TLV (tag + length + content) written to
 * dst. Returns the total length, or 0 if it would not fit in cap. */
static size_t der_wrap(unsigned char tag, const unsigned char *content,
                       size_t clen, unsigned char *dst, size_t cap) {
    unsigned char lb[3];
    size_t ln = der_len(clen, lb);

    if (1 + ln + clen > cap) {
        return 0;
    }
    dst[0] = tag;
    memcpy(dst + 1, lb, ln);
    if (clen > 0 && content != NULL) {
        memcpy(dst + 1 + ln, content, clen);
    }
    return 1 + ln + clen;
}

/* DER INTEGER for a small non-negative value. */
static size_t der_int(unsigned int v, unsigned char *dst, size_t cap) {
    unsigned char tmp[5];
    size_t n = 0;
    unsigned char bytes[4];
    int i;
    int start;

    bytes[0] = (unsigned char)(v >> 24);
    bytes[1] = (unsigned char)(v >> 16);
    bytes[2] = (unsigned char)(v >> 8);
    bytes[3] = (unsigned char)(v & 0xFF);
    start = 0;
    while (start < 3 && bytes[start] == 0) {
        start++;
    }
    /* Prepend 0x00 if the top bit is set (keep it non-negative). */
    if (bytes[start] & 0x80) {
        tmp[n++] = 0x00;
    }
    for (i = start; i < 4; i++) {
        tmp[n++] = bytes[i];
    }
    return der_wrap(DER_INT, tmp, n, dst, cap);
}

/* DER GeneralString. */
static size_t der_genstr(const char *s, unsigned char *dst, size_t cap) {
    return der_wrap(DER_GENSTR, (const unsigned char *)s, strlen(s), dst, cap);
}

/* PrincipalName ::= SEQUENCE { [0] name-type INTEGER,
 *                              [1] name-string SEQUENCE OF GeneralString } */
static size_t der_princ(int name_type, const char *const *parts, int nparts,
                        unsigned char *dst, size_t cap) {
    unsigned char strseq[256];
    unsigned char nt[16];
    unsigned char field[16];
    unsigned char body[320];
    size_t so = 0;
    size_t nt_n;
    size_t f_n;
    size_t bo = 0;
    size_t w;
    int i;

    for (i = 0; i < nparts; i++) {
        w = der_genstr(parts[i], strseq + so, sizeof(strseq) - so);
        if (w == 0) {
            return 0;
        }
        so += w;
    }
    /* name-type: [0] INTEGER */
    nt_n = der_int((unsigned int)name_type, nt, sizeof(nt));
    w = der_wrap(0xA0, nt, nt_n, field, sizeof(field));
    if (w == 0) {
        return 0;
    }
    f_n = w;
    memcpy(body + bo, field, f_n);
    bo += f_n;
    /* name-string: [1] SEQUENCE OF GeneralString */
    {
        unsigned char seqwrap[300];
        unsigned char ctx1[320];
        size_t sw = der_wrap(DER_SEQ, strseq, so, seqwrap, sizeof(seqwrap));
        size_t cw;
        if (sw == 0) {
            return 0;
        }
        cw = der_wrap(0xA1, seqwrap, sw, ctx1, sizeof(ctx1));
        if (cw == 0 || bo + cw > sizeof(body)) {
            return 0;
        }
        memcpy(body + bo, ctx1, cw);
        bo += cw;
    }
    return der_wrap(DER_SEQ, body, bo, dst, cap);
}

/* Build a full AS-REQ for (cname, realm) into out. Returns length or 0. */
static size_t build_as_req(const char *cname, const char *realm,
                           unsigned int nonce, unsigned char *out,
                           size_t cap) {
    unsigned char body[1024];
    size_t bo = 0;
    size_t w;
    unsigned char tmp[512];

    /* [0] kdc-options BIT STRING (forwardable|renewable|renewable-ok). */
    {
        unsigned char opts[5] = { 0x00, 0x40, 0x81, 0x00, 0x10 };
        unsigned char bs[8];
        size_t bn = der_wrap(DER_BITSTR, opts, sizeof(opts), bs, sizeof(bs));
        w = der_wrap(0xA0, bs, bn, body + bo, sizeof(body) - bo);
        if (w == 0) {
            return 0;
        }
        bo += w;
    }
    /* [1] cname PrincipalName (NT-PRINCIPAL = 1). */
    {
        const char *parts[1];
        unsigned char pr[256];
        size_t pn;
        parts[0] = cname;
        pn = der_princ(1, parts, 1, pr, sizeof(pr));
        if (pn == 0) {
            return 0;
        }
        w = der_wrap(0xA1, pr, pn, body + bo, sizeof(body) - bo);
        if (w == 0) {
            return 0;
        }
        bo += w;
    }
    /* [2] realm GeneralString. */
    {
        unsigned char r[128];
        size_t rn = der_genstr(realm, r, sizeof(r));
        if (rn == 0) {
            return 0;
        }
        w = der_wrap(0xA2, r, rn, body + bo, sizeof(body) - bo);
        if (w == 0) {
            return 0;
        }
        bo += w;
    }
    /* [3] sname PrincipalName (NT-SRV-INST = 2): krbtgt/REALM. */
    {
        const char *parts[2];
        unsigned char pr[256];
        size_t pn;
        parts[0] = "krbtgt";
        parts[1] = realm;
        pn = der_princ(2, parts, 2, pr, sizeof(pr));
        if (pn == 0) {
            return 0;
        }
        w = der_wrap(0xA3, pr, pn, body + bo, sizeof(body) - bo);
        if (w == 0) {
            return 0;
        }
        bo += w;
    }
    /* [5] till KerberosTime (far future). */
    {
        const char till[] = "20370913024805Z";
        unsigned char t[32];
        size_t tn = der_wrap(DER_GENTIME, (const unsigned char *)till,
                             sizeof(till) - 1, t, sizeof(t));
        w = der_wrap(0xA5, t, tn, body + bo, sizeof(body) - bo);
        if (w == 0) {
            return 0;
        }
        bo += w;
    }
    /* [7] nonce INTEGER. */
    {
        unsigned char nb[8];
        size_t nn = der_int(nonce & 0x7FFFFFFFu, nb, sizeof(nb));
        w = der_wrap(0xA7, nb, nn, body + bo, sizeof(body) - bo);
        if (w == 0) {
            return 0;
        }
        bo += w;
    }
    /* [8] etype SEQUENCE OF INTEGER { AES256, AES128, RC4-HMAC }. */
    {
        unsigned char el[32];
        unsigned char seq[48];
        unsigned char ctx8[48];
        size_t eo = 0;
        size_t sn;
        size_t cn;
        static const unsigned int etypes[] = { 18, 17, 23 };
        size_t i;
        for (i = 0; i < sizeof(etypes) / sizeof(etypes[0]); i++) {
            size_t en = der_int(etypes[i], el + eo, sizeof(el) - eo);
            if (en == 0) {
                return 0;
            }
            eo += en;
        }
        sn = der_wrap(DER_SEQ, el, eo, seq, sizeof(seq));
        cn = der_wrap(0xA8, seq, sn, ctx8, sizeof(ctx8));
        if (cn == 0 || bo + cn > sizeof(body)) {
            return 0;
        }
        memcpy(body + bo, ctx8, cn);
        bo += cn;
    }

    /* req-body = SEQUENCE { ...fields... }, then KDC-REQ wrapper. */
    {
        unsigned char reqbody[1100];
        unsigned char kdcreq[1200];
        size_t rb;
        size_t ko = 0;
        size_t sq;

        rb = der_wrap(DER_SEQ, body, bo, reqbody, sizeof(reqbody));
        if (rb == 0) {
            return 0;
        }
        /* [1] pvno INTEGER 5 */
        w = der_int(5, tmp, sizeof(tmp));
        w = der_wrap(0xA1, tmp, w, kdcreq + ko, sizeof(kdcreq) - ko);
        if (w == 0) {
            return 0;
        }
        ko += w;
        /* [2] msg-type INTEGER 10 (AS-REQ) */
        w = der_int(10, tmp, sizeof(tmp));
        w = der_wrap(0xA2, tmp, w, kdcreq + ko, sizeof(kdcreq) - ko);
        if (w == 0) {
            return 0;
        }
        ko += w;
        /* [4] req-body */
        w = der_wrap(0xA4, reqbody, rb, kdcreq + ko, sizeof(kdcreq) - ko);
        if (w == 0) {
            return 0;
        }
        ko += w;
        /* KDC-REQ SEQUENCE, then [APPLICATION 10] AS-REQ. */
        sq = der_wrap(DER_SEQ, kdcreq, ko, tmp, sizeof(tmp));
        if (sq == 0) {
            return 0;
        }
        return der_wrap(0x6A, tmp, sq, out, cap);
    }
}

static const char *krb_err_name(int code) {
    switch (code) {
        case 6: return "KDC_ERR_C_PRINCIPAL_UNKNOWN (user not found)";
        case 7: return "KDC_ERR_S_PRINCIPAL_UNKNOWN";
        case 12: return "KDC_ERR_POLICY";
        case 18: return "KDC_ERR_CLIENT_REVOKED (account disabled/locked)";
        case 23: return "KDC_ERR_KEY_EXPIRED (password expired)";
        case 24: return "KDC_ERR_PREAUTH_FAILED";
        case 25: return "KDC_ERR_PREAUTH_REQUIRED (account found)";
        case 68: return "KDC_ERR_WRONG_REALM";
        default: return "KRB error";
    }
}

/* Parse the AS-REQ reply. The DER starts with an application tag:
 *   0x6B = AS-REP, 0x7E = KRB-ERROR. For KRB-ERROR the error-code lives
 * in the [6] (0xA6) field as a small INTEGER. */
static int parse_reply(const unsigned char *p, int len, int *is_rep,
                       int *errcode) {
    int i;

    *is_rep = 0;
    *errcode = -1;
    if (p == NULL || len < 2) {
        return -1;
    }
    if (p[0] == 0x6B) {
        *is_rep = 1;
        return 0;
    }
    if (p[0] != 0x7E) {
        return -1;
    }
    /* Find [6] error-code: 0xA6 <len> 0x02 <ilen> <bytes...>. */
    for (i = 0; i + 4 < len; i++) {
        if (p[i] == 0xA6 && p[i + 2] == DER_INT) {
            int ilen = p[i + 3];
            int v = 0;
            int j;
            if (ilen < 1 || ilen > 4 || i + 4 + ilen > len) {
                continue;
            }
            for (j = 0; j < ilen; j++) {
                v = (v << 8) | p[i + 4 + j];
            }
            *errcode = v;
            return 0;
        }
    }
    return 0;
}

int almap_script_run(AlScriptContext *ctx) {
    unsigned char req[1400];
    unsigned char framed[1408];
    unsigned char resp[4096];
    size_t reqlen;
    unsigned int nonce;
    int fd;
    int n;
    int is_rep = 0;
    int errcode = -1;

    if (!ar_valid(ctx)) {
        return 1;
    }
    srand((unsigned int)time(NULL) ^ (unsigned int)ctx->port);
    nonce = ((unsigned int)rand() << 16) ^ (unsigned int)rand();

    reqlen = build_as_req(KRB_DEF_CNAME, KRB_DEF_REALM, nonce, req,
                          sizeof(req));
    if (reqlen == 0) {
        ar_out(ctx, "kerberos-asreq-full: failed to encode AS-REQ");
        return 0;
    }
    /* TCP Kerberos: 4-byte big-endian length prefix. */
    framed[0] = (unsigned char)(reqlen >> 24);
    framed[1] = (unsigned char)(reqlen >> 16);
    framed[2] = (unsigned char)(reqlen >> 8);
    framed[3] = (unsigned char)(reqlen & 0xFF);
    memcpy(framed + 4, req, reqlen);

    fd = as_connect(ctx);
    if (fd < 0) {
        ar_out(ctx, "kerberos-asreq-full: KDC not reachable on TCP %d",
               ctx->port);
        return 0;
    }
    if (as_send_all(fd, framed, reqlen + 4, ctx->timeout_ms) != 0) {
        close(fd);
        ar_out(ctx, "kerberos-asreq-full: send failed");
        return 0;
    }
    /* Read the 4-byte reply length, then the body. */
    {
        unsigned char lh[4];
        unsigned int blen;
        if (as_recv_exact(fd, lh, 4, ctx->timeout_ms) != 0) {
            close(fd);
            ar_out(ctx, "kerberos-asreq-full: no AS-REP/KRB-ERROR "
                   "(realm=%s likely not %s)", KRB_DEF_REALM, "this KDC's");
            return 0;
        }
        blen = ((unsigned int)lh[0] << 24) | ((unsigned int)lh[1] << 16) |
               ((unsigned int)lh[2] << 8) | lh[3];
        if (blen == 0 || blen > sizeof(resp)) {
            close(fd);
            ar_out(ctx, "kerberos-asreq-full: oversized reply (%u bytes)",
                   blen);
            return 0;
        }
        if (as_recv_exact(fd, resp, blen, ctx->timeout_ms) != 0) {
            close(fd);
            ar_out(ctx, "kerberos-asreq-full: truncated reply");
            return 0;
        }
        n = (int)blen;
    }
    close(fd);

    if (parse_reply(resp, n, &is_rep, &errcode) != 0) {
        ar_out(ctx, "kerberos-asreq-full: KDC reachable, unrecognized reply "
               "(%d bytes)", n);
        return 0;
    }
    if (is_rep) {
        ar_out(ctx, "kerberos-asreq-full: AS-REP received for %s@%s "
               "- NO pre-auth required (AS-REP roastable)",
               KRB_DEF_CNAME, KRB_DEF_REALM);
        return 0;
    }
    ar_out(ctx, "kerberos-asreq-full: KRB-ERROR %d - %s (probe %s@%s)",
           errcode, krb_err_name(errcode), KRB_DEF_CNAME, KRB_DEF_REALM);
    return 0;
}
