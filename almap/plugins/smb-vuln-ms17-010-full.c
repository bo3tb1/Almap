/*
 * smb-vuln-ms17-010-full - full MS17-010 "EternalBlue" detection.
 *
 * Unlike the lightweight variants (which only confirm that SMBv1 is
 * offered), this port performs the authoritative check used by the Nmap
 * and Metasploit detectors:
 *
 *   1. SMB1 NEGOTIATE (confirm the NT LM 0.12 dialect is offered).
 *   2. Anonymous SESSION SETUP AndX.
 *   3. TREE CONNECT AndX to \\<ip>\IPC$.
 *   4. A SMB_COM_TRANSACTION "PeekNamedPipe" (subcommand 0x23) with an
 *      invalid FID. The server's NT status is decisive:
 *        0xC0000205 STATUS_INSUFF_SERVER_RESOURCES -> VULNERABLE
 *        0xC0000022 STATUS_ACCESS_DENIED           -> patched
 *        0xC0000008 STATUS_INVALID_HANDLE          -> patched
 *
 * Read-only: it sends only an anonymous session and a malformed peek; no
 * exploit payload is delivered.
 *
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_smb.h"

/* SMB1 header bytes shared across the request builders (matches the
 * arsenal's wire convention so UID/TID round-trip byte-for-byte). */
static void ms17_hdr(unsigned char *smb, unsigned char cmd,
                     unsigned int tid, unsigned int uid) {
    memset(smb, 0, 32);
    smb[0] = 0xFF;
    smb[1] = 'S';
    smb[2] = 'M';
    smb[3] = 'B';
    smb[4] = cmd;
    smb[9] = 0x18;            /* flags: canonical + case-insensitive */
    smb[10] = 0x53;           /* flags2 low */
    smb[11] = 0xC8;           /* flags2 high */
    smb[24] = (unsigned char)(tid >> 8);
    smb[25] = (unsigned char)(tid & 0xFFu);
    smb[26] = 0xFE;           /* PID low */
    smb[27] = 0xFF;
    smb[28] = (unsigned char)(uid >> 8);
    smb[29] = (unsigned char)(uid & 0xFFu);
}

/* Read the SMB1 NT_STATUS (little-endian DWORD at header offset 5). */
static unsigned int ms17_status(const unsigned char *resp, int len) {
    if (resp == NULL || len < 9) {
        return 0xFFFFFFFFu;
    }
    return (unsigned int)resp[5] | ((unsigned int)resp[6] << 8) |
           ((unsigned int)resp[7] << 16) | ((unsigned int)resp[8] << 24);
}

/* Send the PeekNamedPipe transaction on an open, tree-connected fd and
 * return the server's NT status (or 0xFFFFFFFF on I/O failure). */
static unsigned int ms17_peek(int fd, unsigned int tid, unsigned int uid,
                              int timeout_ms) {
    unsigned char req[96];
    unsigned char resp[1024];
    unsigned char *smb = req + 4;
    unsigned char *w;
    int n;
    const unsigned int msglen = 74;   /* SMB message length (no NetBIOS) */

    memset(req, 0, sizeof(req));
    /* NetBIOS session message header. */
    req[0] = 0x00;
    req[1] = (unsigned char)((msglen >> 16) & 0xFFu);
    req[2] = (unsigned char)((msglen >> 8) & 0xFFu);
    req[3] = (unsigned char)(msglen & 0xFFu);

    ms17_hdr(smb, 0x25 /* SMB_COM_TRANSACTION */, tid, uid);

    smb[32] = 16;             /* WordCount (14 + SetupCount) */
    w = smb + 33;
    /* TotalParameterCount, TotalDataCount = 0 (w[0..3]) */
    w[4] = 0xFF; w[5] = 0xFF; /* MaxParameterCount = 0xFFFF */
    w[6] = 0xFF; w[7] = 0xFF; /* MaxDataCount = 0xFFFF */
    /* MaxSetupCount(w8)=0, Reserved(w9)=0, Flags(w10..11)=0,
     * Timeout(w12..15)=0, Reserved2(w16..17)=0, ParameterCount(w18..19)=0 */
    w[20] = 0x4A; w[21] = 0x00; /* ParameterOffset = 0x004A (74) */
    /* DataCount(w22..23)=0 */
    w[24] = 0x4A; w[25] = 0x00; /* DataOffset = 0x004A (74) */
    w[26] = 0x02;             /* SetupCount = 2 */
    /* Reserved3(w27)=0 */
    w[28] = 0x23; w[29] = 0x00; /* Setup[0] = 0x0023 PeekNamedPipe */
    w[30] = 0x00; w[31] = 0x00; /* Setup[1] = FID = 0 */

    /* ByteCount (2) at smb[65..66], then the transaction name "\PIPE\". */
    smb[65] = 0x07;
    smb[66] = 0x00;
    smb[67] = '\\';
    smb[68] = 'P';
    smb[69] = 'I';
    smb[70] = 'P';
    smb[71] = 'E';
    smb[72] = '\\';
    smb[73] = 0x00;

    if (as_send_all(fd, req, msglen + 4, timeout_ms) != 0) {
        return 0xFFFFFFFFu;
    }
    n = ar_smb_recv_nb(fd, resp, sizeof(resp), timeout_ms);
    if (n < 9) {
        return 0xFFFFFFFFu;
    }
    return ms17_status(resp, n);
}

int almap_script_run(AlScriptContext *ctx) {
    unsigned char resp[2048];
    char os[256];
    char lan[256];
    char ip[32];
    unsigned int uid = 0;
    unsigned int tid = 0;
    unsigned int d1 = 0xFFFF;
    unsigned int d2 = 0xFFFF;
    unsigned int status;
    int treestatus;
    int fd = -1;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    /* Report the offered dialects first. */
    n = ar_smb2_negotiate(ctx, resp, sizeof(resp));
    if (n > 0) {
        d2 = ar_smb2_dialect(resp, n);
    }
    n = ar_smb1_negotiate(ctx, resp, sizeof(resp));
    if (n > 0) {
        d1 = ar_smb1_dialect(resp, n);
    }
    if (d1 > 5) {
        ar_out(ctx, "smb-vuln-ms17-010-full: SMBv1 not offered "
               "(SMB2 dialect %s); MS17-010 not applicable",
               ar_smb2_dialect_name(d2));
        return 0;
    }

    /* Open an anonymous SMB1 session (negotiate + session setup). */
    if (ar_smb1_open_session(ctx, &fd, &uid, os, sizeof(os),
                             lan, sizeof(lan)) != 0 || fd < 0) {
        ar_out(ctx, "smb-vuln-ms17-010-full: SMBv1 %s offered but session "
               "setup failed; cannot confirm MS17-010",
               ar_smb1_dialect_name(d1));
        return 0;
    }

    as_ip_text(ctx->target_ip, ip, sizeof(ip));
    treestatus = ar_smb1_tree_connect(fd, uid, ip, "IPC$", "?????",
                                      &tid, ctx->timeout_ms);
    if (treestatus != 0) {
        close(fd);
        ar_out(ctx, "smb-vuln-ms17-010-full: SMBv1 %s; IPC$ tree connect "
               "denied (status 0x%08X); likely patched or hardened",
               ar_smb1_dialect_name(d1), (unsigned int)treestatus);
        if (os[0] != '\0') {
            ar_append(ctx, " OS=%s", os);
        }
        return 0;
    }

    status = ms17_peek(fd, tid, uid, ctx->timeout_ms);
    close(fd);

    if (status == 0xC0000205u) {
        ar_out(ctx, "VULNERABLE: MS17-010 EternalBlue (CVE-2017-0143) - "
               "PeekNamedPipe returned STATUS_INSUFF_SERVER_RESOURCES");
    } else if (status == 0xC0000022u || status == 0xC0000008u) {
        ar_out(ctx, "not vulnerable: MS17-010 (PeekNamedPipe status "
               "0x%08X; patched)", status);
    } else if (status == 0xFFFFFFFFu) {
        ar_out(ctx, "potentially vulnerable: MS17-010 (SMBv1 %s, IPC$ "
               "reachable; no PeekNamedPipe reply - verify manually)",
               ar_smb1_dialect_name(d1));
    } else {
        ar_out(ctx, "MS17-010 inconclusive: SMBv1 %s, PeekNamedPipe status "
               "0x%08X", ar_smb1_dialect_name(d1), status);
    }
    if (os[0] != '\0') {
        ar_append(ctx, " OS=%s", os);
    }
    return 0;
}
