/*
 * kerberos-asreq-full (Rust) - full Kerberos AS-REQ probe (RFC 4120).
 *
 * Faithful port of kerberos-asreq-full.c. Builds a complete DER-encoded
 * AS-REQ with no pre-authentication (AS-REP roasting), frames it with the
 * TCP 4-byte length prefix, and decodes the reply:
 *   AS-REP (0x6B)    -> no pre-auth required (roastable)
 *   KRB-ERROR (0x7E) -> the error code is decoded
 *
 * Read-only: no credentials, no ticket material. Pure std; the fixed-cap
 * buffers of the C become growable Vecs (the wire output is identical).
 * Use only on networks you own or have permission to scan.
 */
#![allow(dead_code, non_snake_case, non_upper_case_globals)]

include!("alscript.rs");

const KRB_DEF_CNAME: &str = "administrator";
const KRB_DEF_REALM: &str = "EXAMPLE.COM";

const DER_INT: u8 = 0x02;
const DER_BITSTR: u8 = 0x03;
const DER_GENSTR: u8 = 0x1B;
const DER_GENTIME: u8 = 0x18;
const DER_SEQ: u8 = 0x30;

/// DER length encoding (port of der_len).
fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    }
}

/// Wrap `content` in a DER TLV (port of der_wrap).
fn der_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 3 + content.len());
    out.push(tag);
    out.extend_from_slice(&der_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// DER INTEGER for a small non-negative value (port of der_int).
fn der_int(v: u32) -> Vec<u8> {
    let bytes = [(v >> 24) as u8, (v >> 16) as u8, (v >> 8) as u8, (v & 0xFF) as u8];
    let mut start = 0usize;
    while start < 3 && bytes[start] == 0 {
        start += 1;
    }
    let mut tmp: Vec<u8> = Vec::new();
    if bytes[start] & 0x80 != 0 {
        tmp.push(0x00);
    }
    tmp.extend_from_slice(&bytes[start..]);
    der_wrap(DER_INT, &tmp)
}

/// DER GeneralString (port of der_genstr).
fn der_genstr(s: &str) -> Vec<u8> {
    der_wrap(DER_GENSTR, s.as_bytes())
}

/// PrincipalName SEQUENCE (port of der_princ).
fn der_princ(name_type: i32, parts: &[&str]) -> Vec<u8> {
    let mut strseq: Vec<u8> = Vec::new();
    for p in parts {
        strseq.extend_from_slice(&der_genstr(p));
    }
    let mut body: Vec<u8> = Vec::new();
    // [0] name-type INTEGER
    let nt = der_int(name_type as u32);
    body.extend_from_slice(&der_wrap(0xA0, &nt));
    // [1] name-string SEQUENCE OF GeneralString
    let seqwrap = der_wrap(DER_SEQ, &strseq);
    body.extend_from_slice(&der_wrap(0xA1, &seqwrap));
    der_wrap(DER_SEQ, &body)
}

/// Build a full AS-REQ for (cname, realm) (port of build_as_req).
fn build_as_req(cname: &str, realm: &str, nonce: u32) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();

    // [0] kdc-options BIT STRING (forwardable|renewable|renewable-ok).
    let opts: [u8; 5] = [0x00, 0x40, 0x81, 0x00, 0x10];
    let bs = der_wrap(DER_BITSTR, &opts);
    body.extend_from_slice(&der_wrap(0xA0, &bs));

    // [1] cname PrincipalName (NT-PRINCIPAL = 1).
    let pr = der_princ(1, &[cname]);
    body.extend_from_slice(&der_wrap(0xA1, &pr));

    // [2] realm GeneralString.
    let r = der_genstr(realm);
    body.extend_from_slice(&der_wrap(0xA2, &r));

    // [3] sname PrincipalName (NT-SRV-INST = 2): krbtgt/REALM.
    let pr = der_princ(2, &["krbtgt", realm]);
    body.extend_from_slice(&der_wrap(0xA3, &pr));

    // [5] till KerberosTime (far future).
    let till = b"20370913024805Z";
    let t = der_wrap(DER_GENTIME, till);
    body.extend_from_slice(&der_wrap(0xA5, &t));

    // [7] nonce INTEGER.
    let nb = der_int(nonce & 0x7FFF_FFFF);
    body.extend_from_slice(&der_wrap(0xA7, &nb));

    // [8] etype SEQUENCE OF INTEGER { AES256, AES128, RC4-HMAC }.
    let mut el: Vec<u8> = Vec::new();
    for &e in &[18u32, 17, 23] {
        el.extend_from_slice(&der_int(e));
    }
    let seq = der_wrap(DER_SEQ, &el);
    body.extend_from_slice(&der_wrap(0xA8, &seq));

    // req-body SEQUENCE, then the KDC-REQ wrapper.
    let reqbody = der_wrap(DER_SEQ, &body);
    let mut kdcreq: Vec<u8> = Vec::new();
    // [1] pvno INTEGER 5
    kdcreq.extend_from_slice(&der_wrap(0xA1, &der_int(5)));
    // [2] msg-type INTEGER 10 (AS-REQ)
    kdcreq.extend_from_slice(&der_wrap(0xA2, &der_int(10)));
    // [4] req-body
    kdcreq.extend_from_slice(&der_wrap(0xA4, &reqbody));
    // KDC-REQ SEQUENCE, then [APPLICATION 10] AS-REQ.
    let sq = der_wrap(DER_SEQ, &kdcreq);
    der_wrap(0x6A, &sq)
}

fn krb_err_name(code: i32) -> &'static str {
    match code {
        6 => "KDC_ERR_C_PRINCIPAL_UNKNOWN (user not found)",
        7 => "KDC_ERR_S_PRINCIPAL_UNKNOWN",
        12 => "KDC_ERR_POLICY",
        18 => "KDC_ERR_CLIENT_REVOKED (account disabled/locked)",
        23 => "KDC_ERR_KEY_EXPIRED (password expired)",
        24 => "KDC_ERR_PREAUTH_FAILED",
        25 => "KDC_ERR_PREAUTH_REQUIRED (account found)",
        68 => "KDC_ERR_WRONG_REALM",
        _ => "KRB error",
    }
}

/// Parse the AS-REQ reply (port of parse_reply). Returns None when the
/// reply is unrecognized, Some((is_rep, errcode)) otherwise.
fn parse_reply(p: &[u8]) -> Option<(bool, i32)> {
    if p.len() < 2 {
        return None;
    }
    if p[0] == 0x6B {
        return Some((true, -1));
    }
    if p[0] != 0x7E {
        return None;
    }
    let mut errcode = -1i32;
    let mut i = 0usize;
    while i + 4 < p.len() {
        if p[i] == 0xA6 && p[i + 2] == DER_INT {
            let ilen = p[i + 3] as usize;
            if ilen >= 1 && ilen <= 4 && i + 4 + ilen <= p.len() {
                let mut v = 0i32;
                for j in 0..ilen {
                    v = (v << 8) | p[i + 4 + j] as i32;
                }
                errcode = v;
                return Some((false, errcode));
            }
        }
        i += 1;
    }
    Some((false, errcode))
}

fn make_nonce(ctx: &AlScriptContext) -> u32 {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u32)
        .unwrap_or(0x1234_5678);
    t ^ (ctx.port as u32).wrapping_mul(2654435761)
}

fn run(ctx: &AlScriptContext) -> i32 {
    if !ar_valid(ctx) {
        return 1;
    }
    let nonce = make_nonce(ctx);
    let req = build_as_req(KRB_DEF_CNAME, KRB_DEF_REALM, nonce);
    if req.is_empty() {
        ar_out(ctx, "kerberos-asreq-full: failed to encode AS-REQ");
        return 0;
    }
    let reqlen = req.len();
    // TCP Kerberos: 4-byte big-endian length prefix.
    let mut framed = Vec::with_capacity(reqlen + 4);
    framed.push((reqlen >> 24) as u8);
    framed.push((reqlen >> 16) as u8);
    framed.push((reqlen >> 8) as u8);
    framed.push((reqlen & 0xFF) as u8);
    framed.extend_from_slice(&req);

    let mut s = match as_connect(ctx) {
        Some(s) => s,
        None => {
            ar_out(
                ctx,
                &format!("kerberos-asreq-full: KDC not reachable on TCP {}", ctx.port),
            );
            return 0;
        }
    };
    if !as_send_all(&mut s, &framed) {
        ar_out(ctx, "kerberos-asreq-full: send failed");
        return 0;
    }
    // Read the 4-byte reply length, then the body.
    let mut lh = [0u8; 4];
    if !as_recv_exact(&mut s, &mut lh) {
        ar_out(
            ctx,
            &format!(
                "kerberos-asreq-full: no AS-REP/KRB-ERROR (realm={} likely not this KDC's)",
                KRB_DEF_REALM
            ),
        );
        return 0;
    }
    let blen = ((lh[0] as usize) << 24)
        | ((lh[1] as usize) << 16)
        | ((lh[2] as usize) << 8)
        | lh[3] as usize;
    if blen == 0 || blen > 4096 {
        ar_out(
            ctx,
            &format!("kerberos-asreq-full: oversized reply ({} bytes)", blen),
        );
        return 0;
    }
    let mut resp = vec![0u8; blen];
    if !as_recv_exact(&mut s, &mut resp) {
        ar_out(ctx, "kerberos-asreq-full: truncated reply");
        return 0;
    }

    match parse_reply(&resp) {
        None => {
            ar_out(
                ctx,
                &format!(
                    "kerberos-asreq-full: KDC reachable, unrecognized reply ({} bytes)",
                    blen
                ),
            );
        }
        Some((true, _)) => {
            ar_out(
                ctx,
                &format!(
                    "kerberos-asreq-full: AS-REP received for {}@{} - NO pre-auth \
                     required (AS-REP roastable)",
                    KRB_DEF_CNAME, KRB_DEF_REALM
                ),
            );
        }
        Some((false, errcode)) => {
            ar_out(
                ctx,
                &format!(
                    "kerberos-asreq-full: KRB-ERROR {} - {} (probe {}@{})",
                    errcode,
                    krb_err_name(errcode),
                    KRB_DEF_CNAME,
                    KRB_DEF_REALM
                ),
            );
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if ctx.is_null() {
        return 1;
    }
    let ctx: &AlScriptContext = unsafe { &*ctx };
    run(ctx)
}
