/* kerberos-asreq-full - Kerberos AS-REQ probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
const CNAME: &str = "administrator";
    const REALM: &str = "EXAMPLE.COM";

    fn der_len(len: usize, out: &mut [u8]) -> usize {
        if len < 0x80 { out[0] = len as u8; return 1; }
        if len < 0x100 { out[0] = 0x81; out[1] = len as u8; return 2; }
        out[0] = 0x82; out[1] = (len >> 8) as u8; out[2] = (len & 0xff) as u8; 3
    }
    fn der_wrap(tag: u8, content: &[u8], dst: &mut [u8]) -> usize {
        let mut lb = [0u8; 3];
        let ln = der_len(content.len(), &mut lb);
        if 1 + ln + content.len() > dst.len() { return 0; }
        dst[0] = tag;
        dst[1..1 + ln].copy_from_slice(&lb[..ln]);
        dst[1 + ln..1 + ln + content.len()].copy_from_slice(content);
        1 + ln + content.len()
    }
    fn der_int(v: u32, dst: &mut [u8]) -> usize {
        let bytes = [(v >> 24) as u8, (v >> 16) as u8, (v >> 8) as u8, v as u8];
        let mut start = 0usize;
        while start < 3 && bytes[start] == 0 { start += 1; }
        let mut tmp = Vec::new();
        if bytes[start] & 0x80 != 0 { tmp.push(0u8); }
        tmp.extend_from_slice(&bytes[start..]);
        der_wrap(0x02, &tmp, dst)
    }
    fn der_genstr(s: &str, dst: &mut [u8]) -> usize {
        der_wrap(0x1B, s.as_bytes(), dst)
    }
    fn der_princ(name_type: i32, parts: &[&str], dst: &mut [u8]) -> usize {
        let mut strseq = [0u8; 256];
        let mut so = 0usize;
        for p in parts {
            let w = der_genstr(p, &mut strseq[so..]);
            if w == 0 { return 0; }
            so += w;
        }
        let mut nt = [0u8; 16];
        let nt_n = der_int(name_type as u32, &mut nt);
        let mut field = [0u8; 16];
        let f_n = der_wrap(0xA0, &nt[..nt_n], &mut field);
        if f_n == 0 { return 0; }
        let mut body = [0u8; 320];
        let mut bo = 0usize;
        body[..f_n].copy_from_slice(&field[..f_n]);
        bo += f_n;
        let mut seqwrap = [0u8; 300];
        let sw = der_wrap(0x30, &strseq[..so], &mut seqwrap);
        if sw == 0 { return 0; }
        let mut ctx1 = [0u8; 320];
        let cw = der_wrap(0xA1, &seqwrap[..sw], &mut ctx1);
        if cw == 0 || bo + cw > body.len() { return 0; }
        body[bo..bo + cw].copy_from_slice(&ctx1[..cw]);
        bo += cw;
        der_wrap(0x30, &body[..bo], dst)
    }
    fn build_as_req(cname: &str, realm: &str, nonce: u32, out: &mut [u8]) -> usize {
        let mut body = [0u8; 1024];
        let mut bo = 0usize;
        let mut tmp = [0u8; 512];
        // [0] kdc-options
        let opts: [u8; 5] = [0x00, 0x40, 0x81, 0x00, 0x10];
        let mut bs = [0u8; 8];
        let bn = der_wrap(0x03, &opts, &mut bs);
        let w = der_wrap(0xA0, &bs[..bn], &mut body[bo..]);
        if w == 0 { return 0; }
        bo += w;
        // [1] cname
        let mut pr = [0u8; 256];
        let pn = der_princ(1, &[cname], &mut pr);
        if pn == 0 { return 0; }
        let w = der_wrap(0xA1, &pr[..pn], &mut body[bo..]);
        if w == 0 { return 0; }
        bo += w;
        // [2] realm
        let mut r = [0u8; 128];
        let rn = der_genstr(realm, &mut r);
        if rn == 0 { return 0; }
        let w = der_wrap(0xA2, &r[..rn], &mut body[bo..]);
        if w == 0 { return 0; }
        bo += w;
        // [3] sname
        let mut pr = [0u8; 256];
        let pn = der_princ(2, &["krbtgt", realm], &mut pr);
        if pn == 0 { return 0; }
        let w = der_wrap(0xA3, &pr[..pn], &mut body[bo..]);
        if w == 0 { return 0; }
        bo += w;
        // [5] till
        let mut t = [0u8; 32];
        let tn = der_wrap(0x18, b"20370913024805Z", &mut t);
        let w = der_wrap(0xA5, &t[..tn], &mut body[bo..]);
        if w == 0 { return 0; }
        bo += w;
        // [7] nonce
        let mut nb = [0u8; 8];
        let nn = der_int(nonce & 0x7FFFFFFF, &mut nb);
        let w = der_wrap(0xA7, &nb[..nn], &mut body[bo..]);
        if w == 0 { return 0; }
        bo += w;
        // [8] etypes
        let mut el = [0u8; 32];
        let mut eo = 0usize;
        for e in [18u32, 17, 23] {
            let en = der_int(e, &mut el[eo..]);
            if en == 0 { return 0; }
            eo += en;
        }
        let mut seq = [0u8; 48];
        let sn = der_wrap(0x30, &el[..eo], &mut seq);
        let mut ctx8 = [0u8; 48];
        let cn = der_wrap(0xA8, &seq[..sn], &mut ctx8);
        if cn == 0 || bo + cn > body.len() { return 0; }
        body[bo..bo + cn].copy_from_slice(&ctx8[..cn]);
        bo += cn;
        // req-body + KDC-REQ
        let mut reqbody = [0u8; 1100];
        let rb = der_wrap(0x30, &body[..bo], &mut reqbody);
        if rb == 0 { return 0; }
        let mut kdcreq = [0u8; 1200];
        let mut ko = 0usize;
        let w = der_int(5, &mut tmp);
        let w = der_wrap(0xA1, &tmp[..w], &mut kdcreq[ko..]);
        if w == 0 { return 0; }
        ko += w;
        let w = der_int(10, &mut tmp);
        let w = der_wrap(0xA2, &tmp[..w], &mut kdcreq[ko..]);
        if w == 0 { return 0; }
        ko += w;
        let w = der_wrap(0xA4, &reqbody[..rb], &mut kdcreq[ko..]);
        if w == 0 { return 0; }
        ko += w;
        let sq = der_wrap(0x30, &kdcreq[..ko], &mut tmp);
        if sq == 0 { return 0; }
        der_wrap(0x6A, &tmp[..sq], out)
    }
    fn err_name(code: i32) -> &'static str {
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

    let nonce = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0))
        ^ (unsafe { (*ctx).port } as u32).wrapping_mul(2654435761);
    let mut req = [0u8; 1400];
    let reqlen = build_as_req(CNAME, REALM, nonce, &mut req);
    if reqlen == 0 {
        set_out(ctx, "kerberos-asreq-full: failed to encode AS-REQ");
        return 0;
    }
    let mut framed = vec![0u8; reqlen + 4];
    framed[0] = (reqlen >> 24) as u8;
    framed[1] = (reqlen >> 16) as u8;
    framed[2] = (reqlen >> 8) as u8;
    framed[3] = reqlen as u8;
    framed[4..].copy_from_slice(&req[..reqlen]);

    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            set_out(ctx, &format!("kerberos-asreq-full: KDC not reachable on TCP {}", unsafe { (*ctx).port }));
            return 0;
        }
    };
    if send_all(&mut s, &framed).is_err() {
        set_out(ctx, "kerberos-asreq-full: send failed");
        return 0;
    }
    let lh = match recv_exact(&mut s, 4) {
        Some(v) => v,
        None => {
            set_out(ctx, &format!("kerberos-asreq-full: no AS-REP/KRB-ERROR (realm={} likely not {})", REALM, "this KDC's"));
            return 0;
        }
    };
    let blen = ((lh[0] as usize) << 24) | ((lh[1] as usize) << 16)
        | ((lh[2] as usize) << 8) | lh[3] as usize;
    if blen == 0 || blen > 4096 {
        set_out(ctx, &format!("kerberos-asreq-full: oversized reply ({} bytes)", blen));
        return 0;
    }
    let resp = match recv_exact(&mut s, blen) {
        Some(v) => v,
        None => { set_out(ctx, "kerberos-asreq-full: truncated reply"); return 0; }
    };
    let n = resp.len();
    if resp[0] == 0x6B {
        set_out(ctx, &format!("kerberos-asreq-full: AS-REP received for {}@{} - NO pre-auth required (AS-REP roastable)", CNAME, REALM));
        return 0;
    }
    let mut errcode: i32 = -1;
    if resp[0] == 0x7E {
        let mut i = 0usize;
        while i + 4 < n {
            if resp[i] == 0xA6 && resp[i + 2] == 0x02 {
                let ilen = resp[i + 3] as usize;
                if ilen >= 1 && ilen <= 4 && i + 4 + ilen <= n {
                    let mut v: i32 = 0;
                    for j in 0..ilen { v = (v << 8) | resp[i + 4 + j] as i32; }
                    errcode = v;
                    break;
                }
            }
            i += 1;
        }
    }
    set_out(ctx, &format!("kerberos-asreq-full: KRB-ERROR {} - {} (probe {}@{})",
                          errcode, err_name(errcode), CNAME, REALM));
    0
}
