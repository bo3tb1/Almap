/*
 * ldap_rootdse.rs - NSE ldap-rootdse analog.
 *
 * Performs an anonymous LDAPv3 bind, searches the Root DSE for the
 * defaultNamingContext attribute, and writes its value.
 * Output: "defaultNamingContext: <dn>" (empty when unavailable).
 * Use only on networks you own or have permission to scan.
 */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;
use std::net::TcpStream;

fn ldap_ber_next(buf: &[u8], end: usize, pos: &mut usize) -> Option<(u8, usize, usize)> {
    let mut p = *pos;
    if p >= end {
        return None;
    }
    let tag = buf[p];
    p += 1;
    if p >= end {
        return None;
    }
    let first = buf[p];
    p += 1;
    let len;
    if first & 0x80 != 0 {
        let nb = (first & 0x7F) as usize;
        if nb < 1 || nb > 3 || p + nb > end {
            return None;
        }
        let mut l = 0usize;
        for _ in 0..nb {
            l = (l << 8) | buf[p] as usize;
            p += 1;
        }
        len = l;
    } else {
        len = first as usize;
    }
    if p + len > end {
        return None;
    }
    let vstart = p;
    *pos = p + len;
    Some((tag, vstart, len))
}

fn ldap_recv_message(stream: &mut TcpStream, cap: usize) -> Option<Vec<u8>> {
    let hdr = recv_exact(stream, 2)?;
    if hdr[0] != 0x30 {
        return None;
    }
    let first = hdr[1];
    let mut hlen = 2usize;
    let mut len;
    let mut extra: Vec<u8> = Vec::new();
    if first & 0x80 != 0 {
        let nb = (first & 0x7F) as usize;
        if nb < 1 || nb > 3 {
            return None;
        }
        extra = recv_exact(stream, nb)?;
        len = 0usize;
        for b in extra.iter() {
            len = (len << 8) | *b as usize;
        }
        hlen += nb;
    } else {
        len = first as usize;
    }
    if len > cap - hlen {
        return None;
    }
    let mut msg = vec![0u8; hlen + len];
    msg[0] = 0x30;
    msg[1] = first;
    if hlen > 2 {
        msg[2..hlen].copy_from_slice(&extra);
    }
    let body = recv_exact(stream, len)?;
    msg[hlen..].copy_from_slice(&body);
    Some(msg)
}

fn ldap_extract_default_naming_context(msg: &[u8]) -> Option<String> {
    let n = msg.len();
    if n < 2 {
        return None;
    }
    let attr = b"defaultNamingContext";
    let mut pos = 0usize;
    let (tag, s, l) = ldap_ber_next(msg, n, &mut pos)?;
    if tag != 0x30 {
        return None;
    }
    let mut end = s + l;
    let mut p = s;
    let (tag, _s, _l) = ldap_ber_next(msg, end, &mut p)?;
    if tag != 0x02 {
        return None;
    }
    let (tag, s, l) = ldap_ber_next(msg, end, &mut p)?;
    if tag != 0x64 {
        return None;
    }
    end = s + l;
    p = s;
    let (tag, _s, _l) = ldap_ber_next(msg, end, &mut p)?;
    if tag != 0x04 {
        return None;
    }
    let (tag, s, l) = ldap_ber_next(msg, end, &mut p)?;
    if tag != 0x30 {
        return None;
    }
    end = s + l;
    p = s;
    while p < end {
        let (tag, s, l) = ldap_ber_next(msg, end, &mut p)?;
        if tag != 0x30 {
            return None;
        }
        let aend = s + l;
        let mut ap = s;
        let (tag, ts, tl) = ldap_ber_next(msg, aend, &mut ap)?;
        if tag != 0x04 {
            return None;
        }
        let (tag, vs, vl) = ldap_ber_next(msg, aend, &mut ap)?;
        if tag != 0x31 {
            return None;
        }
        if tl == attr.len() && &msg[ts..ts + tl] == attr {
            let mut vp = vs;
            let vend = vs + vl;
            if let Some((tag, ds, dl)) = ldap_ber_next(msg, vend, &mut vp) {
                if tag == 0x04 {
                    let copy = dl.min(1023);
                    let out = clean(&String::from_utf8_lossy(&msg[ds..ds + copy]));
                    if !out.is_empty() {
                        return Some(out);
                    }
                }
            }
            return None;
        }
    }
    None
}

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let bind_req: [u8; 14] = [
        0x30, 0x0C, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04,
        0x00, 0x80, 0x00,
    ];
    let mut search_req: Vec<u8> = vec![
        0x30, 0x3B, 0x02, 0x01, 0x02, 0x63, 0x36, 0x04, 0x00, 0x0A, 0x01,
        0x00, 0x0A, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x01,
        0x01, 0x00, 0x87, 0x0B,
    ];
    search_req.extend_from_slice(b"objectClass");
    search_req.extend_from_slice(&[0x30, 0x16, 0x04, 0x14]);
    search_req.extend_from_slice(b"defaultNamingContext");

    if !valid(ctx) {
        return 1;
    }
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => return 1,
    };
    if send_all(&mut s, &bind_req).is_err() {
        return 1;
    }
    let _ = ldap_recv_message(&mut s, 3584);

    if send_all(&mut s, &search_req).is_err() {
        return 1;
    }

    let mut value = String::new();
    for _ in 0..8 {
        let msg = match ldap_recv_message(&mut s, 3584) {
            Some(m) => m,
            None => break,
        };
        if let Some(v) = ldap_extract_default_naming_context(&msg) {
            value = v;
            break;
        }
    }
    drop(s);

    if !value.is_empty() {
        set_out(ctx, &format!("defaultNamingContext: {}", value));
    }
    0
}
