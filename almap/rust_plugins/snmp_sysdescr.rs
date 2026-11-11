/* snmp_sysdescr - SNMPv2c GET for sysDescr (1.3.6.1.2.1.1.1.0). */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

/* Returns (tag, value-start, value-len, new-pos) or None. */
fn snmp_ber_next(buf: &[u8], end: usize, pos: usize) -> Option<(u8, usize, usize, usize)> {
    let mut p = pos;
    if p >= end {
        return None;
    }
    let t = buf[p];
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
    Some((t, p, len, p + len))
}

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }

    // Fixed SNMPv2c GET, community "public", sysDescr.0, one varbind.
    let mut req: Vec<u8> = Vec::new();
    req.extend_from_slice(&[0x30, 0x29, 0x02, 0x01, 0x01, 0x04, 0x06]);
    req.extend_from_slice(b"public");
    req.extend_from_slice(&[
        0xA0, 0x1C, 0x02, 0x04, 0x12, 0x34, 0x56, 0x78, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30,
        0x0E, 0x30, 0x0C,
    ]);
    // varbind: OID (sysDescr.0) + NULL
    req.extend_from_slice(&[
        0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
    ]);
    req.extend_from_slice(&[0x05, 0x00]);

    let resp = match udp_exchange(ctx, &req, 2048) {
        Some(r) => r,
        None => return 0,
    };
    let n = resp.len();
    if n < 16 {
        return 0;
    }

    let mut end = n;
    let mut p = 0usize;
    // message SEQUENCE
    let (tag, s, l, _np) = match snmp_ber_next(&resp, end, p) {
        Some(v) => v,
        None => return 0,
    };
    if tag != 0x30 {
        return 0;
    }
    end = s + l;
    p = s;
    // version INTEGER
    let (tag, _s, _l, np) = match snmp_ber_next(&resp, end, p) {
        Some(v) => v,
        None => return 0,
    };
    if tag != 0x02 {
        return 0;
    }
    p = np;
    // community OCTET STRING
    let (tag, _s, _l, np) = match snmp_ber_next(&resp, end, p) {
        Some(v) => v,
        None => return 0,
    };
    if tag != 0x04 {
        return 0;
    }
    p = np;
    // PDU (GetResponse 0xA2)
    let (tag, s, l, _np) = match snmp_ber_next(&resp, end, p) {
        Some(v) => v,
        None => return 0,
    };
    if tag != 0xA2 {
        return 0;
    }
    end = s + l;
    p = s;
    // request-id, error-status, error-index
    for _ in 0..3 {
        let (tag, _s, _l, np) = match snmp_ber_next(&resp, end, p) {
            Some(v) => v,
            None => return 0,
        };
        if tag != 0x02 {
            return 0;
        }
        p = np;
    }
    // varbind list SEQUENCE
    let (tag, s, l, _np) = match snmp_ber_next(&resp, end, p) {
        Some(v) => v,
        None => return 0,
    };
    if tag != 0x30 {
        return 0;
    }
    end = s + l;
    p = s;
    // varbind SEQUENCE
    let (tag, s, l, _np) = match snmp_ber_next(&resp, end, p) {
        Some(v) => v,
        None => return 0,
    };
    if tag != 0x30 {
        return 0;
    }
    end = s + l;
    p = s;
    // OID
    let (tag, _s, _l, np) = match snmp_ber_next(&resp, end, p) {
        Some(v) => v,
        None => return 0,
    };
    if tag != 0x06 {
        return 0;
    }
    p = np;
    // value OCTET STRING
    let (tag, s, l, _np) = match snmp_ber_next(&resp, end, p) {
        Some(v) => v,
        None => return 0,
    };
    if tag != 0x04 {
        return 0;
    }
    let value = clean(&String::from_utf8_lossy(&resp[s..s + l]));
    if !value.is_empty() {
        set_out(ctx, &format!("sysDescr: {}", value));
    }
    0
}
