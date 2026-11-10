/* snmp-sysdescr - SNMPv2c GET for 1.3.6.1.2.1.1.1.0 (sysDescr). */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

fn snmp_ber_next(buf: &[u8], end: usize, pos: &mut usize) -> Option<(u8, usize, usize)> {
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
    let len: usize;
    if (first & 0x80) != 0 {
        let nb = (first & 0x7F) as usize;
        if nb < 1 || nb > 3 || p + nb > end {
            return None;
        }
        let mut v = 0usize;
        for _ in 0..nb {
            v = (v << 8) | buf[p] as usize;
            p += 1;
        }
        len = v;
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

fn snmp_req() -> Vec<u8> {
    let mut req = Vec::with_capacity(43);
    req.extend_from_slice(&[0x30, 0x29, 0x02, 0x01, 0x01, 0x04, 0x06]);
    req.extend_from_slice(b"public");
    req.extend_from_slice(&[
        0xA0, 0x1C, 0x02, 0x04, 0x12, 0x34, 0x56, 0x78, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
        0x30, 0x0E, 0x30, 0x0C,
    ]);
    req.extend_from_slice(&[
        0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
    ]);
    req
}

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let req = snmp_req();
    let resp = match udp_exchange(ctx, &req, 2048) {
        Some(r) => r,
        None => return 0,
    };
    if resp.len() < 16 {
        return 0;
    }
    let mut p = 0usize;
    let (tag, s, l) = match snmp_ber_next(&resp, resp.len(), &mut p) {
        Some(v) => v,
        None => return 0,
    };
    if tag != 0x30 {
        return 0;
    }
    let mut end = s + l;
    p = s;
    let (tag, _, _) = match snmp_ber_next(&resp, end, &mut p) {
        Some(v) => v,
        None => return 0,
    };
    if tag != 0x02 {
        return 0;
    }
    let (tag, _, _) = match snmp_ber_next(&resp, end, &mut p) {
        Some(v) => v,
        None => return 0,
    };
    if tag != 0x04 {
        return 0;
    }
    let (tag, s, l) = match snmp_ber_next(&resp, end, &mut p) {
        Some(v) => v,
        None => return 0,
    };
    if tag != 0xA2 {
        return 0;
    }
    end = s + l;
    p = s;
    for _ in 0..3 {
        let (tag, _, _) = match snmp_ber_next(&resp, end, &mut p) {
            Some(v) => v,
            None => return 0,
        };
        if tag != 0x02 {
            return 0;
        }
    }
    let (tag, s, l) = match snmp_ber_next(&resp, end, &mut p) {
        Some(v) => v,
        None => return 0,
    };
    if tag != 0x30 {
        return 0;
    }
    end = s + l;
    p = s;
    let (tag, s, l) = match snmp_ber_next(&resp, end, &mut p) {
        Some(v) => v,
        None => return 0,
    };
    if tag != 0x30 {
        return 0;
    }
    end = s + l;
    p = s;
    let (tag, _, _) = match snmp_ber_next(&resp, end, &mut p) {
        Some(v) => v,
        None => return 0,
    };
    if tag != 0x06 {
        return 0;
    }
    let (tag, s, l) = match snmp_ber_next(&resp, end, &mut p) {
        Some(v) => v,
        None => return 0,
    };
    if tag != 0x04 {
        return 0;
    }
    let take = l.min(1023);
    let value = clean(&String::from_utf8_lossy(&resp[s..s + take]));
    if !value.is_empty() {
        set_out(ctx, &format!("sysDescr: {}", value));
    }
    0
}
