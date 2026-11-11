/*
 * mongodb_info.rs - NSE mongodb-info analog (version only).
 *
 * Sends a MongoDB OP_MSG buildInfo command to admin and extracts the
 * BSON "version" string from the reply.
 * Output: "mongodb_version:<version>" (empty when unavailable).
 * Use only on networks you own or have permission to scan.
 */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

fn put_le32(p: &mut [u8], off: usize, v: u32) {
    p[off] = (v & 255) as u8;
    p[off + 1] = ((v >> 8) & 255) as u8;
    p[off + 2] = ((v >> 16) & 255) as u8;
    p[off + 3] = ((v >> 24) & 255) as u8;
}

fn get_le32(p: &[u8]) -> u32 {
    (p[0] as u32) | ((p[1] as u32) << 8) | ((p[2] as u32) << 16) | ((p[3] as u32) << 24)
}

fn bson_skip_value(doc: &[u8], doclen: usize, pos: &mut usize, ty: u8) -> bool {
    let p = *pos;
    match ty {
        0x01 | 0x09 | 0x11 | 0x12 => {
            if p + 8 > doclen {
                return false;
            }
            *pos = p + 8;
            true
        }
        0x02 | 0x0D | 0x0E => {
            if p + 4 > doclen {
                return false;
            }
            let n = get_le32(&doc[p..]) as usize;
            if p + 4 + n > doclen {
                return false;
            }
            *pos = p + 4 + n;
            true
        }
        0x03 | 0x04 => {
            if p + 4 > doclen {
                return false;
            }
            let n = get_le32(&doc[p..]) as usize;
            if n < 5 || p + n > doclen {
                return false;
            }
            *pos = p + n;
            true
        }
        0x05 => {
            if p + 5 > doclen {
                return false;
            }
            let n = get_le32(&doc[p..]) as usize;
            if p + 5 + n > doclen {
                return false;
            }
            *pos = p + 5 + n;
            true
        }
        0x06 | 0x0A | 0x7F | 0xFF => {
            *pos = p;
            true
        }
        0x07 => {
            if p + 12 > doclen {
                return false;
            }
            *pos = p + 12;
            true
        }
        0x08 => {
            if p + 1 > doclen {
                return false;
            }
            *pos = p + 1;
            true
        }
        0x0B => {
            let mut a = p;
            while a < doclen && doc[a] != 0 {
                a += 1;
            }
            if a >= doclen {
                return false;
            }
            a += 1;
            while a < doclen && doc[a] != 0 {
                a += 1;
            }
            if a >= doclen {
                return false;
            }
            *pos = a + 1;
            true
        }
        0x0C => {
            if p + 4 > doclen {
                return false;
            }
            let n = get_le32(&doc[p..]) as usize;
            if p + 4 + n + 12 > doclen {
                return false;
            }
            *pos = p + 4 + n + 12;
            true
        }
        0x0F => {
            if p + 4 > doclen {
                return false;
            }
            let n = get_le32(&doc[p..]) as usize;
            if n < 4 || p + n > doclen {
                return false;
            }
            *pos = p + n;
            true
        }
        0x13 => {
            if p + 16 > doclen {
                return false;
            }
            *pos = p + 16;
            true
        }
        _ => false,
    }
}

fn bson_find_string(doc: &[u8], avail: usize, name: &str) -> Option<String> {
    if avail < 5 {
        return None;
    }
    let doclen = get_le32(doc) as usize;
    if doclen < 5 || doclen > avail {
        return None;
    }
    let mut pos = 4usize;
    while pos < doclen {
        let ty = doc[pos];
        pos += 1;
        if ty == 0 {
            break;
        }
        let key_start = pos;
        let mut end = pos;
        while end < doclen && doc[end] != 0 {
            end += 1;
        }
        if end >= doclen {
            return None;
        }
        let key = &doc[key_start..end];
        pos = end + 1;
        if key == name.as_bytes() {
            if ty == 0x02 && pos + 4 <= doclen {
                let slen = get_le32(&doc[pos..]) as usize;
                pos += 4;
                if slen < 1 || pos + slen > doclen {
                    return None;
                }
                let copy = (slen - 1).min(255);
                let out = clean(&String::from_utf8_lossy(&doc[pos..pos + copy]));
                return if out.is_empty() { None } else { Some(out) };
            }
            return None;
        }
        if !bson_skip_value(doc, doclen, &mut pos, ty) {
            return None;
        }
    }
    None
}

fn build_buildinfo() -> Vec<u8> {
    let mut doc = vec![0u8; 256];
    let mut off = 4usize;
    doc[off] = 0x10; /* int32 */
    off += 1;
    doc[off..off + 10].copy_from_slice(b"buildInfo\0");
    off += 10;
    put_le32(&mut doc, off, 1);
    off += 4;
    doc[off] = 0x02; /* string */
    off += 1;
    doc[off..off + 4].copy_from_slice(b"$db\0");
    off += 4;
    put_le32(&mut doc, off, 6); /* "admin" including NUL */
    off += 4;
    doc[off..off + 6].copy_from_slice(b"admin\0");
    off += 6;
    doc[off] = 0; /* document terminator */
    off += 1;
    put_le32(&mut doc, 0, off as u32);
    doc.truncate(off);
    doc
}

fn run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let doc = build_buildinfo();
    let doclen = doc.len();
    let msglen = 21 + doclen;
    let mut msg = vec![0u8; msglen];
    put_le32(&mut msg, 0, msglen as u32);
    put_le32(&mut msg, 4, 1); /* requestID */
    put_le32(&mut msg, 8, 0); /* responseTo */
    put_le32(&mut msg, 12, 2013); /* OP_MSG */
    put_le32(&mut msg, 16, 0); /* flagBits */
    msg[20] = 0; /* section kind 0 */
    msg[21..].copy_from_slice(&doc);

    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => return 1,
    };
    if send_all(&mut s, &msg).is_err() {
        return 1;
    }
    let hdr = match recv_exact(&mut s, 16) {
        Some(h) => h,
        None => return 0,
    };
    let rlen = get_le32(&hdr) as usize;
    let opcode = get_le32(&hdr[12..]);
    if rlen < 21 || rlen - 16 > 4000 {
        return 0;
    }
    let resp = match recv_exact(&mut s, rlen - 16) {
        Some(r) => r,
        None => return 0,
    };
    drop(s);

    let (rdoc, avail): (&[u8], usize) = if opcode == 2013 {
        if resp[4] != 0 {
            return 0;
        }
        (&resp[5..], (rlen - 16) - 5)
    } else if opcode == 1 {
        if rlen - 16 < 20 {
            return 0;
        }
        (&resp[20..], (rlen - 16) - 20)
    } else {
        return 0;
    };

    if let Some(version) = bson_find_string(rdoc, avail, "version") {
        set_out(ctx, &format!("mongodb_version:{}", version));
    }
    0
}

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    run(ctx)
}
