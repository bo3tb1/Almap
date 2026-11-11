/* rdp_info - RDP X.224 negotiation probe; report selected security protocol. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

fn rdp_protocol_name(p: u32) -> &'static str {
    match p {
        0 => "RDP",
        1 => "TLS",
        2 => "CredSSP",
        3 => "CredSSP (early user auth)",
        4 => "RDSTLS",
        8 => "CredSSP (extended)",
        _ => "unknown",
    }
}

/* First printable run (>=4, <256 bytes) containing a dot and a digit. */
fn rdp_find_version_string(buf: &[u8]) -> Option<String> {
    let n = buf.len();
    let mut i = 0usize;
    while i < n {
        while i < n && (buf[i] < 32 || buf[i] > 126) {
            i += 1;
        }
        let start = i;
        while i < n && buf[i] >= 32 && buf[i] <= 126 {
            i += 1;
        }
        let len = i - start;
        if len < 4 || len >= 256 {
            continue;
        }
        let seg = &buf[start..i];
        let has_dot = seg.contains(&b'.');
        let has_digit = seg.iter().any(|&c| (b'0'..=b'9').contains(&c));
        if has_dot && has_digit {
            let s = clean(&String::from_utf8_lossy(seg));
            return if s.is_empty() { None } else { Some(s) };
        }
    }
    None
}

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    const REQ: [u8; 19] = [
        0x03, 0x00, 0x00, 0x13, 0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00,
        0x03, 0x00, 0x00, 0x00,
    ];
    if !valid(ctx) {
        return 1;
    }
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => return 1,
    };
    if send_all(&mut s, &REQ).is_err() {
        return 1;
    }
    let tpkt = match recv_exact(&mut s, 4) {
        Some(h) => h,
        None => return 0,
    };
    if tpkt[0] != 0x03 {
        return 0;
    }
    let tpkt_len = ((tpkt[2] as usize) << 8) | tpkt[3] as usize;
    if tpkt_len < 11 {
        return 0;
    }
    let mut body_len = tpkt_len - 4;
    if body_len > 2048 - 4 {
        body_len = 2048 - 4;
    }
    let body = match recv_exact(&mut s, body_len) {
        Some(b) => b,
        None => return 0,
    };
    drop(s);

    // Full buffer = 4-byte TPKT header + body (resp[k] == buf[k] in the C).
    let mut buf: Vec<u8> = Vec::with_capacity(4 + body_len);
    buf.extend_from_slice(&tpkt);
    buf.extend_from_slice(&body);

    let os = rdp_find_version_string(&buf).unwrap_or_default();

    if body_len >= 15 && buf[11] == 0x02 {
        let selected = buf[15] as u32
            | ((buf[16] as u32) << 8)
            | ((buf[17] as u32) << 16)
            | ((buf[18] as u32) << 24);
        if !os.is_empty() {
            set_out(
                ctx,
                &format!(
                    "RDP selected protocol: {} ({}) OS: {}",
                    rdp_protocol_name(selected),
                    selected,
                    os
                ),
            );
        } else {
            set_out(
                ctx,
                &format!(
                    "RDP selected protocol: {} ({})",
                    rdp_protocol_name(selected),
                    selected
                ),
            );
        }
        return 0;
    }
    if body_len >= 15 && buf[11] == 0x03 {
        let failure = buf[15] as u32
            | ((buf[16] as u32) << 8)
            | ((buf[17] as u32) << 16)
            | ((buf[18] as u32) << 24);
        set_out(ctx, &format!("RDP negotiation failure: {}", failure));
        return 0;
    }
    if !os.is_empty() {
        set_out(ctx, &format!("RDP OS: {}", os));
    }
    0
}
