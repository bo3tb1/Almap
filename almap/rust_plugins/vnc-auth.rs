/* vnc-auth - read the RFB banner and extract offered auth types. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

fn auth_name(t: u32) -> Option<&'static str> {
    match t {
        0 => Some("Invalid"),
        1 => Some("None"),
        2 => Some("VNC Auth"),
        16 => Some("Tight"),
        18 => Some("TLS"),
        19 => Some("VeNCrypt"),
        20 => Some("SASL"),
        21 => Some("MD5"),
        22 => Some("xvp"),
        30 => Some("Apple Remote Desktop"),
        35 => Some("Ultra"),
        36 => Some("TLSVNC"),
        _ => None,
    }
}

fn append_auth(out: &mut String, name: &str, typ: u32) {
    if !out.is_empty() {
        out.push_str(", ");
    }
    out.push_str(&format!("{} ({})", name, typ));
}

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let mut stream = match connect_ctx(ctx) {
        Some(s) => s,
        None => return 1,
    };
    let banner = match recv_exact(&mut stream, 12) {
        Some(b) => b,
        None => return 0,
    };
    if !banner.starts_with(b"RFB ") {
        return 0;
    }
    let mut minor: u32 = 8;
    let mut digits = String::new();
    for &b in banner.iter().skip(8).take(3) {
        if b.is_ascii_digit() {
            digits.push(b as char);
        } else {
            break;
        }
    }
    if !digits.is_empty() {
        minor = digits.parse::<u32>().unwrap_or(8);
    }
    if minor < 3 || minor > 889 {
        minor = 8;
    }
    let client = format!("RFB 003.{:03}\n", minor);
    if send_all(&mut stream, client.as_bytes()).is_err() {
        return 1;
    }

    let mut types = String::new();
    if minor >= 7 {
        let one = match recv_exact(&mut stream, 1) {
            Some(v) => v,
            None => return 0,
        };
        let count = one[0] as usize;
        if count == 0 {
            let rl = match recv_exact(&mut stream, 4) {
                Some(v) => v,
                None => return 0,
            };
            let mut rlen = ((rl[0] as usize) << 24)
                | ((rl[1] as usize) << 16)
                | ((rl[2] as usize) << 8)
                | rl[3] as usize;
            if rlen > 1023 {
                rlen = 1023;
            }
            if rlen > 0 {
                if let Some(buf) = recv_exact(&mut stream, rlen) {
                    let reason = clean(&String::from_utf8_lossy(&buf));
                    if !reason.is_empty() {
                        set_out(ctx, &format!("VNC auth: {}", reason));
                    }
                }
            }
            return 0;
        }
        let count = count.min(1024);
        let buf = match recv_exact(&mut stream, count) {
            Some(v) => v,
            None => return 0,
        };
        for &t in buf.iter() {
            if let Some(name) = auth_name(t as u32) {
                append_auth(&mut types, name, t as u32);
            }
        }
    } else {
        let buf = match recv_exact(&mut stream, 4) {
            Some(v) => v,
            None => return 0,
        };
        let t = ((buf[0] as u32) << 24) | ((buf[1] as u32) << 16) | ((buf[2] as u32) << 8)
            | buf[3] as u32;
        if t <= 255 {
            if let Some(name) = auth_name(t) {
                append_auth(&mut types, name, t);
            }
        }
    }
    drop(stream);
    if !types.is_empty() {
        set_out(ctx, &format!("VNC auth: {}", types));
    }
    0
}
