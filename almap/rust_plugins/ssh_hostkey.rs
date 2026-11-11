/* ssh_hostkey - KEXINIT exchange and server host-key algorithm name-list. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;
use std::net::TcpStream;

fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.push((v >> 24) as u8);
    buf.push((v >> 16) as u8);
    buf.push((v >> 8) as u8);
    buf.push(v as u8);
}

fn get_u32(p: &[u8]) -> u32 {
    ((p[0] as u32) << 24) | ((p[1] as u32) << 16) | ((p[2] as u32) << 8) | p[3] as u32
}

fn put_namelist(buf: &mut Vec<u8>, s: &str) {
    put_u32(buf, s.len() as u32);
    buf.extend_from_slice(s.as_bytes());
}

fn send_ssh_packet(stream: &mut TcpStream, payload: &[u8]) -> bool {
    let paylen = payload.len();
    let mut pad = 8 - ((paylen + 5) % 8);
    if pad < 4 {
        pad += 8;
    }
    let plen = 1 + paylen + pad;
    if 4 + plen > 1200 {
        return false;
    }
    let mut pkt = Vec::new();
    put_u32(&mut pkt, plen as u32);
    pkt.push(pad as u8);
    pkt.extend_from_slice(payload);
    pkt.extend(std::iter::repeat(0u8).take(pad));
    send_all(stream, &pkt).is_ok()
}

fn recv_ssh_packet(stream: &mut TcpStream, cap: usize) -> Option<Vec<u8>> {
    let hdr = recv_exact(stream, 4)?;
    let plen = get_u32(&hdr) as usize;
    if plen < 5 || plen > 4000 {
        return None;
    }
    let pkt = recv_exact(stream, plen)?;
    let pad = pkt[0] as usize;
    if pad + 1 > plen {
        return None;
    }
    let paylen = plen - 1 - pad;
    if paylen > cap {
        return None;
    }
    Some(pkt[1..1 + paylen].to_vec())
}

fn parse_hostkey_algorithms(payload: &[u8]) -> Option<String> {
    let len = payload.len();
    if len < 17 || payload[0] != 20 {
        return None;
    }
    let mut pos = 17usize; // message type + 16-byte cookie
    for i in 0..10 {
        if pos + 4 > len {
            return None;
        }
        let n = get_u32(&payload[pos..pos + 4]) as usize;
        pos += 4;
        if pos + n > len {
            return None;
        }
        if i == 1 {
            let s = clean(&String::from_utf8_lossy(&payload[pos..pos + n]));
            if s.is_empty() {
                return None;
            }
            return Some(s);
        }
        pos += n;
    }
    None
}

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => return 1,
    };
    if send_all(&mut s, b"SSH-2.0-ALmap_1.0\r\n").is_err() {
        return 1;
    }
    // Consume lines until the SSH identification line.
    for _ in 0..8 {
        let line = recv_line(&mut s, 512);
        if line.is_empty() {
            break;
        }
        if line.starts_with("SSH-") {
            break;
        }
    }

    // Minimal KEXINIT payload.
    let mut payload: Vec<u8> = Vec::new();
    payload.push(20);
    for i in 0..16u8 {
        payload.push(0x41 + i);
    }
    for nl in [
        "curve25519-sha256",
        "ssh-ed25519",
        "aes128-ctr",
        "aes128-ctr",
        "hmac-sha2-256",
        "hmac-sha2-256",
        "none",
        "none",
        "",
        "",
    ]
    .iter()
    {
        put_namelist(&mut payload, nl);
    }
    payload.push(0); // first_kex_packet_follows
    put_u32(&mut payload, 0); // reserved

    if !send_ssh_packet(&mut s, &payload) {
        return 1;
    }

    let mut keys = String::new();
    for _ in 0..8 {
        let pkt = match recv_ssh_packet(&mut s, 1024) {
            Some(p) if !p.is_empty() => p,
            _ => break,
        };
        if pkt[0] == 20 {
            if let Some(k) = parse_hostkey_algorithms(&pkt) {
                keys = k;
            }
            break;
        }
        if pkt[0] == 1 {
            // SSH_MSG_DISCONNECT
            break;
        }
    }
    drop(s);

    if !keys.is_empty() {
        set_out(ctx, &format!("Host key algorithms: {}", keys));
    }
    0
}
