/*
 * arsenal.rs - shared Rust helpers for the AlScript plugin port.
 *
 * Mirrors plugins/alscript_net.h, plugins/arsenal_util.h,
 * plugins/arsenal_smb.h, plugins/arsenal_ssh.h and plugins/arsenal_dns.h
 * using std::net only (no external crates).
 *
 * Use only on networks you own or have permission to scan.
 */
#![allow(dead_code)]

use std::ffi::c_char;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const AR_BUF: usize = 8192;

#[repr(C)]
pub struct AlScriptContext {
    pub target_ip: u32,
    pub port: i32,
    pub timeout_ms: i32,
    pub output_buf: *mut c_char,
    pub output_max: i32,
}

/* ---------------------------------------------------------------- */
/* Context / output helpers                                         */
/* ---------------------------------------------------------------- */

pub fn ctx_check(ctx: *mut AlScriptContext) -> bool {
    if ctx.is_null() {
        return false;
    }
    unsafe {
        let c = &*ctx;
        if c.output_buf.is_null() || c.output_max < 2 {
            return false;
        }
        if c.port < 1 || c.port > 65535 || c.timeout_ms <= 0 {
            return false;
        }
        c.target_ip != 0
    }
}

pub fn valid(ctx: *mut AlScriptContext) -> bool {
    if !ctx_check(ctx) {
        return false;
    }
    unsafe {
        *(*ctx).output_buf = 0;
    }
    true
}

pub fn set_out(ctx: *mut AlScriptContext, s: &str) {
    if ctx.is_null() {
        return;
    }
    unsafe {
        let c = &*ctx;
        if c.output_buf.is_null() || c.output_max < 2 {
            return;
        }
        let cap = c.output_max as usize - 1;
        let bytes = s.as_bytes();
        let n = if bytes.len() < cap { bytes.len() } else { cap };
        let dst = std::slice::from_raw_parts_mut(c.output_buf as *mut u8, n + 1);
        dst[..n].copy_from_slice(&bytes[..n]);
        dst[n] = 0;
    }
}

pub fn trim(s: &str) -> String {
    s.trim_matches(|c| c == ' ' || c == '\t' || c == '\r' || c == '\n')
        .to_string()
}

pub fn clean(s: &str) -> String {
    trim(s)
        .chars()
        .map(|c| {
            let v = c as u32;
            if v < 32 || v == 127 {
                ' '
            } else {
                c
            }
        })
        .collect()
}

pub fn starts_ci(s: &str, prefix: &str) -> bool {
    let sb = s.as_bytes();
    let pb = prefix.as_bytes();
    if sb.len() < pb.len() {
        return false;
    }
    for i in 0..pb.len() {
        if sb[i].to_ascii_lowercase() != pb[i].to_ascii_lowercase() {
            return false;
        }
    }
    true
}

pub fn contains_ci(hay: &str, needle: &str) -> bool {
    let h = hay.to_ascii_lowercase();
    h.contains(&needle.to_ascii_lowercase())
}

/* ---------------------------------------------------------------- */
/* TCP / timeout primitives                                         */
/* ---------------------------------------------------------------- */

pub fn timeout_of(ctx: *mut AlScriptContext) -> Duration {
    let ms = unsafe { (*ctx).timeout_ms };
    Duration::from_millis(if ms > 0 { ms as u64 } else { 1000 })
}

pub fn connect_ctx(ctx: *mut AlScriptContext) -> Option<TcpStream> {
    if !ctx_check(ctx) {
        return None;
    }
    let c = unsafe { &*ctx };
    let ip = Ipv4Addr::from(c.target_ip);
    let addr = SocketAddr::new(IpAddr::V4(ip), c.port as u16);
    let to = timeout_of(ctx);
    let s = TcpStream::connect_timeout(&addr, to).ok()?;
    let _ = s.set_read_timeout(Some(to));
    let _ = s.set_write_timeout(Some(to));
    let _ = s.set_nodelay(true);
    Some(s)
}

pub fn send_all(stream: &mut TcpStream, data: &[u8]) -> std::io::Result<()> {
    stream.write_all(data)
}

pub fn ip_text(ctx: *mut AlScriptContext) -> String {
    if ctx.is_null() {
        return String::new();
    }
    let ip = unsafe { (*ctx).target_ip };
    Ipv4Addr::from(ip).to_string()
}

/* Send one UDP datagram to (ctx->target_ip, ctx->port) and return the
 * first reply, mirroring as_udp_exchange(). */
pub fn udp_exchange(ctx: *mut AlScriptContext, req: &[u8], cap: usize) -> Option<Vec<u8>> {
    if !ctx_check(ctx) || req.is_empty() || cap < 2 {
        return None;
    }
    let c = unsafe { &*ctx };
    let ip = Ipv4Addr::from(c.target_ip);
    let addr = SocketAddr::new(IpAddr::V4(ip), c.port as u16);
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    let to = timeout_of(ctx);
    let _ = sock.set_read_timeout(Some(to));
    let _ = sock.set_write_timeout(Some(to));
    sock.connect(addr).ok()?;
    sock.send(req).ok()?;
    let mut buf = vec![0u8; cap - 1];
    let n = sock.recv(&mut buf).ok()?;
    buf.truncate(n);
    Some(buf)
}

/* Read until EOF / timeout / cap-1 bytes, mirroring as_recv_all(). */
pub fn recv_all(stream: &mut TcpStream, cap: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 1024];
    if cap < 2 {
        return out;
    }
    loop {
        if out.len() + 1 >= cap {
            break;
        }
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                let room = cap - 1 - out.len();
                let take = if n < room { n } else { room };
                out.extend_from_slice(&tmp[..take]);
            }
            Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    out
}

pub fn recv_exact(stream: &mut TcpStream, len: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).ok()?;
    Some(buf)
}

/* Read a single line (including newline), mirroring as_recv_line(). */
pub fn recv_line(stream: &mut TcpStream, cap: usize) -> String {
    let mut out: Vec<u8> = Vec::new();
    let mut b = [0u8; 1];
    if cap < 2 {
        return String::new();
    }
    while out.len() + 1 < cap {
        match stream.read(&mut b) {
            Ok(0) => break,
            Ok(_) => {
                out.push(b[0]);
                if b[0] == b'\n' {
                    break;
                }
            }
            Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/* ---------------------------------------------------------------- */
/* HTTP (arsenal_util.h)                                            */
/* ---------------------------------------------------------------- */

/* Extract a header value (case-insensitive name, line-anchored). */
pub fn http_header(resp: &str, name: &str) -> Option<String> {
    let nlen = name.len();
    let nb = name.as_bytes();
    for raw in resp.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let lb = line.as_bytes();
        if lb.len() > nlen && lb[nlen] == b':' {
            let mut eq = true;
            for i in 0..nlen {
                if lb[i].to_ascii_lowercase() != nb[i].to_ascii_lowercase() {
                    eq = false;
                    break;
                }
            }
            if eq {
                let v = &line[nlen + 1..];
                return Some(clean(v.trim_matches(|c| c == ' ' || c == '\t')));
            }
        }
    }
    None
}

pub fn http_body(resp: &str) -> &str {
    if let Some(i) = resp.find("\r\n\r\n") {
        &resp[i + 4..]
    } else if let Some(i) = resp.find("\n\n") {
        &resp[i + 2..]
    } else {
        ""
    }
}

pub fn http_status(resp: &str) -> i32 {
    if !resp.starts_with("HTTP/") {
        return 0;
    }
    let mut it = resp.split_whitespace();
    let _ = it.next();
    match it.next() {
        Some(code) => code.parse::<i32>().unwrap_or(0),
        None => 0,
    }
}

pub fn http_ok(resp: &str) -> bool {
    let code = http_status(resp);
    code >= 200 && code < 400
}

#[allow(clippy::too_many_arguments)]
pub fn http_request(
    ctx: *mut AlScriptContext,
    method: &str,
    path: &str,
    host: Option<&str>,
    extra: &str,
    body: &str,
    ctype: Option<&str>,
    cap: usize,
) -> Option<String> {
    if !ctx_check(ctx) {
        return None;
    }
    let c = unsafe { &*ctx };
    let ip = Ipv4Addr::from(c.target_ip);
    let host = match host {
        Some(h) if !h.is_empty() => h.to_string(),
        _ => ip.to_string(),
    };
    let path = if path.starts_with('/') { path } else { "/" };
    let req = match ctype {
        Some(ct) if !ct.is_empty() => format!(
            "{} {} HTTP/1.0\r\nHost: {}\r\n\
             User-Agent: ALmap/5.0\r\nAccept: */*\r\n\
             Connection: close\r\nContent-Type: {}\r\n\
             Content-Length: {}\r\n{}{}\r\n",
            method,
            path,
            host,
            ct,
            body.len(),
            extra,
            body
        ),
        _ => format!(
            "{} {} HTTP/1.0\r\nHost: {}\r\n\
             User-Agent: ALmap/5.0\r\nAccept: */*\r\n\
             Connection: close\r\n{}{}\r\n",
            method, path, host, extra, body
        ),
    };
    let mut s = connect_ctx(ctx)?;
    send_all(&mut s, req.as_bytes()).ok()?;
    let b = recv_all(&mut s, cap);
    Some(String::from_utf8_lossy(&b).into_owned())
}

/* ---------------------------------------------------------------- */
/* FTP (arsenal_util.h)                                             */
/* ---------------------------------------------------------------- */

pub fn ftp_reply(stream: &mut TcpStream, cap: usize) -> (i32, String) {
    let mut out = String::new();
    let mut code: i32 = -1;
    loop {
        let line = recv_line(stream, 512);
        if line.is_empty() {
            return (code, out);
        }
        if out.len() + line.len() + 1 < cap {
            out.push_str(&line);
        }
        let b = line.as_bytes();
        if b.len() >= 3 && b[0].is_ascii_digit() && b[1].is_ascii_digit() && b[2].is_ascii_digit() {
            let c = (b[0] - b'0') as i32 * 100 + (b[1] - b'0') as i32 * 10 + (b[2] - b'0') as i32;
            if code < 0 {
                code = c;
            }
            if b.len() < 4 || b[3] == b' ' || b[3] == b'\r' || b[3] == b'\n' {
                return (code, out);
            }
        } else {
            return (code, out);
        }
    }
}

pub fn ftp_open(ctx: *mut AlScriptContext) -> Option<(TcpStream, String)> {
    let mut s = connect_ctx(ctx)?;
    let (code, banner) = ftp_reply(&mut s, 1024);
    if code < 0 {
        return None;
    }
    Some((s, banner))
}

pub fn ftp_cmd(stream: &mut TcpStream, cmd: &str, cap: usize) -> (i32, String) {
    let line = format!("{}\r\n", cmd);
    if send_all(stream, line.as_bytes()).is_err() {
        return (-1, String::new());
    }
    ftp_reply(stream, cap)
}

pub fn ftp_login(stream: &mut TcpStream, user: &str, pass: &str, cap: usize) -> (i32, String) {
    let (code, mut out) = ftp_cmd(stream, &format!("USER {}", user), cap);
    if code == 230 {
        return (230, out);
    }
    if code != 331 && code != 332 {
        return (code, out);
    }
    let (code2, out2) = ftp_cmd(stream, &format!("PASS {}", pass), cap);
    if !out2.is_empty() {
        out = out2;
    }
    (code2, out)
}

/* ---------------------------------------------------------------- */
/* SMB (arsenal_smb.h)                                              */
/* ---------------------------------------------------------------- */

fn be24(v: usize) -> [u8; 3] {
    [
        ((v >> 16) & 0xff) as u8,
        ((v >> 8) & 0xff) as u8,
        (v & 0xff) as u8,
    ]
}

fn be32(b: &[u8]) -> u32 {
    ((b[0] as u32) << 24) | ((b[1] as u32) << 16) | ((b[2] as u32) << 8) | b[3] as u32
}

fn smb_recv_nb(stream: &mut TcpStream, cap: usize) -> Option<Vec<u8>> {
    if cap < 5 {
        return None;
    }
    let hdr = recv_exact(stream, 4)?;
    if hdr[0] != 0 {
        return None;
    }
    let len = ((hdr[1] as usize) << 16) | ((hdr[2] as usize) << 8) | hdr[3] as usize;
    if len + 1 > cap {
        return None;
    }
    recv_exact(stream, len)
}

const SMB1_DIALECTS: &[u8] = b"\x02PC NETWORK PROGRAM 1.0\x00\
\x02LANMAN1.0\x00\
\x02Windows for Workgroups 3.1a\x00\
\x02LM1.2X002\x00\
\x02LANMAN2.1\x00\
\x02NT LM 0.12\x00\
\x02SMB 2.002\x00\
\x02SMB 2.???\x00";

fn smb1_negotiate_stream(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let dlen = SMB1_DIALECTS.len();
    if dlen + 35 > 256 {
        return None;
    }
    let mut body = [0u8; 256];
    let msglen = 35 + dlen;
    body[0] = 0xFF;
    body[1] = b'S';
    body[2] = b'M';
    body[3] = b'B';
    body[4] = 0x72;
    body[9] = 0x18;
    body[10] = 0x53;
    body[11] = 0xC8;
    body[26] = 0xFE;
    body[27] = 0xFF;
    body[32] = 0;
    body[33] = (dlen & 255) as u8;
    body[34] = ((dlen >> 8) & 255) as u8;
    body[39..39 + dlen].copy_from_slice(SMB1_DIALECTS);
    let mut req = vec![0u8; msglen + 4];
    req[1..4].copy_from_slice(&be24(msglen));
    req[4..].copy_from_slice(&body[..msglen]);
    send_all(stream, &req).ok()?;
    smb_recv_nb(stream, 2044)
}

fn prefix_resp(payload: Vec<u8>) -> Vec<u8> {
    let n = payload.len();
    let mut resp = vec![0u8; 4];
    resp[1..4].copy_from_slice(&be24(n));
    resp.extend_from_slice(&payload);
    resp
}

pub fn smb1_negotiate(ctx: *mut AlScriptContext) -> Option<Vec<u8>> {
    let mut s = connect_ctx(ctx)?;
    let payload = smb1_negotiate_stream(&mut s)?;
    Some(prefix_resp(payload))
}

pub fn smb2_negotiate(ctx: *mut AlScriptContext) -> Option<Vec<u8>> {
    let dialects: [u16; 5] = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311];
    let len = 4 + 64 + 36 + dialects.len() * 2;
    let mut req = vec![0u8; 160];
    req[1..4].copy_from_slice(&be24(len));
    req[4] = 0xFE;
    req[5] = b'S';
    req[6] = b'M';
    req[7] = b'B';
    req[8] = 64;
    req[10] = 0;
    req[68] = 36;
    req[70] = dialects.len() as u8;
    req[72] = 1;
    for (i, d) in dialects.iter().enumerate() {
        req[104 + i * 2] = (*d & 255) as u8;
        req[105 + i * 2] = (*d >> 8) as u8;
    }
    let mut s = connect_ctx(ctx)?;
    send_all(&mut s, &req[..len]).ok()?;
    let payload = smb_recv_nb(&mut s, 2044)?;
    Some(prefix_resp(payload))
}

pub fn smb1_dialect(resp: &[u8]) -> u32 {
    if resp.len() < 4 + 35 {
        return 0xFFFF;
    }
    resp[4 + 33] as u32 | ((resp[4 + 34] as u32) << 8)
}

pub fn smb2_dialect(resp: &[u8]) -> u32 {
    if resp.len() < 4 + 74 {
        return 0xFFFF;
    }
    if resp[4] != 0xFE || resp[5] != b'S' || resp[6] != b'M' || resp[7] != b'B' {
        return 0xFFFF;
    }
    resp[72] as u32 | ((resp[73] as u32) << 8)
}

pub fn smb1_dialect_name(d: u32) -> &'static str {
    match d {
        0 => "PC NETWORK PROGRAM 1.0",
        1 => "LANMAN1.0",
        2 => "Windows for Workgroups 3.1a",
        3 => "LM1.2X002",
        4 => "LANMAN2.1",
        5 => "NT LM 0.12",
        6 => "SMB 2.002",
        7 => "SMB 2.???",
        _ => "unknown",
    }
}

pub fn smb2_dialect_name(d: u32) -> &'static str {
    match d {
        0x0202 => "SMB 2.0.2",
        0x0210 => "SMB 2.1",
        0x0300 => "SMB 3.0",
        0x0302 => "SMB 3.0.2",
        0x0311 => "SMB 3.1.1",
        _ => "SMB 2/3",
    }
}

pub fn smb1_security_mode(resp: &[u8]) -> i32 {
    if resp.len() < 4 + 36 {
        return -1;
    }
    resp[4 + 35] as i32
}

pub fn smb2_security_mode(resp: &[u8]) -> i32 {
    if resp.len() < 4 + 72 {
        return -1;
    }
    ((resp[70] as i32) << 8) | resp[71] as i32
}

fn smb1_session_setup(
    stream: &mut TcpStream,
    os_cap: usize,
    lan_cap: usize,
) -> Option<(i32, u32, String, String)> {
    let bodylen: usize = 32 + 1 + 24 + 2;
    let mut req = [0u8; 256];
    req[0] = 0;
    req[1] = 0;
    req[2] = 0;
    req[3] = bodylen as u8;
    /* smb[k] == req[4 + k] */
    req[4] = 0xFF;
    req[5] = b'S';
    req[6] = b'M';
    req[7] = b'B';
    req[8] = 0x73;
    req[13] = 0x18;
    req[14] = 0x53;
    req[15] = 0xC8;
    req[30] = 0xFE;
    req[31] = 0xFF;
    req[36] = 12;
    req[37] = 0xFF;
    req[38] = 0;
    req[39] = 0;
    req[40] = 0;
    req[41] = 0xFF;
    req[42] = 0xFF;
    req[43] = 2;
    /* req[44..62] already zero (24-byte security blob) */
    send_all(stream, &req[..4 + bodylen]).ok()?;
    let resp = smb_recv_nb(stream, 2048)?;
    if resp.len() < 32 {
        return None;
    }
    let status = be32(&resp[5..9]) as i32;
    let mut uid: u32 = 0;
    let mut os: Vec<u8> = Vec::new();
    let mut lan: Vec<u8> = Vec::new();
    if status == 0 {
        uid = ((resp[28] as u32) << 8) | resp[29] as u32;
        if resp.len() >= 35 {
            let wc = resp[32] as usize;
            let boff = 33 + wc * 2;
            if boff + 2 <= resp.len() {
                let blen = ((resp[boff] as usize) << 8) | resp[boff + 1] as usize;
                let mut bdata = boff + 2;
                let mut end = bdata + blen;
                if end > resp.len() {
                    end = resp.len();
                }
                if bdata < end {
                    let mut l = 0usize;
                    while bdata + l < end && resp[bdata + l] != 0 && l + 1 < os_cap {
                        os.push(resp[bdata + l]);
                        l += 1;
                    }
                    bdata += l + 1;
                    l = 0;
                    while bdata + l < end && resp[bdata + l] != 0 && l + 1 < lan_cap {
                        lan.push(resp[bdata + l]);
                        l += 1;
                    }
                }
            }
        }
    }
    Some((
        status,
        uid,
        clean(&String::from_utf8_lossy(&os)),
        clean(&String::from_utf8_lossy(&lan)),
    ))
}

pub fn smb1_open_session(
    ctx: *mut AlScriptContext,
) -> Option<(TcpStream, u32, String, String)> {
    let mut s = connect_ctx(ctx)?;
    let payload = smb1_negotiate_stream(&mut s)?;
    if payload.len() < 32 {
        return None;
    }
    let (_status, uid, os, lan) = smb1_session_setup(&mut s, 256, 256)?;
    Some((s, uid, os, lan))
}

/* ---------------------------------------------------------------- */
/* SSH (arsenal_ssh.h)                                              */
/* ---------------------------------------------------------------- */

pub const SSH_MSG_KEXINIT: u8 = 20;
pub const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
pub const SSH_MSG_USERAUTH_FAILURE: u8 = 51;
pub const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;

pub fn ssh_open(ctx: *mut AlScriptContext) -> Option<(TcpStream, String)> {
    let mut s = connect_ctx(ctx)?;
    let banner = recv_line(&mut s, 256);
    if banner.is_empty() || !starts_ci(&banner, "SSH-") {
        return None;
    }
    Some((s, clean(&banner)))
}

fn ssh_send_packet(stream: &mut TcpStream, payload: &[u8]) -> std::io::Result<()> {
    let plen = payload.len();
    if plen + 5 + 8 > 2048 {
        return Err(std::io::Error::new(ErrorKind::InvalidInput, "packet too big"));
    }
    let mut pad = 8 - ((plen + 5) % 8);
    if pad < 4 {
        pad += 8;
    }
    let total = 4 + 1 + plen + pad;
    let mut buf = vec![0u8; total];
    let pkt_len = plen + 1 + pad;
    buf[0] = ((pkt_len >> 24) & 0xff) as u8;
    buf[1] = ((pkt_len >> 16) & 0xff) as u8;
    buf[2] = ((pkt_len >> 8) & 0xff) as u8;
    buf[3] = (pkt_len & 0xff) as u8;
    buf[4] = pad as u8;
    buf[5..5 + plen].copy_from_slice(payload);
    for i in 0..pad {
        buf[5 + plen + i] = b'A';
    }
    send_all(stream, &buf)
}

fn ssh_recv_packet(stream: &mut TcpStream, cap: usize) -> Option<Vec<u8>> {
    if cap < 2 {
        return None;
    }
    let hdr = recv_exact(stream, 4)?;
    let plen = ((hdr[0] as usize) << 24)
        | ((hdr[1] as usize) << 16)
        | ((hdr[2] as usize) << 8)
        | hdr[3] as usize;
    if plen < 5 || plen > 4096 {
        return None;
    }
    let buf = recv_exact(stream, plen)?;
    let pad = buf[0] as usize;
    if pad + 1 >= plen {
        return None;
    }
    let mut body = plen - 1 - pad;
    if body > cap - 1 {
        body = cap - 1;
    }
    Some(buf[1..1 + body].to_vec())
}

fn ssh_put_u32(out: &mut Vec<u8>, v: u32) {
    out.push(((v >> 24) & 0xff) as u8);
    out.push(((v >> 16) & 0xff) as u8);
    out.push(((v >> 8) & 0xff) as u8);
    out.push((v & 0xff) as u8);
}

fn ssh_get_u32(p: &[u8]) -> u32 {
    ((p[0] as u32) << 24) | ((p[1] as u32) << 16) | ((p[2] as u32) << 8) | p[3] as u32
}

fn ssh_build_kexinit() -> Vec<u8> {
    let lists: [&str; 10] = [
        "curve25519-sha256,curve25519-sha256@libssh.org,\
         ecdh-sha2-nistp256,diffie-hellman-group14-sha256,\
         diffie-hellman-group14-sha1",
        "ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256,ssh-rsa",
        "aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,\
         chacha20-poly1305@openssh.com",
        "aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,\
         chacha20-poly1305@openssh.com",
        "hmac-sha2-256,hmac-sha2-512,hmac-sha1",
        "hmac-sha2-256,hmac-sha2-512,hmac-sha1",
        "none,zlib@openssh.com,zlib",
        "none,zlib@openssh.com,zlib",
        "",
        "",
    ];
    let mut out = Vec::new();
    out.push(SSH_MSG_KEXINIT);
    for i in 0..16u8 {
        out.push(0x20 + i);
    }
    for l in lists.iter() {
        ssh_put_u32(&mut out, l.len() as u32);
        out.extend_from_slice(l.as_bytes());
    }
    out.push(0);
    ssh_put_u32(&mut out, 0);
    out
}

pub fn ssh_get_kexinit(stream: &mut TcpStream, cap: usize) -> Option<Vec<u8>> {
    let kex = ssh_build_kexinit();
    ssh_send_packet(stream, &kex).ok()?;
    for _ in 0..4 {
        let p = ssh_recv_packet(stream, cap)?;
        if !p.is_empty() && p[0] == SSH_MSG_KEXINIT {
            return Some(p);
        }
    }
    None
}

pub fn ssh_kex_field(payload: &[u8], field: usize, cap: usize) -> Option<String> {
    if payload.len() < 17 || field > 9 || cap < 2 {
        return None;
    }
    let mut off = 17usize;
    for i in 0..=field {
        if off + 4 > payload.len() {
            return None;
        }
        let n = ssh_get_u32(&payload[off..off + 4]) as usize;
        off += 4;
        if n > payload.len() - off {
            return None;
        }
        if i == field {
            let mut copy = n;
            if copy >= cap {
                copy = cap - 1;
            }
            return Some(String::from_utf8_lossy(&payload[off..off + copy]).into_owned());
        }
        off += n;
    }
    None
}

pub fn ssh_auth_none(stream: &mut TcpStream, user: &str, cap: usize) -> (i32, String) {
    let ulen = user.len();
    if ulen > 200 {
        return (-1, String::new());
    }
    let mut pkt = Vec::new();
    pkt.push(SSH_MSG_USERAUTH_REQUEST);
    ssh_put_u32(&mut pkt, ulen as u32);
    pkt.extend_from_slice(user.as_bytes());
    ssh_put_u32(&mut pkt, 14);
    pkt.extend_from_slice(b"ssh-connection");
    ssh_put_u32(&mut pkt, 4);
    pkt.extend_from_slice(b"none");
    if ssh_send_packet(stream, &pkt).is_err() {
        return (-1, String::new());
    }
    let resp = match ssh_recv_packet(stream, 1024) {
        Some(r) => r,
        None => return (-1, String::new()),
    };
    if resp.is_empty() {
        return (-1, String::new());
    }
    if resp[0] == SSH_MSG_USERAUTH_SUCCESS {
        return (1, "none".to_string());
    }
    if resp[0] == SSH_MSG_USERAUTH_FAILURE && resp.len() >= 5 {
        let mlen = ssh_get_u32(&resp[1..5]) as usize;
        if mlen < cap && 5 + mlen <= resp.len() {
            return (
                0,
                String::from_utf8_lossy(&resp[5..5 + mlen]).into_owned(),
            );
        }
    }
    (-1, String::new())
}

/* ---------------------------------------------------------------- */
/* DNS (arsenal_dns.h)                                              */
/* ---------------------------------------------------------------- */

pub const DNS_A: u16 = 1;
pub const DNS_NS: u16 = 2;
pub const DNS_CNAME: u16 = 5;
pub const DNS_SOA: u16 = 6;
pub const DNS_PTR: u16 = 12;
pub const DNS_MX: u16 = 15;
pub const DNS_TXT: u16 = 16;
pub const DNS_AAAA: u16 = 28;

fn dns_encode_name(name: &str, out: &mut Vec<u8>, cap: usize) -> Option<usize> {
    let start = out.len();
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        let len = label.len();
        if len > 63 || out.len() - start + len + 1 >= cap {
            return None;
        }
        out.push(len as u8);
        out.extend_from_slice(label.as_bytes());
    }
    if out.len() - start + 1 > cap {
        return None;
    }
    out.push(0);
    Some(out.len() - start)
}

fn dns_make_query(name: &str, qtype: u16, flags: u16) -> Option<Vec<u8>> {
    let id = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        & 0xFFFF) as u16;
    let mut buf = vec![0u8; 12];
    buf[0] = (id >> 8) as u8;
    buf[1] = (id & 255) as u8;
    buf[2] = (flags >> 8) as u8;
    buf[3] = (flags & 255) as u8;
    buf[5] = 1;
    let nlen = dns_encode_name(name, &mut buf, 500)?;
    let need = 12 + nlen + 4;
    if need > 512 {
        return None;
    }
    buf.resize(need, 0);
    buf[12 + nlen] = (qtype >> 8) as u8;
    buf[13 + nlen] = (qtype & 255) as u8;
    buf[14 + nlen] = 0;
    buf[15 + nlen] = 1;
    Some(buf[..need].to_vec())
}

pub fn dns_udp(
    ctx: *mut AlScriptContext,
    name: &str,
    qtype: u16,
    flags: u16,
    cap: usize,
) -> Option<Vec<u8>> {
    let req = dns_make_query(name, qtype, flags)?;
    let c = unsafe { &*ctx };
    let ip = Ipv4Addr::from(c.target_ip);
    let addr = SocketAddr::new(IpAddr::V4(ip), c.port as u16);
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    let to = timeout_of(ctx);
    let _ = sock.set_read_timeout(Some(to));
    let _ = sock.set_write_timeout(Some(to));
    sock.connect(addr).ok()?;
    sock.send(&req).ok()?;
    let mut buf = vec![0u8; if cap > 1 { cap - 1 } else { 1 }];
    let n = sock.recv(&mut buf).ok()?;
    buf.truncate(n);
    Some(buf)
}

pub fn dns_rcode(resp: &[u8]) -> i32 {
    if resp.len() < 4 {
        return -1;
    }
    (resp[3] & 15) as i32
}

pub fn dns_qdcount(resp: &[u8]) -> usize {
    if resp.len() < 6 {
        return 0;
    }
    ((resp[4] as usize) << 8) | resp[5] as usize
}

pub fn dns_ancount(resp: &[u8]) -> usize {
    if resp.len() < 8 {
        return 0;
    }
    ((resp[6] as usize) << 8) | resp[7] as usize
}

fn dns_name_len(base: &[u8], off: usize) -> Option<usize> {
    let mut p = off;
    while p < base.len() {
        if (base[p] & 0xC0) == 0xC0 {
            return if p + 2 <= base.len() { Some(2) } else { None };
        }
        if base[p] == 0 {
            return Some(p + 1 - off);
        }
        let l = base[p] as usize;
        if p + 1 + l > base.len() {
            return None;
        }
        p += 1 + l;
    }
    None
}

fn dns_name_at(base: &[u8], off: usize, cap: usize) -> Option<String> {
    if cap < 2 || off >= base.len() {
        return None;
    }
    let mut out: Vec<u8> = Vec::new();
    let mut p = off;
    let mut guard = 0usize;
    while p < base.len() && guard < 64 {
        guard += 1;
        if (base[p] & 0xC0) == 0xC0 {
            if p + 1 >= base.len() {
                return None;
            }
            p = (((base[p] & 0x3F) as usize) << 8) | base[p + 1] as usize;
            continue;
        }
        if base[p] == 0 {
            break;
        }
        let l = base[p] as usize;
        if p + 1 + l > base.len() {
            return None;
        }
        if !out.is_empty() && out.len() + 1 < cap {
            out.push(b'.');
        }
        if out.len() + l >= cap {
            return None;
        }
        out.extend_from_slice(&base[p + 1..p + 1 + l]);
        p += 1 + l;
    }
    if out.is_empty() {
        out.push(b'.');
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

fn dns_type_name(t: u16) -> &'static str {
    match t {
        DNS_A => "A",
        DNS_AAAA => "AAAA",
        DNS_CNAME => "CNAME",
        DNS_NS => "NS",
        DNS_PTR => "PTR",
        DNS_MX => "MX",
        DNS_TXT => "TXT",
        DNS_SOA => "SOA",
        _ => "TYPE",
    }
}

pub fn dns_dump_answers(out: &mut String, resp: &[u8], max: usize) -> usize {
    if resp.len() < 12 {
        return 0;
    }
    let qd = dns_qdcount(resp);
    let an = dns_ancount(resp);
    let mut off = 12usize;
    for _ in 0..qd {
        let nl = match dns_name_len(resp, off) {
            Some(v) => v,
            None => return 0,
        };
        if off + nl + 4 > resp.len() {
            return 0;
        }
        off += nl + 4;
    }
    let mut printed = 0usize;
    for _ in 0..an {
        if printed >= max {
            break;
        }
        let nl = match dns_name_len(resp, off) {
            Some(v) => v,
            None => break,
        };
        if off + nl + 10 > resp.len() {
            break;
        }
        let name = dns_name_at(resp, off, 256).unwrap_or_else(|| "?".to_string());
        off += nl;
        let rtype = ((resp[off] as u16) << 8) | resp[off + 1] as u16;
        let rdlen = ((resp[off + 8] as usize) << 8) | resp[off + 9] as usize;
        off += 10;
        if off + rdlen > resp.len() {
            break;
        }
        let val = if rtype == DNS_A && rdlen == 4 {
            format!(
                "{}.{}.{}.{}",
                resp[off],
                resp[off + 1],
                resp[off + 2],
                resp[off + 3]
            )
        } else if rtype == DNS_AAAA && rdlen == 16 {
            let b = &resp[off..off + 16];
            format!(
                "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:\
                 {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11],
                b[12], b[13], b[14], b[15]
            )
        } else if rtype == DNS_CNAME || rtype == DNS_NS || rtype == DNS_PTR {
            dns_name_at(resp, off, 256).unwrap_or_default()
        } else if rtype == DNS_TXT && rdlen > 0 {
            let mut tl = resp[off] as usize;
            if tl > rdlen - 1 {
                tl = rdlen - 1;
            }
            if tl >= 256 {
                tl = 255;
            }
            clean(&String::from_utf8_lossy(&resp[off + 1..off + 1 + tl]))
        } else if rtype == DNS_SOA {
            "SOA".to_string()
        } else if rtype == DNS_MX && rdlen >= 3 {
            match dns_name_at(resp, off + 2, 200) {
                Some(mx) => format!(
                    "{} {}",
                    ((resp[off] as u16) << 8) | resp[off + 1] as u16,
                    mx
                ),
                None => String::new(),
            }
        } else {
            format!("{} bytes", rdlen)
        };
        if printed > 0 {
            out.push('\n');
        }
        out.push_str(&format!("{} {} {}", name, dns_type_name(rtype), val));
        printed += 1;
        off += rdlen;
    }
    printed
}

/* ---------------------------------------------------------------- */
/* SMB Tree Connect (arsenal_smb.h)                                 */
/* ---------------------------------------------------------------- */

/* Returns (status, tid). status == 0 means the share is accessible. */
pub fn smb1_tree_connect(
    stream: &mut TcpStream,
    uid: u32,
    server: &str,
    share: &str,
    service: &str,
) -> (i32, u32) {
    let path = format!("\\\\{}\\{}", server, share);
    let pathb = path.as_bytes();
    let pathlen = pathb.len() + 1;
    let svcb = service.as_bytes();
    let servicelen = svcb.len() + 1;
    let bodylen = 32 + 1 + 8 + 2 + pathlen + servicelen;
    if bodylen > 508 {
        return (-1, 0);
    }
    let mut req = vec![0u8; 4 + bodylen];
    req[3] = bodylen as u8;
    let smb = &mut req[4..];
    smb[0] = 0xFF;
    smb[1] = b'S';
    smb[2] = b'M';
    smb[3] = b'B';
    smb[4] = 0x75;
    smb[9] = 0x18;
    smb[10] = 0x53;
    smb[11] = 0xC8;
    smb[26] = 0xFE;
    smb[27] = 0xFF;
    smb[28] = (uid >> 8) as u8;
    smb[29] = (uid & 255) as u8;
    smb[32] = 4;
    smb[33] = 0xFF;
    smb[41] = ((pathlen + servicelen) & 255) as u8;
    smb[42] = (((pathlen + servicelen) >> 8) & 255) as u8;
    smb[43..43 + pathlen - 1].copy_from_slice(pathb);
    smb[43 + pathlen - 1] = 0;
    smb[43 + pathlen..43 + pathlen + servicelen - 1].copy_from_slice(svcb);
    smb[43 + pathlen + servicelen - 1] = 0;
    if send_all(stream, &req).is_err() {
        return (-1, 0);
    }
    let resp = match smb_recv_nb(stream, 1024) {
        Some(r) => r,
        None => return (-1, 0),
    };
    if resp.len() < 32 {
        return (-1, 0);
    }
    let status = be32(&resp[5..9]) as i32;
    let tid = if status == 0 {
        ((resp[24] as u32) << 8) | resp[25] as u32
    } else {
        0
    };
    (status, tid)
}

/* ---------------------------------------------------------------- */
/* MSSQL / TDS 7.x (arsenal_mssql.h)                                */
/* ---------------------------------------------------------------- */

fn mssql_read_packet(stream: &mut TcpStream) -> Option<(u8, Vec<u8>)> {
    let hdr = recv_exact(stream, 8)?;
    let typ = hdr[0];
    let len = ((hdr[2] as usize) << 8) | hdr[3] as usize;
    if len < 8 {
        return None;
    }
    let body = len - 8;
    if body == 0 {
        return Some((typ, Vec::new()));
    }
    let data = recv_exact(stream, body)?;
    Some((typ, data))
}

/* Returns (version, instance) from the TDS prelogin response. */
pub fn mssql_prelogin(ctx: *mut AlScriptContext) -> Option<(String, String)> {
    if !ctx_check(ctx) {
        return None;
    }
    let total: usize = 8 + 18;
    let mut pkt = [0u8; 26];
    pkt[0] = 0x12;
    pkt[1] = 0x01;
    pkt[2] = (total >> 8) as u8;
    pkt[3] = (total & 255) as u8;
    pkt[6] = 1;
    pkt[10] = 0x0B;
    pkt[12] = 0x06;
    pkt[13] = 0x01;
    pkt[15] = 0x11;
    pkt[17] = 0x01;
    pkt[18] = 0xFF;
    pkt[19] = 0x0F;
    pkt[21] = 0x07;
    pkt[22] = 0xD0;
    let mut s = connect_ctx(ctx)?;
    send_all(&mut s, &pkt[..total]).ok()?;
    let (typ, resp) = mssql_read_packet(&mut s)?;
    if typ != 0x04 || resp.is_empty() {
        return None;
    }
    let n = resp.len();
    let mut version = String::new();
    let mut instance = String::new();
    let mut off = 0usize;
    while off + 5 <= n && resp[off] != 0xFF {
        let opt = resp[off];
        let o = ((resp[off + 1] as usize) << 8) | resp[off + 2] as usize;
        let l = ((resp[off + 3] as usize) << 8) | resp[off + 4] as usize;
        off += 5;
        if o + l > n {
            continue;
        }
        if opt == 0x00 && l >= 6 {
            let major = resp[o];
            let minor = resp[o + 1];
            let build = ((resp[o + 2] as u32) << 8) | resp[o + 3] as u32;
            let sub = ((resp[o + 4] as u32) << 8) | resp[o + 5] as u32;
            version = format!("{}.{}.{}.{}", major, minor, build, sub);
        } else if opt == 0x02 && l > 0 {
            instance = clean(&String::from_utf8_lossy(&resp[o..o + l]));
        }
    }
    Some((version, instance))
}

/* ---------------------------------------------------------------- */
/* HTTP Basic auth + brute wordlist (arsenal_util.h)                */
/* ---------------------------------------------------------------- */

pub const BRUTE_WORDS: [&str; 10] = [
    "admin", "root", "password", "123456", "admin123",
    "root123", "toor", "letmein", "qwerty", "test",
];

/* Standard base64 (matches ar_b64 in arsenal_util.h). */
pub fn b64(input: &[u8]) -> String {
    const TAB: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0usize;
    while i + 3 <= input.len() {
        let v = ((input[i] as u32) << 16)
            | ((input[i + 1] as u32) << 8)
            | (input[i + 2] as u32);
        out.push(TAB[((v >> 18) & 63) as usize] as char);
        out.push(TAB[((v >> 12) & 63) as usize] as char);
        out.push(TAB[((v >> 6) & 63) as usize] as char);
        out.push(TAB[(v & 63) as usize] as char);
        i += 3;
    }
    match input.len() - i {
        1 => {
            let v = (input[i] as u32) << 16;
            out.push(TAB[((v >> 18) & 63) as usize] as char);
            out.push(TAB[((v >> 12) & 63) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let v = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
            out.push(TAB[((v >> 18) & 63) as usize] as char);
            out.push(TAB[((v >> 12) & 63) as usize] as char);
            out.push(TAB[((v >> 6) & 63) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

/* Build an HTTP Basic "Authorization:" header line (with trailing CRLF). */
pub fn basic_auth(user: &str, pass: &str) -> String {
    let raw = format!("{}:{}", user, pass);
    format!("Authorization: Basic {}\r\n", b64(raw.as_bytes()))
}
