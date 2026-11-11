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

/* Append text to the current output buffer without clearing it. */
pub fn append_out(ctx: *mut AlScriptContext, s: &str) {
    if ctx.is_null() {
        return;
    }
    unsafe {
        let c = &*ctx;
        if c.output_buf.is_null() || c.output_max < 2 {
            return;
        }
        let cap = c.output_max as usize - 1;
        let p = c.output_buf as *const u8;
        let mut len = 0usize;
        while len < cap && *p.add(len) != 0 {
            len += 1;
        }
        let bytes = s.as_bytes();
        let room = cap - len;
        let n = if bytes.len() < room { bytes.len() } else { room };
        let dst = std::slice::from_raw_parts_mut(c.output_buf as *mut u8, len + n + 1);
        dst[len..len + n].copy_from_slice(&bytes[..n]);
        dst[len + n] = 0;
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
pub const DNS_AXFR: u16 = 252;

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

pub fn dns_make_query(name: &str, qtype: u16, flags: u16) -> Option<Vec<u8>> {
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

/* Send a DNS query over TCP with the two-byte length prefix. */
pub fn dns_tcp_send(stream: &mut TcpStream, query: &[u8]) -> bool {
    if query.is_empty() || query.len() > 65535 {
        return false;
    }
    let mut frame = Vec::with_capacity(query.len() + 2);
    frame.push((query.len() >> 8) as u8);
    frame.push((query.len() & 255) as u8);
    frame.extend_from_slice(query);
    send_all(stream, &frame).is_ok()
}

/* Receive one length-prefixed DNS message over TCP. */
pub fn dns_tcp_recv(stream: &mut TcpStream, cap: usize) -> Option<Vec<u8>> {
    if cap < 12 {
        return None;
    }
    let hdr = recv_exact(stream, 2)?;
    let len = ((hdr[0] as usize) << 8) | hdr[1] as usize;
    if len < 12 || len > cap {
        return None;
    }
    recv_exact(stream, len)
}

/* One DNS-over-TCP query/reply exchange, mirroring ar_dns_tcp_query(). */
pub fn dns_tcp_query(
    ctx: *mut AlScriptContext,
    name: &str,
    qtype: u16,
    flags: u16,
    cap: usize,
) -> Option<Vec<u8>> {
    let query = dns_make_query(name, qtype, flags)?;
    let mut stream = connect_ctx(ctx)?;
    if !dns_tcp_send(&mut stream, &query) {
        return None;
    }
    dns_tcp_recv(&mut stream, cap)
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

/* ---------------------------------------------------------------- */
/* DES (arsenal_des.h) - compact single-DES ECB for VNC auth         */
/* ---------------------------------------------------------------- */

const DES_IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

const DES_FP: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

const DES_E: [u8; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];

const DES_P: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
];

const DES_PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
];

const DES_PC2: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

const DES_SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

const DES_S: [[[u8; 16]; 4]; 8] = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
];

fn des_perm(input: u64, tab: &[u8], inbits: u32) -> u64 {
    let mut out: u64 = 0;
    for &t in tab.iter() {
        out <<= 1;
        out |= (input >> (inbits - t as u32)) & 1;
    }
    out
}

fn des_rotl28(v: u32, n: u32) -> u32 {
    ((v << n) | (v >> (28 - n))) & 0x0FFF_FFFF
}

fn des_key_schedule(key: &[u8; 8]) -> [u64; 16] {
    let mut k: u64 = 0;
    for i in 0..8 {
        k = (k << 8) | key[i] as u64;
    }
    let pc1 = des_perm(k, &DES_PC1, 64);
    let mut c = ((pc1 >> 28) & 0x0FFF_FFFF) as u32;
    let mut d = (pc1 & 0x0FFF_FFFF) as u32;
    let mut sub = [0u64; 16];
    for i in 0..16 {
        c = des_rotl28(c, DES_SHIFTS[i] as u32);
        d = des_rotl28(d, DES_SHIFTS[i] as u32);
        sub[i] = des_perm(((c as u64) << 28) | d as u64, &DES_PC2, 56);
    }
    sub
}

pub fn des_encrypt_block(key: &[u8; 8], input: &[u8; 8]) -> [u8; 8] {
    let mut block: u64 = 0;
    for i in 0..8 {
        block = (block << 8) | input[i] as u64;
    }
    let sub = des_key_schedule(key);
    let ip = des_perm(block, &DES_IP, 64);
    let mut l = (ip >> 32) as u32;
    let mut r = (ip & 0xFFFF_FFFF) as u32;
    for i in 0..16 {
        let er = des_perm(r as u64, &DES_E, 32) ^ sub[i];
        let mut s: u32 = 0;
        for j in 0..8u32 {
            let six = ((er >> (42 - j * 6)) & 0x3F) as u32;
            let row = (((six & 0x20) >> 4) | (six & 1)) as usize;
            let col = ((six >> 1) & 0x0F) as usize;
            s = (s << 4) | DES_S[j as usize][row][col] as u32;
        }
        let f = des_perm(s as u64, &DES_P, 32) as u32;
        let nr = l ^ f;
        l = r;
        r = nr;
    }
    block = ((r as u64) << 32) | l as u64;
    block = des_perm(block, &DES_FP, 64);
    let mut out = [0u8; 8];
    let mut i = 8;
    while i > 0 {
        i -= 1;
        out[i] = (block & 0xFF) as u8;
        block >>= 8;
    }
    out
}

pub fn des_reverse8(b: u8) -> u8 {
    let mut r = 0u8;
    let mut b = b;
    for _ in 0..8 {
        r = (r << 1) | (b & 1);
        b >>= 1;
    }
    r
}

/* ---------------------------------------------------------------- */
/* VNC / RFB authentication (arsenal_vnc.h)                          */
/* ---------------------------------------------------------------- */

/* Try one VNC password. Mirrors ar_vnc_try_password():
 *   1  = password accepted
 *   2  = no authentication required (security type None)
 *   0  = rejected
 *  -1  = connection / protocol error */
pub fn vnc_try_password(ctx: *mut AlScriptContext, pass: &str) -> i32 {
    let mut stream = match connect_ctx(ctx) {
        Some(s) => s,
        None => return -1,
    };
    let ver = match recv_exact(&mut stream, 12) {
        Some(v) => v,
        None => return -1,
    };
    if &ver[0..4] != b"RFB " {
        return -1;
    }
    if send_all(&mut stream, b"RFB 003.008\n").is_err() {
        return -1;
    }
    let sectype: i32;
    if ver[4] == b'0' && ver[5] == b'0' && ver[6] == b'3' && ver[8] == b'0'
        && ver[9] == b'0' && ver[10] < b'8'
    {
        let buf = match recv_exact(&mut stream, 4) {
            Some(v) => v,
            None => return -1,
        };
        sectype = ((buf[0] as i32) << 24)
            | ((buf[1] as i32) << 16)
            | ((buf[2] as i32) << 8)
            | buf[3] as i32;
    } else {
        let one = match recv_exact(&mut stream, 1) {
            Some(v) => v,
            None => return -1,
        };
        let mut n = one[0] as usize;
        if n == 0 {
            return -1;
        }
        if n > 256 {
            n = 256;
        }
        let buf = match recv_exact(&mut stream, n) {
            Some(v) => v,
            None => return -1,
        };
        let mut st = 0i32;
        for i in 0..n {
            if buf[i] == 2 {
                st = 2;
                break;
            }
            if buf[i] == 1 && st == 0 {
                st = 1;
            }
        }
        if st == 0 {
            return -1;
        }
        sectype = st;
        if send_all(&mut stream, &[st as u8]).is_err() {
            return -1;
        }
    }
    if sectype == 1 {
        return 2;
    }
    if sectype != 2 {
        return 0;
    }
    let challenge = match recv_exact(&mut stream, 16) {
        Some(v) => v,
        None => return -1,
    };
    let mut key = [0u8; 8];
    let pb = pass.as_bytes();
    for i in 0..8 {
        if i < pb.len() {
            key[i] = des_reverse8(pb[i]);
        }
    }
    let mut c0 = [0u8; 8];
    let mut c1 = [0u8; 8];
    c0.copy_from_slice(&challenge[0..8]);
    c1.copy_from_slice(&challenge[8..16]);
    let mut resp = [0u8; 16];
    resp[0..8].copy_from_slice(&des_encrypt_block(&key, &c0));
    resp[8..16].copy_from_slice(&des_encrypt_block(&key, &c1));
    if send_all(&mut stream, &resp).is_err() {
        return -1;
    }
    let res = match recv_exact(&mut stream, 4) {
        Some(v) => v,
        None => return -1,
    };
    let result = ((res[0] as i32) << 24)
        | ((res[1] as i32) << 16)
        | ((res[2] as i32) << 8)
        | res[3] as i32;
    if result == 0 {
        1
    } else {
        0
    }
}

/* ---------------------------------------------------------------- */
/* SSH password auth (arsenal_ssh.h) - mirrors ar_ssh_auth_password  */
/* ---------------------------------------------------------------- */

pub fn ssh_auth_password(
    stream: &mut TcpStream,
    user: &str,
    pass: &str,
    cap: usize,
) -> (i32, String) {
    let ulen = user.len();
    let plen = pass.len();
    if ulen > 200 || plen > 400 {
        return (-1, String::new());
    }
    let mut pkt = Vec::new();
    pkt.push(SSH_MSG_USERAUTH_REQUEST);
    ssh_put_u32(&mut pkt, ulen as u32);
    pkt.extend_from_slice(user.as_bytes());
    ssh_put_u32(&mut pkt, 14);
    pkt.extend_from_slice(b"ssh-connection");
    ssh_put_u32(&mut pkt, 8);
    pkt.extend_from_slice(b"password");
    pkt.push(0);
    ssh_put_u32(&mut pkt, plen as u32);
    pkt.extend_from_slice(pass.as_bytes());
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
        return (1, "password".to_string());
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
/* TLS record/handshake probes (arsenal_tls.h)                       */
/*                                                                   */
/* Faithful port: tls_read_record returns the record CONTENT (the    */
/* 5-byte header is stripped), exactly as ar_tls_read_record did, so  */
/* downstream indexing matches the C plugins byte-for-byte.           */
/* ---------------------------------------------------------------- */

pub const TLS_CCS: u8 = 20;
pub const TLS_ALERT: u8 = 21;
pub const TLS_HANDSHAKE: u8 = 22;
pub const TLS_HEARTBEAT: u8 = 24;

pub const TLS_CIPHERS: [u16; 24] = [
    0xC02F, 0xC030, 0xC02B, 0xC02C, 0xCCA8, 0xCCA9, 0x009E, 0x009F, 0x002F, 0x0035, 0x003C, 0x003D,
    0x000A, 0x0005, 0x0004, 0x0067, 0x006B, 0x0033, 0x0039, 0x0016, 0x0023, 0x0009, 0x0006, 0x0003,
];

pub const TLS_CBC_CIPHERS: [u16; 16] = [
    0x002F, 0x0035, 0x003C, 0x003D, 0x000A, 0x0005, 0x0004, 0x0067, 0x006B, 0x0033, 0x0039, 0x0016,
    0x0023, 0x0009, 0x0006, 0x0003,
];

pub fn tls_is_cbc(cipher: u16) -> bool {
    TLS_CBC_CIPHERS.iter().any(|&c| c == cipher)
}

pub fn tls_cipher_name(c: u16) -> &'static str {
    match c {
        0xC02F => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xC030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xC02B => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xC02C => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xCCA8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
        0xCCA9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
        0x009E => "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        0x009F => "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        0x002F => "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
        0x003C => "TLS_RSA_WITH_AES_128_CBC_SHA256",
        0x003D => "TLS_RSA_WITH_AES_256_CBC_SHA256",
        0x000A => "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        0x0005 => "TLS_RSA_WITH_RC4_128_SHA",
        0x0004 => "TLS_RSA_WITH_RC4_128_MD5",
        0x0067 => "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        0x006B => "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        0x0033 => "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        0x0039 => "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        0x0016 => "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
        0x0023 => "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
        0x0009 => "TLS_RSA_WITH_DES_CBC_SHA",
        0x0006 => "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
        0x0003 => "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
        _ => "unknown",
    }
}

pub fn tls_version_name(v: u16) -> &'static str {
    match v {
        0x0300 => "SSLv3",
        0x0301 => "TLSv1.0",
        0x0302 => "TLSv1.1",
        0x0303 => "TLSv1.2",
        0x0304 => "TLSv1.3",
        _ => "unknown",
    }
}

/* Build a ClientHello record (byte-for-byte port of ar_tls_client_hello). */
fn tls_client_hello(version: u16, ciphers: &[u16], heartbeat: bool) -> Option<Vec<u8>> {
    if ciphers.is_empty() {
        return None;
    }
    let mut body: Vec<u8> = Vec::new();
    body.push((version >> 8) as u8);
    body.push((version & 0xff) as u8);
    for i in 0..32u8 {
        body.push(0x30 + i);
    }
    body.push(0); // session id length
    let nc = ciphers.len();
    body.push(((nc * 2) >> 8) as u8);
    body.push(((nc * 2) & 0xff) as u8);
    for &c in ciphers.iter() {
        body.push((c >> 8) as u8);
        body.push((c & 0xff) as u8);
    }
    body.push(1); // compression methods length
    body.push(0); // null compression
    let mut ext: Vec<u8> = Vec::new();
    if version >= 0x0301 {
        ext.extend_from_slice(&[
            0x00, 0x0A, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1D, 0x00, 0x17, 0x00, 0x18,
        ]);
        ext.extend_from_slice(&[0x00, 0x0B, 0x00, 0x02, 0x01, 0x00]);
        ext.extend_from_slice(&[
            0x00, 0x0D, 0x00, 0x0A, 0x00, 0x08, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x01,
        ]);
        ext.extend_from_slice(&[0xFF, 0x01, 0x00, 0x01, 0x00]);
        if heartbeat {
            ext.extend_from_slice(&[0x00, 0x0F, 0x00, 0x01, 0x01]);
        }
    }
    body.push((ext.len() >> 8) as u8);
    body.push((ext.len() & 0xff) as u8);
    body.extend_from_slice(&ext);
    let b = body.len();
    let mut out: Vec<u8> = Vec::new();
    out.push(TLS_HANDSHAKE);
    out.push((version >> 8) as u8);
    out.push((version & 0xff) as u8);
    out.push(((b + 4) >> 8) as u8);
    out.push(((b + 4) & 0xff) as u8);
    out.push(1); // handshake type: ClientHello
    out.push((b >> 16) as u8);
    out.push((b >> 8) as u8);
    out.push((b & 0xff) as u8);
    out.extend_from_slice(&body);
    Some(out)
}

/* Read one TLS record; returns its CONTENT (header stripped), or None. */
fn tls_read_record(stream: &mut TcpStream, cap: usize) -> Option<Vec<u8>> {
    let hdr = recv_exact(stream, 5)?;
    let len = ((hdr[3] as usize) << 8) | hdr[4] as usize;
    if len + 1 > cap {
        return None;
    }
    if len == 0 {
        return Some(Vec::new());
    }
    recv_exact(stream, len)
}

/* (version, cipher, sid_len) from ServerHello content, or None. */
fn tls_parse_server_hello(p: &[u8]) -> Option<(u16, u16, usize)> {
    let len = p.len();
    if len < 40 || p[0] != 2 {
        return None;
    }
    let version = ((p[4] as u16) << 8) | p[5] as u16;
    let mut off = 6 + 32;
    if off >= len {
        return None;
    }
    let sid_len = p[off] as usize;
    off += 1 + sid_len;
    if off + 2 > len {
        return None;
    }
    let cipher = ((p[off] as u16) << 8) | p[off + 1] as u16;
    Some((version, cipher, sid_len))
}

/* (rc, selver, selcipher). rc: 1 handshake ok, 0 alert, -1 failure. */
pub fn tls_probe(
    ctx: *mut AlScriptContext,
    version: u16,
    ciphers: &[u16],
    heartbeat: bool,
) -> (i32, u16, u16) {
    let hello = match tls_client_hello(version, ciphers, heartbeat) {
        Some(h) => h,
        None => return (-1, 0, 0),
    };
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => return (-1, 0, 0),
    };
    if send_all(&mut s, &hello).is_err() {
        return (-1, 0, 0);
    }
    let rec = match tls_read_record(&mut s, 4096) {
        Some(r) => r,
        None => return (-1, 0, 0),
    };
    drop(s);
    if !rec.is_empty() && rec[0] == TLS_ALERT {
        return (0, 0, 0);
    }
    match tls_parse_server_hello(&rec) {
        Some((v, c, _)) => (1, v, c),
        None => (-1, 0, 0),
    }
}

/* rc: 1 vulnerable, 0 not, -1 handshake failed. */
pub fn tls_heartbleed(ctx: *mut AlScriptContext) -> i32 {
    let hello = match tls_client_hello(0x0301, &TLS_CIPHERS, true) {
        Some(h) => h,
        None => return -1,
    };
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => return -1,
    };
    if send_all(&mut s, &hello).is_err() {
        return -1;
    }
    let rec = match tls_read_record(&mut s, 4096) {
        Some(r) if !r.is_empty() => r,
        _ => return 0,
    };
    if rec[0] == TLS_ALERT {
        return 0;
    }
    let ver = match tls_parse_server_hello(&rec) {
        Some((v, _, _)) => v,
        None => return 0,
    };
    let hb = [
        TLS_HEARTBEAT,
        (ver >> 8) as u8,
        (ver & 0xff) as u8,
        0,
        3,
        1,
        0x40,
        0x00,
    ];
    if send_all(&mut s, &hb).is_err() {
        return 0;
    }
    match tls_read_record(&mut s, 4096) {
        Some(r) if r.len() > 3 && r[0] == TLS_HEARTBEAT => 1,
        _ => 0,
    }
}

/* (rc, selver, selcipher). rc: 1 early-CCS accepted, 0 rejected, -1 failed. */
pub fn tls_ccs_test(ctx: *mut AlScriptContext) -> (i32, u16, u16) {
    let hello = match tls_client_hello(0x0303, &TLS_CIPHERS, false) {
        Some(h) => h,
        None => return (-1, 0, 0),
    };
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => return (-1, 0, 0),
    };
    if send_all(&mut s, &hello).is_err() {
        return (-1, 0, 0);
    }
    let mut rec = match tls_read_record(&mut s, 4096) {
        Some(r) if !r.is_empty() => r,
        _ => return (-1, 0, 0),
    };
    let (ver, cipher, _) = match tls_parse_server_hello(&rec) {
        Some(v) => v,
        None => return (-1, 0, 0),
    };
    // Drain the server flight through ServerHelloDone (type 14).
    for _ in 0..6 {
        if !rec.is_empty() && rec[0] == TLS_ALERT {
            return (0, ver, cipher);
        }
        if rec.len() >= 4 && rec[0] == 14 {
            break;
        }
        match tls_read_record(&mut s, 4096) {
            Some(r) if !r.is_empty() => rec = r,
            _ => break,
        }
    }
    let ccs = [TLS_CCS, 0x03, 0x01, 0x00, 0x01, 0x01];
    if send_all(&mut s, &ccs).is_err() {
        return (-1, ver, cipher);
    }
    match tls_read_record(&mut s, 4096) {
        Some(r) if !r.is_empty() && r[0] != TLS_ALERT => (1, ver, cipher),
        _ => (0, ver, cipher),
    }
}

/* (rc, bits, group_len). rc: 0 ok (bits/group_len set), -1 handshake failed. */
pub fn tls_dh_bits(ctx: *mut AlScriptContext) -> (i32, i32, u32) {
    const DHE: [u16; 7] = [0x009E, 0x009F, 0x0067, 0x006B, 0x0033, 0x0039, 0x0016];
    let hello = match tls_client_hello(0x0303, &DHE, false) {
        Some(h) => h,
        None => return (-1, 0, 0),
    };
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => return (-1, 0, 0),
    };
    if send_all(&mut s, &hello).is_err() {
        return (-1, 0, 0);
    }
    let rec = match tls_read_record(&mut s, 4096) {
        Some(r) if !r.is_empty() => r,
        _ => return (-1, 0, 0),
    };
    if tls_parse_server_hello(&rec).is_none() {
        return (-1, 0, 0);
    }
    let mut bits = 0i32;
    let mut group_len = 0u32;
    for _ in 0..4 {
        let rec = match tls_read_record(&mut s, 4096) {
            Some(r) if !r.is_empty() => r,
            _ => break,
        };
        if rec[0] != 12 {
            continue;
        }
        let n = rec.len();
        let mut off = 4usize;
        if off + 2 > n {
            break;
        }
        if off < n && rec[off] == 3 {
            // ECDHE named curve: no finite-field DH group.
            bits = 0;
            group_len = 0;
            break;
        }
        let plen = ((rec[off] as usize) << 8) | rec[off + 1] as usize;
        off += 2;
        if plen > 1024 || plen > n - off || plen < 64 {
            bits = 0;
            group_len = 0;
            break;
        }
        if plen >= 2 {
            let pbits = ((rec[off] as u32) << 8) | rec[off + 1] as u32;
            if (512..=8192).contains(&pbits) {
                bits = pbits as i32;
                group_len = pbits / 8;
            }
        }
        break;
    }
    drop(s);
    (0, bits, group_len)
}

/* ---------------------------------------------------------------- */
/* SNMPv2c / BER (arsenal_snmp.h)                                    */
/* ---------------------------------------------------------------- */

fn ber_len(out: &mut Vec<u8>, len: usize) {
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xff) as u8);
    }
}

fn ber_tlv(tag: u8, val: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(tag);
    ber_len(&mut out, val.len());
    out.extend_from_slice(val);
    out
}

fn ber_int(v: u32) -> Vec<u8> {
    let mut tmp: Vec<u8> = Vec::new();
    let mut v = v;
    if v == 0 {
        tmp.push(0);
    } else {
        while v > 0 && tmp.len() < 5 {
            tmp.push((v & 0xff) as u8);
            v >>= 8;
        }
    }
    if tmp.len() > 1 && (tmp[tmp.len() - 1] & 0x80) != 0 {
        tmp.push(0);
    }
    let rev: Vec<u8> = tmp.iter().rev().cloned().collect();
    ber_tlv(0x02, &rev)
}

fn ber_oid(oid: &str) -> Option<Vec<u8>> {
    let mut parts: Vec<u32> = Vec::new();
    for seg in oid.split('.') {
        if parts.len() >= 32 {
            break;
        }
        if seg.is_empty() {
            return None;
        }
        let v: u32 = seg.parse().ok()?;
        parts.push(v);
    }
    if parts.len() < 2 {
        return None;
    }
    let mut tmp: Vec<u8> = Vec::new();
    tmp.push((parts[0] * 40 + parts[1]) as u8);
    for i in 2..parts.len() {
        let mut v = parts[i];
        let mut stack: Vec<u8> = Vec::new();
        loop {
            stack.push((v & 0x7F) as u8);
            v >>= 7;
            if v == 0 {
                break;
            }
        }
        while let Some(mut b) = stack.pop() {
            if !stack.is_empty() {
                b |= 0x80;
            }
            tmp.push(b);
        }
    }
    Some(ber_tlv(0x06, &tmp))
}

fn snmp_make_get(community: &str, oid: &str) -> Option<Vec<u8>> {
    let oidbuf = ber_oid(oid)?;
    let nullbuf = ber_tlv(0x05, &[]);
    let mut vbcontent = Vec::new();
    vbcontent.extend_from_slice(&oidbuf);
    vbcontent.extend_from_slice(&nullbuf);
    let varbind = ber_tlv(0x30, &vbcontent);
    let vblist = ber_tlv(0x30, &varbind);
    let mut pducontent = Vec::new();
    pducontent.extend_from_slice(&ber_int(1)); // request-id
    pducontent.extend_from_slice(&ber_int(0)); // error-status
    pducontent.extend_from_slice(&ber_int(0)); // error-index
    pducontent.extend_from_slice(&vblist);
    let pdu = ber_tlv(0xA0, &pducontent); // GetRequest
    let mut msgcontent = Vec::new();
    msgcontent.extend_from_slice(&ber_int(1)); // version = SNMPv2c
    msgcontent.extend_from_slice(&ber_tlv(0x04, community.as_bytes()));
    msgcontent.extend_from_slice(&pdu);
    Some(ber_tlv(0x30, &msgcontent))
}

/* (tag, value-offset, value-len, consumed) from a BER TLV, or None. */
fn ber_read_tlv(p: &[u8]) -> Option<(u8, usize, usize, usize)> {
    let len = p.len();
    if len < 2 {
        return None;
    }
    let tag = p[0];
    let (l, o);
    if p[1] & 0x80 == 0 {
        l = p[1] as usize;
        o = 2usize;
    } else {
        let n = (p[1] & 0x7F) as usize;
        if n < 1 || n > 3 || len < 2 + n {
            return None;
        }
        let mut ll = 0usize;
        for i in 0..n {
            ll = (ll << 8) | p[2 + i] as usize;
        }
        l = ll;
        o = 2 + n;
    }
    if o + l > len {
        return None;
    }
    Some((tag, o, l, o + l))
}

fn snmp_format_value(tag: u8, v: &[u8]) -> String {
    let vl = v.len();
    let out = if tag == 0x04 {
        String::from_utf8_lossy(v).into_owned()
    } else if tag == 0x06 {
        let mut s = String::new();
        let mut x: u32 = 0;
        let mut first = true;
        for &b in v.iter() {
            x = (x << 7) | (b & 0x7F) as u32;
            if b & 0x80 == 0 {
                if first {
                    s.push_str(&format!("{}.{}", x / 40, x % 40));
                    first = false;
                } else {
                    s.push_str(&format!(".{}", x));
                }
                x = 0;
            }
        }
        s
    } else if tag == 0x02 || tag == 0x41 || tag == 0x42 || tag == 0x43 {
        let mut x: u32 = 0;
        for &b in v.iter() {
            x = (x << 8) | b as u32;
        }
        format!("{}", x)
    } else {
        format!("tag 0x{:02x} len {}", tag, vl)
    };
    clean(&out)
}

/* SNMPv2c GET; returns the first varbind value as text, or None. */
pub fn snmp_get(ctx: *mut AlScriptContext, community: &str, oid: &str) -> Option<String> {
    let req = snmp_make_get(community, oid)?;
    let resp = udp_exchange(ctx, &req, 2048)?;
    if resp.is_empty() {
        return None;
    }
    let (tag, o, vl, _c) = ber_read_tlv(&resp)?;
    if tag != 0x30 {
        return None;
    }
    let v = &resp[o..o + vl];
    let mut off = 0usize;
    for i in 0..3 {
        if off >= vl {
            break;
        }
        let (t, oo, l, c) = ber_read_tlv(&v[off..])?;
        let seg = &v[off + oo..off + oo + l];
        off += c;
        if i == 2 && t == 0xA2 {
            let mut po = 0usize;
            for j in 0..4 {
                if po >= l {
                    break;
                }
                let (pt, poo, pl, pc) = ber_read_tlv(&seg[po..])?;
                let pseg = &seg[po + poo..po + poo + pl];
                po += pc;
                if j == 3 && pt == 0x30 {
                    let (_vt, voo, vll, _vc) = ber_read_tlv(pseg)?;
                    let vseg = &pseg[voo..voo + vll];
                    let (_t1, _o1, _l1, c1) = ber_read_tlv(vseg)?;
                    let (vt2, o2, l2, _c2) = ber_read_tlv(&vseg[c1..])?;
                    let valslice = &vseg[c1 + o2..c1 + o2 + l2];
                    return Some(snmp_format_value(vt2, valslice));
                }
            }
        }
    }
    None
}

/* ---------------------------------------------------------------- */
/* MySQL (arsenal_mysql.h)                                          */
/* ---------------------------------------------------------------- */

fn mysql_read_packet(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let hdr = recv_exact(stream, 4)?;
    let len = (hdr[0] as usize) | ((hdr[1] as usize) << 8) | ((hdr[2] as usize) << 16);
    if len == 0 {
        return Some(Vec::new());
    }
    recv_exact(stream, len)
}

fn mysql_send_packet(stream: &mut TcpStream, payload: &[u8], seq: u8) -> bool {
    let len = payload.len();
    if len > 0xFF_FFFF {
        return false;
    }
    let hdr = [
        (len & 255) as u8,
        ((len >> 8) & 255) as u8,
        ((len >> 16) & 255) as u8,
        seq,
    ];
    send_all(stream, &hdr).is_ok() && send_all(stream, payload).is_ok()
}

/* Connect and read the MySQL initial handshake; returns (stream, version). */
pub fn mysql_open(ctx: *mut AlScriptContext) -> Option<(TcpStream, String)> {
    let mut s = connect_ctx(ctx)?;
    let pkt = mysql_read_packet(&mut s)?;
    if pkt.len() < 2 || pkt[0] != 10 {
        return None;
    }
    let mut i = 1usize;
    while i < pkt.len() && pkt[i] != 0 {
        i += 1;
    }
    let version = clean(&String::from_utf8_lossy(&pkt[1..i]));
    Some((s, version))
}

/* Attempt a login. Returns 0 on OK, the MySQL error code on an error
 * packet, or -1 on I/O / unexpected reply. */
pub fn mysql_login(stream: &mut TcpStream, user: &str, pass: &str, empty: bool) -> i32 {
    let caps: u32 = 0x000A_A201;
    let ulen = user.len();
    if ulen > 200 {
        return -1;
    }
    let mut plen = if empty { 0 } else { pass.len() };
    if !empty && plen > 20 {
        plen = 20;
    }
    let _ = plen;
    let mut pkt: Vec<u8> = Vec::new();
    pkt.extend_from_slice(&caps.to_le_bytes());
    pkt.extend_from_slice(&[0, 0, 0, 1]);
    pkt.push(33);
    pkt.extend_from_slice(&[0u8; 23]);
    pkt.extend_from_slice(user.as_bytes());
    pkt.push(0);
    pkt.push(if empty { 0 } else { 20 });
    if !empty {
        /* Deterministic non-matching scramble; a probe, not a credential. */
        pkt.extend_from_slice(&[0x41u8; 20]);
    }
    pkt.extend_from_slice(b"mysql_native_password");
    pkt.push(0);
    pkt.push(0);

    if !mysql_send_packet(stream, &pkt, 1) {
        return -1;
    }
    let resp = match mysql_read_packet(stream) {
        Some(r) if !r.is_empty() => r,
        _ => return -1,
    };
    if resp[0] == 0x00 {
        return 0;
    }
    if resp[0] == 0xFF {
        let mut code = 0i32;
        if resp.len() >= 3 {
            code = resp[1] as i32 | ((resp[2] as i32) << 8);
        }
        return code;
    }
    -1
}

/* ---------------------------------------------------------------- */
/* MSSQL blank-password login (arsenal_mssql.h)                     */
/* ---------------------------------------------------------------- */

fn mssql_set16(p: &mut [u8], off: usize, v: u16) {
    p[off] = (v & 255) as u8;
    p[off + 1] = ((v >> 8) & 255) as u8;
}

fn mssql_set32(p: &mut [u8], off: usize, v: u32) {
    p[off] = (v & 255) as u8;
    p[off + 1] = ((v >> 8) & 255) as u8;
    p[off + 2] = ((v >> 16) & 255) as u8;
    p[off + 3] = ((v >> 24) & 255) as u8;
}

fn mssql_field(login: &mut [u8], pair: usize, s: &str, voff: &mut usize) {
    let base = 42 + pair * 4;
    let len = s.len();
    if len == 0 {
        mssql_set16(login, base, 0);
        mssql_set16(login, base + 2, 0);
        return;
    }
    mssql_set16(login, base, *voff as u16);
    mssql_set16(login, base + 2, len as u16);
    let start = *voff;
    for (i, b) in s.bytes().enumerate() {
        login[start + i * 2] = b;
        login[start + i * 2 + 1] = 0;
    }
    *voff += len * 2;
}

/* Returns (rc, message): 0 accepted, 1 rejected, -1 no response. */
pub fn mssql_empty_login(ctx: *mut AlScriptContext) -> (i32, String) {
    if !ctx_check(ctx) {
        return (-1, String::new());
    }
    let ip = ip_text(ctx);
    let mut login = vec![0u8; 1024];
    let mut voff = 100usize;
    mssql_field(&mut login, 0, "ALMAP", &mut voff);
    mssql_field(&mut login, 1, "sa", &mut voff);
    mssql_field(&mut login, 2, "", &mut voff);
    mssql_field(&mut login, 3, "ALmap", &mut voff);
    mssql_field(&mut login, 4, &ip, &mut voff);
    mssql_field(&mut login, 5, "", &mut voff);
    mssql_field(&mut login, 6, "ALmap", &mut voff);
    mssql_field(&mut login, 7, "", &mut voff);
    mssql_field(&mut login, 8, "", &mut voff);

    mssql_set32(&mut login, 4, 0x7400_0004);
    mssql_set32(&mut login, 8, 4096);
    login[24] = 0xE0;
    login[28] = 0x03;

    let total = voff;
    mssql_set32(&mut login, 0, total as u32);

    let mut pkt = vec![0u8; 1200];
    pkt[0] = 0x10;
    pkt[1] = 0x01;
    let total8 = total + 8;
    pkt[2] = (total8 >> 8) as u8;
    pkt[3] = (total8 & 255) as u8;
    pkt[6] = 1;
    pkt[8..8 + total].copy_from_slice(&login[..total]);

    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => return (-1, String::new()),
    };
    if send_all(&mut s, &pkt[..total8]).is_err() {
        return (-1, String::new());
    }
    let (typ, resp) = match mssql_read_packet(&mut s) {
        Some(v) => v,
        None => return (-1, String::new()),
    };
    drop(s);
    if typ == 0x04 {
        return (0, "login accepted".to_string());
    }
    let n = resp.len();
    let mut i = 0usize;
    while i + 9 < n {
        if resp[i] == 0xAA {
            let mut mlen = ((resp[i + 7] as usize) << 8) | resp[i + 8] as usize;
            if i + 9 + mlen > n {
                mlen = n - i - 9;
            }
            let mut msg = String::new();
            let mut k = 0usize;
            while k < mlen {
                msg.push(resp[i + 9 + k] as char);
                k += 2;
            }
            return (1, clean(&msg));
        }
        i += 1;
    }
    (1, format!("login failed (TDS type 0x{:02x})", typ))
}

/* ---------------------------------------------------------------- */
/* Oracle TNS CONNECT (arsenal_oracle.h)                            */
/* ---------------------------------------------------------------- */

pub fn oracle_tns(
    ctx: *mut AlScriptContext,
    connect_data: &str,
    cap: usize,
) -> Option<Vec<u8>> {
    if !ctx_check(ctx) {
        return None;
    }
    let ip = ip_text(ctx);
    let port = unsafe { (*ctx).port };
    let desc = format!(
        "(DESCRIPTION=(CONNECT_DATA={})(ADDRESS=(PROTOCOL=TCP)(HOST={})(PORT={})))",
        connect_data, ip, port
    );
    let dlen = desc.len();
    let total = 58 + dlen;
    if total > 1024 {
        return None;
    }
    let mut pkt = vec![0u8; 1024];
    pkt[0] = (total >> 8) as u8;
    pkt[1] = (total & 255) as u8;
    pkt[4] = 1; /* TNS CONNECT */
    pkt[8] = 0x01;
    pkt[9] = 0x36;
    pkt[10] = 0x01;
    pkt[11] = 0x2C;
    pkt[18] = 0x00;
    pkt[19] = 0x01;
    pkt[20] = (dlen >> 8) as u8;
    pkt[21] = (dlen & 255) as u8;
    pkt[22] = 0x00;
    pkt[23] = 0x3A;
    pkt[26] = 0x00;
    pkt[27] = 0x01;
    pkt[58..58 + dlen].copy_from_slice(desc.as_bytes());

    let mut s = connect_ctx(ctx)?;
    send_all(&mut s, &pkt[..total]).ok()?;
    let buf = recv_all(&mut s, cap);
    if buf.is_empty() {
        return None;
    }
    Some(buf)
}

/* ---------------------------------------------------------------- */
/* PostgreSQL v3 startup / auth (arsenal_pgsql.h)                    */
/* ---------------------------------------------------------------- */

fn pg_startup_body(user: &str, db: &str) -> Vec<u8> {
    let u = if user.is_empty() { "postgres" } else { user };
    let d = if db.is_empty() { "postgres" } else { db };
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(b"user\0");
    body.extend_from_slice(u.as_bytes());
    body.push(0);
    body.extend_from_slice(b"database\0");
    body.extend_from_slice(d.as_bytes());
    body.push(0);
    body.push(0);
    let total = (8 + body.len()) as u32;
    let mut pkt: Vec<u8> = Vec::new();
    pkt.extend_from_slice(&total.to_be_bytes());
    pkt.extend_from_slice(&196608u32.to_be_bytes());
    pkt.extend_from_slice(&body);
    pkt
}

/* Mirrors ar_pg_start. Returns (rc, ssl): rc = 0 startup sent (stream
 * returned), -2 server requires/offers SSL, -1 unreachable/error. */
fn pg_start_stream(ctx: *mut AlScriptContext, user: &str, db: &str) -> (i32, bool, Option<TcpStream>) {
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => return (-1, false, None),
    };
    let sslreq = [0u8, 0, 0, 8, 0x04, 0xD2, 0x16, 0x2F];
    if send_all(&mut s, &sslreq).is_err() {
        return (-1, false, None);
    }
    let b = match recv_exact(&mut s, 1) {
        Some(v) => v,
        None => return (-1, false, None),
    };
    if b[0] == b'S' {
        return (-2, true, None);
    }
    if b[0] != b'N' {
        return (-1, false, None);
    }
    let pkt = pg_startup_body(user, db);
    if send_all(&mut s, &pkt).is_err() {
        return (-1, false, None);
    }
    (0, false, Some(s))
}

/* Public: (rc, ssl) with the connection closed. rc: 0 ok, -2 ssl, -1 error. */
pub fn pg_start(ctx: *mut AlScriptContext, user: &str, db: &str) -> (i32, bool) {
    let (rc, ssl, _s) = pg_start_stream(ctx, user, db);
    (rc, ssl)
}

fn pg_read_msg(stream: &mut TcpStream) -> Option<(u8, Vec<u8>)> {
    let hdr = recv_exact(stream, 5)?;
    let len = ((hdr[1] as usize) << 24)
        | ((hdr[2] as usize) << 16)
        | ((hdr[3] as usize) << 8)
        | hdr[4] as usize;
    if len < 4 || len - 4 > 512 {
        return None;
    }
    let body = if len - 4 > 0 {
        recv_exact(stream, len - 4)?
    } else {
        Vec::new()
    };
    Some((hdr[0], body))
}

/* Mirrors ar_pg_login. Returns (rc, msg): 1 accepted, 0 denied/other, -1 error. */
pub fn pg_login(ctx: *mut AlScriptContext, user: &str, pass: &str) -> (i32, String) {
    let (rc, _ssl, stream) = pg_start_stream(ctx, user, "postgres");
    if rc == -2 {
        return (0, "SSL required".to_string());
    }
    let mut s = match stream {
        Some(s) => s,
        None => return (-1, String::new()),
    };
    let (tag, body) = match pg_read_msg(&mut s) {
        Some(v) => v,
        None => return (-1, String::new()),
    };
    if tag != b'R' {
        return (0, format!("auth type {}", tag as char));
    }
    if body.len() < 4 {
        return (-1, String::new());
    }
    let code = ((body[0] as u32) << 24)
        | ((body[1] as u32) << 16)
        | ((body[2] as u32) << 8)
        | body[3] as u32;
    if code == 0 {
        return (1, "OK".to_string());
    }
    if code != 3 {
        return (0, format!("auth code {}", code));
    }
    // Cleartext password request. The length field mirrors ar_pg_login's
    // `o` exactly (it counts the type byte: 1 + 4 + passlen + 1 = 6 + passlen),
    // so the wire bytes match the C probe one-for-one.
    let mut pkt: Vec<u8> = Vec::new();
    pkt.push(b'p');
    let lenfield = (6 + pass.len()) as u32;
    pkt.extend_from_slice(&lenfield.to_be_bytes());
    pkt.extend_from_slice(pass.as_bytes());
    pkt.push(0);
    if send_all(&mut s, &pkt).is_err() {
        return (-1, String::new());
    }
    let (tag2, body2) = match pg_read_msg(&mut s) {
        Some(v) => v,
        None => return (-1, String::new()),
    };
    let ok = tag2 == b'R' && body2.len() >= 4 && body2[0] == 0 && body2[1] == 0 && body2[2] == 0 && body2[3] == 0;
    if ok {
        (1, "OK".to_string())
    } else {
        (0, "denied".to_string())
    }
}
