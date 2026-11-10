/*
 * rust_plugins/alscript.rs - shared core for the Rust AlScript arsenal.
 *
 * Faithful port of c/alscript.h (the ABI), plugins/alscript_net.h (raw
 * TCP/UDP helpers) and plugins/arsenal_util.h (output + HTTP + FTP
 * helpers). Pure std only: no external crates, no OpenSSL, no unsafe
 * beyond the unavoidable FFI output-buffer writes (all bounds-checked).
 *
 * This file is textually `include!`d at the top of every plugin, so the
 * `use` imports here are shared by the whole compilation unit; plugin
 * and protocol files must NOT repeat them.
 *
 * Use only on networks you own or have permission to scan.
 */

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::os::raw::c_char;
use std::time::Duration;

/// Mirror of the C `AlScriptContext` struct (c/alscript.h). The field
/// order, types and `#[repr(C)]` layout match byte-for-byte so the ALmap
/// loader can call this .so exactly as it calls the C plugins.
#[repr(C)]
pub struct AlScriptContext {
    pub target_ip: u32,   // host-order u32, first octet high (127.0.0.1 = 0x7F000001)
    pub port: i32,        // host-order 1..65535
    pub timeout_ms: i32,  // suggested network timeout, > 0
    pub output_buf: *mut c_char,
    pub output_max: i32,
}

// ---------------------------------------------------------------------------
// Context validation + output (ar_check / ar_valid / ar_out / ar_append).
// ---------------------------------------------------------------------------

pub fn ar_check(ctx: &AlScriptContext) -> bool {
    if ctx.output_buf.is_null() || ctx.output_max < 2 {
        return false;
    }
    if ctx.port < 1 || ctx.port > 65535 || ctx.timeout_ms <= 0 {
        return false;
    }
    ctx.target_ip != 0
}

/// Returns true when the context is usable, and clears the output buffer.
pub fn ar_valid(ctx: &AlScriptContext) -> bool {
    if !ar_check(ctx) {
        return false;
    }
    unsafe {
        *ctx.output_buf = 0;
    }
    true
}

fn buf_strlen(ctx: &AlScriptContext) -> usize {
    let max = ctx.output_max as usize;
    let mut i = 0usize;
    unsafe {
        while i < max && *ctx.output_buf.add(i) != 0 {
            i += 1;
        }
    }
    i
}

/// Overwrite the output buffer with `s`, truncated to output_max-1 bytes,
/// always NUL-terminated. Mirrors ar_out() (printf formatting is done by
/// the caller via format!()).
pub fn ar_out(ctx: &AlScriptContext, s: &str) {
    if ctx.output_buf.is_null() || ctx.output_max < 2 {
        return;
    }
    let max = ctx.output_max as usize;
    let bytes = s.as_bytes();
    let n = bytes.len().min(max - 1);
    unsafe {
        for i in 0..n {
            *ctx.output_buf.add(i) = bytes[i] as c_char;
        }
        *ctx.output_buf.add(n) = 0;
    }
}

/// Append `s` to the existing NUL-terminated output, never exceeding
/// output_max-1 bytes. Mirrors ar_append().
pub fn ar_append(ctx: &AlScriptContext, s: &str) {
    if ctx.output_buf.is_null() || ctx.output_max < 2 {
        return;
    }
    let max = ctx.output_max as usize;
    let used = buf_strlen(ctx);
    if used + 1 >= max {
        return;
    }
    let bytes = s.as_bytes();
    let avail = max - 1 - used;
    let n = bytes.len().min(avail);
    unsafe {
        for i in 0..n {
            *ctx.output_buf.add(used + i) = bytes[i] as c_char;
        }
        *ctx.output_buf.add(used + n) = 0;
    }
}

// ---------------------------------------------------------------------------
// TCP/UDP helpers (port of alscript_net.h). std TcpStream read/write
// timeouts replace the poll()-based non-blocking loops; behaviour matches.
// ---------------------------------------------------------------------------

fn dur_ms(ms: i32) -> Duration {
    Duration::from_millis(ms.max(1) as u64)
}

/// Connect to (ctx.target_ip, ctx.port) with the context timeout and arm
/// per-operation read/write deadlines. Returns None on any failure.
pub fn as_connect(ctx: &AlScriptContext) -> Option<TcpStream> {
    let ip = Ipv4Addr::from(ctx.target_ip);
    let addr = SocketAddr::new(IpAddr::V4(ip), ctx.port as u16);
    let s = TcpStream::connect_timeout(&addr, dur_ms(ctx.timeout_ms)).ok()?;
    let _ = s.set_read_timeout(Some(dur_ms(ctx.timeout_ms)));
    let _ = s.set_write_timeout(Some(dur_ms(ctx.timeout_ms)));
    Some(s)
}

/// Override the read deadline for the next reads on this stream.
pub fn set_rtimeout(s: &TcpStream, ms: i32) {
    let _ = s.set_read_timeout(Some(dur_ms(ms)));
}

/// Send the whole buffer. Returns true on success (mirrors `== 0`).
pub fn as_send_all(s: &mut TcpStream, data: &[u8]) -> bool {
    s.write_all(data).is_ok()
}

/// Read exactly `buf.len()` bytes. Returns true on success.
pub fn as_recv_exact(s: &mut TcpStream, buf: &mut [u8]) -> bool {
    s.read_exact(buf).is_ok()
}

/// Read until the peer closes or a read times out, capped at `cap` bytes.
pub fn as_recv_all_cap(s: &mut TcpStream, cap: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 4096];
    while out.len() + 1 < cap {
        match s.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                let room = (cap - 1 - out.len()).min(n);
                out.extend_from_slice(&tmp[..room]);
                if room < n {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    out
}

/// Read a single line (through '\n'), capped at `cap` bytes.
pub fn as_recv_line(s: &mut TcpStream, cap: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut b = [0u8; 1];
    while out.len() + 1 < cap {
        match s.read(&mut b) {
            Ok(0) => break,
            Ok(_) => {
                out.push(b[0]);
                if b[0] == b'\n' {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    out
}

/// Dotted-quad text for a host-order u32 (port of as_ip_text).
pub fn as_ip_text(ip: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (ip >> 24) & 255,
        (ip >> 16) & 255,
        (ip >> 8) & 255,
        ip & 255
    )
}

/// Send one UDP datagram and return the first reply (port of
/// as_udp_exchange), capped at `cap` bytes.
pub fn as_udp_exchange(
    ctx: &AlScriptContext,
    req: &[u8],
    cap: usize,
    timeout_ms: i32,
) -> Option<Vec<u8>> {
    if req.is_empty() || cap < 1 {
        return None;
    }
    let ip = Ipv4Addr::from(ctx.target_ip);
    let sock = UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    sock.connect(SocketAddr::new(IpAddr::V4(ip), ctx.port as u16)).ok()?;
    sock.set_read_timeout(Some(dur_ms(timeout_ms))).ok()?;
    sock.send(req).ok()?;
    let mut buf = vec![0u8; cap];
    let n = sock.recv(&mut buf).ok()?;
    buf.truncate(n);
    Some(buf)
}

// ---------------------------------------------------------------------------
// Text helpers (port of arsenal_util.h string utilities).
// ---------------------------------------------------------------------------

/// Case-insensitive substring test (port of ar_contains_ci / ar_stristr).
pub fn ar_contains_ci(hay: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    hay.to_ascii_lowercase().contains(&needle.to_ascii_lowercase())
}

/// Case-insensitive prefix test (port of ar_starts_ci).
pub fn ar_starts_ci(s: &str, prefix: &str) -> bool {
    let sb = s.as_bytes();
    let pb = prefix.as_bytes();
    sb.len() >= pb.len() && sb[..pb.len()].eq_ignore_ascii_case(pb)
}

/// Trim ASCII whitespace and replace control bytes with spaces
/// (port of ar_clean), returning a clean owned String.
pub fn ar_clean(bytes: &[u8]) -> String {
    let mapped: Vec<u8> = bytes
        .iter()
        .map(|&c| if c < 32 || c == 127 { b' ' } else { c })
        .collect();
    let start = mapped.iter().position(|&c| c != b' ').unwrap_or(mapped.len());
    let end = mapped
        .iter()
        .rposition(|&c| c != b' ')
        .map(|i| i + 1)
        .unwrap_or(start);
    String::from_utf8_lossy(&mapped[start..end]).into_owned()
}

/// Return the HTTP body (after the header terminator), or "" (port of
/// as_http_body / ar_http_body).
pub fn ar_http_body(resp: &[u8]) -> &[u8] {
    if let Some(p) = find_sub(resp, b"\r\n\r\n") {
        return &resp[p + 4..];
    }
    if let Some(p) = find_sub(resp, b"\n\n") {
        return &resp[p + 2..];
    }
    b""
}

fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

// ---------------------------------------------------------------------------
// HTTP (port of ar_http_request + helpers). Returns the raw response bytes.
// ---------------------------------------------------------------------------

pub fn ar_http_request(
    ctx: &AlScriptContext,
    method: &str,
    path: &str,
    extra: &str,
    body: Option<&str>,
    ctype: Option<&str>,
) -> Option<Vec<u8>> {
    if !ar_check(ctx) {
        return None;
    }
    let host = as_ip_text(ctx.target_ip);
    let path = if path.starts_with('/') { path } else { "/" };
    let body_s = body.unwrap_or("");
    let req = match ctype {
        Some(ct) if !ct.is_empty() => format!(
            "{m} {p} HTTP/1.0\r\nHost: {h}\r\nUser-Agent: ALmap/5.0\r\n\
             Accept: */*\r\nConnection: close\r\nContent-Type: {ct}\r\n\
             Content-Length: {cl}\r\n{ex}{b}\r\n",
            m = method,
            p = path,
            h = host,
            ct = ct,
            cl = body_s.len(),
            ex = extra,
            b = body_s
        ),
        _ => format!(
            "{m} {p} HTTP/1.0\r\nHost: {h}\r\nUser-Agent: ALmap/5.0\r\n\
             Accept: */*\r\nConnection: close\r\n{ex}{b}\r\n",
            m = method,
            p = path,
            h = host,
            ex = extra,
            b = body_s
        ),
    };
    let mut s = as_connect(ctx)?;
    if !as_send_all(&mut s, req.as_bytes()) {
        return None;
    }
    Some(as_recv_all_cap(&mut s, 8192))
}

pub fn ar_http_get(ctx: &AlScriptContext, path: &str) -> Option<Vec<u8>> {
    ar_http_request(ctx, "GET", path, "", None, None)
}

// ---------------------------------------------------------------------------
// FTP (port of ar_ftp_reply / ar_ftp_open / ar_ftp_cmd).
// ---------------------------------------------------------------------------

/// Read a (possibly multi-line) FTP reply. Returns (code, text); code is
/// -1 when no 3-digit status was seen.
pub fn ar_ftp_reply(s: &mut TcpStream, cap: usize, timeout_ms: i32) -> (i32, String) {
    set_rtimeout(s, timeout_ms);
    let mut code: i32 = -1;
    let mut out = String::new();
    loop {
        let line = as_recv_line(s, 512);
        if line.is_empty() {
            return (code, out);
        }
        if out.len() + line.len() + 1 < cap {
            out.push_str(&String::from_utf8_lossy(&line));
        }
        if line.len() >= 3
            && line[0].is_ascii_digit()
            && line[1].is_ascii_digit()
            && line[2].is_ascii_digit()
        {
            let c = (line[0] - b'0') as i32 * 100
                + (line[1] - b'0') as i32 * 10
                + (line[2] - b'0') as i32;
            if code < 0 {
                code = c;
            }
            if line.len() < 4 || line[3] == b' ' || line[3] == b'\r' || line[3] == b'\n' {
                break;
            }
        } else {
            break;
        }
    }
    (code, out)
}

/// Open an FTP connection and read the greeting. Returns (stream, banner).
pub fn ar_ftp_open(ctx: &AlScriptContext, cap: usize) -> Option<(TcpStream, String)> {
    let mut s = as_connect(ctx)?;
    let (code, banner) = ar_ftp_reply(&mut s, cap, ctx.timeout_ms);
    if code < 0 {
        return None;
    }
    Some((s, banner))
}

/// Send one FTP command (CRLF appended) and read the reply code+text.
pub fn ar_ftp_cmd(s: &mut TcpStream, cmd: &str, cap: usize, timeout_ms: i32) -> (i32, String) {
    let line = format!("{}\r\n", cmd);
    if !as_send_all(s, line.as_bytes()) {
        return (-1, String::new());
    }
    ar_ftp_reply(s, cap, timeout_ms)
}
