import modules.target;
import modules.sigdb;
namespace service;

// modules/service.goose - Step 16: basic service/version detection for
// open connect-scan ports only.
//
// Probe rules (minimal, no service database, no OS fingerprinting, no
// NSE):
//   - HTTP: ports 80, 8080, 8000 send the fixed request
//     "HEAD / HTTP/1.0\r\n\r\n" from c/net.c and match a Server: header.
//   - SSH: passive read, match a banner starting with "SSH-".
//   - FTP: passive read, match a banner starting with "220".
//   - SMTP: passive read, match "220" and "SMTP".
//   - MySQL: passive read, match the protocol version byte 10 at
//     offset 4 of the initial greeting packet.
//   - Fallback: use the cleaned banner text when it is non-empty.
//
// Everything uses fixed u8 buffers (no heap, no GC). The probe helpers
// are the existing c/net.c socket code: almap_sock_grab_banner for
// passive reads and almap_sock_http_probe for the fixed HTTP request.
// Service detection is only called for ports already known to be open.

extern fn almap_sock_grab_banner(addr_be: u32, port: i32, timeout_ms: i32, out: u8&, out_cap: i32) -> i32;
extern fn almap_sock_http_probe(addr_be: u32, port: i32, timeout_ms: i32, out: u8&, out_cap: i32) -> i32;

fn is_http_port(port: i32) -> bool {
    if port == 80 { return true; }
    if port == 8080 { return true; }
    if port == 8000 { return true; }
    return false;
}

fn starts_with(s: const u8[:], prefix: const u8[:]) -> bool {
    if s.len < prefix.len { return false; }
    for i in 0..prefix.len {
        if s[i] != prefix[i] { return false; }
    }
    return true;
}

fn contains(s: const u8[:], needle: const u8[:]) -> bool {
    if needle.len == 0 { return true; }
    if s.len < needle.len { return false; }
    for i in 0..(s.len - needle.len + 1) {
        var ok = true;
        for j in 0..needle.len {
            if s[i + j] != needle[j] { ok = false; break; }
        }
        if ok { return true; }
    }
    return false;
}

fn has_server_header(data: const u8[:]) -> bool {
    return contains(data, "Server:") || contains(data, "server:");
}

// Copies a literal service name into out; returns the byte count.
fn copy_into(out: u8[:], src: const u8[:]) -> i64 {
    var i: i64 = 0;
    while i < src.len && i < out.len {
        out[i] = src[i];
        i++;
    }
    return i;
}

// Fallback service text: first n response bytes with trailing CR/LF
// trimmed and other control bytes replaced by '.'; bounded by out.len.
fn copy_cleaned(out: u8[:], src: const u8[:], n: i64) -> i64 {
    var end = n;
    if end > src.len { end = src.len; }
    while end > 0 && (src[end - 1] == '\r' || src[end - 1] == '\n') { end--; }
    var i: i64 = 0;
    while i < end && i < out.len {
        let b = src[i];
        if b < 32 { out[i] = '.'; } else { out[i] = b; }
        i++;
    }
    return i;
}

// Pure signature matcher (unit-tested); returns "" when no signature
// matches so the caller can fall back to the banner text.
fn classify_banner(data: const u8[:]) -> const u8[:] {
    if data.len == 0 { return ""; }
    if starts_with(data, "SSH-") { return "ssh"; }
    if starts_with(data, "220") {
        if contains(data, "SMTP") { return "smtp"; }
        return "ftp";
    }
    // MySQL initial handshake: 3-byte payload length, 1-byte sequence
    // id, then protocol version (10) at offset 4.
    if data.len >= 5 && data[4] == 10 { return "mysql"; }
    return "";
}

// Pure HTTP matcher (unit-tested): the Server: header is the minimal
// HTTP signature. Response text is otherwise left to the fallback.
fn classify_http(data: const u8[:]) -> bool {
    return has_server_header(data);
}

// Probes one open port and writes service text into out. Returns the
// text length (0 = no service detected). timeout_ms is validated at the
// CLI (1..60000) and cast to i32 for C. The external signature DB is
// consulted first; the hardcoded rules below are the fallback.
fn detect(ip_be: u32, port: i32, timeout_ms: i64, out: u8[:], db: sigdb::SigDB&) -> i64 {
    var buf: u8[512] = [0; 512];
    let tmo = timeout_ms as i32;
    var n: i32 = -1;
    if is_http_port(port) {
        n = almap_sock_http_probe(ip_be, port, tmo, buf[0], 512);
    } else {
        n = almap_sock_grab_banner(ip_be, port, tmo, buf[0], 512);
    }
    if n <= 0 {
        return 0;
    }
    let nn: i64 = n;
    let data = buf[..nn];
    // Step 23: external signatures take precedence over the hardcoded
    // defaults below.
    var ext_buf: u8[64] = [0; 64];
    let ext_len = sigdb::match_into(db, port, data, ext_buf[..]);
    if ext_len > 0 {
        return copy_into(out, ext_buf[..ext_len]);
    }
    if is_http_port(port) && classify_http(data) {
        return copy_into(out, "http");
    }
    let name = classify_banner(data);
    if name.len > 0 {
        return copy_into(out, name);
    }
    return copy_cleaned(out, data, nn);
}
