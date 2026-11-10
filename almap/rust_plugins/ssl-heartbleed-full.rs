/*
 * ssl-heartbleed-full (Rust) - OpenSSL Heartbleed probe (CVE-2014-0160).
 *
 * Pure-std raw-TLS port. The C original had two stages; stage 1 used
 * OpenSSL (libssl) only to report the negotiated version/cipher. Per the
 * migration decision this port keeps the authoritative stage 2 - the raw
 * malformed-HeartbeatRequest probe - in pure Rust and drops the OpenSSL
 * convenience stage (no TLS crate is available with rustc-only).
 *
 * The TLS record reader returns FULL records (5-byte header + content),
 * which is what ssl-heartbleed-full.c's own logic indexes against
 * (resp[0] = content type, resp[5] = handshake type, a HeartbeatResponse
 * record has resp[0] == 24). The shared arsenal_tls.h reader stripped the
 * header, which is inconsistent with that logic; this port resolves it in
 * favour of a detector that actually fires on a leaking server.
 *
 * Read-only: sends a ClientHello and one malformed heartbeat; no exploit
 * payload. Use only on networks you own or have permission to scan.
 */
#![allow(dead_code, non_snake_case, non_upper_case_globals)]

include!("alscript.rs");

const AR_TLS_ALERT: u8 = 21;
const AR_TLS_HANDSHAKE: u8 = 22;
const AR_TLS_HEARTBEAT: u8 = 24;

const TLS_CIPHERS: [u16; 24] = [
    0xC02F, 0xC030, 0xC02B, 0xC02C, 0xCCA8, 0xCCA9, 0x009E, 0x009F, 0x002F, 0x0035, 0x003C, 0x003D,
    0x000A, 0x0005, 0x0004, 0x0067, 0x006B, 0x0033, 0x0039, 0x0016, 0x0023, 0x0009, 0x0006, 0x0003,
];

fn tls_version_name(v: u32) -> &'static str {
    match v {
        0x0300 => "SSLv3",
        0x0301 => "TLSv1.0",
        0x0302 => "TLSv1.1",
        0x0303 => "TLSv1.2",
        0x0304 => "TLSv1.3",
        _ => "unknown",
    }
}

/// Build a ClientHello record (port of ar_tls_client_hello). The returned
/// bytes are a complete TLS record including the 5-byte header.
fn tls_client_hello(version: u32, ciphers: &[u16], heartbeat: bool) -> Option<Vec<u8>> {
    let mut body: Vec<u8> = Vec::new();
    body.push((version >> 8) as u8);
    body.push((version & 0xFF) as u8);
    for i in 0..32u8 {
        body.push(0x30 + i);
    }
    body.push(0); // session id length
    let nc = ciphers.len();
    body.push(((nc * 2) >> 8) as u8);
    body.push(((nc * 2) & 0xFF) as u8);
    for &c in ciphers {
        body.push((c >> 8) as u8);
        body.push((c & 0xFF) as u8);
    }
    body.push(1); // compression methods length
    body.push(0); // null compression
    let ext_len_pos = body.len();
    body.push(0);
    body.push(0);
    let ext_start = body.len();
    if version >= 0x0301 {
        // supported_groups: x25519, secp256r1, secp384r1
        body.extend_from_slice(&[0x00, 0x0A, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1D, 0x00, 0x17, 0x00, 0x18]);
        // ec_point_formats: uncompressed
        body.extend_from_slice(&[0x00, 0x0B, 0x00, 0x02, 0x01, 0x00]);
        // signature_algorithms
        body.extend_from_slice(&[
            0x00, 0x0D, 0x00, 0x0A, 0x00, 0x08, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x01,
        ]);
        // renegotiation_info (empty)
        body.extend_from_slice(&[0xFF, 0x01, 0x00, 0x01, 0x00]);
        if heartbeat {
            body.extend_from_slice(&[0x00, 0x0F, 0x00, 0x01, 0x01]);
        }
    }
    let ext_len = body.len() - ext_start;
    body[ext_len_pos] = (ext_len >> 8) as u8;
    body[ext_len_pos + 1] = (ext_len & 0xFF) as u8;

    let b = body.len();
    let mut out = Vec::with_capacity(9 + b);
    out.push(AR_TLS_HANDSHAKE);
    out.push((version >> 8) as u8);
    out.push((version & 0xFF) as u8);
    out.push(((b + 4) >> 8) as u8);
    out.push(((b + 4) & 0xFF) as u8);
    out.push(1); // handshake type: ClientHello
    out.push((b >> 16) as u8);
    out.push((b >> 8) as u8);
    out.push((b & 0xFF) as u8);
    out.extend_from_slice(&body);
    Some(out)
}

/// Read one full TLS record (5-byte header + content).
fn tls_read_record(s: &mut TcpStream, timeout_ms: i32) -> Option<Vec<u8>> {
    set_rtimeout(s, timeout_ms);
    let mut hdr = [0u8; 5];
    if !as_recv_exact(s, &mut hdr) {
        return None;
    }
    let len = ((hdr[3] as usize) << 8) | hdr[4] as usize;
    let mut rec = Vec::with_capacity(5 + len);
    rec.extend_from_slice(&hdr);
    if len > 0 {
        let mut body = vec![0u8; len];
        if !as_recv_exact(s, &mut body) {
            return None;
        }
        rec.extend_from_slice(&body);
    }
    Some(rec)
}

/// True when `rec` is a ServerHello handshake record.
fn is_server_hello(rec: &[u8]) -> bool {
    rec.len() >= 11 && rec[0] == AR_TLS_HANDSHAKE && rec[5] == 2
}

/// Raw Heartbleed probe for one TLS version. Returns Some(leaked_bytes)
/// when the server leaks, Some(0) when a ServerHello was seen but no
/// leak, None when no ServerHello was obtained.
fn hb_raw_probe(ctx: &AlScriptContext, version: u32) -> Option<Option<usize>> {
    let hello = tls_client_hello(version, &TLS_CIPHERS, true)?;
    let mut s = as_connect(ctx)?;
    if !as_send_all(&mut s, &hello) {
        return None;
    }
    let mut rec = tls_read_record(&mut s, ctx.timeout_ms)?;
    if rec.is_empty() || rec[0] == AR_TLS_ALERT || !is_server_hello(&rec) {
        return None;
    }
    // Drain the server flight until ServerHelloDone (handshake type 14).
    for _ in 0..8 {
        if rec[0] == AR_TLS_HANDSHAKE && rec.len() >= 6 && rec[5] == 14 {
            break;
        }
        if rec[0] == AR_TLS_ALERT {
            break;
        }
        match tls_read_record(&mut s, 300) {
            Some(r) if !r.is_empty() => rec = r,
            _ => break,
        }
    }
    // Malformed HeartbeatRequest: claims 0x4000 payload, carries none.
    let hb: [u8; 8] = [
        AR_TLS_HEARTBEAT,
        (version >> 8) as u8,
        (version & 0xFF) as u8,
        0x00,
        0x03,
        0x01,
        0x40,
        0x00,
    ];
    if !as_send_all(&mut s, &hb) {
        return None;
    }
    match tls_read_record(&mut s, 800) {
        Some(r) if r.len() > 3 && r[0] == AR_TLS_HEARTBEAT => Some(Some(r.len())),
        _ => Some(Some(0)),
    }
}

fn run(ctx: &AlScriptContext) -> i32 {
    if !ar_valid(ctx) {
        return 1;
    }
    let versions: [u32; 3] = [0x0303, 0x0302, 0x0301];
    let mut got_hello = false;
    for &v in versions.iter() {
        match hb_raw_probe(ctx, v) {
            Some(Some(leaked)) if leaked > 0 => {
                ar_out(
                    ctx,
                    &format!(
                        "VULNERABLE: OpenSSL Heartbleed (CVE-2014-0160) - \
                         server leaked {} bytes via {} HeartbeatResponse",
                        leaked,
                        tls_version_name(v)
                    ),
                );
                return 0;
            }
            Some(_) => got_hello = true,
            None => {}
        }
    }
    if got_hello {
        ar_out(
            ctx,
            "not vulnerable: OpenSSL Heartbleed (TLS ServerHello seen; heartbeat not honored)",
        );
    } else {
        ar_out(ctx, &format!("Heartbleed: no TLS handshake on port {}", ctx.port));
    }
    0
}

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if ctx.is_null() {
        return 1;
    }
    let ctx: &AlScriptContext = unsafe { &*ctx };
    run(ctx)
}
