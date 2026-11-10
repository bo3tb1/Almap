/*
 * ms-sql-info (Rust) - TDS prelogin version and instance discovery.
 * Faithful port of ms-sql-info.c with the arsenal_mssql.h prelogin
 * helper. Use only on networks you own or have permission to scan.
 */
#![allow(dead_code, non_snake_case, non_upper_case_globals)]

include!("alscript.rs");

/// Read one TDS packet body (port of ar_mssql_read_packet). Returns
/// (body, packet_type).
fn mssql_read_packet(s: &mut TcpStream, timeout_ms: i32) -> Option<(Vec<u8>, u8)> {
    set_rtimeout(s, timeout_ms);
    let mut hdr = [0u8; 8];
    if !as_recv_exact(s, &mut hdr) {
        return None;
    }
    let ptype = hdr[0];
    let len = ((hdr[2] as usize) << 8) | hdr[3] as usize;
    if len < 8 {
        return None;
    }
    let body_len = len - 8;
    let mut body = vec![0u8; body_len];
    if body_len > 0 && !as_recv_exact(s, &mut body) {
        return None;
    }
    Some((body, ptype))
}

/// Send a TDS prelogin and parse version/instance (port of
/// ar_mssql_prelogin). Returns (version, instance) on success.
fn mssql_prelogin(ctx: &AlScriptContext) -> Option<(String, String)> {
    let total: usize = 8 + 18;
    let mut pkt = [0u8; 128];
    pkt[0] = 0x12;
    pkt[1] = 0x01;
    pkt[2] = (total >> 8) as u8;
    pkt[3] = (total & 0xFF) as u8;
    pkt[6] = 1;
    // 18-byte prelogin option payload.
    let body: [u8; 18] = [
        0x00, 0x00, 0x0B, 0x00, 0x06, 0x01, 0x00, 0x11, 0x00, 0x01, 0xFF, 0x0F, 0x00, 0x07, 0xD0,
        0x00, 0x00, 0x00,
    ];
    pkt[8..8 + 18].copy_from_slice(&body);

    let mut s = as_connect(ctx)?;
    if !as_send_all(&mut s, &pkt[..total]) {
        return None;
    }
    let (resp, ptype) = mssql_read_packet(&mut s, ctx.timeout_ms)?;
    if ptype != 0x04 {
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
            let major = resp[o] as u32;
            let minor = resp[o + 1] as u32;
            let build = ((resp[o + 2] as u32) << 8) | resp[o + 3] as u32;
            let sub = ((resp[o + 4] as u32) << 8) | resp[o + 5] as u32;
            version = format!("{}.{}.{}.{}", major, minor, build, sub);
        } else if opt == 0x02 && l > 0 {
            instance = ar_clean(&resp[o..o + l]);
        }
    }
    Some((version, instance))
}

fn run(ctx: &AlScriptContext) -> i32 {
    if !ar_valid(ctx) {
        return 1;
    }
    match mssql_prelogin(ctx) {
        Some((version, instance)) => {
            ar_out(
                ctx,
                &format!(
                    "MSSQL version: {}",
                    if version.is_empty() { "unknown" } else { &version }
                ),
            );
            if !instance.is_empty() {
                ar_append(ctx, &format!(" instance: {}", instance));
            }
        }
        None => {
            ar_out(ctx, "MSSQL info: no TDS prelogin response");
        }
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
