/*
 * smb-vuln-ms17-010-full (Rust) - full MS17-010 "EternalBlue" detection.
 *
 * Faithful port of smb-vuln-ms17-010-full.c:
 *   1. SMB1 NEGOTIATE (confirm NT LM 0.12 offered) + report SMB2 dialect.
 *   2. Anonymous SESSION SETUP AndX.
 *   3. TREE CONNECT AndX to \\<ip>\IPC$.
 *   4. SMB_COM_TRANSACTION PeekNamedPipe (0x23) with an invalid FID.
 *      NT status decides:
 *        0xC0000205 STATUS_INSUFF_SERVER_RESOURCES -> VULNERABLE
 *        0xC0000022 / 0xC0000008                   -> patched
 *
 * Read-only: anonymous session + malformed peek only, no exploit payload.
 * Use only on networks you own or have permission to scan.
 */
#![allow(dead_code, non_snake_case, non_upper_case_globals)]

include!("alscript.rs");
include!("smb.rs");

/// Write the shared SMB1 header into `req` at NetBIOS offset 4 (port of
/// ms17_hdr).
fn ms17_hdr(req: &mut [u8], cmd: u8, tid: u32, uid: u32) {
    for b in req[4..36].iter_mut() {
        *b = 0;
    }
    req[4] = 0xFF;
    req[5] = b'S';
    req[6] = b'M';
    req[7] = b'B';
    req[8] = cmd; // smb[4]
    req[13] = 0x18; // smb[9] flags
    req[14] = 0x53; // smb[10] flags2 low
    req[15] = 0xC8; // smb[11] flags2 high
    req[28] = (tid >> 8) as u8; // smb[24]
    req[29] = (tid & 0xFF) as u8; // smb[25]
    req[30] = 0xFE; // smb[26] PID low
    req[31] = 0xFF; // smb[27]
    req[32] = (uid >> 8) as u8; // smb[28]
    req[33] = (uid & 0xFF) as u8; // smb[29]
}

/// Little-endian... actually big-endian NT_STATUS at offset 5 of the SMB
/// body, matching ms17_status (header offset 5 DWORD, read big-endian as
/// the C does with resp[5]<<0 | resp[6]<<8 ...). The C reads it
/// LITTLE-endian here (resp[5] | resp[6]<<8 | resp[7]<<16 | resp[8]<<24).
fn ms17_status(resp: &[u8]) -> u32 {
    if resp.len() < 9 {
        return 0xFFFF_FFFF;
    }
    (resp[5] as u32)
        | ((resp[6] as u32) << 8)
        | ((resp[7] as u32) << 16)
        | ((resp[8] as u32) << 24)
}

/// Send the PeekNamedPipe transaction and return the server NT status
/// (port of ms17_peek).
fn ms17_peek(s: &mut TcpStream, tid: u32, uid: u32, timeout_ms: i32) -> u32 {
    let msglen: usize = 74; // SMB message length (no NetBIOS header)
    let mut req = [0u8; 96];
    // NetBIOS session message header.
    req[0] = 0x00;
    req[1] = ((msglen >> 16) & 0xFF) as u8;
    req[2] = ((msglen >> 8) & 0xFF) as u8;
    req[3] = (msglen & 0xFF) as u8;

    ms17_hdr(&mut req, 0x25 /* SMB_COM_TRANSACTION */, tid, uid);

    // smb = req + 4 ; w = smb + 33 = req + 37
    req[4 + 32] = 16; // WordCount (14 + SetupCount)
    // w[4..8] MaxParameterCount / MaxDataCount = 0xFFFF each
    req[37 + 4] = 0xFF;
    req[37 + 5] = 0xFF;
    req[37 + 6] = 0xFF;
    req[37 + 7] = 0xFF;
    req[37 + 20] = 0x4A; // ParameterOffset = 0x004A (74)
    req[37 + 21] = 0x00;
    req[37 + 24] = 0x4A; // DataOffset = 0x004A (74)
    req[37 + 25] = 0x00;
    req[37 + 26] = 0x02; // SetupCount = 2
    req[37 + 28] = 0x23; // Setup[0] = 0x0023 PeekNamedPipe
    req[37 + 29] = 0x00;
    req[37 + 30] = 0x00; // Setup[1] = FID = 0
    req[37 + 31] = 0x00;
    // ByteCount (2) at smb[65..67], then the name "\PIPE\\0".
    req[4 + 65] = 0x07;
    req[4 + 66] = 0x00;
    req[4 + 67] = b'\\';
    req[4 + 68] = b'P';
    req[4 + 69] = b'I';
    req[4 + 70] = b'P';
    req[4 + 71] = b'E';
    req[4 + 72] = b'\\';
    req[4 + 73] = 0x00;

    if !as_send_all(s, &req[..msglen + 4]) {
        return 0xFFFF_FFFF;
    }
    match ar_smb_recv_nb(s, 1024, timeout_ms) {
        Some(resp) if resp.len() >= 9 => ms17_status(&resp),
        _ => 0xFFFF_FFFF,
    }
}

fn run(ctx: &AlScriptContext) -> i32 {
    if !ar_valid(ctx) {
        return 1;
    }
    // Report the offered dialects first.
    let mut d2: u32 = 0xFFFF;
    let mut d1: u32 = 0xFFFF;
    if let Some(r) = ar_smb2_negotiate(ctx) {
        d2 = ar_smb2_dialect(&r);
    }
    if let Some(r) = ar_smb1_negotiate(ctx) {
        d1 = ar_smb1_dialect(&r);
    }
    if d1 > 5 {
        ar_out(
            ctx,
            &format!(
                "smb-vuln-ms17-010-full: SMBv1 not offered (SMB2 dialect {}); \
                 MS17-010 not applicable",
                ar_smb2_dialect_name(d2)
            ),
        );
        return 0;
    }

    // Open an anonymous SMB1 session (negotiate + session setup).
    let (mut s, uid, os, _lan) = match ar_smb1_open_session(ctx) {
        Some(t) => t,
        None => {
            ar_out(
                ctx,
                &format!(
                    "smb-vuln-ms17-010-full: SMBv1 {} offered but session setup \
                     failed; cannot confirm MS17-010",
                    ar_smb1_dialect_name(d1)
                ),
            );
            return 0;
        }
    };

    let ip = as_ip_text(ctx.target_ip);
    let (treestatus, tid) = ar_smb1_tree_connect(&mut s, uid, &ip, "IPC$", "?????", ctx.timeout_ms);
    if treestatus != 0 {
        ar_out(
            ctx,
            &format!(
                "smb-vuln-ms17-010-full: SMBv1 {}; IPC$ tree connect denied \
                 (status 0x{:08X}); likely patched or hardened",
                ar_smb1_dialect_name(d1),
                treestatus as u32
            ),
        );
        if !os.is_empty() {
            ar_append(ctx, &format!(" OS={}", os));
        }
        return 0;
    }

    let status = ms17_peek(&mut s, tid, uid, ctx.timeout_ms);

    if status == 0xC000_0205 {
        ar_out(
            ctx,
            "VULNERABLE: MS17-010 EternalBlue (CVE-2017-0143) - \
             PeekNamedPipe returned STATUS_INSUFF_SERVER_RESOURCES",
        );
    } else if status == 0xC000_0022 || status == 0xC000_0008 {
        ar_out(
            ctx,
            &format!(
                "not vulnerable: MS17-010 (PeekNamedPipe status 0x{:08X}; patched)",
                status
            ),
        );
    } else if status == 0xFFFF_FFFF {
        ar_out(
            ctx,
            &format!(
                "potentially vulnerable: MS17-010 (SMBv1 {}, IPC$ reachable; \
                 no PeekNamedPipe reply - verify manually)",
                ar_smb1_dialect_name(d1)
            ),
        );
    } else {
        ar_out(
            ctx,
            &format!(
                "MS17-010 inconclusive: SMBv1 {}, PeekNamedPipe status 0x{:08X}",
                ar_smb1_dialect_name(d1),
                status
            ),
        );
    }
    if !os.is_empty() {
        ar_append(ctx, &format!(" OS={}", os));
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
