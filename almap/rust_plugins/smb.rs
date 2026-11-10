/*
 * rust_plugins/smb.rs - SMB1/SMB2 negotiation helpers, faithful port of
 * plugins/arsenal_smb.h. Textually included AFTER alscript.rs, so it
 * reuses that file's imports and helpers. Raw TCP, fixed buffers.
 *
 * The on-wire byte layout (including the negotiate dialect placement and
 * the big-endian NT_STATUS reads) is reproduced exactly as the C emits
 * it, so a server cannot tell the Rust probe from the C one.
 */

/// The SMB1 dialect list, byte-identical to the C string literal.
fn smb_dialects() -> Vec<u8> {
    let names: [&str; 8] = [
        "PC NETWORK PROGRAM 1.0",
        "LANMAN1.0",
        "Windows for Workgroups 3.1a",
        "LM1.2X002",
        "LANMAN2.1",
        "NT LM 0.12",
        "SMB 2.002",
        "SMB 2.???",
    ];
    let mut v = Vec::new();
    for n in names.iter() {
        v.push(0x02u8);
        v.extend_from_slice(n.as_bytes());
        v.push(0x00u8);
    }
    v
}

/// Read one NetBIOS-framed SMB message body (port of ar_smb_recv_nb).
fn ar_smb_recv_nb(s: &mut TcpStream, cap: usize, timeout_ms: i32) -> Option<Vec<u8>> {
    set_rtimeout(s, timeout_ms);
    let mut hdr = [0u8; 4];
    if !as_recv_exact(s, &mut hdr) {
        return None;
    }
    if hdr[0] != 0 {
        return None;
    }
    let len = ((hdr[1] as usize) << 16) | ((hdr[2] as usize) << 8) | hdr[3] as usize;
    if len + 1 > cap {
        return None;
    }
    let mut out = vec![0u8; len];
    if len > 0 && !as_recv_exact(s, &mut out) {
        return None;
    }
    Some(out)
}

/// SMB1 NEGOTIATE on a fresh connection. Returns a buffer whose layout
/// matches the C `resp` (4-byte NetBIOS prefix + body) so the dialect
/// readers index identically.
fn ar_smb1_negotiate(ctx: &AlScriptContext) -> Option<Vec<u8>> {
    let dialects = smb_dialects();
    let dlen = dialects.len();
    if dlen + 35 > 256 {
        return None;
    }
    let msglen = 35 + dlen;
    let mut body = [0u8; 256];
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
    body[33] = (dlen & 0xFF) as u8;
    body[34] = ((dlen >> 8) & 0xFF) as u8;
    // Faithful to the C: dialects are memcpy'd at body+39 while only
    // body[0..35+dlen] is transmitted.
    let copy = dlen.min(256 - 39);
    body[39..39 + copy].copy_from_slice(&dialects[..copy]);

    let mut req = Vec::with_capacity(msglen + 4);
    req.push(0);
    req.push(((msglen >> 16) & 0xFF) as u8);
    req.push(((msglen >> 8) & 0xFF) as u8);
    req.push((msglen & 0xFF) as u8);
    req.extend_from_slice(&body[..msglen]);

    let mut s = as_connect(ctx)?;
    if !as_send_all(&mut s, &req) {
        return None;
    }
    let body = ar_smb_recv_nb(&mut s, 4096 - 4, ctx.timeout_ms)?;
    let n = body.len();
    let mut resp = Vec::with_capacity(n + 4);
    resp.push(0);
    resp.push(((n >> 16) & 0xFF) as u8);
    resp.push(((n >> 8) & 0xFF) as u8);
    resp.push((n & 0xFF) as u8);
    resp.extend_from_slice(&body);
    Some(resp)
}

/// SMB2 NEGOTIATE on a fresh connection (port of ar_smb2_negotiate).
fn ar_smb2_negotiate(ctx: &AlScriptContext) -> Option<Vec<u8>> {
    let dialects: [u16; 5] = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311];
    let mut req = [0u8; 160];
    let len = 4 + 64 + 36 + dialects.len() * 2;
    req[0] = 0;
    req[1] = ((len >> 16) & 0xFF) as u8;
    req[2] = ((len >> 8) & 0xFF) as u8;
    req[3] = (len & 0xFF) as u8;
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
        req[104 + i * 2] = (d & 0xFF) as u8;
        req[105 + i * 2] = (d >> 8) as u8;
    }
    let mut s = as_connect(ctx)?;
    if !as_send_all(&mut s, &req[..len]) {
        return None;
    }
    let body = ar_smb_recv_nb(&mut s, 4096 - 4, ctx.timeout_ms)?;
    let n = body.len();
    let mut resp = Vec::with_capacity(n + 4);
    resp.push(0);
    resp.push(((n >> 16) & 0xFF) as u8);
    resp.push(((n >> 8) & 0xFF) as u8);
    resp.push((n & 0xFF) as u8);
    resp.extend_from_slice(&body);
    Some(resp)
}

fn ar_smb1_dialect(resp: &[u8]) -> u32 {
    if resp.len() < 4 + 35 {
        return 0xFFFF;
    }
    resp[4 + 33] as u32 | ((resp[4 + 34] as u32) << 8)
}

fn ar_smb2_dialect(resp: &[u8]) -> u32 {
    if resp.len() < 4 + 74 {
        return 0xFFFF;
    }
    if resp[4] != 0xFE || resp[5] != b'S' || resp[6] != b'M' || resp[7] != b'B' {
        return 0xFFFF;
    }
    resp[72] as u32 | ((resp[73] as u32) << 8)
}

fn ar_smb1_dialect_name(d: u32) -> &'static str {
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

fn ar_smb2_dialect_name(d: u32) -> &'static str {
    match d {
        0x0202 => "SMB 2.0.2",
        0x0210 => "SMB 2.1",
        0x0300 => "SMB 3.0",
        0x0302 => "SMB 3.0.2",
        0x0311 => "SMB 3.1.1",
        _ => "SMB 2/3",
    }
}

/// Big-endian NT_STATUS at body offset 5 (as the C reads it).
fn smb_status_be(resp: &[u8]) -> u32 {
    ((resp[5] as u32) << 24)
        | ((resp[6] as u32) << 16)
        | ((resp[7] as u32) << 8)
        | resp[8] as u32
}

/// Anonymous SESSION SETUP AndX (port of ar_smb1_session_setup).
/// Returns (nt_status, uid, os, lan_manager).
fn ar_smb1_session_setup(s: &mut TcpStream, timeout_ms: i32) -> (i32, u32, String, String) {
    let bodylen: usize = 32 + 1 + 24 + 2; // 59
    let mut req = [0u8; 256];
    req[3] = bodylen as u8;
    // smb = req + 4
    req[4] = 0xFF;
    req[5] = b'S';
    req[6] = b'M';
    req[7] = b'B';
    req[8] = 0x73;
    req[13] = 0x18; // smb[9]
    req[14] = 0x53; // smb[10]
    req[15] = 0xC8; // smb[11]
    req[30] = 0xFE; // smb[26]
    req[31] = 0xFF; // smb[27]
    req[36] = 12; // smb[32] WordCount
    req[37] = 0xFF; // smb[33] AndXCommand = none
    req[41] = 0xFF; // smb[37] MaxBuffer low
    req[42] = 0xFF; // smb[38] MaxBuffer high
    req[43] = 2; // smb[39] MaxMpxCount
    // remaining parameter/words already zero
    if !as_send_all(s, &req[..4 + bodylen]) {
        return (-1, 0, String::new(), String::new());
    }
    let resp = match ar_smb_recv_nb(s, 2048, timeout_ms) {
        Some(r) => r,
        None => return (-1, 0, String::new(), String::new()),
    };
    let n = resp.len();
    if n < 32 {
        return (-1, 0, String::new(), String::new());
    }
    let status = smb_status_be(&resp);
    let mut uid = 0u32;
    let mut os = String::new();
    let mut lan = String::new();
    if status == 0 {
        uid = ((resp[28] as u32) << 8) | resp[29] as u32;
        if n >= 35 {
            let wc = resp[32] as usize;
            let boff = 33 + wc * 2;
            if boff + 2 <= n {
                let blen = ((resp[boff] as usize) << 8) | resp[boff + 1] as usize;
                let bdata = boff + 2;
                let mut end = bdata + blen;
                if end > n {
                    end = n;
                }
                if bdata < end {
                    let mut i = bdata;
                    let start = i;
                    while i < end && resp[i] != 0 {
                        i += 1;
                    }
                    os = ar_clean(&resp[start..i]);
                    i += 1; // skip NUL
                    let start2 = i;
                    while i < end && resp[i] != 0 {
                        i += 1;
                    }
                    if start2 <= end {
                        let stop = i.min(end);
                        if start2 <= stop {
                            lan = ar_clean(&resp[start2..stop]);
                        }
                    }
                }
            }
        }
    }
    (status as i32, uid, os, lan)
}

/// TREE CONNECT AndX to \\server\share (port of ar_smb1_tree_connect).
/// Returns (nt_status, tid).
fn ar_smb1_tree_connect(
    s: &mut TcpStream,
    uid: u32,
    server: &str,
    share: &str,
    service: &str,
    timeout_ms: i32,
) -> (i32, u32) {
    let path = format!("\\\\{}\\{}", server, share);
    let pathlen = path.len() + 1; // include NUL
    let servicelen = service.len() + 1;
    let bodylen = 32 + 1 + 8 + 2 + pathlen + servicelen;
    if bodylen > 512 - 4 {
        return (-1, 0);
    }
    let mut req = vec![0u8; 4 + bodylen];
    req[3] = bodylen as u8;
    req[4] = 0xFF;
    req[5] = b'S';
    req[6] = b'M';
    req[7] = b'B';
    req[8] = 0x75; // smb[4]
    req[13] = 0x18; // smb[9]
    req[14] = 0x53; // smb[10]
    req[15] = 0xC8; // smb[11]
    req[30] = 0xFE; // smb[26]
    req[31] = 0xFF; // smb[27]
    req[32] = (uid >> 8) as u8; // smb[28]
    req[33] = (uid & 0xFF) as u8; // smb[29]
    req[36] = 4; // smb[32] WordCount
    req[37] = 0xFF; // smb[33] AndXCommand = none
    // ByteCount at smb[41..43] = pathlen + servicelen
    let bc = pathlen + servicelen;
    req[45] = (bc & 0xFF) as u8; // smb[41]
    req[46] = ((bc >> 8) & 0xFF) as u8; // smb[42]
    // path at smb[43], service after it
    let poff = 4 + 43;
    req[poff..poff + path.len()].copy_from_slice(path.as_bytes());
    req[poff + path.len()] = 0; // NUL
    let soff = poff + pathlen;
    req[soff..soff + service.len()].copy_from_slice(service.as_bytes());
    req[soff + service.len()] = 0; // NUL

    if !as_send_all(s, &req) {
        return (-1, 0);
    }
    let resp = match ar_smb_recv_nb(s, 1024, timeout_ms) {
        Some(r) => r,
        None => return (-1, 0),
    };
    if resp.len() < 32 {
        return (-1, 0);
    }
    let status = smb_status_be(&resp);
    let mut tid = 0u32;
    if status == 0 {
        tid = ((resp[24] as u32) << 8) | resp[25] as u32;
    }
    (status as i32, tid)
}

/// Open an anonymous SMB1 session: NEGOTIATE then SESSION SETUP on one
/// connection (port of ar_smb1_open_session). Returns the live stream
/// plus (uid, os, lan) on success.
fn ar_smb1_open_session(ctx: &AlScriptContext) -> Option<(TcpStream, u32, String, String)> {
    let mut s = as_connect(ctx)?;
    // Negotiate (same wire format as ar_smb1_negotiate) on this socket.
    let dialects = smb_dialects();
    let dlen = dialects.len();
    let msglen = 35 + dlen;
    let mut body = [0u8; 256];
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
    body[33] = (dlen & 0xFF) as u8;
    body[34] = ((dlen >> 8) & 0xFF) as u8;
    let copy = dlen.min(256 - 39);
    body[39..39 + copy].copy_from_slice(&dialects[..copy]);
    let mut req = Vec::with_capacity(msglen + 4);
    req.push(0);
    req.push(((msglen >> 16) & 0xFF) as u8);
    req.push(((msglen >> 8) & 0xFF) as u8);
    req.push((msglen & 0xFF) as u8);
    req.extend_from_slice(&body[..msglen]);
    if !as_send_all(&mut s, &req) {
        return None;
    }
    let neg = ar_smb_recv_nb(&mut s, 2048, ctx.timeout_ms)?;
    if neg.len() < 32 {
        return None;
    }
    let (_status, uid, os, lan) = ar_smb1_session_setup(&mut s, ctx.timeout_ms);
    Some((s, uid, os, lan))
}
