/*
 * ike_version.rs - NSE ike-version analog.
 *
 * Sends an IKEv2 IKE_SA_INIT request (AES-CBC-128, HMAC-SHA2-256,
 * DH group 14) and extracts the IKE version from the response header
 * plus any printable Vendor ID payloads.
 * Output: "IKE version: <major>.<minor> [vendor: <id>, ...]".
 * Use only on networks you own or have permission to scan.
 */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

fn ike_put16(p: &mut [u8], off: usize, v: u16) {
    p[off] = ((v >> 8) & 255) as u8;
    p[off + 1] = (v & 255) as u8;
}

fn ike_put32(p: &mut [u8], off: usize, v: u32) {
    p[off] = ((v >> 24) & 255) as u8;
    p[off + 1] = ((v >> 16) & 255) as u8;
    p[off + 2] = ((v >> 8) & 255) as u8;
    p[off + 3] = (v & 255) as u8;
}

fn ike_printable(p: &[u8]) -> bool {
    if p.len() < 3 {
        return false;
    }
    p.iter().all(|&b| b >= 32 && b <= 126)
}

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }

    let mut req = vec![0u8; 512];
    req[0] = 0x10;
    req[1] = 0x11;
    req[2] = 0x12;
    req[3] = 0x13;
    req[4] = 0x14;
    req[5] = 0x15;
    req[6] = 0x16;
    req[7] = 0x17;
    req[16] = 33; /* next payload: SA */
    req[17] = 0x20; /* IKEv2, minor 0 */
    req[18] = 34; /* IKE_SA_INIT */
    req[19] = 0x08; /* initiator */
    let mut off = 28usize;

    /* SA payload with one proposal and four transforms. */
    let sa = off;
    req[off] = 34; /* next payload: KE */
    off += 1;
    req[off] = 0;
    off += 1;
    let sa_len_at = off;
    off += 2;
    let prop = off;
    req[off] = 2; /* last proposal */
    off += 1;
    req[off] = 0;
    off += 1;
    let prop_len_at = off;
    off += 2;
    req[off] = 1; /* proposal number */
    off += 1;
    req[off] = 1; /* protocol ID: IKE */
    off += 1;
    req[off] = 0; /* SPI size */
    off += 1;
    req[off] = 4; /* transforms */
    off += 1;

    /* ENCR AES-CBC-128 (type 1, id 12, key length 128). */
    req[off] = 0;
    off += 1;
    req[off] = 0;
    off += 1;
    ike_put16(&mut req, off, 12);
    off += 2;
    req[off] = 1;
    off += 1;
    req[off] = 0;
    off += 1;
    ike_put16(&mut req, off, 12);
    off += 2;
    ike_put16(&mut req, off, 0x800E);
    off += 2;
    ike_put16(&mut req, off, 128);
    off += 2;

    /* PRF HMAC-SHA2-256 (type 2, id 5). */
    req[off] = 0;
    off += 1;
    req[off] = 0;
    off += 1;
    ike_put16(&mut req, off, 8);
    off += 2;
    req[off] = 2;
    off += 1;
    req[off] = 0;
    off += 1;
    ike_put16(&mut req, off, 5);
    off += 2;

    /* Integrity HMAC-SHA2-256-128 (type 3, id 12). */
    req[off] = 0;
    off += 1;
    req[off] = 0;
    off += 1;
    ike_put16(&mut req, off, 8);
    off += 2;
    req[off] = 3;
    off += 1;
    req[off] = 0;
    off += 1;
    ike_put16(&mut req, off, 12);
    off += 2;

    /* DH group 14 (type 4, id 14), last transform. */
    req[off] = 3;
    off += 1;
    req[off] = 0;
    off += 1;
    ike_put16(&mut req, off, 8);
    off += 2;
    req[off] = 4;
    off += 1;
    req[off] = 0;
    off += 1;
    ike_put16(&mut req, off, 14);
    off += 2;

    ike_put16(&mut req, prop_len_at, (off - prop) as u16);
    ike_put16(&mut req, sa_len_at, (off - sa) as u16);

    /* KE payload: DH group 14 with the public value 2. */
    let ke = off;
    req[off] = 0;
    off += 1;
    req[off] = 0;
    off += 1;
    let ke_len_at = off;
    off += 2;
    ike_put16(&mut req, off, 14);
    off += 2;
    ike_put16(&mut req, off, 0);
    off += 2;
    req[off + 255] = 0x02;
    off += 256;
    ike_put16(&mut req, ke_len_at, (off - ke) as u16);

    ike_put32(&mut req, 24, off as u32);

    let resp = match udp_exchange(ctx, &req[..off], 2048) {
        Some(r) => r,
        None => return 0,
    };
    let n = resp.len();
    if n < 28 {
        return 0;
    }

    let major = ((resp[17] as u32) >> 4) & 15;
    let minor = (resp[17] as u32) & 15;
    let version = format!("{}.{}", major, minor);

    let mut vendors: Vec<String> = Vec::new();
    let mut next = resp[16];
    let mut pos = 28usize;
    let mut guard = 0;
    while guard < 32 && next != 0 {
        guard += 1;
        if pos + 4 > n {
            break;
        }
        let plen = ((resp[pos + 2] as usize) << 8) | (resp[pos + 3] as usize);
        if plen < 4 || pos + plen > n {
            break;
        }
        if next == 43 && ike_printable(&resp[pos + 4..pos + plen]) {
            let payload = &resp[pos + 4..pos + plen];
            let mut copy = payload.len();
            if copy >= 512 {
                copy = 511;
            }
            let vendor = clean(&String::from_utf8_lossy(&payload[..copy]));
            if !vendor.is_empty() {
                vendors.push(vendor);
            }
        }
        next = resp[pos];
        pos += plen;
    }

    if !vendors.is_empty() {
        set_out(
            ctx,
            &format!("IKE version: {} vendor: {}", version, vendors.join(", ")),
        );
    } else {
        set_out(ctx, &format!("IKE version: {}", version));
    }
    0
}
