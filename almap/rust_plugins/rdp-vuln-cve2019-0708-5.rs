/* rdp-vuln-cve2019-0708-5 - RDP BlueKeep (CVE-2019-0708) negotiation probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    const REQ: [u8; 19] = [0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
    if !valid(ctx) {
        return 1;
    }
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            let port = unsafe { (*ctx).port };
            set_out(ctx, &format!("rdp-vuln-cve2019-0708-5: TCP {} not reachable", port));
            return 0;
        }
    };
    if send_all(&mut s, &REQ).is_err() {
        set_out(ctx, "rdp-vuln-cve2019-0708-5: send failed");
        return 0;
    }
    let resp = recv_all(&mut s, 4096);
    drop(s);
    if resp.is_empty() {
        set_out(ctx, "rdp-vuln-cve2019-0708-5: no response");
        return 0;
    }
    let n = resp.len();
    if n >= 11 && resp[0] == 0x03 && resp[5] == 0xd0 {
        set_out(ctx, &format!("rdp-vuln-cve2019-0708-5: expected reply seen ({} bytes)", n));
    } else {
        set_out(ctx, &format!("rdp-vuln-cve2019-0708-5: unexpected reply ({} bytes)", n));
    }
    0
}
