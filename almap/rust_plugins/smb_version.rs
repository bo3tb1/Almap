/* smb_version - NSE smb-version analog. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match smb1_negotiate(ctx) {
        Some(r) => r,
        None => return 0,
    };
    let n = resp.len();

    if n >= 74 && resp[4] == 0xFE && resp[5] == b'S' && resp[6] == b'M' && resp[7] == b'B' {
        let d = smb2_dialect(&resp);
        let name = match d {
            0x0202 => "SMB 2.0.2",
            0x0210 => "SMB 2.1",
            0x0300 => "SMB 3.0",
            0x0302 => "SMB 3.0.2",
            0x0311 => "SMB 3.1.1",
            0x02FF => "SMB 2.???",
            _ => {
                set_out(
                    ctx,
                    &format!("SMB version: SMB 2/3 (dialect 0x{:04x})", d),
                );
                return 0;
            }
        };
        set_out(ctx, &format!("SMB version: {}", name));
    } else if n >= 35
        && resp[4] == 0xFF
        && resp[5] == b'S'
        && resp[6] == b'M'
        && resp[7] == b'B'
    {
        let d = smb1_dialect(&resp);
        if d > 7 {
            set_out(ctx, &format!("SMB version: SMB1 (dialect {})", d));
            return 0;
        }
        set_out(ctx, &format!("SMB version: {}", smb1_dialect_name(d)));
    }
    0
}
