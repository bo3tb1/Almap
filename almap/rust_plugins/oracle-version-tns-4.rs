/* oracle-version-tns-4 - Oracle TNS version command probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match oracle_tns(ctx, "(CONNECT_DATA=(COMMAND=version))", 512) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "oracle-version-tns-4: Oracle TNS listener not responding");
            return 0;
        }
    };
    let n = resp.len();
    let cleaned = clean(&String::from_utf8_lossy(&resp));
    let show: String = cleaned.chars().take(200).collect();
    set_out(ctx, &format!("oracle-version-tns-4: TNS reply [{} bytes] {}", n, show));
    0
}
