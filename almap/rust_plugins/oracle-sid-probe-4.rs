/* oracle-sid-probe-4 - Oracle SID (ORCL) reachability probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let buf = match oracle_tns(ctx, "(CONNECT_DATA=(SID=ORCL)(CID=(PROGRAM=)(HOST=)(USER=)))", 512) {
        Some(b) => b,
        None => {
            set_out(ctx, "oracle-sid-probe-4: Oracle TNS listener not responding");
            return 0;
        }
    };
    let text = clean(&String::from_utf8_lossy(&buf));
    let shown: String = text.chars().take(200).collect();
    set_out(
        ctx,
        &format!("oracle-sid-probe-4: TNS reply [{} bytes] {}", buf.len(), shown),
    );
    0
}
