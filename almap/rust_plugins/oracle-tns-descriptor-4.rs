/* oracle-tns-descriptor-4 - Oracle TNS listener probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let (text, n) = match oracle_tns(ctx, "(CONNECT_DATA=(COMMAND=version))", 512) {
        Some(v) => v,
        None => {
            set_out(ctx, "oracle-tns-descriptor-4: Oracle TNS listener not responding");
            return 0;
        },
    };
    let shown: String = text.chars().take(200).collect();
    set_out(ctx, &format!("oracle-tns-descriptor-4: TNS reply [{} bytes] {}", n, shown));
    0
}
