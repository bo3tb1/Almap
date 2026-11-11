/* ms-sql-info-2 - TDS prelogin version and instance discovery */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let (version, instance) = match mssql_prelogin(ctx) {
        Some(v) => v,
        None => { set_out(ctx, "MSSQL info: no TDS prelogin response"); return 0; },
    };
    set_out(ctx, &format!("MSSQL version: {}",
                          if version.is_empty() { "unknown" } else { version.as_str() }));
    if !instance.is_empty() {
        append_out(ctx, &format!(" instance: {}", instance));
    }
    0
}
