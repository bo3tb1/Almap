/* ms-sql-info - TDS prelogin version and instance discovery. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let (version, instance) = match mssql_prelogin(ctx) {
        Some(v) => v,
        None => {
            set_out(ctx, "MSSQL info: no TDS prelogin response");
            return 0;
        }
    };
    let mut out = format!(
        "MSSQL version: {}",
        if version.is_empty() { "unknown" } else { &version }
    );
    if !instance.is_empty() {
        out.push_str(&format!(" instance: {}", instance));
    }
    set_out(ctx, &out);
    0
}
