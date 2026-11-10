/* snmp_sysdescr - * plugins/snmp_sysdescr.c - NSE snmp-sysdescr analog. * * Build: * gcc -shared -fPIC -o plugins/snmp_sysdescr.so plugins/snmp_sysdescr.c * R */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let text: String;
let req = "snmp_sysdescr".as_bytes();
let resp = match udp_exchange(ctx, req, 4096) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "snmp_sysdescr: no response"); return 0; }
};
text = clean(&String::from_utf8_lossy(&resp));
set_out(ctx, &format!("snmp_sysdescr: {}", &text[..text.len().min(220)]));
0
}
