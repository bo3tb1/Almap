/* cloud-aws-userdata-check-4 - AWS EC2 IMDS user-data exposure check */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match http_request(
        ctx,
        "GET",
        "/latest/user-data/",
        Some("169.254.169.254"),
        "",
        "",
        None,
        8192,
    ) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "cloud-aws-userdata-check: no response from metadata endpoint");
            return 0;
        }
    };
    let code = http_status(&resp);
    let suffix = if code == 200 {
        " (user-data EXPOSED; verify)"
    } else {
        ""
    };
    set_out(
        ctx,
        &format!("cloud-aws-userdata-check: GET /latest/user-data/ [{}]{}", code, suffix),
    );
    0
}
