/* cloud-aws-identity-doc-4 - AWS EC2 instance identity document */
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
        "/latest/dynamic/instance-identity/document",
        Some("169.254.169.254"),
        "",
        "",
        None,
        8192,
    ) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "cloud-aws-identity-doc-4: no response from metadata endpoint");
            return 0;
        }
    };
    let code = http_status(&resp);
    let suffix = if code == 200 {
        " (metadata EXPOSED; verify)"
    } else {
        ""
    };
    set_out(
        ctx,
        &format!("cloud-aws-identity-doc-4: GET /latest/dynamic/instance-identity... [{}]{}", code, suffix),
    );
    0
}
