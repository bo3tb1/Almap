/* cloud-aws-imdsv2-token-4 - AWS EC2 IMDSv2 token endpoint */
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
        "PUT",
        "/latest/api/token",
        Some("169.254.169.254"),
        "X-aws-ec2-metadata-token-ttl-seconds: 21600\r\n",
        "",
        None,
        8192,
    ) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "cloud-aws-imdsv2-token-4: no response from metadata endpoint");
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
        &format!("cloud-aws-imdsv2-token-4: PUT /latest/api/token [{}]{}", code, suffix),
    );
    0
}
