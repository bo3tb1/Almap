/* cloud-azure-imds-check-4 - Azure IMDS instance metadata exposure */
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
        "/metadata/instance?api-version=2021-02-01",
        Some("169.254.169.254"),
        "Metadata: true\r\n",
        "",
        None,
        8192,
    ) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "cloud-azure-imds-check-4: no response from metadata endpoint");
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
        &format!("cloud-azure-imds-check-4: GET /metadata/instance?api-version=20... [{}]{}", code, suffix),
    );
    0
}
