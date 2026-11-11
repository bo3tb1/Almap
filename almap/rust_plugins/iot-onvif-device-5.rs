/* iot-onvif-device-5 - ONVIF GetDeviceInformation probe
 * Use only on networks you own or have permission to scan.
 */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let body = "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Body><GetDeviceInformation xmlns=\"http://www.onvif.org/ver10/device/wsdl\"/></s:Body></s:Envelope>";
    let resp = match http_request(
        ctx,
        "POST",
        "/onvif/device_service",
        None,
        "",
        body,
        Some("application/soap+xml"),
        4096,
    ) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "iot-onvif-device-5: no HTTP response");
            return 0;
        }
    };
    let code = http_status(&resp);
    if contains_ci(&resp, "GetDeviceInformationResponse") {
        set_out(ctx, &format!("iot-onvif-device-5: detected (HTTP {})", code));
    } else {
        set_out(ctx, &format!("iot-onvif-device-5: not detected (HTTP {})", code));
    }
    0
}
