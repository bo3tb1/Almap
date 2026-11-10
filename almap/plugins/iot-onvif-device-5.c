/* iot-onvif-device-5 - ONVIF GetDeviceInformation probe
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[4096];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "POST", "/onvif/device_service", NULL, NULL, "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Body><GetDeviceInformation xmlns=\"http://www.onvif.org/ver10/device/wsdl\"/></s:Body></s:Envelope>", "application/soap+xml",
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "iot-onvif-device-5: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "GetDeviceInformationResponse")) {
        ar_out(ctx, "iot-onvif-device-5: detected (HTTP %d)", ar_http_status(resp));
    } else {
        ar_out(ctx, "iot-onvif-device-5: not detected (HTTP %d)", ar_http_status(resp));
    }
    return 0;
}
