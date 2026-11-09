/* snmp-brute-2 - five fixed SNMPv2c community strings. */
#include "arsenal_snmp.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *communities[] = {
        "public", "private", "admin", "root", "password"
    };
    char val[512];
    int found = 0;
    size_t i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < sizeof(communities) / sizeof(communities[0]); i++) {
        if (ar_snmp_get(ctx, communities[i], "1.3.6.1.2.1.1.1.0",
                        val, sizeof(val)) == 0) {
            ar_append(ctx, "%s%s", (found == 0) ?
                      "SNMP communities: " : ", ", communities[i]);
            found++;
        }
    }
    if (found == 0) {
        ar_out(ctx, "SNMP communities: none accepted");
    }
    return 0;
}
