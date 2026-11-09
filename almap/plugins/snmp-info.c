/* snmp-info - SNMPv2c system group discovery. */
#include "arsenal_snmp.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *communities[] = { "public", "private" };
    static const char *oids[] = {
        "1.3.6.1.2.1.1.1.0",
        "1.3.6.1.2.1.1.5.0",
        "1.3.6.1.2.1.1.2.0",
        "1.3.6.1.2.1.1.3.0"
    };
    static const char *labels[] = {
        "sysDescr", "sysName", "sysObjectID", "sysUpTime"
    };
    char val[512];
    int found = 0;
    size_t c;
    size_t i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (c = 0; c < sizeof(communities) / sizeof(communities[0]); c++) {
        for (i = 0; i < sizeof(oids) / sizeof(oids[0]); i++) {
            if (ar_snmp_get(ctx, communities[c], oids[i],
                            val, sizeof(val)) == 0) {
                ar_append(ctx, "%s%s: %s", (found == 0) ?
                          "SNMP info: " : "; ", labels[i], val);
                found++;
            }
        }
        if (found > 0) {
            ar_append(ctx, " (community %s)", communities[c]);
            break;
        }
    }
    if (found == 0) {
        ar_out(ctx, "SNMP info: no response with public/private");
    }
    return 0;
}
