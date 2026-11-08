import modules.target;
import modules.connect_scan;
import modules.output;
import modules.ratelimit;
namespace udp_scan;

// modules/udp_scan.goose - Step 17: sequential UDP scan with text,
// JSON, table, or XML output and per-port rate limiting.
// No worker pool, no banners, no service detection, no host discovery,
// no OS fingerprinting, NSE, or evasion. Uses C interop via extern fn
// (C is in c/udp.c, listed in almap.build). No heap, no GC, no
// lifetime annotations. Reuses connect_scan::fmt_ip and the existing
// output helpers, so UDP results use the same deterministic
// target/host/port ordering and output shapes as the TCP scans.
//
// State mapping for almap_udp_scan() codes from c/udp.c:
//   0 = open, 1 = closed, 2 = open|filtered (timeout), 3 = error,
//   4 = permission (the CLI pre-check catches it; if it appears mid-run
//   it is reported as error).

extern fn almap_udp_can_raw() -> i32;
extern fn almap_udp_scan(dst_be: u32, port: i32, timeout_ms: i32) -> i32;

fn can_raw() -> bool {
    almap_udp_can_raw() == 1
}

fn state_name(code: i32) -> const u8[:] {
    if code == 0 {
        return "open";
    }
    if code == 1 {
        return "closed";
    }
    if code == 2 {
        return "open|filtered";
    }
    return "error";
}

// Step 17: scans every target in input order (hosts ascending, ports in
// CLI order) inside one output document, sharing one rate limiter.
fn scan_udp(targets: target::TargetList, ports: target::PortRanges, timeout_ms: i64, json: bool, rate_per_sec: i64, table: bool, xml: bool) -> bool {
    var lim = ratelimit::limiter_new(rate_per_sec);
    if xml {
        output::xml_begin_scan();
    } else if table {
        output::emit_table_header(false);
    } else {
        output::begin(json);
    }
    var first = true;
    for tgt in targets {
        let cnt, ok = target::usable_host_count(tgt);
        if !ok {
            if xml { output::xml_end_scan(); } else if !table { output::end(json); }
            return false;
        }
        var hi: i64 = 0;
    while hi < cnt {
        let dst, ok2 = target::host_at(tgt, hi);
        if !ok2 {
            if xml { output::xml_end_scan(); } else if !table { output::end(json); }
            return false;
        }
        for range in ports {
            var p: i32 = range.lo;
            while p <= range.hi {
                ratelimit::limiter_wait(lim);
                let code = almap_udp_scan(dst, p, timeout_ms as i32);
                if code == 4 {
                    if xml { output::xml_end_scan(); } else if !table { output::end(json); }
                    print("UDP scan requires root or CAP_NET_RAW");
                    return false;
                }
                var ip_text: u8[>..] = [];
                connect_scan::fmt_ip(ip_text, dst);
                let sname = state_name(code);
                if xml {
                    output::xml_emit_scan_result(ip_text, p, sname, "udp", "");
                } else if table {
                    output::emit_table_row(ip_text, p, sname, "udp", "");
                } else {
                    first = output::emit_result(json, first, ip_text, p, sname, "udp");
                }
                p++;
            }
        }
        hi++;
    }
    }
    if xml {
        output::xml_end_scan();
    } else if !table {
        output::end(json);
    }
    return true;
}
