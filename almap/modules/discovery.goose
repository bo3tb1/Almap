import modules.target;
import modules.connect_scan;
import modules.output;
namespace discovery;

// modules/discovery.goose - Steps 13,14: host discovery only with
// text, JSON, table, or XML output, sequential or via the bounded C
// pool. No port scan, banner grabbing, OS fingerprinting, NSE, or
// evasion.
// For each usable host (target::usable_host_count / host_at):
//   1. TCP ping on 80 then 443 via connect_scan::scan_one (reused C layer).
//      Open or closed (RST) means up; timeout means no reply on that port.
//   2. ICMP echo via c/icmp.c if TCP does not prove up and ICMP is available.
//      No ICMP privilege is not an error: warn once and use TCP only.
// Parallel discovery (Step 13) materializes hosts into a fixed
// u32[4096] and makes one c/pool.c call that reuses the same probes.
// No heap, no GC, no lifetime annotations.

extern fn almap_icmp_can_raw() -> i32;
extern fn almap_icmp_ping(dst_be: u32, timeout_ms: i32) -> i32;
// Parallel discovery arrays: same verified pointer form as the scan
// pools (const u32& and u8& cross as raw uint32_t* / uint8_t*
// pointers; the C declarations take the input as const);
// callers pass hosts[0] and up_buf[0] over fixed u32[4096] / u8[4096].
extern fn almap_discover_hosts(hosts_be: const u32&, host_count: i32, timeout_ms: i32, workers: i32, icmp_available: i32, up_out: u8&) -> i32;

fn can_icmp() -> bool {
    almap_icmp_can_raw() == 1
}

// Pure cap check for the parallel discovery buffer. Sequential
// discovery has no host array, but parallel discovery materializes
// hosts into u32[4096]; the CLI reports overflow with this helper.
fn host_cap_ok(host_count: i64) -> bool {
    return host_count >= 0 && host_count <= 4096;
}

// Pure classification: up if TCP proved it, or ICMP proved it while
// ICMP was available. When ICMP is unavailable icmp_up is ignored.
fn classify(tcp_up: bool, icmp_up: bool, icmp_available: bool) -> bool {
    if tcp_up { return true; }
    if icmp_available && icmp_up { return true; }
    return false;
}

// TCP ping: scan_one maps C 0/1 to open/closed; both mean the host
// answered. State is compared via state_name text to avoid relying
// on enum equality across modules.
fn tcp_ping(ip_be: u32, timeout_ms: i64) -> bool {
    let s80 = connect_scan::scan_one(ip_be, 80, timeout_ms);
    let n80 = connect_scan::state_name(s80);
    if n80 == "open" || n80 == "closed" { return true; }
    let s443 = connect_scan::scan_one(ip_be, 443, timeout_ms);
    let n443 = connect_scan::state_name(s443);
    if n443 == "open" || n443 == "closed" { return true; }
    return false;
}

fn icmp_ping(ip_be: u32, timeout_ms: i64) -> bool {
    let tmo = timeout_ms as i32;
    let code = almap_icmp_ping(ip_be, tmo);
    return code == 1;
}

// Step 15: discovery over the whole target list, in input order, then
// hosts ascending, inside one output document.
fn discover(targets: target::TargetList, timeout_ms: i64, json: bool, table: bool, xml: bool) -> bool {
    let icmp_ok = can_icmp();
    if !icmp_ok && !json && !table && !xml {
        print("warning: ICMP unavailable (needs root or CAP_NET_RAW); using TCP ping only");
    }
    if xml {
        output::xml_begin_discovery();
    } else if table {
        output::emit_table_header(true);
    } else {
        output::begin(json);
    }
    var first = true;
    for tgt in targets {
        let cnt, ok = target::usable_host_count(tgt);
        if !ok {
            if xml { output::xml_end_discovery(); } else if !table { output::end(json); }
            return false;
        }
        var hi: i64 = 0;
    while hi < cnt {
        let dst, ok2 = target::host_at(tgt, hi);
        if !ok2 {
            if xml { output::xml_end_discovery(); } else if !table { output::end(json); }
            return false;
        }
        let tcp = tcp_ping(dst, timeout_ms);
        var icmp = false;
        if !tcp && icmp_ok {
            icmp = icmp_ping(dst, timeout_ms);
        }
        let up = classify(tcp, icmp, icmp_ok);
        var ip_text: u8[>..] = [];
        connect_scan::fmt_ip(ip_text, dst);
        if xml {
            output::xml_emit_discovery_host(ip_text, up);
        } else if table {
            output::emit_table_discovery_row(ip_text, up);
        } else {
            first = output::emit_discovery(json, first, ip_text, up);
        }
        hi++;
    }
    }
    if xml {
        output::xml_end_discovery();
    } else if !table {
        output::end(json);
    }
    return true;
}

// Step 18: IPv6 TCP ping. Reuses the limited IPv6 connect probe in
// connect_scan::scan_one6 (c/net6.c). No ICMPv6 is attempted in this
// step, so IPv6 discovery is TCP-only: open or closed (RST) means up.
fn tcp_ping6(t6: target::Target6, timeout_ms: i64) -> bool {
    let s80 = connect_scan::scan_one6(t6, 80, timeout_ms);
    let n80 = connect_scan::state_name(s80);
    if n80 == "open" || n80 == "closed" { return true; }
    let s443 = connect_scan::scan_one6(t6, 443, timeout_ms);
    let n443 = connect_scan::state_name(s443);
    if n443 == "open" || n443 == "closed" { return true; }
    return false;
}

fn close_discovery_doc(xml: bool, table: bool, json: bool) {
    if xml {
        output::xml_end_discovery();
    } else if !table {
        output::end(json);
    }
}

// Step 18: discovery over a mixed IPv4/IPv6 list, in input order, hosts
// ascending, one output document. IPv4 entries keep the Step 13 TCP ping
// plus optional ICMP echo fallback. IPv6 entries use the TCP-only ping
// above (no ICMPv6 in this step). Text and table bracket IPv6; JSON/XML
// use the plain address.
fn discover_mixed(targets: target::MixedTargetList, timeout_ms: i64, json: bool, table: bool, xml: bool) -> bool {
    let icmp_ok = can_icmp();
    if !icmp_ok && !json && !table && !xml {
        print("warning: ICMP unavailable (needs root or CAP_NET_RAW); using TCP ping only");
    }
    if xml {
        output::xml_begin_discovery();
    } else if table {
        output::emit_table_header(true);
    } else {
        output::begin(json);
    }
    var first = true;
    for entry in targets {
        if entry.v6 {
            let cnt, ok = target::usable_host_count6(entry.t6);
            if !ok {
                close_discovery_doc(xml, table, json);
                return false;
            }
            var hi: i64 = 0;
            while hi < cnt {
                let host6, ok2 = target::target6_host_at(entry.t6, hi);
                if !ok2 {
                    close_discovery_doc(xml, table, json);
                    return false;
                }
                let up = tcp_ping6(host6, timeout_ms);
                var plain: u8[>..] = [];
                target::format_ipv6(plain, host6);
                var brack: u8[>..] = [];
                target::format_ipv6_bracket(brack, host6);
                if xml {
                    output::xml_emit_discovery_host(plain, up);
                } else if table {
                    output::emit_table_discovery_row(brack, up);
                } else if json {
                    first = output::emit_discovery(true, first, plain, up);
                } else {
                    first = output::emit_discovery(false, first, brack, up);
                }
                hi++;
            }
        } else {
            let cnt, ok = target::usable_host_count(entry.t4);
            if !ok {
                close_discovery_doc(xml, table, json);
                return false;
            }
            var hi: i64 = 0;
            while hi < cnt {
                let dst, ok2 = target::host_at(entry.t4, hi);
                if !ok2 {
                    close_discovery_doc(xml, table, json);
                    return false;
                }
                let tcp = tcp_ping(dst, timeout_ms);
                var icmp = false;
                if !tcp && icmp_ok {
                    icmp = icmp_ping(dst, timeout_ms);
                }
                let up = classify(tcp, icmp, icmp_ok);
                var ip_text: u8[>..] = [];
                connect_scan::fmt_ip(ip_text, dst);
                if xml {
                    output::xml_emit_discovery_host(ip_text, up);
                } else if table {
                    output::emit_table_discovery_row(ip_text, up);
                } else {
                    first = output::emit_discovery(json, first, ip_text, up);
                }
                hi++;
            }
        }
    }
    close_discovery_doc(xml, table, json);
    return true;
}

// Parallel discovery (Step 13): materialize usable hosts into a fixed
// u32[4096] (cap shared with the scan pools; overflow returns false
// and the CLI prints the cap error), call the C pool once, then emit
// up/down in ascending host order. The C pool reuses the Step 10
// bounded queue/threads and the same TCP ping/optional ICMP probes;
// discovery never uses --rate (the CLI rejects that combination).
fn discover_parallel(targets: target::TargetList, timeout_ms: i64, json: bool, table: bool, workers: i64, xml: bool) -> bool {
    let icmp_ok = can_icmp();
    if !icmp_ok && !json && !table && !xml {
        print("warning: ICMP unavailable (needs root or CAP_NET_RAW); using TCP ping only");
    }
    let icmp_flag: i32 = if icmp_ok { 1 } else { 0 };
    if xml {
        output::xml_begin_discovery();
    } else if table {
        output::emit_table_header(true);
    } else {
        output::begin(json);
    }
    var first = true;
    for tgt in targets {
        let cnt, ok = target::usable_host_count(tgt);
        if !ok {
            if xml { output::xml_end_discovery(); } else if !table { output::end(json); }
            return false;
        }
        if !host_cap_ok(cnt) {
            if xml { output::xml_end_discovery(); } else if !table { output::end(json); }
            return false;
        }
        var hosts: u32[4096] = [0; 4096];
        var hi: i64 = 0;
        while hi < cnt {
            let dst, ok2 = target::host_at(tgt, hi);
            if !ok2 {
                if xml { output::xml_end_discovery(); } else if !table { output::end(json); }
                return false;
            }
            hosts[hi] = dst;
            hi++;
        }
        var up_buf: u8[4096] = [0; 4096];
        let rc = almap_discover_hosts(hosts[0], cnt as i32, timeout_ms as i32, workers as i32, icmp_flag, up_buf[0]);
        if rc != 0 {
            if xml { output::xml_end_discovery(); } else if !table { output::end(json); }
            print("error: worker pool failed");
            return false;
        }
        hi = 0;
        while hi < cnt {
        let up = up_buf[hi] != 0;
        var ip_text: u8[>..] = [];
        connect_scan::fmt_ip(ip_text, hosts[hi]);
        if xml {
            output::xml_emit_discovery_host(ip_text, up);
        } else if table {
            output::emit_table_discovery_row(ip_text, up);
        } else {
            first = output::emit_discovery(json, first, ip_text, up);
        }
        hi++;
    }
    }
    if xml {
        output::xml_end_discovery();
    } else if !table {
        output::end(json);
    }
    return true;
}
