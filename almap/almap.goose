import std;
import os;
import modules.target;
import modules.connect_scan;
import modules.syn_scan;
import modules.udp_scan;
import modules.discovery;
import modules.evasion;
import modules.alscript;
import modules.sigdb;
import modules.os_fingerprint;
import modules.webui;

// ALmap Step 26: CLI, multiple targets (-t comma list or -iL file),
// parsing, CIDR expansion, sequential scans, text, JSON, table, or XML
// output, host discovery (sequential or pool), connect-scan banners and
// basic service detection (--service, sequential only), raw-socket UDP
// scan (--scan udp / -sU, sequential only, needs root or CAP_NET_RAW),
// limited IPv6 for --scan connect and --discover (mixed IPv4/IPv6 target
// lists; SYN, UDP, banners, and service detection reject IPv6 targets),
// per-port rate limiting, bounded C pthread pools for connect scans
// without banners/service, SYN scans, and discovery, minimal SYN/ACK OS
// fingerprinting (--os, SYN only, needs root or CAP_NET_RAW; coarse
// linux-like/windows-like/network-device/unknown labels, with optional
// external Step 26 OS signature DB), Step 20 asynchronous IPv4 connect
// scans via the C epoll engine (--fast; no banners/service/IPv6), Step
// 21 evasion (--fragment, --decoys, --mtu, --spoof-mac; SYN or connect
// only, raw-socket effects on the SYN path), Step 22 AlScript plugins
// (--script <so>; dynamic C libraries loaded with dlopen/dlsym, run
// against open ports of connect/SYN scans), and Step 25 external
// signature DB (--sigdb <path>; EXACT substring and REGEX POSIX ERE
// signatures; default ~/.almap/signatures.db; signatures.db in the
// repo root is the shipped default; tools/import_nmap.py imports
// nmap-service-probes), and Step 26 external OS signature DB
// (--osdb <path>; OS_NAME|MIN_TTL|MAX_TTL|WINDOW_SIZE|TCP_OPTIONS_FLAG;
// default ~/.almap/os-signatures.db; DB hits win and the hardcoded
// Step 19 labels remain the fallback; tools/import_nmap_os.py imports
// nmap-os-db).
// No NSE or additional databases beyond the service and OS signature DBs.
// Main reads args via os args(), calls modules/target.goose parsers
// and, for --scan connect/syn, modules/connect_scan.goose /
// modules/syn_scan.goose, for --scan udp, modules/udp_scan.goose, or
// for --discover, modules/discovery.goose.
// Every scan and discovery run iterates the target list in input
// order, hosts ascending, and ports in CLI order, so output is
// deterministic.
// Uses only documented Goose: print, args, exit, if/while/for, struct,
// trailing parse results, std parse_int, and os read_file.

struct Config {
    targets: target::MixedTargetList,
    ports: target::PortRanges,
    syn: bool,
    udp: bool,
    discover: bool,
    banners: bool,
    service: bool,
    rate_per_sec: i64,
    timeout_ms: i64,
    workers: i64,
    retries: i64,
    json: bool,
    table: bool,
    xml: bool,
    os: bool,
    fast: bool,
    evasion: evasion::Evasion,
    have_evasion: bool,
    have_script: bool,
    have_sigdb: bool,
    have_osdb: bool,
}

fn print_help() {
    print("ALmap v5.0.0 - modular network scanner");
    print("Usage: almap -t <targets> -p <ports> [--scan <connect|syn|udp>] [--timeout <ms>] [--workers <n>] [--retries <n>] [--rate <n>] [--fast] [-f] [--mtu <size>] [-D <ip1,ip2,...>] [--spoof-mac <mac>] [--script <so>] [--sigdb <path>] [--osdb <path>] [--json] [--table] [--xml] [--banners] [--service] [--os] [-sU] [--help]");
    print("       almap -iL <file> -p <ports> [--scan <connect|syn|udp>] [--timeout <ms>] [--workers <n>] [--retries <n>] [--rate <n>] [--fast] [-f] [--mtu <size>] [-D <ip1,ip2,...>] [--spoof-mac <mac>] [--script <so>] [--sigdb <path>] [--osdb <path>] [--json] [--table] [--xml] [--banners] [--service] [--os] [-sU] [--help]");
    print("       almap -t <targets> --discover [--timeout <ms>] [--workers <n>] [--json] [--table] [--xml] [--help]");
    print("       almap -iL <file> --discover [--timeout <ms>] [--workers <n>] [--json] [--table] [--xml] [--help]");
    print("       almap --web [--web-port <port>] | almap --ui [--web-port <port>]");
    print("");
    print("Flags:");
    print("  -t <targets>     IPv4/IPv6/CIDR or comma-separated mixed list, up to 64,");
    print("                   e.g. 127.0.0.1,::1,10.0.0.0/30 (required unless -iL; IPv4 CIDR");
    print("                   /24.., IPv6 CIDR /112..; one family per entry)");
    print("  -iL <file>       Read IPv4/IPv6 targets from a file, one per line; blank lines");
    print("                   and lines starting with # are ignored (max 64; cannot combine with -t)");
    print("  -p <ports>       Ports/ranges, e.g. 22,80,443, 1-1024, 22,80-90,443 (required unless --discover)");
    print("  --scan <mode>    connect, syn, or udp (default: connect; syn and udp need root or CAP_NET_RAW)");
    print("                   IPv6 targets are supported by connect (and --discover) only");
    print("  -sU              Alias for --scan udp (raw UDP scan; needs root or CAP_NET_RAW)");
    print("  --discover       Discovery only, no port scan (IPv4/IPv6; cannot combine with -p or --scan)");
    print("  --banners        Grab banners on open ports (connect scan with -p only; IPv4 only)");
    print("  --service        Detect basic service/version on open ports (connect scan with -p only;");
    print("                   IPv4 only; forces the sequential path: no worker pool)");
    print("  --fast           Asynchronous epoll connect scan (IPv4; --scan connect only; cannot");
    print("                   combine with --banners or --service; up to 10,000 in-flight sockets)");
    print("  -f, --fragment   Split SYN packets into 8-byte IP fragments (SYN or connect only;");
    print("                   raw-socket effect on --scan syn; needs root or CAP_NET_RAW)");
    print("  --mtu <size>     Custom fragment MTU, multiple of 8 (implies --fragment)");
    print("  -D, --decoys <ips> Up to 5 decoy IPs: identical SYN probes from spoofed sources");
    print("  --spoof-mac <mac> Spoof source MAC on local networks (aa:bb:cc:dd:ee:ff)");
    print("  --script <so>    AlScript C plugin (.so) run against open ports");
    print("                   (connect/SYN only; output as script_out)");
    print("  --sigdb <path>   External service signature DB (needs --service;");
    print("                   default ~/.almap/signatures.db)");
    print("  --osdb <path>    External OS signature DB (needs --os;");
    print("                   default ~/.almap/os-signatures.db)");
    print("  --os             Minimal SYN/ACK OS fingerprinting (--scan syn only; needs root or");
    print("                   CAP_NET_RAW; --osdb rows override the coarse fallback labels)");
    print("  --rate <n>       Port attempts per second, 0..1000000 (default: 0 = unlimited)");
    print("  --timeout <ms>   Timeout in ms, 1..60000 (default: 1000)");
    print("  --workers <n>    Workers, 1..1000 (default: 10; pool for connect without banners/service, syn, and discover)");
    print("  --retries <n>    Extra attempts after a timeout in the --fast engine, 0..10 (default: 3)");
    print("  --json           Emit JSON array to stdout (cannot combine with --table or --xml)");
    print("  --table          Emit tab-separated table to stdout (cannot combine with --json or --xml)");
    print("  --xml            Emit XML document to stdout (cannot combine with --json or --table)");
    print("  --web            Start Web UI HTTP server (default port 8080; Zenmap Killer)");
    print("  --ui             Alias for --web");
    print("  --web-port <port> Web UI listen port (1..65535, default 8080)");
    print("  --help, -h       Show this help and exit 0");
    print("");
    print("IPv6: -t/-iL accept plain IPv6 like ::1 or 2001:db8::/120.");
    print("  IPv6 works with --scan connect and --discover only; --scan syn, --scan udp,");
    print("  --banners, and --service report \"not implemented for IPv6\" and exit 2.");
    print("  Text/table bracket IPv6 hosts ([addr]:port); JSON/XML use the plain address.");
    print("");
    print("OS fingerprinting: --os uses only SYN+ACK TTL, TCP window,");
    print("  MSS/SACK/Timestamps option presence, and IP ID behaviour. Labels are");
    print("  coarse guesses (not an Nmap OS database); a host with no open port is");
    print("  unknown, routers/NAT/proxies can mislead it, and it is IPv4 SYN only.");
    print("  --osdb loads OS_NAME|MIN_TTL|MAX_TTL|WINDOW_SIZE|OPTIONS lines");
    print("  (first match wins; window 0 and an empty option list are wildcards).");
    print("  Without --osdb, ~/.almap/os-signatures.db is tried when present; the");
    print("  coarse labels above remain the fallback when no row matches.");
    print("");
    print("Async connect scan: --fast uses one non-blocking epoll");
    print("  engine for --scan connect (IPv4 only), with up to 10,000 sockets");
    print("  in flight. --workers is ignored on this path; --rate still paces");
    print("  connection attempts.");
    print("");
    print("Evasion: -f/--fragment, --mtu, -D/--decoys, and --spoof-mac");
    print("  are valid only with --scan syn or --scan connect (IPv4 only).");
    print("  Fragmentation, decoys, MTU, and MAC spoofing shape raw SYN packets");
    print("  and need root or CAP_NET_RAW; connect scans use the kernel TCP stack,");
    print("  so those options do not alter connect packets. Decoys send identical");
    print("  SYNs from up to 5 spoofed IPs; MTU sets the per-fragment IP size.");
    print("");
    print("AlScript: --script loads a .so exporting almap_script_run");
    print("  and runs it against each open port; the output is script_out in");
    print("  text, JSON, table, and XML. Plugins are trusted native code with");
    print("  full process privileges; the sample plugin is plugins/sample_banner.c.");
    print("");
    print("Use only on networks you own or have permission to scan.");
}

fn scan_is_syn(s: const u8[:]) -> bool, bool {
    if s == "connect" { return false, true; }
    if s == "syn" { return true, true; }
    return false, false;
}

fn parse_scan_mode(s: const u8[:]) -> i32, bool {
    if s == "connect" { return 0, true; }
    if s == "syn" { return 1, true; }
    if s == "udp" { return 2, true; }
    return 0, false;
}

fn parse_timeout_ms(s: const u8[:]) -> i64, bool {
    let v, ok = parse_int(s);
    if !ok { return 0, false; }
    if v < 1 || v > 60000 { return 0, false; }
    return v, true;
}

fn parse_workers(s: const u8[:]) -> i64, bool {
    let v, ok = parse_int(s);
    if !ok { return 0, false; }
    if v < 1 || v > 1000 { return 0, false; }
    return v, true;
}

fn parse_retries(s: const u8[:]) -> i64, bool {
    let v, ok = parse_int(s);
    if !ok { return 0, false; }
    if v < 0 || v > 10 { return 0, false; }
    return v, true;
}

fn parse_rate(s: const u8[:]) -> i64, bool {
    let v, ok = parse_int(s);
    if !ok { return 0, false; }
    if v < 0 || v > 1000000 { return 0, false; }
    return v, true;
}

fn format_ip(out: u8[>..]&, ip: u32) {
    format(out, ((ip >> 24) & 255), ".", ((ip >> 16) & 255), ".", ((ip >> 8) & 255), ".", (ip & 255));
}

// Step 18: the IPv4-only module paths (SYN, UDP, banners, service) are
// rejected for IPv6 in the validation block, so this extraction is
// always safe there. It also keeps the old module signatures unchanged.
fn v4_targets_or_exit(list: target::MixedTargetList) -> target::TargetList {
    let t4, ok = target::v4_only(list);
    if !ok {
        print("error: IPv4-only scan path received an IPv6 target");
        exit(2);
    }
    return t4;
}

fn main() {
    let argv = args();
    if argv.len <= 1 {
        print_help();
        exit(2);
    }
    for i in 1..argv.len {
        if argv[i] == "--help" || argv[i] == "-h" {
            print_help();
            exit(0);
        }
    }
    var have_targets = false;
    var have_t = false;
    var have_il = false;
    var have_ports = false;
    var have_scan = false;
    var targets: target::MixedTargetList = [];
    var prs: target::PortRanges = [];
    var syn = false;
    var udp = false;
    var have_workers = false;
    var discover = false;
    var banners = false;
    var service = false;
    var os = false;
    var fast = false;
    var eva: evasion::Evasion = evasion::default_evasion();
    var have_evasion = false;
    var have_script = false;
    var script_path_buf: u8[512] = [0; 512];
    var script_path_len: i64 = 0;
    var have_sigdb = false;
    var sigdb_path_buf: u8[512] = [0; 512];
    var sigdb_path_len: i64 = 0;
    var have_osdb = false;
    var osdb_path_buf: u8[512] = [0; 512];
    var osdb_path_len: i64 = 0;
    var have_mtu = false;
    var decoy_buf: u32[5] = [0; 5];
    var rate_per_sec = 0;
    var have_rate = false;
    var table = false;
    var timeout_ms = 1000;
    var workers = 10;
    var retries = 3;
    var json = false;
    var xml = false;
    var web = false;
    var web_port = 8080;
    var have_web_port = false;
    var idx = 1;
    while idx < argv.len {
        let a = argv[idx];
        if a == "-t" {
            if idx + 1 >= argv.len {
                print("error: -t requires a value");
                print_help();
                exit(2);
            }
            let tl, tstatus = target::parse_mixed_target_list(argv[idx + 1]);
            if tstatus == 2 {
                print("error: too many targets in -t list (max ", target::mixed_list_cap(), ")");
                exit(1);
            }
            if tstatus != 0 {
                print("error: invalid target list '", argv[idx + 1], "' (expected comma-separated IPv4/IPv6/CIDR, e.g. 127.0.0.1,10.0.0.0/30,::1)");
                exit(1);
            }
            targets = tl;
            have_targets = true;
            have_t = true;
            idx += 2;
            continue;
        }
        if a == "-iL" {
            if idx + 1 >= argv.len {
                print("error: -iL requires a value (path)");
                print_help();
                exit(2);
            }
            var file_text: u8[>..] = [];
            if !read_file(argv[idx + 1], file_text) {
                print("error: cannot read -iL file '", argv[idx + 1], "'");
                exit(1);
            }
            if file_text.len > 8192 {
                print("error: -iL file too large (max 8192 bytes)");
                exit(1);
            }
            let tl, tstatus = target::parse_mixed_target_lines(file_text);
            if tstatus == 0 && tl.len == 0 {
                print("error: no targets found in -iL file '", argv[idx + 1], "' (blank lines and # comments are ignored)");
                exit(1);
            }
            if tstatus == 2 {
                print("error: too many targets in -iL file (max ", target::mixed_list_cap(), ")");
                exit(1);
            }
            if tstatus != 0 {
                print("error: invalid target in -iL file '", argv[idx + 1], "' (one IPv4/IPv6/CIDR per line; blank lines and # comments ignored)");
                exit(1);
            }
            targets = tl;
            have_targets = true;
            have_il = true;
            idx += 2;
            continue;
        }
        if a == "-p" {
            if idx + 1 >= argv.len {
                print("error: -p requires a value");
                print_help();
                exit(2);
            }
            let p, ok = target::parse_ports(argv[idx + 1]);
            if !ok {
                print("error: invalid ports '", argv[idx + 1], "' (expected e.g. 22,80,443 or 1-1024)");
                exit(1);
            }
            prs = p;
            have_ports = true;
            idx += 2;
            continue;
        }
        if a == "--scan" {
            if idx + 1 >= argv.len {
                print("error: --scan requires a value (connect|syn|udp)");
                print_help();
                exit(2);
            }
            let mode, ok = parse_scan_mode(argv[idx + 1]);
            if !ok {
                print("error: invalid --scan '", argv[idx + 1], "' (expected connect, syn, or udp)");
                exit(2);
            }
            syn = mode == 1;
            udp = mode == 2;
            have_scan = true;
            idx += 2;
            continue;
        }
        if a == "-sU" {
            udp = true;
            have_scan = true;
            idx += 1;
            continue;
        }
        if a == "--discover" {
            discover = true;
            idx += 1;
            continue;
        }
        if a == "--banners" {
            banners = true;
            idx += 1;
            continue;
        }
        if a == "--service" {
            service = true;
            idx += 1;
            continue;
        }
        if a == "--os" {
            os = true;
            idx += 1;
            continue;
        }
        if a == "--fast" {
            fast = true;
            idx += 1;
            continue;
        }
        if a == "-f" || a == "--fragment" {
            eva.fragment = true;
            have_evasion = true;
            idx += 1;
            continue;
        }
        if a == "--mtu" {
            if idx + 1 >= argv.len {
                print("error: --mtu requires a value (size)");
                print_help();
                exit(2);
            }
            let v, ok = evasion::parse_mtu(argv[idx + 1]);
            if !ok {
                print("error: invalid --mtu '", argv[idx + 1], "' (expected multiple of 8 in 32..65535)");
                print_help();
                exit(2);
            }
            eva.mtu = v;
            eva.fragment = true;
            have_evasion = true;
            have_mtu = true;
            idx += 2;
            continue;
        }
        if a == "-D" || a == "--decoys" {
            if idx + 1 >= argv.len {
                print("error: --decoys requires a value (ip1,ip2,...)");
                print_help();
                exit(2);
            }
            var tmp: u32[5] = [0; 5];
            let cnt, ok = evasion::parse_decoys(argv[idx + 1], tmp[..]);
            if !ok {
                if cnt < 0 {
                    print("error: too many decoys (max 5)");
                } else {
                    print("error: invalid decoys '", argv[idx + 1], "' (expected up to 5 IPv4 addresses)");
                }
                print_help();
                exit(2);
            }
            decoy_buf = tmp;
            eva.decoy0 = tmp[0];
            eva.decoy1 = tmp[1];
            eva.decoy2 = tmp[2];
            eva.decoy3 = tmp[3];
            eva.decoy4 = tmp[4];
            eva.decoy_count = cnt;
            have_evasion = true;
            idx += 2;
            continue;
        }
        if a == "--spoof-mac" {
            if idx + 1 >= argv.len {
                print("error: --spoof-mac requires a value (aa:bb:cc:dd:ee:ff)");
                print_help();
                exit(2);
            }
            let mac, ok = evasion::parse_mac(argv[idx + 1]);
            if !ok {
                print("error: invalid --spoof-mac '", argv[idx + 1], "' (expected aa:bb:cc:dd:ee:ff)");
                print_help();
                exit(2);
            }
            eva.spoof_mac = mac;
            eva.spoof_mac_enabled = true;
            have_evasion = true;
            idx += 2;
            continue;
        }
        if a == "--script" {
            if idx + 1 >= argv.len {
                print("error: --script requires a value (path_to_so)");
                print_help();
                exit(2);
            }
            let arg = argv[idx + 1];
            if arg.len == 0 || arg.len > 511 {
                print("error: --script path too long or empty (max 511 bytes)");
                print_help();
                exit(2);
            }
            var i: i64 = 0;
            while i < arg.len {
                script_path_buf[i] = arg[i];
                i++;
            }
            script_path_buf[arg.len] = 0;
            script_path_len = arg.len;
            have_script = true;
            idx += 2;
            continue;
        }
        if a == "--sigdb" {
            if idx + 1 >= argv.len {
                print("error: --sigdb requires a value (path)");
                print_help();
                exit(2);
            }
            let arg = argv[idx + 1];
            if arg.len == 0 || arg.len > 511 {
                print("error: --sigdb path too long or empty (max 511 bytes)");
                print_help();
                exit(2);
            }
            var i: i64 = 0;
            while i < arg.len {
                sigdb_path_buf[i] = arg[i];
                i++;
            }
            sigdb_path_buf[arg.len] = 0;
            sigdb_path_len = arg.len;
            have_sigdb = true;
            idx += 2;
            continue;
        }
        if a == "--osdb" {
            if idx + 1 >= argv.len {
                print("error: --osdb requires a value (path)");
                print_help();
                exit(2);
            }
            let arg = argv[idx + 1];
            if arg.len == 0 || arg.len > 511 {
                print("error: --osdb path too long or empty (max 511 bytes)");
                print_help();
                exit(2);
            }
            var i: i64 = 0;
            while i < arg.len {
                osdb_path_buf[i] = arg[i];
                i++;
            }
            osdb_path_buf[arg.len] = 0;
            osdb_path_len = arg.len;
            have_osdb = true;
            idx += 2;
            continue;
        }
        if a == "--rate" {
            if idx + 1 >= argv.len {
                print("error: --rate requires a value (n)");
                print_help();
                exit(2);
            }
            let v, ok = parse_rate(argv[idx + 1]);
            if !ok {
                print("error: invalid --rate '", argv[idx + 1], "' (expected 0..1000000)");
                print_help();
                exit(2);
            }
            rate_per_sec = v;
            have_rate = true;
            idx += 2;
            continue;
        }
        if a == "--timeout" {
            if idx + 1 >= argv.len {
                print("error: --timeout requires a value (ms)");
                print_help();
                exit(2);
            }
            let v, ok = parse_timeout_ms(argv[idx + 1]);
            if !ok {
                print("error: invalid --timeout '", argv[idx + 1], "' (expected 1..60000)");
                exit(2);
            }
            timeout_ms = v;
            idx += 2;
            continue;
        }
        if a == "--workers" {
            if idx + 1 >= argv.len {
                print("error: --workers requires a value (n)");
                print_help();
                exit(2);
            }
            let v, ok = parse_workers(argv[idx + 1]);
            if !ok {
                print("error: invalid --workers '", argv[idx + 1], "' (expected 1..1000)");
                exit(2);
            }
            workers = v;
            have_workers = true;
            idx += 2;
            continue;
        }
        if a == "--retries" {
            if idx + 1 >= argv.len {
                print("error: --retries requires a value (n)");
                print_help();
                exit(2);
            }
            let v, ok = parse_retries(argv[idx + 1]);
            if !ok {
                print("error: invalid --retries '", argv[idx + 1], "' (expected 0..10)");
                print_help();
                exit(2);
            }
            retries = v;
            idx += 2;
            continue;
        }
        if a == "--json" {
            json = true;
            idx += 1;
            continue;
        }
        if a == "--table" {
            table = true;
            idx += 1;
            continue;
        }
        if a == "--xml" {
            xml = true;
            idx += 1;
            continue;
        }
        if a == "--web" || a == "--ui" {
            web = true;
            if idx + 1 < argv.len {
                let next_port, next_ok = webui::parse_port(argv[idx + 1]);
                if next_ok {
                    web_port = next_port;
                    have_web_port = true;
                    idx += 2;
                    continue;
                }
            }
            idx += 1;
            continue;
        }
        if a == "--web-port" {
            if idx + 1 >= argv.len {
                print("error: --web-port requires a value (port)");
                print_help();
                exit(2);
            }
            let v, ok = webui::parse_port(argv[idx + 1]);
            if !ok {
                print("error: invalid --web-port '", argv[idx + 1], "' (expected 1..65535)");
                print_help();
                exit(2);
            }
            web_port = v;
            have_web_port = true;
            idx += 2;
            continue;
        }
        print("error: unknown flag '", a, "'");
        print_help();
        exit(2);
    }
    if web {
        if !webui::valid_port(web_port) {
            print("error: invalid web port");
            print_help();
            exit(2);
        }
        if have_targets || have_ports || have_scan || discover || banners || service || os || fast || have_evasion || have_script {
            print("error: --web/--ui cannot be combined with scan flags");
            print_help();
            exit(2);
        }
        let started = webui::serve(web_port);
        if !started {
            exit(1);
        }
        exit(0);
    }
    if os && !syn {
        print("error: --os requires --scan syn and root or CAP_NET_RAW");
        print_help();
        exit(2);
    }
    if fast && (discover || syn || udp) {
        print("error: --fast requires --scan connect");
        print_help();
        exit(2);
    }
    if fast && (banners || service) {
        print("error: --fast cannot be combined with --banners or --service");
        print_help();
        exit(2);
    }
    if have_evasion && (discover || udp) {
        print("error: evasion flags require --scan syn or --scan connect");
        print_help();
        exit(2);
    }
    if have_evasion && fast {
        print("error: --fast cannot be combined with evasion flags");
        print_help();
        exit(2);
    }
    if have_evasion && os {
        print("error: --os cannot be combined with evasion flags");
        print_help();
        exit(2);
    }
    if have_evasion && (banners || service) {
        print("error: evasion flags cannot be combined with --banners or --service");
        print_help();
        exit(2);
    }
    if have_script && (discover || udp) {
        print("error: --script requires --scan connect or --scan syn");
        print_help();
        exit(2);
    }
    if have_script && fast {
        print("error: --script cannot be combined with --fast");
        print_help();
        exit(2);
    }
    if have_script && (banners || service || os || have_evasion) {
        print("error: --script cannot be combined with --banners, --service, --os, or evasion flags");
        print_help();
        exit(2);
    }
    if have_sigdb && !service {
        print("error: --sigdb requires --service");
        print_help();
        exit(2);
    }
    if have_osdb && !os {
        print("error: --osdb requires --os");
        print_help();
        exit(2);
    }
    if udp && banners {
        print("error: --scan udp cannot be combined with --banners");
        print_help();
        exit(2);
    }
    if udp && service {
        print("error: --scan udp cannot be combined with --service");
        print_help();
        exit(2);
    }
    if udp && have_workers && workers > 1 {
        print("error: --scan udp does not support --workers > 1 (sequential scan only)");
        print_help();
        exit(2);
    }
    if service && (discover || syn || !have_ports) {
        print("error: --service requires --scan connect and -p");
        print_help();
        exit(2);
    }
    if discover && (have_ports || have_scan) {
        print("error: --discover cannot be combined with -p or --scan");
        print_help();
        exit(2);
    }
    if banners && (discover || syn || !have_ports) {
        print("error: --banners requires --scan connect and -p");
        print_help();
        exit(2);
    }
    if discover && have_rate {
        print("error: --rate cannot be combined with --discover");
        print_help();
        exit(2);
    }
    if xml && (json || table) {
        print("error: --xml cannot be combined with --json or --table");
        print_help();
        exit(2);
    }
    if table && json {
        print("error: --table cannot be combined with --json");
        print_help();
        exit(2);
    }
    if have_t && have_il {
        print("error: -t and -iL cannot be combined");
        print_help();
        exit(2);
    }
    if !have_targets {
        print("error: missing required -t <targets> or -iL <file>");
        print_help();
        exit(2);
    }
    if !discover && !have_ports {
        print("error: missing required -p <ports>");
        print_help();
        exit(2);
    }
    let cfg = Config { targets: targets, ports: prs, syn: syn, udp: udp, discover: discover, banners: banners, service: service, os: os, fast: fast, evasion: eva, have_evasion: have_evasion, have_script: have_script, have_sigdb: have_sigdb, have_osdb: have_osdb, rate_per_sec: rate_per_sec, timeout_ms: timeout_ms, workers: workers, retries: retries, json: json, table: table, xml: xml };
    // Step 18: target limits are per family (/24../32 IPv4, /112../128
    // IPv6, at most 65536 addresses per target).
    if !target::targets_allowed_mixed(cfg.targets) {
        print("CIDR prefix too large for this step; use /24 (IPv4) or /112 (IPv6) or smaller range");
        exit(1);
    }
    // Step 18: IPv6 is connect/discover only. Reject the other modes
    // before the raw-socket privilege checks so the family error wins.
    let has_v6 = target::list_has_v6(cfg.targets);
    if has_v6 && cfg.have_evasion {
        print("error: evasion not implemented for IPv6");
        print_help();
        exit(2);
    }
    if has_v6 && cfg.have_script {
        print("error: --script not implemented for IPv6");
        print_help();
        exit(2);
    }
    if has_v6 && cfg.fast {
        print("error: fast connect scan not implemented for IPv6");
        print_help();
        exit(2);
    }
    if has_v6 && cfg.syn {
        print("error: syn scan not implemented for IPv6");
        print_help();
        exit(2);
    }
    if has_v6 && cfg.udp {
        print("error: udp scan not implemented for IPv6");
        print_help();
        exit(2);
    }
    if has_v6 && cfg.service {
        print("error: service detection not implemented for IPv6");
        print_help();
        exit(2);
    }
    if has_v6 && cfg.banners {
        print("error: banner grabbing not implemented for IPv6");
        print_help();
        exit(2);
    }
    if cfg.udp {
        if !udp_scan::can_raw() {
            print("UDP scan requires root or CAP_NET_RAW");
            exit(1);
        }
    }
    if cfg.syn {
        if !syn_scan::can_raw() {
            if cfg.os {
                print("error: --os requires --scan syn and root or CAP_NET_RAW");
            } else {
                print("SYN scan requires root or CAP_NET_RAW");
            }
            exit(1);
        }
    }
    if cfg.have_script {
        if !alscript::file_ok(script_path_buf[0]) {
            var err_buf: u8[512] = [0; 512];
            let err_len = alscript::last_error(err_buf[..]);
            let err_slice = err_buf[..err_len];
            print("error: cannot load --script '", script_path_buf[..script_path_len], "': ", err_slice);
            exit(1);
        }
    }
    var sigdb_db: sigdb::SigDB = sigdb::sigdb_new();
    if cfg.service {
        if cfg.have_sigdb {
            let loaded = sigdb::load_file(sigdb_path_buf[..sigdb_path_len], sigdb_db);
            if loaded < 0 {
                print("error: cannot read --sigdb file '", sigdb_path_buf[..sigdb_path_len], "'");
                exit(1);
            }
        } else {
            sigdb::load_default(sigdb_db);
        }
    }
    // Step 26: an explicit --osdb must be readable; the default file is
    // optional so existing hosts keep the hardcoded fallback labels.
    var os_db: os_fingerprint::OsDB = os_fingerprint::osdb_new();
    if cfg.os {
        if cfg.have_osdb {
            let loaded = os_fingerprint::load_file(osdb_path_buf[..osdb_path_len], os_db);
            if loaded < 0 {
                print("error: cannot read --osdb file '", osdb_path_buf[..osdb_path_len], "'");
                exit(1);
            }
        } else {
            os_fingerprint::load_default(os_db);
        }
    }
    if cfg.discover {
        if has_v6 {
            if have_workers && cfg.workers > 1 && !cfg.json && !cfg.table && !cfg.xml {
                print("warning: IPv6 discovery is TCP-only and sequential; --workers ignored");
            }
            let found_mixed = discovery::discover_mixed(cfg.targets, cfg.timeout_ms, cfg.json, cfg.table, cfg.xml);
            if !found_mixed {
                print("CIDR prefix too large for this step; use /112 or smaller range for IPv6");
                exit(1);
            }
        } else if cfg.workers > 1 {
            let v4_targets = v4_targets_or_exit(cfg.targets);
            for t in v4_targets {
                let host_count, host_ok = target::usable_host_count(t);
                if !host_ok {
                    print("CIDR prefix too large for this step; use /24 or smaller range");
                    exit(1);
                }
                if !discovery::host_cap_ok(host_count) {
                    print("error: too many hosts for worker pool (max 4096)");
                    exit(1);
                }
            }
            let found_par = discovery::discover_parallel(v4_targets, cfg.timeout_ms, cfg.json, cfg.table, cfg.workers, cfg.xml);
            if !found_par {
                exit(1);
            }
        } else {
            if !cfg.json && !cfg.table && !cfg.xml {
                print("warning: --workers is accepted but not yet used; running sequentially");
            }
            let v4_targets = v4_targets_or_exit(cfg.targets);
            let found = discovery::discover(v4_targets, cfg.timeout_ms, cfg.json, cfg.table, cfg.xml);
            if !found {
                print("CIDR prefix too large for this step; use /24 or smaller range");
                exit(1);
            }
        }
    } else if cfg.syn {
        let v4_targets = v4_targets_or_exit(cfg.targets);
        if cfg.have_script {
            let scanned_script = syn_scan::scan_syn_script(v4_targets, cfg.ports, cfg.timeout_ms, cfg.json, cfg.rate_per_sec, cfg.table, cfg.xml, script_path_buf[..]);
            if !scanned_script {
                exit(1);
            }
        } else if cfg.have_evasion {
            let scanned_eva = syn_scan::scan_syn_evasion(v4_targets, cfg.ports, cfg.timeout_ms, cfg.json, cfg.rate_per_sec, cfg.table, cfg.xml, cfg.evasion);
            if !scanned_eva {
                exit(1);
            }
        } else if cfg.os {
            let scanned_os = syn_scan::scan_syn_os(v4_targets, cfg.ports, cfg.timeout_ms, cfg.json, cfg.table, cfg.workers, cfg.rate_per_sec, cfg.xml, os_db);
            if !scanned_os {
                exit(1);
            }
        } else if cfg.workers > 1 {
            let scanned_syn_par = syn_scan::scan_syn_parallel(v4_targets, cfg.ports, cfg.timeout_ms, cfg.json, cfg.table, cfg.workers, cfg.rate_per_sec, cfg.xml);
            if !scanned_syn_par {
                exit(1);
            }
        } else {
            if !cfg.json && !cfg.table && !cfg.xml {
                print("warning: --workers is accepted but not yet used; running sequentially");
            }
            let scanned_syn = syn_scan::scan_syn(v4_targets, cfg.ports, cfg.timeout_ms, cfg.json, cfg.rate_per_sec, cfg.table, cfg.xml);
            if !scanned_syn {
                print("CIDR prefix too large for this step; use /24 or smaller range");
                exit(1);
            }
        }
    } else if cfg.udp {
        let v4_targets = v4_targets_or_exit(cfg.targets);
        let scanned_udp = udp_scan::scan_udp(v4_targets, cfg.ports, cfg.timeout_ms, cfg.json, cfg.rate_per_sec, cfg.table, cfg.xml);
        if !scanned_udp {
            exit(1);
        }
    } else if has_v6 {
        if have_workers && cfg.workers > 1 && !cfg.json && !cfg.table && !cfg.xml {
            print("warning: IPv6 connect scan is sequential; --workers ignored");
        }
        let scanned_mixed = connect_scan::scan_connect_mixed(cfg.targets, cfg.ports, cfg.timeout_ms, cfg.json, cfg.rate_per_sec, cfg.table, cfg.xml);
        if !scanned_mixed {
            print("CIDR prefix too large for this step; use /112 or smaller range for IPv6");
            exit(1);
        }
    } else if cfg.fast {
        let v4_targets = v4_targets_or_exit(cfg.targets);
        let scanned_fast = connect_scan::scan_connect_fast(v4_targets, cfg.ports, cfg.timeout_ms, cfg.retries, cfg.json, cfg.table, cfg.xml, cfg.rate_per_sec);
        if !scanned_fast {
            exit(1);
        }
    } else if cfg.have_script {
        let v4_targets = v4_targets_or_exit(cfg.targets);
        let scanned_script = connect_scan::scan_connect_script(v4_targets, cfg.ports, cfg.timeout_ms, cfg.json, cfg.rate_per_sec, cfg.table, cfg.xml, script_path_buf[..]);
        if !scanned_script {
            exit(1);
        }
    } else if cfg.have_evasion {
        if !cfg.json && !cfg.table && !cfg.xml {
            print("warning: evasion flags affect raw SYN packets only; connect scan uses kernel TCP");
        }
        let v4_targets = v4_targets_or_exit(cfg.targets);
        let scanned = connect_scan::scan_connect(v4_targets, cfg.ports, cfg.timeout_ms, cfg.json, false, cfg.rate_per_sec, cfg.table, cfg.xml, false, sigdb_db);
        if !scanned {
            print("CIDR prefix too large for this step; use /24 or smaller range");
            exit(1);
        }
    } else if cfg.workers > 1 && !cfg.banners && !cfg.service {
        let v4_targets = v4_targets_or_exit(cfg.targets);
        let scanned_par = connect_scan::scan_connect_parallel(v4_targets, cfg.ports, cfg.timeout_ms, cfg.json, cfg.workers, cfg.rate_per_sec, cfg.table, cfg.xml);
        if !scanned_par {
            exit(1);
        }
    } else {
        if !cfg.json && !cfg.table && !cfg.xml {
            print("warning: --workers is accepted but not yet used; running sequentially");
        }
        let v4_targets = v4_targets_or_exit(cfg.targets);
        let scanned = connect_scan::scan_connect(v4_targets, cfg.ports, cfg.timeout_ms, cfg.json, cfg.banners, cfg.rate_per_sec, cfg.table, cfg.xml, cfg.service, sigdb_db);
        if !scanned {
            print("CIDR prefix too large for this step; use /24 or smaller range");
            exit(1);
        }
    }
}
