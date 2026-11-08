import std;
import os;
namespace os_fingerprint;

// modules/os_fingerprint.goose - Step 31: thin wrapper over the C
// dynamic OS table (c/osdb.c) plus the original Step 19 coarse
// heuristics (c/os.c).
//
// The C helper still computes the fallback class from SYN/ACK fields:
//   0 unknown, 1 linux-like, 2 windows-like, 3 network-device.
// Before using that fallback, classify_os() queries the C table:
//
//   OS_NAME|MIN_TTL|MAX_TTL|WINDOW_SIZE|TCP_OPTIONS_FLAG|PROBE
//   Linux|40|64|5840|MSS,SACK|T1=SYNACK,T2=RST,...,U1=UNREACH
//
// - Blank lines and lines starting with '#' are ignored.
// - OS_NAME is 1..64 printable ASCII bytes; '|', quotes, backslash,
//   '<', '>', and '&' are rejected so the name is safe in every output
//   format. Spaces are allowed (Network Device).
// - MIN_TTL/MAX_TTL are decimal 0..255 and inclusive. A sample must
//   have ttl > 0 to match.
// - WINDOW_SIZE is decimal 0..65535; 0 means "any window".
// - TCP_OPTIONS_FLAG is a comma list of MSS, SACK, TS/TIMESTAMPS, WS/WINDOWSCALE, or
//   empty. Every listed flag must be present; extra observed flags do
//   not prevent a match (a required-subset test).
// - PROBE (optional, Step 31): T1-T7+U1 signature string
//   (e.g. "T1=SYNACK,T2=RST,...,U1=UNREACH,ID=ZERO"). Empty or absent
//   is a wildcard; otherwise exact equality or POSIX ERE decides.
//   The probe may contain '|' (ERE alternation): everything after
//   the 5th '|' is the probe field.
// - First match wins in file order. No fixed cap: the C table holds
//   the full Nmap DB (6000+ Fingerprint blocks, ~1200 unique rows).
// If no DB entry matches, classify_os() returns the hardcoded C class.
// Storage is malloc/realloc in C; Goose holds no arrays.

extern fn almap_osdb_add(name: const u8&, min_ttl: i32, max_ttl: i32, window: i32, opts: i32) -> i32;
extern fn almap_osdb_add2(name: const u8&, min_ttl: i32, max_ttl: i32, window: i32, opts: i32, probe: const u8&) -> i32;
extern fn almap_osdb_lookup_into(ttl: i32, window: i32, opts: i32, name_out: u8&, cap: i32) -> i32;
extern fn almap_osdb_lookup_into_full(ttl: i32, window: i32, opts: i32, probe: const u8&, name_out: u8&, cap: i32) -> i32;
extern fn almap_os_probe_all(src_be: u32, dst_be: u32, open_port: i32, closed_port: i32, timeout_ms: i32, probe_out: u8&, probe_cap: i32) -> i32;
extern fn almap_osdb_count() -> i32;
extern fn almap_osdb_load_file(path: const u8&) -> i32;
extern fn almap_osdb_free() -> i32;

struct OsDB {
    count: i64,
}

fn osdb_cap() -> i64 { return 20000; }
fn name_cap() -> i64 { return 64; }

// Scratch for the last classified name (sequential use only).
var os_scratch: u8[256] = [0; 256];

// Same bits as ALMAP_OS_OPT_* in c/os.h.
fn opt_mss() -> i32 { return 0x01; }
fn opt_sack() -> i32 { return 0x02; }
fn opt_timestamps() -> i32 { return 0x04; }
fn opt_window_scale() -> i32 { return 0x08; }

fn osdb_new() -> OsDB {
    almap_osdb_free();
    return OsDB { count: 0 };
}

fn osdb_free() {
    almap_osdb_free();
}

fn osdb_c_count() -> i64 {
    return almap_osdb_count();
}

fn name_from_code(code: i32) -> const u8[:] {
    if code == 1 { return "linux-like"; }
    if code == 2 { return "windows-like"; }
    if code == 3 { return "network-device"; }
    return "unknown";
}

// True for the four fallback labels the C helper can produce.
fn is_known_name(name: const u8[:]) -> bool {
    if name == "linux-like" { return true; }
    if name == "windows-like" { return true; }
    if name == "network-device" { return true; }
    if name == "unknown" { return true; }
    return false;
}

fn trim_spaces(s: const u8[:]) -> const u8[:] {
    var i: i64 = 0;
    var j = s.len;
    while i < j && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r') { i++; }
    while j > i && (s[j - 1] == ' ' || s[j - 1] == '\t' || s[j - 1] == '\r') { j--; }
    return s[i..j];
}

fn is_valid_os_name(s: const u8[:]) -> bool {
    if s.len == 0 { return false; }
    if s.len > name_cap() { return false; }
    for b in s {
        if b < 32 { return false; }
        if b > 126 { return false; }
        if b == '|' || b == '"' || b == '\\' { return false; }
        if b == '<' || b == '>' || b == '&' { return false; }
    }
    return true;
}

fn parse_ttl_field(s: const u8[:]) -> i32, bool {
    let t = trim_spaces(s);
    if t.len == 0 { return 0, false; }
    if t[0] == '-' || t[0] == '+' { return 0, false; }
    let v, ok = parse_int(t);
    if !ok { return 0, false; }
    if v < 0 || v > 255 { return 0, false; }
    return v as i32, true;
}

fn parse_window_field(s: const u8[:]) -> i32, bool {
    let t = trim_spaces(s);
    if t.len == 0 { return 0, false; }
    if t[0] == '-' || t[0] == '+' { return 0, false; }
    let v, ok = parse_int(t);
    if !ok { return 0, false; }
    if v < 0 || v > 65535 { return 0, false; }
    return v as i32, true;
}

// Parses "MSS,SACK" (also "TS"/"TIMESTAMPS") into the C option bits.
// An empty field means no required flags.
fn parse_opts_field(s: const u8[:]) -> i32, bool {
    let t = trim_spaces(s);
    if t.len == 0 { return 0, true; }
    if t[t.len - 1] == ',' { return 0, false; }
    var mask: i32 = 0;
    var start: i64 = 0;
    while start < t.len {
        var end = start;
        while end < t.len && t[end] != ',' { end++; }
        let tok = trim_spaces(t[start..end]);
        if tok.len == 0 { return 0, false; }
        if tok == "MSS" {
            mask = mask | opt_mss();
        } else if tok == "SACK" {
            mask = mask | opt_sack();
        } else if tok == "TS" || tok == "TIMESTAMPS" {
            mask = mask | opt_timestamps();
        } else if tok == "WS" || tok == "WINDOWSCALE" {
            mask = mask | opt_window_scale();
        } else {
            return 0, false;
        }
        if end >= t.len { break; }
        start = end + 1;
    }
    return mask, true;
}

fn copy_cstr_into(dst: u8[:], src: const u8[:]) -> bool {
    if src.len >= dst.len { return false; }
    var i: i64 = 0;
    while i < src.len {
        dst[i] = src[i];
        i++;
    }
    dst[src.len] = 0;
    return true;
}

fn parse_line(line: const u8[:], db: OsDB&) -> bool {
    let t = trim_spaces(line);
    if t.len == 0 { return false; }
    if t[0] == '#' { return false; }
    var p1: i64 = -1;
    var p2: i64 = -1;
    var p3: i64 = -1;
    var p4: i64 = -1;
    var p5: i64 = -1;
    var i: i64 = 0;
    while i < t.len {
        if t[i] == '|' {
            if p1 < 0 { p1 = i; } else if p2 < 0 { p2 = i; } else if p3 < 0 { p3 = i; } else if p4 < 0 { p4 = i; } else if p5 < 0 { p5 = i; } else { /* probe may contain '|': keep first five as delimiters */ }
        }
        i++;
    }
    if p1 < 0 || p2 < 0 || p3 < 0 || p4 < 0 { return false; }
    let name = trim_spaces(t[..p1]);
    let min_s = t[p1 + 1..p2];
    let max_s = t[p2 + 1..p3];
    let win_s = t[p3 + 1..p4];
    let opts_s = if p5 < 0 { t[p4 + 1..] } else { t[p4 + 1..p5] };
    let probe_s = if p5 < 0 { "" } else { trim_spaces(t[p5 + 1..]) };
    if !is_valid_os_name(name) { return false; }
    let min_ttl, ok_min = parse_ttl_field(min_s);
    if !ok_min { return false; }
    let max_ttl, ok_max = parse_ttl_field(max_s);
    if !ok_max { return false; }
    if min_ttl > max_ttl { return false; }
    let window, ok_win = parse_window_field(win_s);
    if !ok_win { return false; }
    let opts, ok_opts = parse_opts_field(opts_s);
    if !ok_opts { return false; }
    var name_buf: u8[128] = [0; 128];
    if !copy_cstr_into(name_buf[..], name) { return false; }
    var probe_buf: u8[2048] = [0; 2048];
    if probe_s.len >= probe_buf.len { return false; }
    if !copy_cstr_into(probe_buf[..], probe_s) { return false; }
    if almap_osdb_add2(name_buf[0], min_ttl, max_ttl, window, opts, probe_buf[0]) != 1 { return false; }
    db.count = almap_osdb_count();
    return true;
}

// Loads all signatures from text into the C table. Invalid lines are
// skipped. Returns the number of signatures appended.
fn load_text(text: const u8[:], db: OsDB&) -> i64 {
    let before = almap_osdb_count();
    var start: i64 = 0;
    var i: i64 = 0;
    while i <= text.len {
        if i == text.len || text[i] == '\n' {
            parse_line(text[start..i], db);
            start = i + 1;
        }
        i++;
    }
    db.count = almap_osdb_count();
    return db.count - before;
}

// Reads path and loads its OS signatures via the C loader. Returns
// the number loaded, or -1 when the file cannot be read.
fn load_file(path: const u8[:], db: OsDB&) -> i64 {
    if path.len == 0 || path.len >= 1024 { return -1; }
    var pbuf: u8[1024] = [0; 1024];
    if !copy_cstr_into(pbuf[..], path) { return -1; }
    let before = almap_osdb_count();
    let n = almap_osdb_load_file(pbuf[0]);
    if n < 0 { return -1; }
    db.count = almap_osdb_count();
    return db.count - before;
}

// Builds the default path "$HOME/.almap/os-signatures.db" into out.
// Returns false when HOME is unset or empty.
fn default_path(out: u8[>..]&) -> bool {
    var home: u8[>..] = [];
    if !env("HOME", home) { return false; }
    if home.len == 0 { return false; }
    out.append(home);
    out.append("/.almap/os-signatures.db");
    return true;
}

// Tries the default path. Returns true when a file was read, false
// when the default file is absent or unreadable.
fn load_default(db: OsDB&) -> bool {
    var path: u8[>..] = [];
    if !default_path(path) { return false; }
    let n = load_file(path, db);
    return n >= 0;
}

fn ipid_name(code: i32) -> const u8[:] {
    if code == 1 { return "ZERO"; }
    if code == 2 { return "INC"; }
    if code == 4 { return "RAND"; }
    if code == 5 { return "BRKN"; }
    if code == 3 { return "OTH"; }
    return "UNKNOWN";
}

fn ipid_from_sequential(ids: const i32[:]) -> i32 {
    if ids.len == 0 { return 0; }
    var all_zero = true;
    var i: i64 = 0;
    while i < ids.len {
        if (ids[i] & 0xFFFF) != 0 { all_zero = false; break; }
        i++;
    }
    if all_zero { return 1; }
    if ids.len == 1 { return 3; }
    var incremental = true;
    var has_dup = false;
    var has_decrease = false;
    var j: i64 = 1;
    while j < ids.len {
        let prev = ids[j - 1] & 0xFFFF;
        let cur = ids[j] & 0xFFFF;
        let expected = (prev + 1) & 0xFFFF;
        if cur == prev { has_dup = true; }
        if cur != expected { incremental = false; }
        if cur == ((prev + 65535) & 0xFFFF) || cur == ((prev + 65534) & 0xFFFF) { has_decrease = true; }
        j++;
    }
    if incremental { return 2; }
    if has_dup || has_decrease { return 5; }
    return 4;
}

// Lookup probe: 0 when the C table matches, -1 otherwise. Populates
// os_scratch on a hit for classify_os(). Empty probe means wildcard.
fn find_match(db: OsDB&, ttl: i32, window: i32, options: i32) -> i64 {
    if ttl <= 0 { return -1; }
    var empty_buf: u8[8] = [0; 8];
    empty_buf[0] = 0;
    let n = almap_osdb_lookup_into_full(ttl, window, options, empty_buf[0], os_scratch[0], 256);
    if n <= 0 { return -1; }
    return 0;
}

// Step 31 full lookup with probe string (T1-T7+U1 signature).
fn find_match_full(db: OsDB&, ttl: i32, window: i32, options: i32, probe_str: const u8[:]) -> i64 {
    if ttl <= 0 { return -1; }
    if probe_str.len >= 2048 { return -1; }
    var pbuf: u8[2048] = [0; 2048];
    var i: i64 = 0;
    while i < probe_str.len {
        pbuf[i] = probe_str[i];
        i++;
    }
    pbuf[probe_str.len] = 0;
    let n = almap_osdb_lookup_into_full(ttl, window, options, pbuf[0], os_scratch[0], 256);
    if n <= 0 { return -1; }
    return 0;
}

// DB name when a signature matches, otherwise the Step 19 hardcoded
// class name for fallback_code (0..3). The returned slice aliases
// os_scratch on a hit (valid until the next classify call).
fn classify_os(db: OsDB&, ttl: i32, window: i32, options: i32, fallback_code: i32) -> const u8[:] {
    if find_match(db, ttl, window, options) >= 0 {
        let n = almap_osdb_lookup_into(ttl, window, options, os_scratch[0], 256);
        if n > 0 {
            return os_scratch[..n];
        }
    }
    return name_from_code(fallback_code);
}

// Step 31: probe-aware classification. Probe matching is exact or ERE
// in C; an empty probe_str behaves like classify_os. The returned
// slice aliases os_scratch on a hit.
fn classify_os_full(db: OsDB&, ttl: i32, window: i32, options: i32, fallback_code: i32, probe_str: const u8[:]) -> const u8[:] {
    if find_match_full(db, ttl, window, options, probe_str) >= 0 {
        if probe_str.len < 2048 {
            var pbuf: u8[2048] = [0; 2048];
            var i: i64 = 0;
            while i < probe_str.len {
                pbuf[i] = probe_str[i];
                i++;
            }
            pbuf[probe_str.len] = 0;
            let n = almap_osdb_lookup_into_full(ttl, window, options, pbuf[0], os_scratch[0], 256);
            if n > 0 {
                return os_scratch[..n];
            }
        }
    }
    return name_from_code(fallback_code);
}

// Probe signature helper (pure): joins per-probe codes and aggregate
// ID/OPTS/ISN fields into the DB probe format. Codes are e.g.
// SYNACK/RST/NONE/OTHER/UNREACH. Kept for unit tests; the live
// collector in c/raw.c builds the same string from captured packets.
fn make_probe_signature(t1: const u8[:], t2: const u8[:], t3: const u8[:], t4: const u8[:], t5: const u8[:], t6: const u8[:], t7: const u8[:], u1: const u8[:], ipid: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    out.append("T1="); out.append(t1);
    out.append(",T2="); out.append(t2);
    out.append(",T3="); out.append(t3);
    out.append(",T4="); out.append(t4);
    out.append(",T5="); out.append(t5);
    out.append(",T6="); out.append(t6);
    out.append(",T7="); out.append(t7);
    out.append(",U1="); out.append(u1);
    out.append(",ID="); out.append(ipid);
    return out;
}

// Step 31 collector: runs T1-T7+U1 against open/closed ports and
// writes the signature into out. Returns the byte count, -1 on no
// raw access/invalid args. open/closed <1 means skip that half.
fn collect_probe_signature(src_be: u32, dst_be: u32, open_port: i32, closed_port: i32, timeout_ms: i64, out: u8[:]) -> i64 {
    if out.len < 2 { return -1; }
    if src_be == 0 || dst_be == 0 || timeout_ms <= 0 { return -1; }
    let n = almap_os_probe_all(src_be, dst_be, open_port, closed_port, timeout_ms as i32, out[0], out.len as i32);
    return n;
}
