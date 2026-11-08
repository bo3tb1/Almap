import std;
import os;
namespace sigdb;

// modules/sigdb.goose - Step 29: thin wrapper over the C dynamic
// hash table (c/sigdb.c). Goose parses lines and forwards them to C;
// C owns all heap storage (malloc/realloc, up to 20,000+ entries).
//
// File format (plain text, one signature per line):
//   EXACT|<port_or_any>|<pattern_to_match>|<service_name>
//   REGEX|<port_or_any>|<posix_ere_pattern>|<service_name>
// - Blank lines and lines whose first non-space character is '#' are
//   ignored.
// - <port_or_any> is "any" or a decimal port 1..65535.
// - EXACT patterns are literal byte substrings searched in the banner
//   (case-sensitive). REGEX patterns are POSIX extended regular
//   expressions matched via the cached compiled regex in C.
// - Patterns may contain '|': the line is split at the first two '|'
//   separators and at the last one, so everything between the second
//   and last belongs to the pattern.
// - <service_name> is 1..63 printable ASCII bytes, no '|'.
// - Any other line (bad kind, bad port, empty pattern/name) is skipped
//   silently so one bad line cannot break a scan.
// - No fixed cap: the C table holds anything the file contains
//   (full Nmap DB is ~8k entries; the table is sized for 20k+).
// Matching is "first match wins" in file order. A stored signature
// whose port is "any" matches every port; a numeric port matches only
// that port. The C hash table indexes by port, so lookup is O(bucket)
// instead of O(total), merging the port bucket and the "any" bucket
// by insertion order.

extern fn almap_sigdb_match_regex(pattern: const u8&, text: const u8&) -> i32;
extern fn almap_sigdb_add(kind: const u8&, port: i32, pattern: const u8&, name: const u8&) -> i32;
extern fn almap_sigdb_lookup_into(kind: const u8&, port: i32, text: const u8&, name_out: u8&, name_cap: i32) -> i32;
extern fn almap_sigdb_count() -> i32;
extern fn almap_sigdb_hash_table_size() -> i32;
extern fn almap_sigdb_port_hash(port: i32) -> u32;
extern fn almap_sigdb_load_file(path: const u8&) -> i32;
extern fn almap_sigdb_free() -> i32;

struct SigDB {
    count: i64,
}

fn sigdb_cap() -> i64 { return 50000; }
fn pat_cap() -> i64 { return 4096; }
fn name_cap() -> i64 { return 64; }

fn kind_exact() -> i32 { return 0; }
fn kind_regex() -> i32 { return 1; }

fn sigdb_c_count() -> i64 {
    return almap_sigdb_count();
}

fn sigdb_hash_table_size() -> i64 {
    return almap_sigdb_hash_table_size();
}

fn sigdb_port_hash(port: i32) -> u32 {
    return almap_sigdb_port_hash(port);
}

fn sigdb_new() -> SigDB {
    almap_sigdb_free();
    return SigDB { count: 0 };
}

fn sigdb_free() {
    almap_sigdb_free();
}

fn sigdb_is_valid_port(v: i64) -> bool {
    if v < 1 { return false; }
    if v > 65535 { return false; }
    return true;
}

fn trim_spaces(s: const u8[:]) -> const u8[:] {
    var i: i64 = 0;
    var j = s.len;
    while i < j && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r') { i++; }
    while j > i && (s[j - 1] == ' ' || s[j - 1] == '\t' || s[j - 1] == '\r') { j--; }
    return s[i..j];
}

// Parser/line validators used by load_text and unit tests.
fn parse_port_field(s: const u8[:]) -> i32, bool {
    let t = trim_spaces(s);
    if t == "any" { return -1, true; }
    if t.len == 0 { return 0, false; }
    if t[0] == '-' || t[0] == '+' { return 0, false; }
    let v, ok = parse_int(t);
    if !ok { return 0, false; }
    if !sigdb_is_valid_port(v) { return 0, false; }
    return v as i32, true;
}

fn parse_kind_field(s: const u8[:]) -> i32, bool {
    let t = trim_spaces(s);
    if t == "EXACT" { return kind_exact(), true; }
    if t == "REGEX" { return kind_regex(), true; }
    return 0, false;
}

fn is_valid_name(s: const u8[:]) -> bool {
    if s.len == 0 { return false; }
    if s.len > name_cap() { return false; }
    for b in s {
        if b < 33 { return false; }
        if b > 126 { return false; }
        if b == '|' { return false; }
    }
    return true;
}

fn is_valid_pattern(s: const u8[:]) -> bool {
    if s.len == 0 { return false; }
    if s.len >= pat_cap() { return false; }
    for b in s {
        // NUL would truncate the C string.
        if b == 0 { return false; }
    }
    return true;
}

fn sigdb_contains(hay: const u8[:], needle: const u8[:]) -> bool {
    if needle.len == 0 { return true; }
    if hay.len < needle.len { return false; }
    for i in 0..(hay.len - needle.len + 1) {
        var ok = true;
        for j in 0..needle.len {
            if hay[i + j] != needle[j] { ok = false; break; }
        }
        if ok { return true; }
    }
    return false;
}

// Runs one POSIX ERE through c/sigdb.c. Goose passes NUL-terminated
// fixed buffers to C, so both slices are copied first. The C helper
// compiles the pattern on every call; an invalid ERE is a non-match.
fn regex_match(pattern: const u8[:], text: const u8[:]) -> bool {
    if pattern.len == 0 || pattern.len >= pat_cap() { return false; }
    if text.len >= 8192 { return false; }
    var pbuf: u8[4096] = [0; 4096];
    var tbuf: u8[8192] = [0; 8192];
    var i: i64 = 0;
    while i < pattern.len {
        pbuf[i] = pattern[i];
        i++;
    }
    pbuf[pattern.len] = 0;
    var j: i64 = 0;
    while j < text.len {
        tbuf[j] = text[j];
        j++;
    }
    tbuf[text.len] = 0;
    return almap_sigdb_match_regex(pbuf[0], tbuf[0]) == 1;
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

// Parses one already-trimmed, non-comment line and adds it to the C
// table. Returns true when a signature was added.
fn parse_line(line: const u8[:], db: SigDB&) -> bool {
    let t = trim_spaces(line);
    if t.len == 0 { return false; }
    if t[0] == '#' { return false; }
    // First two separators delimit kind and port; the last separator
    // ends the pattern, which may itself contain '|' (ERE alternation).
    var p1: i64 = -1;
    var p2: i64 = -1;
    var p3: i64 = -1;
    var i: i64 = 0;
    while i < t.len {
        if t[i] == '|' {
            if p1 < 0 { p1 = i; } else if p2 < 0 { p2 = i; } else { p3 = i; }
        }
        i++;
    }
    if p1 < 0 || p2 < 0 || p3 < 0 || p3 <= p2 { return false; }
    let kind_s = t[..p1];
    let port_s = t[p1 + 1..p2];
    let pat = trim_spaces(t[p2 + 1..p3]);
    let name = trim_spaces(t[p3 + 1..]);
    let kind, ok_kind = parse_kind_field(kind_s);
    if !ok_kind { return false; }
    if !is_valid_pattern(pat) { return false; }
    if !is_valid_name(name) { return false; }
    let port, ok = parse_port_field(port_s);
    if !ok { return false; }
    var kind_buf: u8[16] = [0; 16];
    var pat_buf: u8[4096] = [0; 4096];
    var name_buf: u8[128] = [0; 128];
    if kind == kind_exact() {
        if !copy_cstr_into(kind_buf[..], "EXACT") { return false; }
    } else {
        if !copy_cstr_into(kind_buf[..], "REGEX") { return false; }
    }
    if !copy_cstr_into(pat_buf[..], pat) { return false; }
    if !copy_cstr_into(name_buf[..], name) { return false; }
    if almap_sigdb_add(kind_buf[0], port, pat_buf[0], name_buf[0]) != 1 { return false; }
    db.count = almap_sigdb_count();
    return true;
}

// Loads all signatures from text. Invalid lines are skipped.
// Returns the number of signatures appended.
fn load_text(text: const u8[:], db: SigDB&) -> i64 {
    let before = almap_sigdb_count();
    // Split into lines on '\n' (CR is trimmed by parse_line).
    var start: i64 = 0;
    var i: i64 = 0;
    while i <= text.len {
        if i == text.len || text[i] == '\n' {
            parse_line(text[start..i], db);
            start = i + 1;
        }
        i++;
    }
    db.count = almap_sigdb_count();
    return db.count - before;
}

// Reads path and loads its signatures via the C loader. Returns the
// number loaded, or -1 when the file cannot be read.
fn load_file(path: const u8[:], db: SigDB&) -> i64 {
    if path.len == 0 || path.len >= 1024 { return -1; }
    var pbuf: u8[1024] = [0; 1024];
    if !copy_cstr_into(pbuf[..], path) { return -1; }
    let before = almap_sigdb_count();
    let n = almap_sigdb_load_file(pbuf[0]);
    if n < 0 { return -1; }
    db.count = almap_sigdb_count();
    return db.count - before;
}

// Builds the default path "$HOME/.almap/signatures.db" into out.
// Returns false when HOME is unset or empty.
fn default_path(out: u8[>..]&) -> bool {
    var home: u8[>..] = [];
    if !env("HOME", home) { return false; }
    if home.len == 0 { return false; }
    out.append(home);
    out.append("/.almap/signatures.db");
    return true;
}

// Tries to load the default path into the C table. Returns true when
// a file was read (even if it held zero valid signatures); false when
// no default file is readable, in which case callers fall back to the
// hardcoded signatures without an error.
fn load_default(db: SigDB&) -> bool {
    var path: u8[>..] = [];
    if !default_path(path) { return false; }
    let n = load_file(path, db);
    return n >= 0;
}

// First-match lookup used by modules/service.goose. Copies the
// matched service name into out and returns its length; returns 0
// when nothing matches. The C hash table merges port and "any"
// buckets in insertion order.
fn match_into(db: SigDB&, port: i32, data: const u8[:], out: u8[:]) -> i64 {
    if out.len < 2 { return 0; }
    if data.len >= 8192 { return 0; }
    if port < 1 || port > 65535 { return 0; }
    var tbuf: u8[8192] = [0; 8192];
    var kind_buf: u8[8] = [0; 8];
    kind_buf[0] = 0;
    var i: i64 = 0;
    while i < data.len {
        tbuf[i] = data[i];
        i++;
    }
    tbuf[data.len] = 0;
    let n = almap_sigdb_lookup_into(kind_buf[0], port, tbuf[0], out[0], out.len as i32);
    return n;
}
