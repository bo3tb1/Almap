#!/usr/bin/env python3
"""Import Nmap service probes into an ALmap signatures.db.

Reads a standard ``nmap-service-probes`` file, extracts the ``match``
(and optionally ``softmatch``) directives, translates the common PCRE
syntax to POSIX extended regular expressions, and writes ALmap's
line format:

    EXACT|port_or_any|literal|service_name
    REGEX|port_or_any|posix_ere|service_name

Nmap match lines do not carry a port: ``p/.../`` in the version info is
the product description. Ports are therefore taken from the sibling
``nmap-services`` file when one is available (service name -> TCP
ports). With no mapping the signature uses ``any``. ``--port`` forces
a port or ``any`` for every line.

The ALmap database has no fixed cap (Step 29 full Nmap DB): output
imports ALL valid signatures by default (up to --max, default 50000).
Patterns that cannot be expressed as portable POSIX ERE (NUL bytes,
PCRE lookarounds, inline flags, non-printable/binary bytes, >4096
bytes) are skipped and counted.
"""

from __future__ import annotations

import argparse
import os
import re
import sys

MAX_SIGS = 50000
MAX_PATTERN = 4096
MAX_NAME = 63

META = set("\\.^$|?*+()[]{}")
WS_ESCAPES = set("nrtfv")
FLAG_OK = set("s")
FLAG_UNSUPPORTED = set("imxU")


class UnsupportedPattern(Exception):
    """Raised when an Nmap pattern has no safe POSIX ERE equivalent."""


def parse_port(value: str) -> int:
    if value.lower() == "any":
        return -1
    try:
        port = int(value, 10)
    except ValueError:
        raise argparse.ArgumentTypeError("port must be 1..65535 or 'any'")
    if port < 1 or port > 65535:
        raise argparse.ArgumentTypeError("port must be 1..65535 or 'any'")
    return port


def find_pattern_end(rest: str, start: int, delim: str) -> int:
    """Return the index of the unescaped closing delimiter."""
    escaped = False
    i = start
    while i < len(rest):
        c = rest[i]
        if escaped:
            escaped = False
        elif c == "\\":
            escaped = True
        elif c == delim:
            return i
        i += 1
    return -1


def parse_match_line(line: str):
    """Parse one match/softmatch line.

    Returns (directive, service, raw_pattern, flags, version_info) or
    None. Raises UnsupportedPattern for a syntactically broken pattern.
    """
    line = line.rstrip("\r\n")
    parts = line.split(None, 2)
    if len(parts) < 3:
        return None
    directive, service, rest = parts[0], parts[1], parts[2].lstrip()
    if directive not in ("match", "softmatch"):
        return None
    if len(rest) < 3 or rest[0] != "m":
        raise UnsupportedPattern("pattern does not start with m<delim>")
    delim = rest[1]
    if delim.isalnum() or delim.isspace() or delim == "\\":
        raise UnsupportedPattern("bad regex delimiter")
    end = find_pattern_end(rest, 2, delim)
    if end < 0:
        raise UnsupportedPattern("unterminated regex")
    raw = rest[2:end]
    j = end + 1
    flags = ""
    while j < len(rest) and rest[j] in "imsxU":
        flags += rest[j]
        j += 1
    if j < len(rest) and not rest[j].isspace():
        raise UnsupportedPattern("unexpected text after regex flags")
    return directive, service, raw, flags, rest[j:]


def parse_p_port_hint(version_info: str):
    """Return ports from a purely numeric p/.../ version field.

    In real nmap-service-probes ``p/`` is the product description, so
    this is only a harmless hint for small/synthetic files; real
    product names (``p/Apache httpd/``) never match.
    """
    match = re.search(r"(?:^|\s)p/([0-9]+(?:,[0-9]+)*)/", version_info)
    if match is None:
        return []
    ports = []
    for piece in match.group(1).split(","):
        port = int(piece, 10)
        if 1 <= port <= 65535:
            ports.append(port)
    return ports


def _escaped_literal(ch: str, in_class: bool) -> str:
    if in_class:
        if ch in "\\]^-":
            return "\\" + ch
        return ch
    if ch in META:
        return "\\" + ch
    return ch


def _byte_text(value: int, in_class: bool, what: str) -> str:
    if value == 0:
        raise UnsupportedPattern("NUL byte in " + what)
    if value in (9, 10, 11, 12, 13):
        return "[:space:]" if in_class else "[[:space:]]"
    if value < 0x20 or value > 0x7E:
        raise UnsupportedPattern("non-printable byte in " + what)
    return _escaped_literal(chr(value), in_class)


def _read_hex_escape(raw: str, i: int):
    """Parse \\xHH or \\x{...}; i points at the 'x'. Return (value, next)."""
    if i + 1 < len(raw) and raw[i + 1] == "{":
        end = raw.find("}", i + 2)
        if end < 0:
            raise UnsupportedPattern("unterminated \\x{...}")
        digits = raw[i + 2:end]
        if not digits or any(c not in "0123456789abcdefABCDEF" for c in digits):
            raise UnsupportedPattern("bad \\x{...} escape")
        return int(digits, 16), end + 1
    if i + 2 >= len(raw):
        raise UnsupportedPattern("short \\x escape")
    digits = raw[i + 1:i + 3]
    if any(c not in "0123456789abcdefABCDEF" for c in digits):
        raise UnsupportedPattern("bad \\xNN escape")
    return int(digits, 16), i + 3


def _read_octal_escape(raw: str, i: int):
    """Parse \\0, \\012, ...; i points at '0'. Return (value, next)."""
    j = i
    digits = ""
    while j < len(raw) and len(digits) < 3 and raw[j] in "01234567":
        digits += raw[j]
        j += 1
    if not digits:
        digits = "0"
        j = i + 1
    return int(digits, 8), j


def _translate_escape(raw: str, i: int, in_class: bool):
    """Translate the escape at raw[i] == '\\'. Return (text, next index)."""
    if i + 1 >= len(raw):
        raise UnsupportedPattern("trailing backslash")
    e = raw[i + 1]
    if e == "d":
        return ("0-9" if in_class else "[0-9]"), i + 2
    if e == "D":
        if in_class:
            raise UnsupportedPattern("\\D inside a character class")
        return "[^0-9]", i + 2
    if e == "w":
        return ("A-Za-z0-9_" if in_class else "[A-Za-z0-9_]"), i + 2
    if e == "W":
        if in_class:
            raise UnsupportedPattern("\\W inside a character class")
        return "[^A-Za-z0-9_]", i + 2
    if e == "s":
        return ("[:space:]" if in_class else "[[:space:]]"), i + 2
    if e == "S":
        if in_class:
            raise UnsupportedPattern("\\S inside a character class")
        return "[^[:space:]]", i + 2
    if e in WS_ESCAPES or e == "0":
        if e == "0":
            value, nxt = _read_octal_escape(raw, i + 1)
            if value == 0:
                raise UnsupportedPattern("NUL byte")
            return _byte_text(value, in_class, "octal escape"), nxt
        return ("[:space:]" if in_class else "[[:space:]]"), i + 2
    if e == "x":
        value, nxt = _read_hex_escape(raw, i + 1)
        return _byte_text(value, in_class, "hex escape"), nxt
    if e == "A":
        if in_class:
            raise UnsupportedPattern("\\A inside a character class")
        return "^", i + 2
    if e in ("z", "Z"):
        if in_class:
            raise UnsupportedPattern("\\" + e + " inside a character class")
        return "$", i + 2
    if e == "b":
        if in_class:
            raise UnsupportedPattern("\\b inside a character class")
        return "\\b", i + 2
    if e == "B":
        if in_class:
            raise UnsupportedPattern("\\B inside a character class")
        return "\\B", i + 2
    if e.isdigit() and e != "0":
        if in_class:
            return e, i + 2
        return "\\" + e, i + 2
    if e in ("Q", "E"):
        raise UnsupportedPattern("\\Q...\\E literal spans")
    if e in ("p", "P"):
        raise UnsupportedPattern("Unicode property class")
    if e in ("G", "K", "R", "X", "C", "N", "g", "k"):
        raise UnsupportedPattern("unsupported PCRE escape \\" + e)
    if e.isalnum():
        raise UnsupportedPattern("unsupported escape \\" + e)
    return _escaped_literal(e, in_class), i + 2


def translate_pattern(raw: str, flags: str) -> str:
    """Translate an Nmap PCRE pattern to a POSIX ERE string."""
    bad_flags = set(flags) - FLAG_OK
    if bad_flags & FLAG_UNSUPPORTED:
        raise UnsupportedPattern("regex flag(s) " + "".join(sorted(bad_flags)))
    if bad_flags:
        raise UnsupportedPattern("unknown regex flag(s) " + "".join(sorted(bad_flags)))

    out = []
    i = 0
    in_class = False
    anchor_ok = True  # '^' is an anchor at the start, after '(' or '|'

    while i < len(raw):
        c = raw[i]

        if c == "\\":
            text, i = _translate_escape(raw, i, in_class)
            out.append(text)
            anchor_ok = False
            continue

        if in_class:
            if raw.startswith("[:", i):
                end = raw.find(":]", i + 2)
                if end < 0:
                    raise UnsupportedPattern("unterminated POSIX class")
                out.append(raw[i:end + 2])
                i = end + 2
                continue
            if raw.startswith("[.", i) or raw.startswith("[=", i):
                close = ".]" if raw.startswith("[.", i) else "=]"
                end = raw.find(close, i + 2)
                if end < 0:
                    raise UnsupportedPattern("unterminated collating class")
                out.append(raw[i:end + 2])
                i = end + 2
                continue
            if c == "]":
                out.append("]")
                in_class = False
                i += 1
                anchor_ok = False
                continue
            if c == "[":
                out.append("[")
                i += 1
                continue
            if ord(c) < 0x20 or ord(c) > 0x7E:
                raise UnsupportedPattern("non-printable literal in character class")
            if c in "\\":
                out.append("\\\\")
            else:
                out.append(c)
            i += 1
            anchor_ok = False
            continue

        if c == "[":
            in_class = True
            out.append("[")
            i += 1
            if i < len(raw) and raw[i] == "^":
                out.append("^")
                i += 1
            if i < len(raw) and raw[i] == "]":
                out.append("\\]")
                i += 1
            anchor_ok = False
            continue

        if c == "(":
            if raw.startswith("(?:", i) or raw.startswith("(?>", i):
                out.append("(")
                i += 3
            elif raw.startswith("(?P<", i):
                end = raw.find(">", i + 4)
                if end < 0:
                    raise UnsupportedPattern("unterminated named group")
                out.append("(")
                i = end + 1
            elif raw.startswith("(?<", i):
                if raw.startswith("(?<=", i) or raw.startswith("(?<!", i):
                    raise UnsupportedPattern("lookbehind assertion")
                end = raw.find(">", i + 3)
                if end < 0:
                    raise UnsupportedPattern("unterminated named group")
                out.append("(")
                i = end + 1
            elif raw.startswith("(?#", i):
                end = raw.find(")", i + 3)
                if end < 0:
                    raise UnsupportedPattern("unterminated comment group")
                i = end + 1
                continue
            elif raw.startswith("(?", i):
                raise UnsupportedPattern("PCRE group assertion/flag")
            else:
                out.append("(")
                i += 1
            anchor_ok = True
            continue

        if c == ")":
            out.append(")")
            i += 1
            anchor_ok = False
            continue

        if c in "*+?":
            out.append(c)
            i += 1
            # Drop lazy/possessive suffixes: POSIX ERE has only greedy.
            if i < len(raw) and raw[i] in "+?":
                i += 1
            anchor_ok = False
            continue

        if c == "{":
            end = raw.find("}", i + 1)
            if end < 0:
                out.append("\\{")
                i += 1
            else:
                body = raw[i + 1:end]
                if re.fullmatch(r"[0-9]+(?:,[0-9]*)?", body):
                    out.append("{" + body + "}")
                    i = end + 1
                    if i < len(raw) and raw[i] in "+?":
                        i += 1
                else:
                    out.append("\\{")
                    i += 1
            anchor_ok = False
            continue

        if c == "^":
            out.append("^" if anchor_ok else "\\^")
            i += 1
            anchor_ok = False
            continue

        if c == "$":
            out.append("$")
            i += 1
            anchor_ok = False
            continue

        if c in "]}":
            out.append("\\" + c)
            i += 1
            anchor_ok = False
            continue

        if c == "|":
            out.append("|")
            i += 1
            anchor_ok = True
            continue

        if c == ".":
            out.append(".")
            i += 1
            anchor_ok = False
            continue

        value = ord(c)
        if value < 0x20 or value > 0x7E:
            raise UnsupportedPattern("non-printable literal")
        out.append(c)
        i += 1
        anchor_ok = False

    if in_class:
        raise UnsupportedPattern("unterminated character class")

    pattern = "".join(out)
    if not pattern:
        raise UnsupportedPattern("empty pattern")
    # The Goose loader trims spaces at pattern boundaries; preserve them
    # with a POSIX class instead.
    if pattern.startswith(" "):
        pattern = "[[:space:]]" + pattern[1:]
    if pattern.endswith(" "):
        pattern = pattern[:-1] + "[[:space:]]"
    if len(pattern) > MAX_PATTERN:
        raise UnsupportedPattern("translated pattern exceeds 4096 bytes")
    return pattern


def literal_candidate(raw: str):
    """Return a plain literal iff the entire Nmap pattern is unanchored
    and regex-free, so EXACT substring matching is equivalent."""
    if raw.startswith("^") or raw.endswith("$"):
        return None
    out = []
    i = 0
    while i < len(raw):
        c = raw[i]
        if c == "\\":
            if i + 1 >= len(raw):
                return None
            e = raw[i + 1]
            if e == "x":
                try:
                    value, nxt = _read_hex_escape(raw, i + 1)
                except UnsupportedPattern:
                    return None
                if value < 0x20 or value > 0x7E:
                    return None
                out.append(chr(value))
                i = nxt
                continue
            if e.isalnum() or e in WS_ESCAPES:
                return None
            out.append(e)
            i += 2
            continue
        if c in META:
            return None
        if ord(c) < 0x20 or ord(c) > 0x7E:
            return None
        out.append(c)
        i += 1
    literal = "".join(out)
    if not literal or literal[0].isspace() or literal[-1].isspace():
        return None
    return literal


def valid_service(name: str) -> bool:
    if not (1 <= len(name) <= MAX_NAME):
        return False
    return all(33 <= ord(c) <= 126 and c != "|" for c in name)


def load_nmap_services(path: str):
    """Map service name -> sorted unique TCP ports."""
    mapping = {}
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split()
            if len(fields) < 2:
                continue
            name = fields[0].lower()
            proto_port = fields[1].split("/")
            if len(proto_port) != 2 or proto_port[1] != "tcp":
                continue
            try:
                port = int(proto_port[0], 10)
            except ValueError:
                continue
            if 1 <= port <= 65535:
                mapping.setdefault(name, set()).add(port)
    return {name: sorted(ports) for name, ports in mapping.items()}


def imported_entries(path, include_softmatch, services, port_override,
                     all_ports, max_sigs):
    """Build the entry list as (kind, port, pattern, service)."""
    entries = []
    stats = {
        "match_lines": 0,
        "softmatch_lines": 0,
        "skipped_pattern": 0,
        "skipped_name": 0,
        "duplicates": 0,
        "truncated": 0,
    }
    reasons = {}
    seen = set()

    def skip(reason):
        stats["skipped_pattern"] += 1
        reasons[reason] = reasons.get(reason, 0) + 1

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if not (line.startswith("match ") or line.startswith("softmatch ")):
                continue
            try:
                parsed = parse_match_line(line)
            except UnsupportedPattern as exc:
                skip(str(exc))
                continue
            if parsed is None:
                continue
            directive, service, raw, flags, version_info = parsed
            if directive == "softmatch":
                stats["softmatch_lines"] += 1
                if not include_softmatch:
                    continue
            else:
                stats["match_lines"] += 1

            if not valid_service(service):
                stats["skipped_name"] += 1
                continue

            try:
                pattern = translate_pattern(raw, flags)
            except UnsupportedPattern as exc:
                skip(str(exc))
                continue

            literal = literal_candidate(raw)
            if literal is not None and len(literal) <= MAX_PATTERN:
                kind = "EXACT"
                pattern = literal
            else:
                kind = "REGEX"

            if port_override is not None:
                ports = [port_override]
            elif services:
                mapped = services.get(service.lower(), [])
                if not mapped:
                    hint = parse_p_port_hint(version_info)
                    if hint:
                        ports = hint if all_ports else [hint[0]]
                    else:
                        ports = [-1]
                elif all_ports:
                    ports = mapped
                else:
                    ports = [mapped[0]]
            else:
                hint = parse_p_port_hint(version_info)
                if hint:
                    ports = hint if all_ports else [hint[0]]
                else:
                    ports = [-1]

            for port in ports:
                key = (kind, port, pattern, service)
                if key in seen:
                    stats["duplicates"] += 1
                    continue
                if len(entries) >= max_sigs:
                    stats["truncated"] += 1
                    continue
                seen.add(key)
                entries.append((kind, port, pattern, service))

    return entries, stats, reasons


def write_db(out, entries, source, services_path):
    out.write("# ALmap signatures.db generated by tools/import_nmap.py (Step 29).\n")
    out.write("# Source: {}\n".format(source))
    if services_path:
        out.write("# Port mapping: {}\n".format(services_path))
    else:
        out.write("# Port mapping: none (signatures use port 'any')\n")
    out.write("# Format: EXACT|port|literal|name or REGEX|port|posix_ere|name\n")
    out.write("# Signature count: {}\n".format(len(entries)))
    for kind, port, pattern, service in entries:
        port_s = "any" if port < 0 else str(port)
        out.write("{}|{}|{}|{}\n".format(kind, port_s, pattern, service))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Import an Nmap nmap-service-probes file into ALmap signatures.db")
    parser.add_argument("probes", help="path to nmap-service-probes")
    parser.add_argument("-o", "--output", default="-",
                        help="output file (default: stdout)")
    parser.add_argument("--services", default=None,
                        help="nmap-services file for name->port mapping "
                             "(default: sibling nmap-services if present)")
    parser.add_argument("--port", type=parse_port, default=None,
                        help="force this port (1..65535) or 'any'")
    parser.add_argument("--all-ports", action="store_true",
                        help="emit one line per mapped TCP port instead of the first")
    parser.add_argument("--include-softmatch", action="store_true",
                        help="also import softmatch directives")
    parser.add_argument("--max", type=int, default=MAX_SIGS,
                        help="maximum signatures to emit (1..50000, default 50000; full DB)")
    parser.add_argument("--quiet", action="store_true",
                        help="do not print the summary to stderr")
    args = parser.parse_args(argv)

    if args.max < 1 or args.max > MAX_SIGS:
        parser.error("--max must be 1..{}".format(MAX_SIGS))
    if not os.path.isfile(args.probes):
        parser.error("probe file not found: " + args.probes)

    services_path = args.services
    if services_path is None:
        sibling = os.path.join(os.path.dirname(os.path.abspath(args.probes)),
                               "nmap-services")
        if os.path.isfile(sibling):
            services_path = sibling
    services = None
    if services_path:
        if not os.path.isfile(services_path):
            parser.error("services file not found: " + services_path)
        services = load_nmap_services(services_path)

    entries, stats, reasons = imported_entries(
        args.probes, args.include_softmatch, services, args.port,
        args.all_ports, args.max)

    if not args.quiet:
        print("imported {} signature(s) from {}".format(len(entries), args.probes),
              file=sys.stderr)
        print("  match lines: {}  softmatch lines: {}{}".format(
            stats["match_lines"], stats["softmatch_lines"],
            "" if args.include_softmatch else " (skipped)"), file=sys.stderr)
        print("  skipped patterns: {}  bad names: {}  duplicates: {}".format(
            stats["skipped_pattern"], stats["skipped_name"], stats["duplicates"]),
            file=sys.stderr)
        if reasons:
            top = sorted(reasons.items(), key=lambda kv: (-kv[1], kv[0]))[:5]
            print("  top skip reasons: " + "; ".join(
                "{} x{}".format(k, v) for k, v in top), file=sys.stderr)
        if stats["truncated"]:
            print("  stopped at --max {} (more entries available)".format(args.max),
                  file=sys.stderr)

    if args.output == "-":
        write_db(sys.stdout, entries, args.probes, services_path)
    else:
        with open(args.output, "w", encoding="utf-8") as f:
            write_db(f, entries, args.probes, services_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
