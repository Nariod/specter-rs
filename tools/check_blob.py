#!/usr/bin/env python3
"""Specter-rs blob guardrails.

Enforces the invariants that keep the beacon true to the project's
philosophy (docs/ETUDE-DE-FAISABILITE.md, section 1):

1. No text strings: the blob must contain no ASCII run of 5+ printable
   bytes. Strings mean leaked panic messages, paths, or identifiers —
   in a raw blob they are signatures for defenders.
2. Size budget: the blob must stay under the budget (raise it
   deliberately, in its own commit, never as a side effect).

Run by `make check` and by CI on every push.
"""

import argparse
import sys

# 5+ printable bytes qualify as a string; 4 or fewer can occur in code.
MIN_RUN = 5
PRINTABLE = range(0x20, 0x7F)
DEFAULT_MAX_SIZE = 4096


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("blob")
    ap.add_argument("--max-size", type=int, default=DEFAULT_MAX_SIZE)
    args = ap.parse_args()
    blob = open(args.blob, "rb").read()

    ok = True

    strings = find_strings(blob)
    if strings:
        ok = False
        print(f"[-] {len(strings)} text string(s) in the blob:")
        for off, s in strings[:10]:
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
