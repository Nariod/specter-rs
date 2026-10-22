#!/usr/bin/env python3
"""Tests for tools/pe_blob.py and tools/check_blob.py (stdlib only).

Builds synthetic PEs in memory (valid layout, controlled content) and runs
the tools against them through their CLI, asserting both success and every
failure mode. Run with `python3 tools/test_pe_blob.py` or `make test`.
"""

import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PE_BLOB = os.path.join(HERE, "pe_blob.py")
CHECK_BLOB = os.path.join(HERE, "check_blob.py")

ENTRY = b"\x48\x83\xec\x08" + b"\xe8\x02\x00\x00\x00" + b"\x0f\x0b"  # sub;call+2;ud2
LOOP = b"\xf3\x90\xeb\xfc"                                            # pause;jmp -2
END_MAGIC = b"\xef\xbe\xad\xde\x00\x00\x00\x00"


def build_pe(text, sections=None):
    """Assemble a minimal PE with the given .text contents.

    sections: optional extra (name, raw) tuples appended after .text.
    """
    if sections is None:
        sections = []

    secs = [(".text", text)] + [(n, r) for n, r in sections]
    headers = 0x40 + 4 + 20 + 0xF0 + 40 * len(secs)
    raw_ptr = 0x200

    blob = bytearray()
    blob += b"MZ" + b"\x00" * 0x3E  # DOS header padded to 0x40 bytes
    struct.pack_into("<I", blob, 0x3C, 0x40)  # e_lfanew
    blob += b"PE\x00\x00"
    # COFF header: machine, nsec, timestamp, ptr_symtab, nsyms, optsz, chars
    blob += struct.pack("<HHIIIHH", 0x8664, len(secs), 0, 0, 0, 0xF0, 0x0102)
    # Optional header PE32+ (zeros are fine for the parser)
    blob += struct.pack("<H", 0x20B) + b"\x00" * (0xF0 - 2)

    offset = raw_ptr
    for name, raw in secs:
        # PE section header: Name(8) VirtualSize(4) VirtualAddress(4)
        # SizeOfRawData(4) PointerToRawData(4) PointerToRelocations(4)
        # PointerToLinenumbers(4) NumberOfRelocations(2) NumberOfLinenumbers(2)
        # Characteristics(4) = 40 bytes.
        blob += name.encode().ljust(8, b"\x00")[:8]
        blob += struct.pack("<IIII", len(raw), 0x1000, len(raw), offset)
        blob += struct.pack("<II", 0, 0)   # reloc ptr, linenum ptr
        blob += struct.pack("<HH", 0, 0)  # reloc count, linenum count
        blob += struct.pack("<I", 0)      # characteristics
        offset += len(raw)

    blob += b"\x00" * (raw_ptr - len(blob))
    for _, raw in secs:
        blob += raw
    return bytes(blob)


def valid_text():
    return ENTRY + LOOP + END_MAGIC


class PeBlobTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def run_tool(self, pe_bytes, expect_ok, tool=PE_BLOB, extra=None):
        exe = os.path.join(self.tmp.name, "beacon.exe")
        blob = os.path.join(self.tmp.name, "beacon.bin")
        with open(exe, "wb") as f:
            f.write(pe_bytes)
        cmd = [sys.executable, tool, exe, blob] if tool == PE_BLOB \
            else [sys.executable, tool, blob] + (extra or [])
        r = subprocess.run(cmd, capture_output=True, text=True)
        if expect_ok:
            self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        else:
            self.assertNotEqual(r.returncode, 0,
                                "tool unexpectedly succeeded:\n" + r.stdout)
        return r.stdout

    def test_valid_blob(self):
        text = valid_text()
        out = self.run_tool(build_pe(text), True)
        self.assertIn("[+] blob:", out)
        with open(os.path.join(self.tmp.name, "beacon.bin"), "rb") as f:
            self.assertEqual(f.read(), text)

    def test_main_target_reported(self):
        # spt_main sits 2 bytes past the end of the call (offset 0xb).
        out = self.run_tool(build_pe(valid_text()), True)
        self.assertIn("spt_main at 0xb", out)

    def test_missing_marker(self):
        text = ENTRY + LOOP
        self.run_tool(build_pe(text), False)

    def test_marker_not_last(self):
        text = ENTRY + LOOP + END_MAGIC + b"\x90"
        self.run_tool(build_pe(text), False)

    def test_bad_prologue(self):
        text = b"\x41" + valid_text()[1:]  # clobber the first byte
        self.run_tool(build_pe(text), False)

    def test_missing_ud2(self):
        text = ENTRY[:9] + b"\x90\x0b" + LOOP + END_MAGIC
        self.run_tool(build_pe(text), False)

    def test_call_target_outside_blob(self):
        # rel32 = 0x7fffffff: call target far past the end of the blob.
        text = b"\x48\x83\xec\x08\xe8\xff\xff\xff\x7f\x0f\x0b" + LOOP + END_MAGIC
        self.run_tool(build_pe(text), False)

    def test_unexpected_section(self):
        out = self.run_tool(build_pe(valid_text(), sections=[(".data", b"XX")]), False)
        self.assertIn(".data", out)

    def test_not_a_pe(self):
        self.run_tool(b"\x00" * 0x200, False)


class CheckBlobTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write_blob(self, data):
        path = os.path.join(self.tmp.name, "blob.bin")
        with open(path, "wb") as f:
            f.write(data)
        return path

    def write_manifest(self, strings):
        path = os.path.join(self.tmp.name, "manifest.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(strings, f)
        return path

    def run_check(self, data, expect_ok, extra=None):
        path = self.write_blob(data)
        cmd = [sys.executable, CHECK_BLOB, path] + (extra or [])
        r = subprocess.run(cmd, capture_output=True, text=True)
        if expect_ok:
            self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        else:
            self.assertNotEqual(r.returncode, 0,
                                "check unexpectedly passed:\n" + r.stdout)
        return r.stdout

    def test_clean_blob_passes(self):
        self.run_check(ENTRY + LOOP + END_MAGIC, True)

    LEAK = b"undeclared secret material"   # 26 bytes: over the fail threshold
    DECLARED = b"declared config payload"  # 23 bytes: over the fail threshold

    def test_string_without_manifest_fails(self):
        data = ENTRY + LOOP + END_MAGIC
        data = data[:-1] + self.LEAK
        out = self.run_check(data, False)
        self.assertIn("undeclared", out)

    def test_declared_string_passes(self):
        data = ENTRY + LOOP + END_MAGIC
        data = data[:-1] + self.DECLARED
        manifest = self.write_manifest([self.DECLARED.decode()])
        self.run_check(data, True, ["--manifest", manifest])

    def test_substring_of_declared_string_passes(self):
        # Code or rodata layout may expose a run shorter than the constant.
        data = ENTRY + LOOP + END_MAGIC
        data = data[:-1] + b"clared config payload"  # 21 bytes, substring of DECLARED
        manifest = self.write_manifest([self.DECLARED.decode()])
        self.run_check(data, True, ["--manifest", manifest])

    def test_short_printable_run_passes(self):
        # Runs under the fail threshold (12) are review-only: executable code
        # naturally contains printable byte runs like "AWAVVWSH".
        data = ENTRY + LOOP + END_MAGIC
        data = data[:-1] + b"AWAVVWSH"  # 8 printable bytes of code-like bytes
        out = self.run_check(data, True)
        self.assertIn("review only", out)

    def test_concatenated_declared_strings_pass(self):
        # Adjacent rdata constants concatenate in the single .text section:
        # a run of several declared strings glued by short segments must
        # pass (the beacon's hosts+uris layout produces exactly this).
        data = ENTRY + LOOP + END_MAGIC
        run = self.DECLARED + b": " + self.DECLARED
        data = data[:-1] + run
        manifest = self.write_manifest([self.DECLARED.decode()])
        self.run_check(data, True, ["--manifest", manifest])

    def test_concatenation_with_long_undeclared_glue_fails(self):
        data = ENTRY + LOOP + END_MAGIC
        run = self.DECLARED + self.LEAK  # 26 bytes of undeclared glue
        data = data[:-1] + run
        manifest = self.write_manifest([self.DECLARED.decode()])
        self.run_check(data, False, ["--manifest", manifest])

    def test_missing_manifest_fails(self):
        data = ENTRY + LOOP + END_MAGIC
        data = data[:-1] + self.LEAK
        self.run_check(data, False, ["--manifest", "/nonexistent/manifest.json"])

    def test_invalid_manifest_fails(self):
        path = os.path.join(self.tmp.name, "manifest.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write("not a json list")
        self.run_check(ENTRY + LOOP + END_MAGIC, False, ["--manifest", path])

    def test_size_budget_fails(self):
        data = b"\x00" * 8192
        out = self.run_check(data, False, ["--max-size", "4096"])
        self.assertIn("budget", out)

    def test_size_budget_override_passes(self):
        self.run_check(b"\x00" * 40, True, ["--max-size", "50"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
