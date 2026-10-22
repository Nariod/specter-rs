#!/usr/bin/env python3
"""Specter-rs blob pipeline: PE inspection and .text extraction.

The beacon is linked by rust-lld (flavor lld-link) into a minimal PE where
everything is merged into a single .text section. This tool:

1. parses the PE and its COFF symbol table,
2. verifies the single-section layout (phase-0 invariant),
3. locates SptEntry (must be at offset 0 of .text) and SPT_END (must be
   the last byte of .text),
4. extracts the raw .text contents as the position-independent blob.

Port of specter's objcopy -O binary -j .text step (tools/gen_blob.py era).
"""

import struct
import sys

DOS_MAGIC = 0x5A4D
PE_MAGIC = 0x00004550

# Byte patterns used for verification: the final link keeps no COFF symbol
# table, so the blob is checked against the expected entry prologue and the
# end-of-beacon magic instead of symbol offsets.
# Entry stub layout (11 bytes):
#   +0  48 83 ec 08      sub rsp, 8
#   +4  e8 <rel32>        call spt_main
#   +9  0f 0b             ud2
ENTRY_PROLOGUE = b"\x48\x83\xec\x08\xe8"   # sub rsp,8 ; call rel32
ENTRY_EPILOGUE = b"\x0f\x0b"                # ud2 (at offset 9)
ENTRY_SIZE = 11
# 0xDEADBEEF little-endian + four zeros: non-ASCII by design (see entry.rs).
END_MAGIC = b"\xef\xbe\xad\xde\x00\x00\x00\x00"


def fail(msg):
    print(f"[-] {msg}", file=sys.stderr)
    sys.exit(1)


def parse_pe(data):
    if len(data) < 0x40 or struct.unpack_from("<H", data, 0)[0] != DOS_MAGIC:
        fail("not a PE file (no DOS header)")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if struct.unpack_from("<I", data, e_lfanew)[0] != PE_MAGIC:
        fail("not a PE file (bad PE signature)")

    coff_off = e_lfanew + 4
    machine, num_sections, _, ptr_symtab, num_syms, opt_size, _ = (
        struct.unpack_from("<HHIIIHH", data, coff_off)
    )  # Machine, NumberOfSections, TimeDateStamp, PtrSymtab, NumSyms, OptSize, Chars
    if machine != 0x8664:
        fail(f"unexpected machine 0x{machine:x} (want x86-64: 0x8664)")

    sections = []
    sec_off = coff_off + 20 + opt_size
    for i in range(num_sections):
        off = sec_off + i * 40
        name = data[off : off + 8].rstrip(b"\x00").decode("ascii", "replace")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, off + 8)
        sections.append(
            {"name": name, "vsize": vsize, "vaddr": vaddr,
             "rawsize": rawsize, "rawptr": rawptr}
        )

    symbols = []
    sym_off = ptr_symtab
    i = 0
    while i < num_syms:
        off = sym_off + i * 18
        raw_name = data[off : off + 8]
        if raw_name[:4] == b"\x00\x00\x00\x00":
            name_off = struct.unpack_from("<I", data, off)[0]
            name = read_string_table_entry(data, ptr_symtab, num_syms, name_off)
        else:
            name = raw_name.rstrip(b"\x00").decode("ascii", "replace")
        value, sec_num, _, storage_class = struct.unpack_from("<IBHB", data, off + 8)
        aux_count = data[off + 17]
        symbols.append({"name": name, "value": value, "sec": sec_num,
                        "class": storage_class})
        i += 1 + aux_count

    return sections, symbols


def read_string_table_entry(data, ptr_symtab, num_syms, name_off):
    # COFF string table starts right after the symbol table.
    strtab_off = ptr_symtab + num_syms * 18
    strtab_len = struct.unpack_from("<I", data, strtab_off)[0]
    start = strtab_off + name_off
    end = data.index(b"\x00", start)
    return data[start:end].decode("ascii", "replace")


def find_symbol(symbols, name):
    for s in symbols:
        if s["name"] == name and s["class"] == 2:  # IMAGE_SYM_CLASS_EXTERNAL
            return s
    return None


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <linked.exe> <blob.bin>", file=sys.stderr)
        sys.exit(1)
    exe_path, blob_path = sys.argv[1], sys.argv[2]
    data = open(exe_path, "rb").read()
    sections, symbols = parse_pe(data)

    print("[*] sections:")
    for s in sections:
        print(f"    {s['name']:<10} vsize={s['vsize']:#8x} vaddr={s['vaddr']:#8x} rawsize={s['rawsize']:#8x}")

    text = None
    for s in sections:
        if s["name"] == ".text":
            text = s
        elif s["name"] not in (".pdata", ".reloc"):
            fail(f"unexpected section {s['name']}")
    if text is None:
        fail("no .text section")

    blob = data[text["rawptr"] : text["rawptr"] + text["rawsize"]]
    blob = blob[: text["vsize"]]  # drop alignment padding

    ok = True
    # Entry stub must open the blob: sub rsp,8 ; call rel32 ; ud2.
    if not blob.startswith(ENTRY_PROLOGUE):
        print("[-] blob does not start with the SptEntry prologue")
        ok = False
    if blob[ENTRY_SIZE - 2 : ENTRY_SIZE] != ENTRY_EPILOGUE:
        print("[-] ud2 not found right after the entry call")
        ok = False
    # spt_main target of the entry call, for the build report.
    if ok:
        rel = struct.unpack_from("<i", blob, 5)[0]
        main_off = ENTRY_SIZE - 2 + rel
        if not (0 < main_off < len(blob)):
            print(f"[-] entry call target 0x{main_off:x} outside the blob")
            ok = False
    # End-of-beacon marker must close the blob.
    if not blob.endswith(END_MAGIC):
        print("[-] blob does not end with the .sptend magic marker")
        ok = False
    if not ok:
        sys.exit(1)

    with open(blob_path, "wb") as f:
        f.write(blob)
    print(f"[+] blob: {blob_path} ({len(blob)} bytes)")
    print(f"[+] SptEntry prologue at 0, spt_main at 0x{main_off:x}, SPT_END magic last 8 bytes")


if __name__ == "__main__":
    main()
