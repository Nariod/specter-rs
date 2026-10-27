//! COFF object parsing for BOF (Beacon Object File) execution — the pure
//! half of the loader (docs/ETUDE-DE-FAISABILITE.md: this is untrusted-input
//! parsing the C original does by hand, in a process where a segfault costs
//! the beacon; here it is bounded and typed, host-tested).
//!
//! Only what x64 MSVC object files need: header, sections, symbols with the
//! auxiliary-record walk, the string table, and relocations. Everything is
//! validated against the slice bounds before the beacon loader touches a
//! pointer. The native beacon limits objects to 512 symbols
//! (`BOF_ERROR_MAX_FUNCS`), kept as the wire contract.

/// x64 machine type (IMAGE_FILE_MACHINE_AMD64).
pub const MACHINE_X64: u16 = 0x8664;
/// Native cap: "The number of functions in the BOF file exceeds 512".
pub const MAX_SYMBOLS: usize = 512;

/// Relocation types of x64 object code (IMAGE_REL_AMD64_*). The loader
/// (beacon crate) patches ADDR64, ADDR32NB and REL32..REL32_5 additively,
/// exactly like the original runner.c; ADDR32 has no case there either.
pub const REL_ADDR64: u16 = 1; // *(u64)P += S
pub const REL_ADDR32: u16 = 2; // accepted, never patched (native parity)
pub const REL_ADDR32NB: u16 = 3; // *(u32)P += S - image_base (.pdata/.xdata)
pub const REL_REL32: u16 = 4; // *(i32)P += S - P - 4
/// REL32 + k for k in 1..=5 (types 5..=9): the addend grows to P + 4 + k.
pub const REL_REL32_5: u16 = 9;
/// Every relocation type the parser accepts (native runner.c switch).
pub const REL_TYPE_MAX: u16 = REL_REL32_5;

/// One COFF section header (the 40-byte on-disk form).
#[derive(Debug, Clone, Copy)]
pub struct Section {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_ptr: u32,
    pub reloc_ptr: u32,
    pub num_relocs: u16,
    pub characteristics: u32,
}

impl Section {
    pub fn executable(&self) -> bool {
        self.characteristics & 0x2000_0000 != 0 // IMAGE_SCN_MEM_EXECUTE
    }
    /// The section raw bytes (empty for BSS-style sections).
    pub fn raw<'a>(&self, blob: &'a [u8]) -> &'a [u8] {
        let start = self.raw_ptr as usize;
        let end = start.saturating_add(self.raw_size as usize);
        if start >= blob.len() || end > blob.len() {
            return &[];
        }
        &blob[start..end]
    }
}

/// One symbol-table entry (18 bytes on disk; the parser reads entries
/// individually and walks over auxiliary records with `aux`).
#[derive(Debug, Clone, Copy)]
pub struct Symbol {
    /// Raw name: inline bytes or an offset into the string table.
    pub name: [u8; 8],
    pub value: u32,
    /// 1-based section index; 0 = import (undefined), -1..-2 special.
    pub secnum: i16,
    /// IMAGE_SYM_CLASS: 2 = external, 3 = static (section symbols).
    pub class: u8,
    /// Number of auxiliary records that follow this entry.
    pub aux: u8,
}

impl Symbol {
    pub fn is_external(&self) -> bool {
        self.class == 2
    }
    pub fn is_import(&self) -> bool {
        self.class == 2 && self.secnum == 0
    }
}

/// A parsed x64 COFF object: a borrowed, allocation-free view. Structures are
/// read on demand (`section(i)`, `symbol(i)`, `reloc(...)`) so the loader
/// never needs a heap or a large stack frame.
#[derive(Clone, Copy)]
pub struct Coff<'a> {
    blob: &'a [u8],
    num_sections: usize,
    sym_ptr: usize,
    num_symbols: usize,
    strings: &'a [u8],
}

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

impl<'a> Coff<'a> {
    /// Parse and validate. `None` on any structural problem — the caller
    /// reports `BOF_ERROR_PARSE`.
    pub fn parse(blob: &'a [u8]) -> Option<Self> {
        if blob.len() < 20 {
            return None;
        }
        let machine = u16_at(blob, 0)?;
        if machine != MACHINE_X64 {
            return None;
        }
        let num_sections = u16_at(blob, 2)? as usize;
        let sym_ptr = u32_at(blob, 8)? as usize;
        let num_symbols = u32_at(blob, 12)? as usize;
        if num_symbols > MAX_SYMBOLS {
            return None; // BOF_ERROR_MAX_FUNCS
        }
        if num_sections > 96 {
            return None;
        }
        // Every section header must be in bounds.
        if 20 + num_sections * 40 > blob.len() {
            return None;
        }

        let strings = {
            let start = sym_ptr.saturating_add(num_symbols * 18);
            if start >= blob.len() {
                // Zero symbols: the string table may legitimately be absent.
                if num_symbols == 0 {
                    &[]
                } else {
                    return None;
                }
            } else {
                blob.get(start..)?
            }
        };

        Some(Coff {
            blob,
            num_sections,
            sym_ptr,
            num_symbols,
            strings,
        })
    }

    pub fn num_sections(&self) -> usize {
        self.num_sections
    }

    pub fn num_symbols(&self) -> usize {
        self.num_symbols
    }

    /// Read section header `index` (0-based).
    pub fn section(&self, index: usize) -> Option<Section> {
        if index >= self.num_sections {
            return None;
        }
        let off = 20 + index * 40;
        let s = self.blob.get(off..off + 40)?;
        let mut name = [0u8; 8];
        name.copy_from_slice(&s[0..8]);
        Some(Section {
            name,
            virtual_size: u32_from(&s[8..12]),
            virtual_address: u32_from(&s[12..16]),
            raw_size: u32_from(&s[16..20]),
            raw_ptr: u32_from(&s[20..24]),
            reloc_ptr: u32_from(&s[24..28]),
            num_relocs: u16_from([s[32], s[33]]),
            characteristics: u32_from(&s[36..40]),
        })
    }

    /// Read raw symbol-table entry `index` (0-based; aux records included —
    /// relocation indices address the raw table).
    pub fn symbol(&self, index: usize) -> Option<Symbol> {
        if index >= self.num_symbols {
            return None;
        }
        let off = self.sym_ptr.saturating_add(index * 18);
        let s = self.blob.get(off..off + 18)?;
        let mut name = [0u8; 8];
        name.copy_from_slice(&s[0..8]);
        Some(Symbol {
            name,
            value: u32_from(&s[8..12]),
            secnum: i16::from_le_bytes([s[12], s[13]]),
            class: s[16],
            aux: s[17],
        })
    }

    /// The symbol name (inline short name or string-table reference).
    pub fn symbol_name(&self, index: usize) -> &'a [u8] {
        let Some(sym) = self.symbol(index) else {
            return &[];
        };
        let blob = self.blob;
        // Zero-prefixed names are offsets into the string table.
        if sym.name[0] == 0 && sym.name[1] == 0 && sym.name[2] == 0 && sym.name[3] == 0 {
            let off =
                u32::from_le_bytes([sym.name[4], sym.name[5], sym.name[6], sym.name[7]]) as usize;
            let strings = self.strings;
            let bytes = strings.get(off..).unwrap_or(&[]);
            let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
            &bytes[..end]
        } else {
            let end = sym
                .name
                .iter()
                .position(|b| *b == 0)
                .unwrap_or(sym.name.len());
            let off = self.sym_ptr.saturating_add(index * 18);
            match blob.get(off..off + end) {
                Some(s) => s,
                None => &[],
            }
        }
    }

    /// Find a defined external symbol by name (the entry point lookup).
    /// Returns the raw symbol index and its value.
    pub fn find_entry(&self, name: &[u8]) -> Option<(usize, u32)> {
        let mut i = 0usize;
        while i < self.num_symbols {
            let sym = self.symbol(i)?;
            let step = 1 + sym.aux as usize; // skip auxiliary records
            if sym.is_external() && sym.secnum > 0 && self.symbol_name(i) == name {
                return Some((i, sym.value));
            }
            i += step;
        }
        None
    }

    /// Relocation `i` of `section` as (site offset, type, symbol index).
    /// Each entry is 10 bytes: rva u32 + symbol index u32 + type u16.
    /// `None` on truncation, an unsupported type, or an out-of-range symbol.
    pub fn reloc(&self, section: &Section, i: usize) -> Option<(u32, u16, u32)> {
        if i >= section.num_relocs as usize {
            return None;
        }
        let off = section.reloc_ptr as usize + i * 10;
        let r = self.blob.get(off..off + 10)?;
        let site = u32::from_le_bytes([r[0], r[1], r[2], r[3]]);
        let sym = u32::from_le_bytes([r[4], r[5], r[6], r[7]]);
        let typ = u16::from_le_bytes([r[8], r[9]]);
        if typ == 0 || typ > REL_TYPE_MAX {
            return None; // unsupported relocation type
        }
        if sym as usize >= self.num_symbols {
            return None;
        }
        Some((site, typ, sym))
    }

    /// The image size: the highest section end, page-ish aligned by the
    /// caller.
    pub fn image_size(&self) -> usize {
        let mut end = 0usize;
        let mut i = 0usize;
        while i < self.num_sections {
            if let Some(s) = self.section(i) {
                let s_end = s.virtual_address as usize + s.virtual_size.max(s.raw_size) as usize;
                if s_end > end {
                    end = s_end;
                }
            }
            i += 1;
        }
        end
    }
}

fn u32_from(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn u16_from(b: [u8; 2]) -> u16 {
    u16::from_le_bytes(b)
}

// ---------------------------------------------------------------------------
// Beacon data API: the argument blob BOFs unpack through BeaconDataParse /
// BeaconDataInt / ... (the CS-compatible layout: int32 LE, short int16 LE,
// string/binary = int32 LE length + bytes).
// ---------------------------------------------------------------------------

/// The parser state the BOF owns (`datap` of beacon.h: four fields, the
/// exact layout BOFs allocate on their own stacks).
#[repr(C)]
pub struct Datum {
    pub original: *mut u8,
    pub buffer: *mut u8,
    pub length: i32,
    pub size: i32,
}

/// BeaconDataParse (compat.c): skip the 4-byte argument count that heads
/// the params blob, then hand the rest to the datum walkers. A blob too
/// small for the count keeps a zeroed parser (native parity).
///
/// # Safety
///
/// `buf` must point to `len` readable bytes.
pub unsafe fn datum_parse(d: &mut Datum, buf: *mut u8, len: i32) {
    if len >= 4 {
        d.original = buf.add(4);
        d.buffer = buf.add(4);
        d.length = len - 4;
        d.size = len - 4;
    } else {
        d.original = buf;
        d.buffer = buf;
        d.length = 0;
        d.size = 0;
    }
}

/// Consume an int32 LE from the datum (BeaconDataInt). `None` = exhausted.
///
/// # Safety
///
/// `buffer` must point to `length` readable bytes.
pub unsafe fn datum_int(d: &mut Datum) -> Option<i32> {
    if d.length < 4 {
        return None;
    }
    let b = d.buffer;
    let v = i32::from_le_bytes([*b, *b.add(1), *b.add(2), *b.add(3)]);
    d.buffer = b.add(4);
    d.length -= 4;
    Some(v)
}

/// Consume a short int16 LE (BeaconDataShort).
///
/// # Safety
///
/// `buffer` must point to `length` readable bytes.
pub unsafe fn datum_short(d: &mut Datum) -> Option<i16> {
    if d.length < 2 {
        return None;
    }
    let b = d.buffer;
    let v = i16::from_le_bytes([*b, *b.add(1)]);
    d.buffer = b.add(2);
    d.length -= 2;
    Some(v)
}

/// Consume a length-prefixed byte run (BeaconDataString / BeaconDataExtract):
/// returns (pointer, length) without copying.
///
/// # Safety
///
/// `buffer` must point to `length` readable bytes; the returned slice borrows
/// the same memory.
pub unsafe fn datum_bytes(d: &mut Datum) -> Option<(*const u8, i32)> {
    let len = datum_int(d)?;
    if len < 0 || d.length < len {
        return None;
    }
    let p = d.buffer;
    d.buffer = p.add(len as usize);
    d.length -= len;
    Some((p, len))
}

// ---------------------------------------------------------------------------
// BOF output formatting: the %s/%d/%u/%x/%c/%p subset BeaconPrintf supports,
// pulling 8-byte vararg slots (the win64 integer stream the naked trampoline
// saved). Floats are not supported (BOFs printing %f are vanishingly rare;
// the trampoline ignores XMM).
// ---------------------------------------------------------------------------

/// The vararg stream the trampoline saved: `slots[i]` is the i-th vararg
/// (an integer or a pointer, always widened to u64).
pub struct Varargs {
    pub slots: [u64; 16],
    pub count: usize,
}

/// Render `fmt` with `args` into `out` (bounded — truncation, never panic).
/// Returns false when a conversion runs out of slots (the rest is skipped).
pub fn bof_format(out: &mut [u8], written: &mut usize, fmt: &[u8], args: &Varargs) -> bool {
    let mut slot = 0usize;
    let mut i = 0usize;
    let mut ok = true;
    while i < fmt.len() {
        let c = fmt[i];
        if c != b'%' {
            push_byte(out, written, c);
            i += 1;
            continue;
        }
        i += 1;
        if i >= fmt.len() {
            break;
        }
        if fmt[i] == b'%' {
            push_byte(out, written, b'%');
            i += 1;
            continue;
        }
        // flags: '-' (ignored — left-align is not needed by BOF output), '0'
        let mut pad_zero = false;
        while i < fmt.len() && (fmt[i] == b'-' || fmt[i] == b'0') {
            if fmt[i] == b'0' {
                pad_zero = true;
            }
            i += 1;
        }
        // width (digits only)
        let mut width = 0usize;
        while i < fmt.len() && fmt[i].is_ascii_digit() {
            width = width
                .saturating_mul(10)
                .saturating_add((fmt[i] - b'0') as usize);
            i += 1;
        }
        // length modifiers ('l', 'h', 'z'): skipped — every win64 vararg slot
        // is 8 bytes wide, so %d/%u/%x/%s read the same slot either way.
        while i < fmt.len() && (fmt[i] == b'l' || fmt[i] == b'h' || fmt[i] == b'z') {
            i += 1;
        }
        if i >= fmt.len() {
            break;
        }
        let conv = fmt[i];
        i += 1;
        if slot >= args.count {
            ok = false;
            break; // out of varargs: stop
        }
        let v = args.slots[slot];
        slot += 1;
        match conv {
            b's' => {
                // pointer to a NUL-terminated string
                let mut p = v as usize;
                let mut n = 0usize;
                while n < 1024 {
                    let ch = unsafe { *(p as *const u8) };
                    if ch == 0 {
                        break;
                    }
                    push_byte(out, written, ch);
                    p += 1;
                    n += 1;
                }
            }
            b'c' => push_byte(out, written, v as u8),
            b'd' | b'i' => {
                let val = v as i64;
                push_signed(out, written, val, 10, width, pad_zero);
            }
            b'u' => {
                push_unsigned(out, written, v, 10, width, pad_zero);
            }
            b'x' => {
                push_unsigned(out, written, v, 16, width, pad_zero);
            }
            b'X' => {
                push_upper_hex(out, written, v, width, pad_zero);
            }
            b'p' => {
                push_str(out, written, b"0x");
                push_unsigned(out, written, v, 16, 0, false);
            }
            _ => {
                // Unknown conversion: emit it verbatim.
                push_byte(out, written, b'%');
                push_byte(out, written, conv);
            }
        }
    }
    ok
}

fn push_byte(out: &mut [u8], written: &mut usize, b: u8) {
    if *written < out.len() {
        out[*written] = b;
        *written += 1;
    }
}

fn push_str(out: &mut [u8], written: &mut usize, s: &[u8]) {
    let mut i = 0;
    while i < s.len() {
        push_byte(out, written, s[i]);
        i += 1;
    }
}

fn push_signed(out: &mut [u8], written: &mut usize, v: i64, base: u32, width: usize, zero: bool) {
    if v < 0 {
        push_byte(out, written, b'-');
        push_unsigned(out, written, (v as u64).wrapping_neg(), base, width, zero);
    } else {
        push_unsigned(out, written, v as u64, base, width, zero);
    }
}

fn push_upper_hex(out: &mut [u8], written: &mut usize, v: u64, width: usize, zero: bool) {
    let mut digits = [0u8; 20];
    let mut n = 0usize;
    let mut val = v;
    loop {
        digits[n] = match (val % 16) as u8 {
            d @ 0..=9 => b'0' + d,
            d => b'A' + d - 10,
        };
        val /= 16;
        n += 1;
        if val == 0 {
            break;
        }
    }
    pad(out, written, n, width, zero);
    while n > 0 {
        n -= 1;
        push_byte(out, written, digits[n]);
    }
}

fn push_unsigned(out: &mut [u8], written: &mut usize, v: u64, base: u32, width: usize, zero: bool) {
    let mut digits = [0u8; 24];
    let mut n = 0usize;
    let mut val = v;
    if val == 0 {
        digits[0] = b'0';
        n = 1;
    }
    while val != 0 {
        let d = (val % base as u64) as u8;
        digits[n] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
        val /= base as u64;
        n += 1;
    }
    pad(out, written, n, width, zero);
    while n > 0 {
        n -= 1;
        push_byte(out, written, digits[n]);
    }
}

fn pad(out: &mut [u8], written: &mut usize, digits: usize, width: usize, zero: bool) {
    let mut fill = width.saturating_sub(digits);
    while fill > 0 {
        push_byte(out, written, if zero { b'0' } else { b' ' });
        fill -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A synthetic x64 COFF, byte-for-byte, the way test_pe_blob.py builds
    // payloads: header, one executable section, its raw data, two
    // relocations, a symbol table with an auxiliary record and a
    // string-table name, then the string table.
    fn synth_coff() -> std::vec::Vec<u8> {
        let mut b = std::vec::Vec::new();
        let p16 = |b: &mut std::vec::Vec<u8>, v: u16| b.extend_from_slice(&v.to_le_bytes());
        let p32 = |b: &mut std::vec::Vec<u8>, v: u32| b.extend_from_slice(&v.to_le_bytes());

        // COFF header (20 bytes).
        p16(&mut b, MACHINE_X64);
        p16(&mut b, 1); // one section
        p32(&mut b, 0); // timestamp
        p32(&mut b, 112); // symbol table pointer (patched below)
        p32(&mut b, 4); // symbols: section, aux, import, go
        p16(&mut b, 0); // no optional header
        p16(&mut b, 0); // characteristics

        // Section header (40 bytes): .text, 0x20 bytes at file offset 60.
        b.extend_from_slice(b".text\0\0\0");
        p32(&mut b, 0x20); // virtual size
        p32(&mut b, 0); // virtual address
        p32(&mut b, 0x20); // raw size
        p32(&mut b, 60); // raw pointer
        p32(&mut b, 92); // relocation pointer
        p32(&mut b, 0); // line numbers
        p16(&mut b, 2); // two relocations
        p16(&mut b, 0); // no line numbers
        p32(&mut b, 0x2000_0020); // EXECUTE | CNT_CODE

        // Raw section data (60..92).
        b.extend_from_slice(&[0xCC; 0x20]);

        // Relocations (92..112), 10 bytes each.
        p32(&mut b, 0); // site 0
        p32(&mut b, 2); // symbol 2 (the import)
        p16(&mut b, REL_ADDR64);
        p32(&mut b, 8); // site 8
        p32(&mut b, 3); // symbol 3 (go)
        p16(&mut b, REL_REL32);

        // Symbol table (112..): entry, aux, import, entry point.
        b.extend_from_slice(b".text\0\0\0"); // section symbol
        p32(&mut b, 0);
        p16(&mut b, 1); // section 1
        p16(&mut b, 0); // type
        b.push(3); // IMAGE_SYM_CLASS_STATIC
        b.push(1); // one auxiliary record
        b.extend_from_slice(&[0u8; 18]); // the auxiliary record
                                         // Import with a string-table name (offset 4, table starts with size).
        b.extend_from_slice(&[0, 0, 0, 0]); // zero prefix: string-table offset
        p32(&mut b, 4); // offset: "BeaconDataParse" is at table start
        p32(&mut b, 0);
        p16(&mut b, 0); // section 0: undefined, an import
        p16(&mut b, 0);
        b.push(2); // IMAGE_SYM_CLASS_EXTERNAL
        b.push(0);
        b.extend_from_slice(b"go\0\0\0\0\0\0"); // defined entry point
        p32(&mut b, 0); // value
        p16(&mut b, 1); // section 1
        p16(&mut b, 0);
        b.push(2); // external
        b.push(0);
        assert_eq!(b.len(), 112 + 4 * 18);

        // String table: u32 total size, then names.
        let st = b"BeaconDataParse\0";
        p32(&mut b, (4 + st.len()) as u32);
        b.extend_from_slice(st);
        b
    }

    #[test]
    fn parse_accepts_synthetic_x64() {
        let blob = synth_coff();
        let coff = Coff::parse(&blob).expect("synthetic COFF must parse");
        assert_eq!(coff.num_sections(), 1);
        assert_eq!(coff.num_symbols(), 4);
        assert_eq!(coff.image_size(), 0x20);
    }

    #[test]
    fn parse_rejects_wrong_machine_and_overflow() {
        let mut blob = synth_coff();
        blob[0] = 0x4C; // IMAGE_FILE_MACHINE_I386 (LE low byte)
        blob[1] = 0x01;
        assert!(Coff::parse(&blob).is_none());

        let mut blob = synth_coff();
        blob[12..16].copy_from_slice(&513u32.to_le_bytes()); // too many symbols
        assert!(Coff::parse(&blob).is_none());

        let blob = synth_coff();
        assert!(Coff::parse(&blob[..30]).is_none()); // truncated
        assert!(Coff::parse(&[]).is_none());
    }

    #[test]
    fn sections_read_on_demand() {
        let blob = synth_coff();
        let coff = Coff::parse(&blob).expect("parse");
        let text = coff.section(0).expect("section 0");
        assert_eq!(&text.name[..5], b".text");
        assert!(text.executable());
        assert_eq!(text.num_relocs, 2);
        assert_eq!(text.raw(&blob).len(), 0x20);
        assert!(coff.section(1).is_none());
    }

    #[test]
    fn symbols_aux_walk_and_names() {
        let blob = synth_coff();
        let coff = Coff::parse(&blob).expect("parse");
        let sec_sym = coff.symbol(0).expect("symbol 0");
        assert_eq!(sec_sym.class, 3);
        assert_eq!(sec_sym.aux, 1);
        let import = coff.symbol(2).expect("symbol 2");
        assert!(import.is_import());
        assert_eq!(coff.symbol_name(2), b"BeaconDataParse"); // from string table
        assert_eq!(coff.symbol_name(3), b"go"); // inline name
        assert!(coff.symbol(4).is_none());
    }

    #[test]
    fn find_entry_skips_aux_and_ignores_imports() {
        let blob = synth_coff();
        let coff = Coff::parse(&blob).expect("parse");
        let (idx, value) = coff.find_entry(b"go").expect("entry found");
        assert_eq!(idx, 3);
        assert_eq!(value, 0);
        // An import shares the external class but must not be an entry.
        assert!(coff.find_entry(b"BeaconDataParse").is_none());
        assert!(coff.find_entry(b"missing").is_none());
    }

    #[test]
    fn relocations_are_ten_bytes_with_bounds_checks() {
        let blob = synth_coff();
        let coff = Coff::parse(&blob).expect("parse");
        let text = coff.section(0).expect("section");
        assert_eq!(coff.reloc(&text, 0), Some((0, REL_ADDR64, 2)));
        assert_eq!(coff.reloc(&text, 1), Some((8, REL_REL32, 3)));
        assert_eq!(coff.reloc(&text, 2), None); // only two entries
        assert_eq!(coff.reloc(&text, 999), None);

        // ADDR32NB and REL32_5 are valid native types (parse-level).
        let mut ok3 = synth_coff();
        ok3[92 + 8] = REL_ADDR32NB as u8;
        let coff = Coff::parse(&ok3).expect("parse");
        let text = coff.section(0).expect("section");
        assert_eq!(coff.reloc(&text, 0), Some((0, REL_ADDR32NB, 2)));
        // Types beyond the native switch (e.g. 0x0A) are load errors.
        let mut bad = synth_coff();
        bad[92 + 8] = 0x0A;
        let coff = Coff::parse(&bad).expect("parse");
        let text = coff.section(0).expect("section");
        assert!(coff.reloc(&text, 0).is_none());
    }

    // ------------------------------------------------------------------
    // Beacon data API
    // ------------------------------------------------------------------

    #[test]
    fn datum_consumes_int_short_and_bytes_in_order() {
        let mut data: [u8; 13] = [0; 13];
        data[0..4].copy_from_slice(&0x1122_3344i32.to_le_bytes());
        data[4..6].copy_from_slice(&(-5i16).to_le_bytes());
        data[6..10].copy_from_slice(&3i32.to_le_bytes()); // string length
        data[10..13].copy_from_slice(b"abc");
        let mut d = Datum {
            original: data.as_mut_ptr(),
            buffer: data.as_mut_ptr(),
            length: 13,
            size: 13,
        };
        unsafe {
            assert_eq!(datum_int(&mut d), Some(0x1122_3344));
            assert_eq!(datum_short(&mut d), Some(-5));
            let (p, len) = datum_bytes(&mut d).expect("bytes");
            assert_eq!(len, 3);
            assert_eq!(core::slice::from_raw_parts(p, 3), b"abc");
            assert_eq!(d.length, 0);
            assert!(datum_int(&mut d).is_none());
            assert!(datum_bytes(&mut d).is_none());
        }
    }

    #[test]
    fn datum_parse_skips_the_argument_count() {
        // The params blob heads with a 4-byte argument count (compat.c
        // BeaconDataParse): the datum walks the bytes after it.
        let mut data: [u8; 8] = [0; 8];
        data[0..4].copy_from_slice(&2i32.to_le_bytes()); // count (skipped)
        data[4..8].copy_from_slice(&0x1122_3344i32.to_le_bytes());
        let mut d = Datum {
            original: core::ptr::null_mut(),
            buffer: core::ptr::null_mut(),
            length: 0,
            size: 0,
        };
        unsafe {
            datum_parse(&mut d, data.as_mut_ptr(), 8);
            assert_eq!(d.length, 4);
            assert_eq!(d.size, 4);
            assert_eq!(datum_int(&mut d), Some(0x1122_3344));
            assert_eq!(d.length, 0);
        }
        // A blob smaller than the count: a zeroed parser (native parity).
        let mut tiny: [u8; 2] = [1, 2];
        let mut d = Datum {
            original: core::ptr::null_mut(),
            buffer: core::ptr::null_mut(),
            length: 0,
            size: 0,
        };
        unsafe {
            datum_parse(&mut d, tiny.as_mut_ptr(), 2);
            assert_eq!(d.length, 0);
            assert_eq!(d.size, 0);
            assert_eq!(d.buffer, tiny.as_mut_ptr());
        }
    }

    #[test]
    fn datum_rejects_trailing_garbage_lengths() {
        let mut data: [u8; 8] = [0; 8];
        data[0..4].copy_from_slice(&100i32.to_le_bytes()); // length > remaining
        let mut d = Datum {
            original: data.as_mut_ptr(),
            buffer: data.as_mut_ptr(),
            length: 8,
            size: 8,
        };
        unsafe {
            assert!(datum_bytes(&mut d).is_none());
            assert!(datum_int(&mut d).is_some()); // stream still usable
        }
    }

    // ------------------------------------------------------------------
    // BeaconPrintf formatting
    // ------------------------------------------------------------------

    fn fmt_out(fmt: &[u8], slots: &[u64]) -> (std::vec::Vec<u8>, bool) {
        let mut args = Varargs {
            slots: [0; 16],
            count: slots.len(),
        };
        args.slots[..slots.len()].copy_from_slice(slots);
        let mut out = [0u8; 256];
        let mut written = 0usize;
        let ok = bof_format(&mut out, &mut written, fmt, &args);
        (out[..written].to_vec(), ok)
    }

    #[test]
    fn format_handles_the_bof_conversion_set() {
        static WORLD: [u8; 6] = *b"world\0";
        let s = WORLD.as_ptr() as u64;
        let (out, ok) = fmt_out(
            b"hello %s: %d %u %x %c %%",
            &[s, (-42i64) as u64, 7, 0xDEAD, b'Z' as u64],
        );
        assert!(ok);
        assert_eq!(out, b"hello world: -42 7 dead Z %");
    }

    #[test]
    fn format_width_padding_and_pointer() {
        let (out, ok) = fmt_out(b"[%08x][%4d][%p]", &[0xCAFE, 42, 0x1234]);
        assert!(ok);
        assert_eq!(out, b"[0000cafe][  42][0x1234]".to_vec());
    }

    #[test]
    fn format_truncates_and_reports_exhausted_slots() {
        let (out, ok) = fmt_out(b"%d %d", &[1]);
        assert!(!ok); // second conversion ran out of varargs
        assert_eq!(out, b"1 ".to_vec());

        let long: &[u8] = &[b'a'; 512];
        let mut args = Varargs {
            slots: [0; 16],
            count: 1,
        };
        args.slots[0] = long.as_ptr() as u64;
        let mut out = [0u8; 32];
        let mut written = 0usize;
        assert!(bof_format(&mut out, &mut written, long, &args)); // no conversions
        assert_eq!(written, 32); // truncated, no panic
    }

    #[test]
    fn format_unknown_conversion_is_verbatim() {
        let (out, ok) = fmt_out(b"%q", &[0]);
        assert!(ok);
        assert_eq!(out, b"%q".to_vec());
    }
}
