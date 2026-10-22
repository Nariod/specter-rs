//! PEB walking and export resolution (port of `src_beacon/src/runtime/`).
//!
//! The beacon resolves every API at runtime — no import table. Module bases
//! come from the PEB loader lists (hash of `BaseDllName`), function pointers
//! from each module's export directory (hash of the export name).
//!
//! Everything here takes explicit pointers and does no I/O, so the host unit
//! tests exercise the exact code the blob runs, against mock PEB/module
//! structures (the original C has no equivalent test seam).
//!
//! Struct layouts: Windows x64 only, offsets pinned and asserted in tests.

use core::ffi::c_void;
use core::ptr;

use crate::fnv::{fnv1a64, fnv1a64_utf16_ci};

/// Doubly-linked list entry (LIST_ENTRY, 16 bytes on x64).
#[repr(C)]
pub struct ListEntry {
    pub flink: *mut ListEntry,
    pub blink: *mut ListEntry,
}

/// UNICODE_STRING: Length is in bytes, so the unit count is Length / 2.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct UnicodeString {
    pub length: u16,
    pub maximum_length: u16,
    pub _pad: u32,
    pub buffer: *mut u16,
}

/// Partial PEB: only the Ldr pointer (offset 0x18 on x64).
#[repr(C)]
pub struct Peb {
    _pad: [u8; 0x18],
    pub ldr: *mut PebLdrData,
}

/// Partial PEB_LDR_DATA: InLoadOrderModuleList is at offset 0x10 on x64.
#[repr(C)]
pub struct PebLdrData {
    _pad: [u8; 0x10],
    pub in_load_order: ListEntry,
}

/// LDR_DATA_TABLE_ENTRY reached through the InLoadOrder links: the link is
/// the first field, so the entry pointer equals the link pointer.
#[repr(C)]
pub struct LdrEntry {
    pub in_load_order: ListEntry,   // +0x00
    pub in_memory_order: ListEntry, // +0x10
    pub in_init_order: ListEntry,   // +0x20
    pub dll_base: *mut c_void,      // +0x30
    pub entry_point: *mut c_void,   // +0x38
    pub size_of_image: u32,         // +0x40
    _pad: u32,
    pub full_dll_name: UnicodeString, // +0x48
    pub base_dll_name: UnicodeString, // +0x58
}

/// Find a module base by case-insensitive FNV-64 hash of its BaseDllName.
///
/// # Safety
///
/// `peb` must point to a valid PEB whose loader lists are intact (the
/// invariant on any live Windows process, and of the mock structures in the
/// tests). Never returns a pointer the caller may free.
pub unsafe fn find_module(peb: *const Peb, name_hash: u64) -> *mut c_void {
    if peb.is_null() {
        return ptr::null_mut();
    }
    let ldr = (*peb).ldr;
    if ldr.is_null() {
        return ptr::null_mut();
    }
    let head: *mut ListEntry = ptr::addr_of_mut!((*ldr).in_load_order);
    let mut link = (*head).flink;
    while link != head && !link.is_null() {
        let entry: *mut LdrEntry = link.cast();
        let name = (*entry).base_dll_name;
        if name.length > 0 && !name.buffer.is_null() {
            let units = core::slice::from_raw_parts(name.buffer, (name.length / 2) as usize);
            if fnv1a64_utf16_ci(units) == name_hash {
                return (*entry).dll_base;
            }
        }
        link = (*link).flink;
    }
    ptr::null_mut()
}

#[inline]
unsafe fn read_u16(base: *const u8, offset: usize) -> u16 {
    ptr::read_unaligned(base.add(offset) as *const u16)
}

#[inline]
unsafe fn read_u32(base: *const u8, offset: usize) -> u32 {
    ptr::read_unaligned(base.add(offset) as *const u32)
}

/// Length of a bounded C string (used for export names: bounded scan, no
/// unbounded walks on untrusted layout data).
const MAX_NAME_LEN: usize = 256;

/// Find an exported function by FNV-64 hash of its ASCII name.
///
/// # Safety
///
/// `base` must point to a mapped PE image with intact headers and export
/// directory (any loaded module satisfies this; the tests build mock images).
pub unsafe fn find_export(base: *const c_void, fn_hash: u64) -> *mut c_void {
    let image = base as *const u8;
    if image.is_null() {
        return ptr::null_mut();
    }

    // DOS header -> PE headers.
    if read_u16(image, 0) != 0x5A4D {
        return ptr::null_mut(); // 'MZ'
    }
    let nt = read_u32(image, 0x3C) as usize;
    if read_u32(image, nt) != 0x0000_4550 {
        return ptr::null_mut(); // 'PE\0\0'
    }
    let optional = nt + 4 + 20; // signature + file header
    if read_u16(image, optional) != 0x020B {
        return ptr::null_mut(); // PE32+ only
    }
    let data_dir = optional + 0x70;
    let export_rva = read_u32(image, data_dir) as usize;
    if export_rva == 0 {
        return ptr::null_mut();
    }
    let exp = image.add(export_rva);

    let num_names = read_u32(exp, 0x18) as usize;
    let addr_funcs = read_u32(exp, 0x1C) as usize;
    let addr_names = read_u32(exp, 0x20) as usize;
    let addr_ords = read_u32(exp, 0x24) as usize;

    for i in 0..num_names {
        let name_rva = read_u32(image, addr_names + 4 * i) as usize;
        let name = image.add(name_rva);
        let mut name_bytes = [0u8; MAX_NAME_LEN];
        let mut len = 0usize;
        while len < MAX_NAME_LEN && *name.add(len) != 0 {
            name_bytes[len] = *name.add(len);
            len += 1;
        }
        if fnv1a64(&name_bytes[..len]) == fn_hash {
            let ord = read_u16(image, addr_ords + 2 * i) as usize;
            let func_rva = read_u32(image, addr_funcs + 4 * ord) as usize;
            return image.add(func_rva) as *mut c_void;
        }
    }
    ptr::null_mut()
}

/// Find a section by name (e.g. `.text`) in a mapped PE image: returns the
/// in-memory pointer (base + VA) and the virtual size.
///
/// # Safety
///
/// `base` must point to a mapped PE image with intact headers.
pub unsafe fn find_section(base: *const c_void, name: &[u8]) -> Option<(*const u8, usize)> {
    let image = base as *const u8;
    if image.is_null() || read_u16(image, 0) != 0x5A4D {
        return None;
    }
    let nt = read_u32(image, 0x3C) as usize;
    if read_u32(image, nt) != 0x0000_4550 {
        return None;
    }
    let num_sections = read_u16(image, nt + 6) as usize;
    let optsz = read_u16(image, nt + 20) as usize;
    let mut off = nt + 4 + 20 + optsz;
    for _ in 0..num_sections {
        let sec = image.add(off);
        let sec_name = core::slice::from_raw_parts(sec, 8);
        // Manual comparison: slice `==` lowers to memcmp, and the blob links
        // without libc — compiler_builtins does not export the raw C symbol.
        let mut eq = sec_name.len() >= name.len();
        let mut i = 0;
        while eq && i < name.len() {
            eq = sec_name[i] == name[i];
            i += 1;
        }
        let matches =
            eq && (sec_name.get(name.len()).copied().unwrap_or(0) == 0 || name.len() == 8);
        if matches {
            let vsize = read_u32(sec, 8) as usize;
            let vaddr = read_u32(sec, 12) as usize;
            return Some((image.add(vaddr), vsize));
        }
        off += 40;
    }
    None
}

/// Iterator over a module's named exports: raw export-name C strings paired
/// with function addresses. Iterates in export-table (name) order.
pub struct ExportIter {
    image: *const u8,
    count: usize,
    addr_names: usize,
    addr_funcs: usize,
    addr_ords: usize,
    i: usize,
}

impl ExportIter {
    /// Next (name pointer, function pointer) pair, or `None` at the end.
    /// The name is a raw C string: read it with a bounded scan.
    ///
    /// # Safety
    ///
    /// The iterator must come from [`exports`] on a valid mapped image.
    #[inline]
    pub unsafe fn next(&mut self) -> Option<(*const u8, *const u8)> {
        if self.i >= self.count {
            return None;
        }
        let image = self.image;
        let name_rva = read_u32(image, self.addr_names + 4 * self.i) as usize;
        let ord = read_u16(image, self.addr_ords + 2 * self.i) as usize;
        let func_rva = read_u32(image, self.addr_funcs + 4 * ord) as usize;
        self.i += 1;
        Some((image.add(name_rva), image.add(func_rva)))
    }
}

/// Open a module's export directory for iteration.
///
/// # Safety
///
/// `base` must point to a mapped PE image with an intact export directory.
pub unsafe fn exports(base: *const c_void) -> Option<ExportIter> {
    let image = base as *const u8;
    if image.is_null() || read_u16(image, 0) != 0x5A4D {
        return None;
    }
    let nt = read_u32(image, 0x3C) as usize;
    if read_u32(image, nt) != 0x0000_4550 {
        return None;
    }
    let optional = nt + 4 + 20;
    if read_u16(image, optional) != 0x020B {
        return None;
    }
    let data_dir = optional + 0x70;
    let export_rva = read_u32(image, data_dir) as usize;
    if export_rva == 0 {
        return None;
    }
    let exp = image.add(export_rva);
    Some(ExportIter {
        image,
        count: read_u32(exp, 0x18) as usize,
        addr_funcs: read_u32(exp, 0x1C) as usize,
        addr_names: read_u32(exp, 0x20) as usize,
        addr_ords: read_u32(exp, 0x24) as usize,
        i: 0,
    })
}

#[cfg(test)]
pub(crate) mod testutil {
    //! Shared mock builders for host tests (used by the peb and syscalls
    //! test modules): mapped-style PE images with sections, export
    //! directories and controlled stub bytes.

    use super::*;
    use std::prelude::v1::*;

    pub const TEXT_VA: usize = 0x1000;
    pub const TEXT_SIZE: usize = 0x1000;

    /// Export descriptor: name, function RVA within the image.
    pub struct MockExport<'a> {
        pub name: &'a str,
        pub func_rva: u32,
    }

    /// Build a mapped-style PE image (leaked) with:
    /// - a `.text` section mapped at TEXT_VA covering TEXT_SIZE bytes,
    /// - the given exports (pointers and export directory),
    /// - `extra` raw bytes placed at `TEXT_VA` (the image file is laid out
    ///   as a mapped image: file offset == RVA).
    pub fn mock_mapped_module(exports: &[MockExport], text: &[u8]) -> *mut c_void {
        assert!(text.len() <= TEXT_SIZE, "mock .text overflow");
        const NT: usize = 0x40;
        const OPTIONAL: usize = NT + 4 + 20;
        const EXPORT_RVA: usize = 0x400;
        const NAMES_PTRS_RVA: usize = 0x600;
        const NAMES_STR_RVA: usize = 0x700;
        const ORDS_RVA: usize = 0x900;
        const FUNCS_RVA: usize = 0xA00;

        let mut image = Vec::new();
        image.resize(TEXT_VA + TEXT_SIZE, 0u8);
        let put_u16 = |img: &mut Vec<u8>, off: usize, v: u16| {
            img[off..off + 2].copy_from_slice(&v.to_le_bytes());
        };
        let put_u32 = |img: &mut Vec<u8>, off: usize, v: u32| {
            img[off..off + 4].copy_from_slice(&v.to_le_bytes());
        };

        put_u16(&mut image, 0, 0x5A4D);
        put_u32(&mut image, 0x3C, NT as u32);
        put_u32(&mut image, NT, 0x0000_4550);
        put_u16(&mut image, NT + 6, 1); // one section
        put_u16(&mut image, NT + 20, 0xF0); // optional header size
        put_u16(&mut image, OPTIONAL, 0x020B);
        put_u32(&mut image, OPTIONAL + 0x70, EXPORT_RVA as u32);
        put_u32(&mut image, OPTIONAL + 0x74, 0x100);

        // .text section header: raw offset == VA (mapped-image style).
        let sec = NT + 4 + 20 + 0xF0;
        image[sec..sec + 8].copy_from_slice(b".text\0\0\0");
        put_u32(&mut image, sec + 8, TEXT_SIZE as u32);
        put_u32(&mut image, sec + 12, TEXT_VA as u32);
        put_u32(&mut image, sec + 16, TEXT_SIZE as u32);
        put_u32(&mut image, sec + 20, TEXT_VA as u32);
        put_u32(&mut image, sec + 36, 0x6000_0060); // code, execute, read

        // Export directory.
        put_u32(&mut image, EXPORT_RVA + 0x18, exports.len() as u32);
        put_u32(&mut image, EXPORT_RVA + 0x1C, FUNCS_RVA as u32);
        put_u32(&mut image, EXPORT_RVA + 0x20, NAMES_PTRS_RVA as u32);
        put_u32(&mut image, EXPORT_RVA + 0x24, ORDS_RVA as u32);

        let mut str_off = 0usize;
        for (i, e) in exports.iter().enumerate() {
            put_u32(
                &mut image,
                NAMES_PTRS_RVA + 4 * i,
                (NAMES_STR_RVA + str_off) as u32,
            );
            put_u16(&mut image, ORDS_RVA + 2 * i, i as u16);
            put_u32(&mut image, FUNCS_RVA + 4 * i, e.func_rva);
            let bytes = e.name.as_bytes();
            image[NAMES_STR_RVA + str_off..NAMES_STR_RVA + str_off + bytes.len()]
                .copy_from_slice(bytes);
            str_off += bytes.len() + 1;
        }

        // Controlled .text content.
        image[TEXT_VA..TEXT_VA + text.len()].copy_from_slice(text);

        Box::leak(image.into_boxed_slice()).as_ptr() as *mut c_void
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;
    use std::prelude::v1::*;

    // --- layout pinning: a change in the target struct offsets must fail ---

    #[test]
    fn x64_offsets_are_pinned() {
        use core::mem::{offset_of, size_of};
        assert_eq!(offset_of!(Peb, ldr), 0x18);
        assert_eq!(offset_of!(PebLdrData, in_load_order), 0x10);
        assert_eq!(offset_of!(LdrEntry, dll_base), 0x30);
        assert_eq!(offset_of!(LdrEntry, size_of_image), 0x40);
        assert_eq!(offset_of!(LdrEntry, full_dll_name), 0x48);
        assert_eq!(offset_of!(LdrEntry, base_dll_name), 0x58);
        assert_eq!(size_of::<UnicodeString>(), 0x10);
        assert_eq!(size_of::<LdrEntry>(), 0x68);
    }

    // --- mock PEB loader list ---

    /// Build a leaked (never freed: test-only) module entry wired into a
    /// fake loader list, with the given base and wide name.
    fn mock_entry(name: &str, base: usize) -> *mut LdrEntry {
        let units: Vec<u16> = name.encode_utf16().collect();
        let byte_len = units.len() * 2;
        let buffer = units.leak().as_ptr();
        let entry = Box::leak(Box::new(LdrEntry {
            in_load_order: ListEntry {
                flink: ptr::null_mut(),
                blink: ptr::null_mut(),
            },
            in_memory_order: ListEntry {
                flink: ptr::null_mut(),
                blink: ptr::null_mut(),
            },
            in_init_order: ListEntry {
                flink: ptr::null_mut(),
                blink: ptr::null_mut(),
            },
            dll_base: base as *mut c_void,
            entry_point: ptr::null_mut(),
            size_of_image: 0x1000,
            _pad: 0,
            full_dll_name: UnicodeString {
                length: 0,
                maximum_length: 0,
                _pad: 0,
                buffer: ptr::null_mut(),
            },
            base_dll_name: UnicodeString {
                length: byte_len as u16,
                maximum_length: byte_len as u16,
                _pad: 0,
                buffer: buffer as *mut u16,
            },
        }));
        entry as *mut LdrEntry
    }

    fn mock_peb(names_bases: &[(&str, usize)]) -> *mut Peb {
        let ldr = Box::leak(Box::new(PebLdrData {
            _pad: [0; 0x10],
            in_load_order: ListEntry {
                flink: ptr::null_mut(),
                blink: ptr::null_mut(),
            },
        }));
        let head: *mut ListEntry = ptr::addr_of_mut!(ldr.in_load_order);
        let mut prev = head;
        for (name, base) in names_bases {
            let entry = mock_entry(name, *base);
            unsafe {
                (*entry).in_load_order.blink = prev;
                (*prev).flink = entry.cast();
            }
            prev = entry.cast();
        }
        unsafe {
            (*head).blink = prev;
            (*prev).flink = head;
        }

        Box::leak(Box::new(Peb {
            _pad: [0; 0x18],
            ldr: ldr as *mut PebLdrData,
        })) as *mut Peb
    }

    fn hash_of(name: &str) -> u64 {
        crate::fnv::fnv1a64_wide_ascii_ci(name.to_lowercase().as_str())
    }

    #[test]
    fn find_module_walks_the_load_order_list() {
        let peb = mock_peb(&[
            ("ntdll.dll", 0x1000),
            ("KERNEL32.DLL", 0x2000),
            ("USER32.dll", 0x3000),
        ]);
        unsafe {
            assert_eq!(find_module(peb, hash_of("ntdll.dll")) as usize, 0x1000);
            assert_eq!(find_module(peb, hash_of("kernel32.dll")) as usize, 0x2000);
            assert_eq!(find_module(peb, hash_of("user32.dll")) as usize, 0x3000);
            // Case-insensitive on both sides.
            assert_eq!(
                find_module(peb, crate::fnv::fnv1a64_wide_ascii_ci("NTDLL.DLL")) as usize,
                0x1000
            );
            // Unknown module.
            assert_eq!(find_module(peb, hash_of("winhttp.dll")), ptr::null_mut());
        }
    }

    #[test]
    fn find_module_handles_bad_peb() {
        unsafe {
            assert_eq!(find_module(ptr::null(), 1), ptr::null_mut());
            let ldrless = Box::leak(Box::new(Peb {
                _pad: [0; 0x18],
                ldr: ptr::null_mut(),
            }));
            assert_eq!(find_module(ldrless as *mut Peb, 1), ptr::null_mut());
        }
    }

    // --- mock PE image with an export directory ---

    /// Build a mock PE image (leaked) exporting `exports` as (name, rva).
    fn mock_module(exports: &[(&str, u32)]) -> *mut c_void {
        const NT: usize = 0x40;
        const OPTIONAL: usize = NT + 4 + 20;
        const EXPORT_RVA: usize = 0x200;
        const NAMES_PTRS_RVA: usize = 0x400; // array of name RVAs
        const NAMES_STR_RVA: usize = 0x480; // the C strings themselves
        const ORDS_RVA: usize = 0x500;
        const FUNCS_RVA: usize = 0x600;

        let mut image = Vec::new();
        image.resize(0x800, 0u8);
        let put_u16 = |img: &mut Vec<u8>, off: usize, v: u16| {
            img[off..off + 2].copy_from_slice(&v.to_le_bytes());
        };
        let put_u32 = |img: &mut Vec<u8>, off: usize, v: u32| {
            img[off..off + 4].copy_from_slice(&v.to_le_bytes());
        };

        put_u16(&mut image, 0, 0x5A4D); // MZ
        put_u32(&mut image, 0x3C, NT as u32);
        put_u32(&mut image, NT, 0x0000_4550); // PE\0\0
        put_u16(&mut image, OPTIONAL, 0x020B); // PE32+
        put_u32(&mut image, OPTIONAL + 0x70, EXPORT_RVA as u32);
        put_u32(&mut image, OPTIONAL + 0x74, 0x80);

        // Export directory.
        put_u32(&mut image, EXPORT_RVA + 0x18, exports.len() as u32);
        put_u32(&mut image, EXPORT_RVA + 0x1C, FUNCS_RVA as u32);
        put_u32(&mut image, EXPORT_RVA + 0x20, NAMES_PTRS_RVA as u32);
        put_u32(&mut image, EXPORT_RVA + 0x24, ORDS_RVA as u32);

        let mut name_off = 0usize;
        for (i, (name, rva)) in exports.iter().enumerate() {
            put_u32(
                &mut image,
                NAMES_PTRS_RVA + 4 * i,
                (NAMES_STR_RVA + name_off) as u32,
            );
            put_u16(&mut image, ORDS_RVA + 2 * i, i as u16);
            put_u32(&mut image, FUNCS_RVA + 4 * i, *rva);
            let bytes = name.as_bytes();
            image[NAMES_STR_RVA + name_off..NAMES_STR_RVA + name_off + bytes.len()]
                .copy_from_slice(bytes);
            name_off += bytes.len() + 1;
        }

        Box::leak(image.into_boxed_slice()).as_ptr() as *mut c_void
    }

    #[test]
    fn find_export_resolves_by_hash() {
        let module = mock_module(&[("HeapAlloc", 0x1234), ("GetProcessHeap", 0x5678)]);
        unsafe {
            assert_eq!(
                find_export(module, fnv1a64(b"GetProcessHeap")) as usize,
                module as usize + 0x5678
            );
            assert_eq!(
                find_export(module, fnv1a64(b"HeapAlloc")) as usize,
                module as usize + 0x1234
            );
            assert_eq!(find_export(module, fnv1a64(b"Sleep")), ptr::null_mut());
        }
    }

    #[test]
    fn find_export_rejects_non_pe_bases() {
        unsafe {
            assert_eq!(find_export(ptr::null(), 1), ptr::null_mut());
            let zeros: *mut c_void =
                Box::leak(vec![0u8; 0x200].into_boxed_slice()).as_ptr() as *mut c_void;
            assert_eq!(find_export(zeros, 1), ptr::null_mut());
        }
    }

    #[test]
    fn find_export_survives_missing_directory() {
        // PE headers without an export directory (export RVA = 0).
        const NT: usize = 0x40;
        const OPTIONAL: usize = NT + 4 + 20;
        let mut image = vec![0u8; 0x200];
        image[0..2].copy_from_slice(&0x5A4Du16.to_le_bytes());
        image[0x3C..0x40].copy_from_slice(&(NT as u32).to_le_bytes());
        image[NT..NT + 4].copy_from_slice(&0x0000_4550u32.to_le_bytes());
        image[OPTIONAL..OPTIONAL + 2].copy_from_slice(&0x020Bu16.to_le_bytes());
        let base = Box::leak(image.into_boxed_slice()).as_ptr() as *mut c_void;
        unsafe {
            assert_eq!(find_export(base, fnv1a64(b"Anything")), ptr::null_mut());
        }
    }

    // --- mapped-style module: sections and export iteration ---

    fn mock_exports() -> Vec<MockExport<'static>> {
        std::vec![
            MockExport {
                name: "NtDelayExecution",
                func_rva: (TEXT_VA + 0x10) as u32
            },
            MockExport {
                name: "ZwDelayExecution",
                func_rva: (TEXT_VA + 0x10) as u32
            },
            MockExport {
                name: "RtlExitUserThread",
                func_rva: (TEXT_VA + 0x40) as u32
            },
        ]
    }

    #[test]
    fn find_section_locates_text() {
        let base = mock_mapped_module(&mock_exports(), &[0u8; 16]);
        unsafe {
            let (ptr, len) = find_section(base, b".text").expect("section");
            assert_eq!(ptr, (base as usize + TEXT_VA) as *const u8);
            assert_eq!(len, TEXT_SIZE);
            assert!(find_section(base, b".rdata").is_none());
            assert!(find_section(ptr::null(), b".text").is_none());
        }
    }

    #[test]
    fn exports_iterate_names_and_addresses() {
        let base = mock_mapped_module(&mock_exports(), &[0u8; 16]);
        unsafe {
            let mut it = exports(base).expect("exports");
            let (name, func) = it.next().expect("first");
            assert_eq!(read_cstr(name, 32), b"NtDelayExecution");
            assert_eq!(func, (base as usize + TEXT_VA + 0x10) as *const u8);

            let (name, _) = it.next().expect("second");
            assert_eq!(read_cstr(name, 32), b"ZwDelayExecution");

            let (name, _) = it.next().expect("third");
            assert_eq!(read_cstr(name, 32), b"RtlExitUserThread");

            assert!(it.next().is_none());
            assert!(exports(ptr::null()).is_none());
        }
    }

    fn read_cstr(ptr: *const u8, max: usize) -> Vec<u8> {
        let mut out = Vec::new();
        unsafe {
            for i in 0..max {
                let b = *ptr.add(i);
                if b == 0 {
                    break;
                }
                out.push(b);
            }
        }
        out
    }
}
