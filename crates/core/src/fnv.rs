//! FNV-1a 64-bit hashing (port of `src_beacon/tools/hash.py`).
//!
//! Every API the beacon calls is resolved at runtime by FNV-64 hash instead
//! of an import table — the same scheme as the original project. The
//! functions are `const` so hash constants can be used in array sizes and
//! match arms without runtime initialization.

/// FNV-1a 64-bit offset basis.
pub const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
/// FNV-1a 64-bit prime.
pub const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// FNV-1a 64 over a byte slice.
#[inline]
pub const fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET;
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
        i += 1;
    }
    hash
}

/// FNV-1a 64 over the UTF-16 code units of a string, encoded little-endian —
/// the representation used by the wide-char Windows APIs the beacon resolves.
#[inline]
pub const fn fnv1a64_utf16(units: &[u16]) -> u64 {
    let mut hash = FNV_OFFSET;
    let mut i = 0;
    while i < units.len() {
        hash ^= (units[i] & 0xff) as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
        hash ^= (units[i] >> 8) as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
        i += 1;
    }
    hash
}

/// FNV-1a 64 over UTF-16 code units with ASCII case folding (A-Z folded to
/// a-z before hashing). Windows module names are not consistently cased
/// (`KERNEL32.DLL`, `ntdll.dll`): module resolution must be
/// case-insensitive, exactly like the original project's hash.py.
#[inline]
pub const fn fnv1a64_utf16_ci(units: &[u16]) -> u64 {
    let mut hash = FNV_OFFSET;
    let mut i = 0;
    while i < units.len() {
        let mut u = units[i];
        if u >= 0x41 && u <= 0x5A {
            u += 0x20;
        }
        hash ^= (u & 0xff) as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
        hash ^= (u >> 8) as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
        i += 1;
    }
    hash
}

/// Compile-time hash of a lowercase ASCII string as UTF-16 LE code units,
/// case-folded — the constant form of [`fnv1a64_utf16_ci`]. Use it to build
/// module-name hash constants: `const H: u64 = fnv1a64_wide_ascii_ci("ntdll.dll");`.
/// The input must be lowercase ASCII (module names are).
#[inline]
pub const fn fnv1a64_wide_ascii_ci(s: &str) -> u64 {
    fnv1a64_bytes_wide_ci(s.as_bytes())
}

/// FNV-1a 64 over ASCII bytes widened to UTF-16 LE code units with case
/// folding — the runtime form of [`fnv1a64_wide_ascii_ci`] when the module
/// name comes as raw bytes (the BOF import table, not a `&str` literal).
#[inline]
pub const fn fnv1a64_bytes_wide_ci(bytes: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET;
    let mut i = 0;
    while i < bytes.len() {
        let mut u = bytes[i] as u16;
        if u >= 0x41 && u <= 0x5A {
            u += 0x20;
        }
        hash ^= (u & 0xff) as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
        hash ^= (u >> 8) as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
        i += 1;
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::ToString;

    /// Reference vectors from the FNV-1a 64 specification
    /// (https://doi.org/10.17487/draft-eastlake-fnv).
    #[test]
    fn fnv1a64_known_vectors() {
        assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a64(b"foobar"), 0x8594_4171_f739_67e8);
    }

    #[test]
    fn fnv1a64_runtime_hash_vectors() {
        // Values the original project hashes at runtime (hash.py references).
        assert_eq!(fnv1a64(b"NtdllCopy"), 0xfe8a_df81_ffa1_0a88);
        assert_eq!(fnv1a64(b"kernel32.dll"), 0xe14b_18a7_acf9_c443);
    }

    #[test]
    fn fnv1a64_is_const_evaluable() {
        // Hash constants must be usable at compile time (match arms, sizes).
        const KERNEL32: u64 = fnv1a64(b"kernel32.dll");
        assert_eq!(KERNEL32, 0xe14b_18a7_acf9_c443);
    }

    #[test]
    fn fnv1a64_utf16_matches_byte_wide_encoding() {
        // FNV over UTF-16 LE bytes must equal FNV over the byte encoding of
        // the same string, unit by unit (little-endian code units).
        let name = "kernel32.dll".to_string();
        let units: std::vec::Vec<u16> = name.encode_utf16().collect();
        assert_eq!(fnv1a64_utf16(&units), 0x7f1b_f8b4_49d1_6c2d);

        let empty: [u16; 0] = [];
        assert_eq!(fnv1a64_utf16(&empty), 0xcbf2_9ce4_8422_2325);
    }

    #[test]
    fn fnv1a64_differs_by_single_byte() {
        // A one-byte difference must change the hash (avalanche sanity
        // check, not a collision proof).
        assert_ne!(fnv1a64(b"kernel32.dll"), fnv1a64(b"kernel32.dlL"));
    }

    #[test]
    fn case_folded_utf16_matches_const_form() {
        // The runtime-side fold over any casing must equal the compile-time
        // constant computed from the lowercase name.
        let units: std::vec::Vec<u16> = "KERNEL32.DLL".encode_utf16().collect();
        let folded = fnv1a64_utf16_ci(&units);
        assert_eq!(folded, fnv1a64_wide_ascii_ci("kernel32.dll"));

        let lower: std::vec::Vec<u16> = "kernel32.dll".encode_utf16().collect();
        assert_eq!(folded, fnv1a64_utf16_ci(&lower));

        // And folding agrees with the exact-casing hash of the lowercase form.
        assert_eq!(folded, fnv1a64_utf16(&lower));
    }

    #[test]
    fn fold_is_a_noop_for_lowercase() {
        let units: std::vec::Vec<u16> = "ntdll.dll".encode_utf16().collect();
        assert_eq!(fnv1a64_utf16_ci(&units), fnv1a64_utf16(&units));
    }
}
