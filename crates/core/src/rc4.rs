//! RC4 (session cipher of the AdaptixC2 native beacon wire, see
//! docs/WIRE.md): Encrypt == Decrypt == RC4 with the session key.
//!
//! Pure, bounded, allocation-free: the beacon writes into caller-provided
//! buffers. Kept deliberately identical to the Go side's RC4Crypt so the
//! session is byte-compatible.

/// RC4 state (256-byte S-box, standard KSA/PRGA).
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    /// New cipher from a key (KSA).
    pub fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        let mut k = 0;
        while k < 256 {
            s[k] = k as u8;
            k += 1;
        }
        let mut j = 0usize;
        let key_len = key.len();
        let mut i = 0;
        while i < 256 {
            j = (j + s[i] as usize + key[i % key_len] as usize) & 0xFF;
            s.swap(i, j);
            i += 1;
        }
        Rc4 { s, i: 0, j: 0 }
    }

    /// XOR `data` with the keystream in place (encrypt == decrypt).
    pub fn crypt_in_place(&mut self, data: &mut [u8]) {
        for b in data.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k =
                self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            *b ^= k;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::format;
    use std::string::String;
    use std::vec::Vec;

    /// RFC 6429 test vectors.
    #[test]
    fn rfc6429_vectors() {
        let cases: [(&str, &str, &str); 3] = [
            ("Key", "Plaintext", "BBF316E8D940AF0AD3"),
            ("Wiki", "pedia", "1021BF0420"),
            ("Secret", "Attack at dawn", "45A01F645FC35B383552544B9BF5"),
        ];
        for (key, plain, cipher_hex) in cases {
            let key = key.as_bytes();
            let mut data = plain.as_bytes().to_vec();
            Rc4::new(key).crypt_in_place(&mut data);
            let hex: String = data.iter().map(|b| format!("{b:02X}")).collect();
            assert_eq!(hex, cipher_hex, "key={key:?}");
            // Symmetry: the same transform decrypts.
            Rc4::new(key).crypt_in_place(&mut data);
            assert_eq!(data, plain.as_bytes());
        }
    }

    #[test]
    fn streams_are_stateful() {
        let mut a = Rc4::new(b"k");
        let mut one = [0u8; 8];
        let mut two = [0u8; 8];
        a.crypt_in_place(&mut one);
        a.crypt_in_place(&mut two);
        // Continuing the stream differs from restarting it.
        let mut b = Rc4::new(b"k");
        let mut both = [0u8; 16];
        b.crypt_in_place(&mut both);
        assert_eq!(&both[..8], &one[..]);
        assert_eq!(&both[8..], &two[..]);
    }
}
