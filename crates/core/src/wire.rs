//! Wire packer/unpacker (see docs/WIRE.md): the byte formats of the
//! AdaptixC2 native beacon session — big-endian primitives on the wire,
//! `u32 BE`-prefixed arrays, and the `PackTasks` little-endian task-id
//! trailer.
//!
//! Pure, bounded, allocation-free: the beacon writes into caller-provided
//! buffers and reads through a cursor. Every format decision is pinned by
//! tests against hand-built vectors taken from the Go reference
//! (`pl_packer.go`, tag v1.2).

/// Bounded writer over a fixed buffer.
pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Writer { buf, pos: 0 }
    }

    #[inline]
    pub fn written(&self) -> usize {
        self.pos
    }

    /// The written prefix of the buffer.
    #[inline]
    pub fn written_bytes(&self) -> &[u8] {
        &self.buf[..self.pos]
    }

    /// Backfill a big-endian u32 at an absolute position (the reserved
    /// results-size field).
    pub fn backfill_u32_be(&mut self, pos: usize, v: u32) {
        if pos + 4 <= self.buf.len() {
            let b = v.to_be_bytes();
            let mut i = 0;
            while i < 4 {
                self.buf[pos + i] = b[i];
                i += 1;
            }
        }
    }

    /// Raw byte push (task framing).
    pub fn push(&mut self, bytes: &[u8]) -> bool {
        if self.buf.len() - self.pos < bytes.len() {
            return false;
        }
        let mut i = 0;
        while i < bytes.len() {
            self.buf[self.pos + i] = bytes[i];
            i += 1;
        }
        self.pos += bytes.len();
        true
    }

    /// Big-endian u8..u64 (wire primitives).
    pub fn u8(&mut self, v: u8) -> bool {
        self.push(&[v])
    }
    pub fn u16(&mut self, v: u16) -> bool {
        self.push(&v.to_be_bytes())
    }
    pub fn u32(&mut self, v: u32) -> bool {
        self.push(&v.to_be_bytes())
    }
    pub fn u64(&mut self, v: u64) -> bool {
        self.push(&v.to_be_bytes())
    }

    /// `u32 BE length || bytes` (array field).
    pub fn array(&mut self, bytes: &[u8]) -> bool {
        self.u32(bytes.len() as u32) && self.push(bytes)
    }

    /// `PackTasks` trailer: `u32 LE` task id.
    pub fn u32_le(&mut self, v: u32) -> bool {
        self.push(&v.to_le_bytes())
    }

    /// Bytes still fitting in the buffer.
    #[inline]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
}

/// Bounded reader (the Go Packer semantics).
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    /// Raw bounded read.
    #[inline]
    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.buf.len() - self.pos < n {
            return None;
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(out)
    }

    pub fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    pub fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    pub fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub fn u32_le(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Look at the next `u32 LE` without consuming it (task command peek).
    pub fn peek_u32_le(&self) -> Option<u32> {
        if self.buf.len() - self.pos < 4 {
            return None;
        }
        Some(u32::from_le_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]))
    }
    pub fn u64(&mut self) -> Option<u64> {
        self.take(8)
            .map(|b| u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    /// `u32 BE length || bytes`.
    pub fn array(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    #[inline]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::format;
    use std::vec;

    #[test]
    fn primitives_are_big_endian() {
        let mut buf = [0u8; 16];
        let mut w = Writer::new(&mut buf);
        assert!(w.u32(0xDEAD_BEEF));
        assert!(w.u16(0x0102));
        assert!(w.u8(0xAB));
        assert!(w.u16(0x0304));
        assert_eq!(w.written(), 9);
        assert_eq!(
            &buf[..9],
            &[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0xAB, 0x03, 0x04]
        );

        let mut r = Reader::new(&buf[..9]);
        assert_eq!(r.u32(), Some(0xDEAD_BEEF));
        assert_eq!(r.u16(), Some(0x0102));
        assert_eq!(r.u8(), Some(0xAB));
        assert_eq!(r.u16(), Some(0x0304));
        assert_eq!(r.u32(), None); // exhausted
    }

    #[test]
    fn arrays_are_length_prefixed_be() {
        let mut buf = [0u8; 16];
        let mut w = Writer::new(&mut buf);
        assert!(w.array(b"abc"));
        assert_eq!(w.written(), 7);
        assert_eq!(&buf[..7], &[0, 0, 0, 3, b'a', b'b', b'c']);

        let mut r = Reader::new(&buf[..7]);
        assert_eq!(r.array(), Some(&b"abc"[..]));
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn writer_refuses_overflow() {
        let mut buf = [0u8; 4];
        let mut w = Writer::new(&mut buf);
        assert!(w.u32(1));
        assert!(!w.u8(1)); // full
        let mut w = Writer::new(&mut buf);
        assert!(!w.array(b"12345")); // len+data > 4
    }

    #[test]
    fn reader_rejects_truncated_arrays() {
        let buf = [0, 0, 0, 9, 1, 2, 3]; // claims 9, has 3
        let mut r = Reader::new(&buf);
        assert_eq!(r.array(), None);
    }

    #[test]
    fn task_ids_are_little_endian() {
        let mut buf = [0u8; 8];
        let mut w = Writer::new(&mut buf);
        assert!(w.push(b"DATA"));
        assert!(w.u32_le(0x0102_0304));
        assert_eq!(&buf, &[b'D', b'A', b'T', b'A', 0x04, 0x03, 0x02, 0x01]);
        let mut r = Reader::new(&buf);
        assert_eq!(r.take(4).map(|b| b.to_vec()), Some(vec![68, 65, 84, 65]));
        assert_eq!(r.u32_le(), Some(0x0102_0304));
    }

    #[test]
    fn u64_round_trip() {
        let mut buf = [0u8; 8];
        let mut w = Writer::new(&mut buf);
        assert!(w.u64(0x0102_0304_0506_0708));
        assert_eq!(buf, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(Reader::new(&buf).u64(), Some(0x0102_0304_0506_0708));
    }
}
