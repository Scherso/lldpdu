//! The raw TLV wire layer (802.1AB §8.4.1).
//!
//! An LLDPDU is a flat sequence of TLVs. Each starts with a 16-bit header:
//! the top 7 bits are the type (0–127), the low 9 bits the value length
//! (0–511). Type 0 with length 0 is the End Of LLDPDU marker; everything
//! after it is padding and must be ignored.

use crate::Error;
use alloc::vec::Vec;

/// TLV type of the End Of LLDPDU marker.
pub const END_OF_LLDPDU: u8 = 0;
/// TLV type of the mandatory Chassis ID (first TLV, §8.5.2).
pub const CHASSIS_ID: u8 = 1;
/// TLV type of the mandatory Port ID (second TLV, §8.5.3).
pub const PORT_ID: u8 = 2;
/// TLV type of the mandatory Time To Live (third TLV, §8.5.4).
pub const TTL: u8 = 3;
/// TLV type of Port Description (§8.5.5).
pub const PORT_DESCRIPTION: u8 = 4;
/// TLV type of System Name (§8.5.6).
pub const SYSTEM_NAME: u8 = 5;
/// TLV type of System Description (§8.5.7).
pub const SYSTEM_DESCRIPTION: u8 = 6;
/// TLV type of System Capabilities (§8.5.8).
pub const SYSTEM_CAPABILITIES: u8 = 7;
/// TLV type of Management Address (§8.5.9).
pub const MANAGEMENT_ADDRESS: u8 = 8;
/// TLV type of Organizationally Specific TLVs (§8.6).
pub const ORG_SPECIFIC: u8 = 127;

/// The largest value the 9-bit TLV length field can carry.
pub const MAX_VALUE_LEN: usize = 511;

/// One TLV, borrowed from the input buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawTlv<'a> {
    /// TLV type, 0–127.
    pub ty: u8,
    /// The value bytes (already bounds-checked against the buffer).
    pub value: &'a [u8],
}

/// A bounds-checked iterator over the TLVs of an LLDPDU.
///
/// Iteration ends at the End Of LLDPDU marker, at the end of the buffer, or —
/// after yielding one [`Error::Truncated`] — where the buffer ends inside a
/// TLV. It never panics and never reads past `buf`.
///
/// ```
/// use lldpdu::tlv::TlvIter;
///
/// // One TLV: type 5 (System Name), length 2, "sw", then End Of LLDPDU.
/// let bytes = [0x0A, 0x02, b's', b'w', 0x00, 0x00];
/// let tlvs: Vec<_> = TlvIter::new(&bytes).collect::<Result<_, _>>().unwrap();
/// assert_eq!(tlvs[0].ty, 5);
/// assert_eq!(tlvs[0].value, b"sw");
/// assert_eq!(tlvs.len(), 1); // the End marker terminates, it isn't yielded
/// ```
#[derive(Debug, Clone)]
pub struct TlvIter<'a> {
    buf: &'a [u8],
    /// Set after End Of LLDPDU or an error: the iterator is fused.
    done: bool,
}

impl<'a> TlvIter<'a> {
    /// Iterate the TLVs of `buf` (an LLDPDU payload, not a whole frame).
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, done: false }
    }
}

impl<'a> Iterator for TlvIter<'a> {
    type Item = Result<RawTlv<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        // The wire shape, as a pattern: two header bytes, then the rest.
        let (hi, lo, rest) = match *self.buf {
            [] => return None,
            [hi, lo, ref rest @ ..] => (hi, lo, rest),
            // One trailing byte: a header can't fit, so the PDU is cut short.
            [_] => {
                self.done = true;
                return Some(Err(Error::Truncated));
            }
        };
        let ty = hi >> 1;
        let len = usize::from(u16::from_be_bytes([hi & 0x01, lo]));
        if ty == END_OF_LLDPDU && len == 0 {
            self.done = true;
            return None;
        }
        if rest.len() < len {
            self.done = true;
            return Some(Err(Error::Truncated));
        }
        let (value, rest) = rest.split_at(len);
        self.buf = rest;
        Some(Ok(RawTlv { ty, value }))
    }
}

/// Append one TLV (header + value) to `out`.
///
/// Fails with [`Error::TooLong`] when `value` exceeds the 9-bit length field;
/// `what` names the field in that error.
pub fn encode(ty: u8, value: &[u8], what: &'static str, out: &mut Vec<u8>) -> Result<(), Error> {
    if value.len() > MAX_VALUE_LEN {
        return Err(Error::TooLong(what));
    }
    let header = (u16::from(ty) << 9) | value.len() as u16;
    out.extend_from_slice(&header.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

/// Append the End Of LLDPDU marker to `out`.
pub fn encode_end(out: &mut Vec<u8>) {
    out.extend_from_slice(&[0, 0]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn iterates_and_stops_at_end_marker() {
        // type 5 len 3 "abc" | type 4 len 0 | end | trailing padding
        let buf = [0x0A, 0x03, b'a', b'b', b'c', 0x08, 0x00, 0x00, 0x00, 0xFF];
        let tlvs: Vec<_> = TlvIter::new(&buf).collect::<Result<_, _>>().unwrap();
        assert_eq!(
            tlvs,
            vec![
                RawTlv {
                    ty: 5,
                    value: b"abc"
                },
                RawTlv { ty: 4, value: b"" },
            ]
        );
    }

    #[test]
    fn truncated_value_yields_one_error_then_fuses() {
        let buf = [0x0A, 0x05, b'a']; // claims 5 bytes, has 1
        let mut it = TlvIter::new(&buf);
        assert_eq!(it.next(), Some(Err(Error::Truncated)));
        assert_eq!(it.next(), None);
    }

    #[test]
    fn lone_header_byte_is_truncated() {
        let mut it = TlvIter::new(&[0x0A]);
        assert_eq!(it.next(), Some(Err(Error::Truncated)));
        assert_eq!(it.next(), None);
    }

    #[test]
    fn nine_bit_length_crosses_the_byte_boundary() {
        // type 6, length 256: header 0x0D 0x00.
        let mut buf = vec![0x0D, 0x00];
        buf.extend_from_slice(&[0x55; 256]);
        let tlv = TlvIter::new(&buf).next().unwrap().unwrap();
        assert_eq!(tlv.ty, 6);
        assert_eq!(tlv.value.len(), 256);
    }

    #[test]
    fn encode_round_trips_and_caps_length() {
        let mut out = Vec::new();
        encode(5, b"host", "system name", &mut out).unwrap();
        encode_end(&mut out);
        let tlv = TlvIter::new(&out).next().unwrap().unwrap();
        assert_eq!((tlv.ty, tlv.value), (5, &b"host"[..]));

        let big = [0u8; MAX_VALUE_LEN + 1];
        assert_eq!(
            encode(5, &big, "system name", &mut out),
            Err(Error::TooLong("system name"))
        );
    }

    /// The parser must be total: arbitrary bytes never panic.
    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut seed = 0x2545F4914F6CDD1Du64;
        for _ in 0..1000 {
            let mut bytes = [0u8; 64];
            for b in &mut bytes {
                // xorshift* — deterministic garbage, no dev-dependencies.
                seed ^= seed >> 12;
                seed ^= seed << 25;
                seed ^= seed >> 27;
                *b = (seed.wrapping_mul(0x2545F4914F6CDD1D) >> 56) as u8;
            }
            for len in [0, 1, 2, 3, 17, 64] {
                let _ = TlvIter::new(&bytes[..len]).count();
            }
        }
    }
}
