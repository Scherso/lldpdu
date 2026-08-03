//! Ethernet-level helpers: where LLDP lives on the wire.
//!
//! LLDP frames carry EtherType [`ETHERTYPE`] (`0x88CC`) and are sent to one
//! of three link-scoped group addresses, chosen by how far the announcement
//! should propagate (802.1AB §7.1): [`NEAREST_BRIDGE`] is what almost every
//! deployment uses.
//!
//! [`lldpdu_of`] walks past any number of 802.1Q VLAN tags (including Q-in-Q)
//! before reading the inner EtherType.

/// The LLDP EtherType.
pub const ETHERTYPE: u16 = 0x88CC;

/// `01-80-C2-00-00-0E`: stopped by every bridge — the per-link scope that
/// ordinary LLDP deployments use.
pub const NEAREST_BRIDGE: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E];

/// `01-80-C2-00-00-03`: forwarded by two-port MAC relays, stopped by bridges.
pub const NEAREST_NON_TPMR_BRIDGE: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x03];

/// `01-80-C2-00-00-00`: forwarded by provider bridges — customer scope.
pub const NEAREST_CUSTOMER_BRIDGE: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x00];

/// The 802.1Q VLAN tag protocol identifier.
const TPID_8021Q: u16 = 0x8100;

/// Locate the LLDPDU payload inside a raw Ethernet frame, or `None` when the
/// frame isn't LLDP. Steps over any number of 802.1Q VLAN tags (Q-in-Q
/// included) before checking the inner EtherType.
///
/// ```
/// use lldpdu::frame;
///
/// let mut eth = Vec::new();
/// eth.extend_from_slice(&frame::NEAREST_BRIDGE);       // destination
/// eth.extend_from_slice(&[2, 0, 0, 0, 0, 1]);          // source
/// eth.extend_from_slice(&frame::ETHERTYPE.to_be_bytes());
/// eth.extend_from_slice(&[0x02, 0x01, 0x07]);          // the LLDPDU bytes…
///
/// assert_eq!(frame::lldpdu_of(&eth), Some(&[0x02, 0x01, 0x07][..]));
/// ```
pub fn lldpdu_of(frame: &[u8]) -> Option<&[u8]> {
    // Destination (6) + source (6) already skipped ahead of the EtherType.
    let mut rest = frame.get(12..)?;
    loop {
        let (ethertype, payload) = ethertype_of(rest)?;
        match ethertype {
            ETHERTYPE => return Some(payload),
            TPID_8021Q => rest = payload.get(2..)?, // skip TCI, peel another tag
            _ => return None,
        }
    }
}

/// Split a big-endian u16 off the front of `bytes`.
fn ethertype_of(bytes: &[u8]) -> Option<(u16, &[u8])> {
    match bytes {
        [hi, lo, rest @ ..] => Some((u16::from_be_bytes([*hi, *lo]), rest)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn eth(ethertype_and_payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&NEAREST_BRIDGE);
        f.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
        f.extend_from_slice(ethertype_and_payload);
        f
    }

    #[test]
    fn untagged_lldp_frame_yields_payload() {
        let f = eth(&[0x88, 0xCC, 0xAA, 0xBB]);
        assert_eq!(lldpdu_of(&f), Some(&[0xAA, 0xBB][..]));
    }

    #[test]
    fn vlan_tagged_lldp_frame_yields_payload() {
        // 802.1Q tag: TPID 0x8100, TCI 0x0064 (VLAN 100), then LLDP.
        let f = eth(&[0x81, 0x00, 0x00, 0x64, 0x88, 0xCC, 0xAA]);
        assert_eq!(lldpdu_of(&f), Some(&[0xAA][..]));
    }

    #[test]
    fn q_in_q_tagged_lldp_frame_yields_payload() {
        // Outer tag (VLAN 100), inner tag (VLAN 200), then LLDP.
        let f = eth(&[
            0x81, 0x00, 0x00, 0x64, 0x81, 0x00, 0x00, 0xC8, 0x88, 0xCC, 0xAA,
        ]);
        assert_eq!(lldpdu_of(&f), Some(&[0xAA][..]));
    }

    #[test]
    fn non_lldp_and_short_frames_yield_none() {
        assert_eq!(lldpdu_of(&eth(&[0x08, 0x00, 0x45])), None); // IPv4
        assert_eq!(lldpdu_of(&[0x01, 0x80]), None); // runt
        assert_eq!(lldpdu_of(&eth(&[0x81, 0x00, 0x00])), None); // cut tag
    }
}
