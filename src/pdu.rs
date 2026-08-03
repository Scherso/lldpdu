//! A whole LLDP data unit: [`Lldpdu::parse`] from bytes, [`Lldpdu::to_bytes`]
//! back to the wire.

use crate::frame;
use crate::tlv::{self, RawTlv, TlvIter};
use crate::types::{ChassisId, ManagementAddress, OrgTlv, PortId, SystemCapabilities};
use crate::Error;
use alloc::vec::Vec;

/// One parsed (or to-be-built) LLDP data unit.
///
/// The three mandatory TLVs (§8.2: Chassis ID, Port ID, TTL, in that order,
/// first) are plain fields; every optional TLV is an `Option` or a `Vec`.
/// Unrecognized standard TLVs are preserved raw in `unknown` so callers can
/// interpret extensions this crate doesn't model, and round-tripping stays
/// lossless.
///
/// # Parsing doctrine
///
/// One rule: **the mandatory preamble must be right and TLV lengths must not
/// lie; every other TLV either folds into a typed field or is preserved
/// verbatim in `unknown`.** So a duplicated singleton (first occurrence
/// wins), non-UTF-8 text, or a malformed optional body never fails the PDU —
/// and never disappears either: it lands in `unknown`, and
/// [`Lldpdu::to_bytes`] re-emits it. Parse → build loses nothing a device
/// said, however buggy the device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lldpdu<'a> {
    /// Chassis ID (§8.5.2) — identifies the device.
    pub chassis_id: ChassisId<'a>,
    /// Port ID (§8.5.3) — identifies the sending port.
    pub port_id: PortId<'a>,
    /// Time to live in seconds (§8.5.4); 0 means "forget this neighbor now".
    pub ttl: u16,
    /// Port Description (§8.5.5).
    pub port_description: Option<&'a str>,
    /// System Name (§8.5.6) — the administratively assigned host name.
    pub system_name: Option<&'a str>,
    /// System Description (§8.5.7) — typically vendor, model, and firmware.
    pub system_description: Option<&'a str>,
    /// System Capabilities (§8.5.8).
    pub capabilities: Option<SystemCapabilities>,
    /// Management Addresses (§8.5.9); the spec allows more than one.
    pub management_addresses: Vec<ManagementAddress<'a>>,
    /// Organizationally Specific TLVs (§8.6), raw payloads preserved.
    pub org: Vec<OrgTlv<'a>>,
    /// Standard-range TLVs this crate doesn't model, preserved verbatim.
    pub unknown: Vec<RawTlv<'a>>,
}

impl<'a> Lldpdu<'a> {
    /// A data unit with the three mandatory TLVs and nothing else; set the
    /// public fields for anything optional.
    pub fn new(chassis_id: ChassisId<'a>, port_id: PortId<'a>, ttl: u16) -> Self {
        Self {
            chassis_id,
            port_id,
            ttl,
            port_description: None,
            system_name: None,
            system_description: None,
            capabilities: None,
            management_addresses: Vec::new(),
            org: Vec::new(),
            unknown: Vec::new(),
        }
    }

    /// Parse an LLDPDU payload (not a whole Ethernet frame — see
    /// [`frame::lldpdu_of`] or [`Self::parse_frame`] for that).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let mut tlvs = TlvIter::new(bytes);
        let chassis_id = ChassisId::parse(mandatory(&mut tlvs, tlv::CHASSIS_ID, "chassis id")?)?;
        let port_id = PortId::parse(mandatory(&mut tlvs, tlv::PORT_ID, "port id")?)?;
        let ttl_body = mandatory(&mut tlvs, tlv::TTL, "ttl")?;
        let ttl: [u8; 2] = ttl_body.try_into().map_err(|_| Error::Malformed("ttl"))?;

        let mut pdu = Self::new(chassis_id, port_id, u16::from_be_bytes(ttl));
        for item in tlvs {
            pdu.take_optional(item?);
        }
        Ok(pdu)
    }

    /// Parse an LLDPDU from a raw Ethernet frame (untagged, 802.1Q, or Q-in-Q).
    ///
    /// Returns [`Error::Malformed`] when the frame is not LLDP.
    pub fn parse_frame(eth: &'a [u8]) -> Result<Self, Error> {
        let payload = frame::lldpdu_of(eth).ok_or(Error::Malformed("ethernet frame"))?;
        Self::parse(payload)
    }

    /// Fold one optional TLV into a typed field, or — when it duplicates a
    /// singleton, isn't valid UTF-8, or its body doesn't parse — preserve it
    /// verbatim in `unknown`. Nothing is dropped and nothing is fatal here.
    fn take_optional(&mut self, tlv: RawTlv<'a>) {
        let folded = match tlv.ty {
            tlv::PORT_DESCRIPTION => keep_first_str(&mut self.port_description, tlv.value),
            tlv::SYSTEM_NAME => keep_first_str(&mut self.system_name, tlv.value),
            tlv::SYSTEM_DESCRIPTION => keep_first_str(&mut self.system_description, tlv.value),
            tlv::SYSTEM_CAPABILITIES => {
                fold_singleton(&mut self.capabilities, tlv.value, SystemCapabilities::parse)
            }
            tlv::MANAGEMENT_ADDRESS => ManagementAddress::parse(tlv.value)
                .map(|ma| self.management_addresses.push(ma))
                .is_ok(),
            tlv::ORG_SPECIFIC => OrgTlv::parse(tlv.value)
                .map(|org| self.org.push(org))
                .is_ok(),
            _ => false,
        };
        if !folded {
            self.unknown.push(tlv);
        }
    }

    /// Encode to wire bytes, mandatory preamble first, End Of LLDPDU last.
    ///
    /// Fails with [`Error::TooLong`] if any value exceeds its wire field.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(128);
        let mut body = Vec::new();

        encode_body(tlv::CHASSIS_ID, &mut body, &mut out, "chassis id", |b| {
            self.chassis_id.encode(b);
        })?;
        encode_body(tlv::PORT_ID, &mut body, &mut out, "port id", |b| {
            self.port_id.encode(b);
        })?;
        tlv::encode(tlv::TTL, &self.ttl.to_be_bytes(), "ttl", &mut out)?;

        if let Some(text) = self.port_description {
            encode_text(tlv::PORT_DESCRIPTION, text, "port description", &mut out)?;
        }
        if let Some(text) = self.system_name {
            encode_text(tlv::SYSTEM_NAME, text, "system name", &mut out)?;
        }
        if let Some(text) = self.system_description {
            encode_text(
                tlv::SYSTEM_DESCRIPTION,
                text,
                "system description",
                &mut out,
            )?;
        }
        if let Some(caps) = self.capabilities {
            encode_body(
                tlv::SYSTEM_CAPABILITIES,
                &mut body,
                &mut out,
                "system capabilities",
                |b| caps.encode(b),
            )?;
        }
        for ma in &self.management_addresses {
            encode_body_result(
                tlv::MANAGEMENT_ADDRESS,
                &mut body,
                &mut out,
                "management address",
                |b| ma.encode(b),
            )?;
        }
        for org in &self.org {
            encode_body(
                tlv::ORG_SPECIFIC,
                &mut body,
                &mut out,
                "organizationally specific tlv",
                |b| org.encode(b),
            )?;
        }
        for raw in &self.unknown {
            tlv::encode(raw.ty, raw.value, "unknown tlv", &mut out)?;
        }

        tlv::encode_end(&mut out);
        Ok(out)
    }
}

/// Pull the next TLV and require it to be `expected` — the §8.2 preamble is
/// strictly ordered, and a PDU that doesn't start with it is not LLDP.
fn mandatory<'a>(
    tlvs: &mut TlvIter<'a>,
    expected: u8,
    what: &'static str,
) -> Result<&'a [u8], Error> {
    match tlvs.next() {
        Some(Ok(tlv)) if tlv.ty == expected => Ok(tlv.value),
        Some(Ok(tlv)) => Err(Error::UnexpectedMandatory {
            expected: what,
            got: tlv.ty,
        }),
        Some(Err(e)) => Err(e),
        None => Err(Error::MissingMandatory(what)),
    }
}

/// Fold a text TLV into an empty slot; report whether it was taken (a full
/// slot or non-UTF-8 bytes leave the TLV for `unknown` to preserve).
fn keep_first_str<'a>(slot: &mut Option<&'a str>, value: &'a [u8]) -> bool {
    match (&*slot, core::str::from_utf8(value)) {
        (None, Ok(text)) => {
            *slot = Some(text);
            true
        }
        _ => false,
    }
}

/// Fold a parseable singleton TLV into an empty slot.
fn fold_singleton<T>(
    slot: &mut Option<T>,
    value: &[u8],
    parse: impl FnOnce(&[u8]) -> Result<T, Error>,
) -> bool {
    if slot.is_some() {
        return false;
    }
    match parse(value) {
        Ok(v) => {
            *slot = Some(v);
            true
        }
        Err(_) => false,
    }
}

/// Encode one TLV whose body is built by `fill`.
fn encode_body(
    ty: u8,
    body: &mut Vec<u8>,
    out: &mut Vec<u8>,
    what: &'static str,
    fill: impl FnOnce(&mut Vec<u8>),
) -> Result<(), Error> {
    body.clear();
    fill(body);
    tlv::encode(ty, body, what, out)
}

/// Encode one TLV whose body is built by `fill`, which may fail.
fn encode_body_result(
    ty: u8,
    body: &mut Vec<u8>,
    out: &mut Vec<u8>,
    what: &'static str,
    fill: impl FnOnce(&mut Vec<u8>) -> Result<(), Error>,
) -> Result<(), Error> {
    body.clear();
    fill(body)?;
    tlv::encode(ty, body, what, out)
}

/// Encode one UTF-8 text TLV.
fn encode_text(ty: u8, text: &str, what: &'static str, out: &mut Vec<u8>) -> Result<(), Error> {
    tlv::encode(ty, text.as_bytes(), what, out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame;

    fn sample() -> Lldpdu<'static> {
        let mut pdu = Lldpdu::new(
            ChassisId::MacAddress([0x00, 0x1B, 0x21, 0x3C, 0x4D, 0x5E]),
            PortId::InterfaceName(b"Gi1/0/24"),
            120,
        );
        pdu.system_name = Some("core-sw-1");
        pdu.system_description = Some("Example OS 9.4, stack of 2");
        pdu.port_description = Some("uplink to idf-2");
        pdu.capabilities = Some(SystemCapabilities {
            capabilities: SystemCapabilities::BRIDGE | SystemCapabilities::ROUTER,
            enabled: SystemCapabilities::BRIDGE,
        });
        pdu
    }

    fn eth(ethertype_and_payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&frame::NEAREST_BRIDGE);
        f.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
        f.extend_from_slice(ethertype_and_payload);
        f
    }

    #[test]
    fn round_trips_losslessly() {
        let pdu = sample();
        let bytes = pdu.to_bytes().unwrap();
        assert_eq!(Lldpdu::parse(&bytes).unwrap(), pdu);
    }

    #[test]
    fn minimal_mandatory_only_pdu_round_trips() {
        let pdu = Lldpdu::new(ChassisId::Local(b"c1"), PortId::Local(b"p1"), 120);
        let bytes = pdu.to_bytes().unwrap();
        assert_eq!(Lldpdu::parse(&bytes).unwrap(), pdu);
    }

    #[test]
    fn parse_frame_from_untagged_ethernet() {
        let bytes = sample().to_bytes().unwrap();
        let frame = eth(&[0x88, 0xCC]);
        let mut frame = frame;
        frame.extend_from_slice(&bytes);
        assert_eq!(Lldpdu::parse_frame(&frame).unwrap(), sample());
    }

    #[test]
    fn parse_frame_rejects_non_lldp() {
        assert_eq!(
            Lldpdu::parse_frame(&eth(&[0x08, 0x00, 0x45])),
            Err(Error::Malformed("ethernet frame"))
        );
    }

    #[test]
    fn mandatory_preamble_is_enforced_in_order() {
        // A PDU that starts with System Name instead of Chassis ID.
        let mut bytes = Vec::new();
        tlv::encode(tlv::SYSTEM_NAME, b"sw", "n", &mut bytes).unwrap();
        assert_eq!(
            Lldpdu::parse(&bytes),
            Err(Error::UnexpectedMandatory {
                expected: "chassis id",
                got: tlv::SYSTEM_NAME,
            })
        );

        // Chassis and port present but swapped.
        let good = sample().to_bytes().unwrap();
        let chassis_len = 2 + 7; // header + subtype + mac
        let port_len = 2 + 9; // header + subtype + "Gi1/0/24"
        let mut swapped = Vec::new();
        swapped.extend_from_slice(&good[chassis_len..chassis_len + port_len]);
        swapped.extend_from_slice(&good[..chassis_len]);
        swapped.extend_from_slice(&good[chassis_len + port_len..]);
        assert_eq!(
            Lldpdu::parse(&swapped),
            Err(Error::UnexpectedMandatory {
                expected: "chassis id",
                got: tlv::PORT_ID,
            })
        );
    }

    /// Append one extra TLV to a sample PDU's bytes, before the End marker.
    fn with_extra_tlv(ty: u8, value: &[u8]) -> Vec<u8> {
        let mut bytes = sample().to_bytes().unwrap();
        bytes.truncate(bytes.len() - 2); // drop End marker
        tlv::encode(ty, value, "extra", &mut bytes).unwrap();
        tlv::encode_end(&mut bytes);
        bytes
    }

    #[test]
    fn duplicate_singleton_keeps_first_and_preserves_second() {
        let bytes = with_extra_tlv(tlv::SYSTEM_NAME, b"impostor");
        let parsed = Lldpdu::parse(&bytes).unwrap();
        assert_eq!(parsed.system_name, Some("core-sw-1"));
        // The duplicate isn't dropped: it survives in `unknown`, so
        // rebuilding reproduces everything the device sent.
        assert_eq!(
            parsed.unknown,
            [RawTlv {
                ty: tlv::SYSTEM_NAME,
                value: b"impostor"
            }]
        );
        let rebuilt = parsed.to_bytes().unwrap();
        assert_eq!(Lldpdu::parse(&rebuilt).unwrap(), parsed);
    }

    #[test]
    fn duplicate_capabilities_keeps_first_and_preserves_second() {
        let mut caps_body = Vec::new();
        SystemCapabilities {
            capabilities: SystemCapabilities::ROUTER,
            enabled: SystemCapabilities::ROUTER,
        }
        .encode(&mut caps_body);
        let bytes = with_extra_tlv(tlv::SYSTEM_CAPABILITIES, &caps_body);
        let parsed = Lldpdu::parse(&bytes).unwrap();
        assert_eq!(
            parsed.capabilities,
            Some(SystemCapabilities {
                capabilities: SystemCapabilities::BRIDGE | SystemCapabilities::ROUTER,
                enabled: SystemCapabilities::BRIDGE,
            })
        );
        assert_eq!(
            parsed.unknown,
            [RawTlv {
                ty: tlv::SYSTEM_CAPABILITIES,
                value: &caps_body
            }]
        );
    }

    #[test]
    fn invalid_utf8_text_is_preserved_not_fatal() {
        let mut pdu = sample();
        pdu.system_name = None;
        let mut bytes = pdu.to_bytes().unwrap();
        bytes.truncate(bytes.len() - 2);
        tlv::encode(tlv::SYSTEM_NAME, &[0xFF, 0xFE], "n", &mut bytes).unwrap();
        tlv::encode_end(&mut bytes);
        let parsed = Lldpdu::parse(&bytes).unwrap();
        assert_eq!(parsed.system_name, None);
        assert_eq!(
            parsed.unknown,
            [RawTlv {
                ty: tlv::SYSTEM_NAME,
                value: &[0xFF, 0xFE]
            }]
        );
    }

    #[test]
    fn malformed_optional_body_is_preserved_not_fatal() {
        // A management address TLV whose body is garbage must not kill the
        // PDU — the neighbor's identity is still perfectly good.
        let bytes = with_extra_tlv(tlv::MANAGEMENT_ADDRESS, &[0xFF]);
        let parsed = Lldpdu::parse(&bytes).unwrap();
        assert_eq!(parsed.system_name, Some("core-sw-1"));
        assert!(parsed.management_addresses.is_empty());
        assert_eq!(
            parsed.unknown,
            [RawTlv {
                ty: tlv::MANAGEMENT_ADDRESS,
                value: &[0xFF]
            }]
        );
        let rebuilt = parsed.to_bytes().unwrap();
        assert_eq!(Lldpdu::parse(&rebuilt).unwrap(), parsed);
    }

    #[test]
    fn unknown_tlvs_survive_a_round_trip() {
        let mut pdu = sample();
        pdu.unknown.push(RawTlv {
            ty: 9,
            value: b"\x01\x02",
        });
        let bytes = pdu.to_bytes().unwrap();
        assert_eq!(Lldpdu::parse(&bytes).unwrap(), pdu);
    }

    #[test]
    fn truncated_pdu_never_panics_and_preamble_cuts_fail() {
        let bytes = sample().to_bytes().unwrap();
        let preamble = 9 + 11 + 4; // chassis + port + ttl TLVs incl. headers
        for cut in 0..bytes.len() {
            let parsed = Lldpdu::parse(&bytes[..cut]);
            if cut < preamble {
                // Inside the mandatory preamble every cut is fatal…
                assert!(parsed.is_err(), "cut={cut}");
            } else if let Err(e) = parsed {
                // …after it, a cut at a TLV boundary is a valid shorter PDU
                // and a cut inside a TLV is Truncated — nothing else.
                assert_eq!(e, Error::Truncated, "cut={cut}");
            }
        }
    }

    #[test]
    fn shutdown_pdu_ttl_zero_parses() {
        let pdu = Lldpdu::new(ChassisId::Local(b"c1"), PortId::Local(b"p1"), 0);
        let bytes = pdu.to_bytes().unwrap();
        let parsed = Lldpdu::parse(&bytes).unwrap();
        assert_eq!(parsed.ttl, 0);
    }
}
