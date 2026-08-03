//! The typed vocabulary of 802.1AB §8.5: identifiers, capabilities, and
//! addresses carried by the standard TLVs. Everything borrows from the input
//! buffer; nothing here allocates.

use crate::Error;
use alloc::vec::Vec;
use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A network address as LLDP encodes one: an IANA address-family number
/// followed by the address bytes (§8.5.9.4). IPv4 and IPv6 get typed
/// accessors; anything else stays available as raw bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkAddress<'a> {
    /// IANA address family number (1 = IPv4, 2 = IPv6, …).
    pub family: u8,
    /// The address bytes, whose meaning depends on `family`.
    pub bytes: &'a [u8],
}

impl NetworkAddress<'_> {
    /// IANA address family number for IPv4.
    pub const FAMILY_IPV4: u8 = 1;
    /// IANA address family number for IPv6.
    pub const FAMILY_IPV6: u8 = 2;

    /// The address as an [`IpAddr`], when the family is IPv4 or IPv6 and the
    /// byte count matches.
    pub fn ip(&self) -> Option<IpAddr> {
        match (self.family, self.bytes) {
            (Self::FAMILY_IPV4, &[a, b, c, d]) => Some(Ipv4Addr::new(a, b, c, d).into()),
            (Self::FAMILY_IPV6, bytes) => {
                let sixteen: [u8; 16] = bytes.try_into().ok()?;
                Some(Ipv6Addr::from(sixteen).into())
            }
            _ => None,
        }
    }
}

/// Chassis ID (§8.5.2): what identifies the whole device. The subtype tells
/// you which naming scheme the value uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChassisId<'a> {
    /// Subtype 1: entPhysicalAlias of a chassis component.
    ChassisComponent(&'a [u8]),
    /// Subtype 2: ifAlias of an interface.
    InterfaceAlias(&'a [u8]),
    /// Subtype 3: entPhysicalAlias of a backplane/port component.
    PortComponent(&'a [u8]),
    /// Subtype 4: a MAC address — the most common choice on switches.
    MacAddress([u8; 6]),
    /// Subtype 5: a network address.
    NetworkAddress(NetworkAddress<'a>),
    /// Subtype 6: ifName of an interface.
    InterfaceName(&'a [u8]),
    /// Subtype 7: an identifier assigned by the local operator.
    Local(&'a [u8]),
    /// A subtype this crate doesn't know; value preserved verbatim.
    Other {
        /// The wire subtype byte.
        subtype: u8,
        /// The identifier bytes.
        value: &'a [u8],
    },
}

/// Port ID (§8.5.3): what identifies the sending port on that device.
/// Same shape as [`ChassisId`] but the subtype numbering differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortId<'a> {
    /// Subtype 1: ifAlias of the port.
    InterfaceAlias(&'a [u8]),
    /// Subtype 2: entPhysicalAlias of a port component.
    PortComponent(&'a [u8]),
    /// Subtype 3: the port's MAC address.
    MacAddress([u8; 6]),
    /// Subtype 4: a network address.
    NetworkAddress(NetworkAddress<'a>),
    /// Subtype 5: ifName — the most common choice ("Gi1/0/24").
    InterfaceName(&'a [u8]),
    /// Subtype 6: agent circuit ID (RFC 3046).
    AgentCircuitId(&'a [u8]),
    /// Subtype 7: an identifier assigned by the local operator.
    Local(&'a [u8]),
    /// A subtype this crate doesn't know; value preserved verbatim.
    Other {
        /// The wire subtype byte.
        subtype: u8,
        /// The identifier bytes.
        value: &'a [u8],
    },
}

/// Split `n` bytes off the front, or `None` when fewer remain. The one
/// length-checking primitive every TLV-body parser composes from.
fn take(bytes: &[u8], n: usize) -> Option<(&[u8], &[u8])> {
    (n <= bytes.len()).then(|| bytes.split_at(n))
}

/// A tag byte followed by a non-empty value — the shared shape of Chassis ID,
/// Port ID, and LLDP network addresses (identifiers are 1..=255 bytes).
fn tagged(body: &[u8]) -> Option<(u8, &[u8])> {
    match body.split_first() {
        Some((&tag, value)) if !value.is_empty() => Some((tag, value)),
        _ => None,
    }
}

fn parse_mac(value: &[u8]) -> Option<[u8; 6]> {
    value.try_into().ok()
}

fn parse_network_address(value: &[u8]) -> Option<NetworkAddress<'_>> {
    let (family, bytes) = tagged(value)?;
    Some(NetworkAddress { family, bytes })
}

fn encode_tagged_id(subtype: u8, value: &[u8], out: &mut Vec<u8>) {
    out.push(subtype);
    out.extend_from_slice(value);
}

fn encode_tagged_network_id(subtype: u8, addr: &NetworkAddress<'_>, out: &mut Vec<u8>) {
    out.push(subtype);
    out.push(addr.family);
    out.extend_from_slice(addr.bytes);
}

fn write_mac(f: &mut fmt::Formatter<'_>, mac: &[u8; 6]) -> fmt::Result {
    for (i, byte) in mac.iter().enumerate() {
        if i > 0 {
            f.write_str(":")?;
        }
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}

fn write_bytes(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    match core::str::from_utf8(bytes) {
        Ok(text) => f.write_str(text),
        Err(_) => {
            for (i, byte) in bytes.iter().enumerate() {
                if i > 0 {
                    f.write_str(":")?;
                }
                write!(f, "{byte:02x}")?;
            }
            Ok(())
        }
    }
}

impl<'a> ChassisId<'a> {
    /// Parse a Chassis ID TLV body (subtype byte + identifier).
    pub fn parse(body: &'a [u8]) -> Result<Self, Error> {
        Self::of(body).ok_or(Error::Malformed("chassis id"))
    }

    /// The Option-shaped parse; the public boundary attaches the error.
    fn of(body: &'a [u8]) -> Option<Self> {
        let (subtype, value) = tagged(body)?;
        Some(match subtype {
            1 => Self::ChassisComponent(value),
            2 => Self::InterfaceAlias(value),
            3 => Self::PortComponent(value),
            4 => Self::MacAddress(parse_mac(value)?),
            5 => Self::NetworkAddress(parse_network_address(value)?),
            6 => Self::InterfaceName(value),
            7 => Self::Local(value),
            subtype => Self::Other { subtype, value },
        })
    }

    /// Encode as a TLV body (subtype byte + identifier).
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::ChassisComponent(v) => encode_tagged_id(1, v, out),
            Self::InterfaceAlias(v) => encode_tagged_id(2, v, out),
            Self::PortComponent(v) => encode_tagged_id(3, v, out),
            Self::MacAddress(m) => encode_tagged_id(4, m, out),
            Self::NetworkAddress(a) => encode_tagged_network_id(5, a, out),
            Self::InterfaceName(v) => encode_tagged_id(6, v, out),
            Self::Local(v) => encode_tagged_id(7, v, out),
            Self::Other { subtype, value } => encode_tagged_id(*subtype, value, out),
        }
    }
}

impl fmt::Display for ChassisId<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChassisComponent(v) => {
                f.write_str("chassis-component ")?;
                write_bytes(f, v)
            }
            Self::InterfaceAlias(v) => {
                f.write_str("interface-alias ")?;
                write_bytes(f, v)
            }
            Self::PortComponent(v) => {
                f.write_str("port-component ")?;
                write_bytes(f, v)
            }
            Self::MacAddress(m) => {
                f.write_str("mac ")?;
                write_mac(f, m)
            }
            Self::NetworkAddress(a) => {
                write!(f, "network-address({}) ", a.family)?;
                write_bytes(f, a.bytes)
            }
            Self::InterfaceName(v) => {
                f.write_str("interface-name ")?;
                write_bytes(f, v)
            }
            Self::Local(v) => {
                f.write_str("local ")?;
                write_bytes(f, v)
            }
            Self::Other { subtype, value } => {
                write!(f, "other({subtype}) ")?;
                write_bytes(f, value)
            }
        }
    }
}

impl<'a> PortId<'a> {
    /// Parse a Port ID TLV body (subtype byte + identifier).
    pub fn parse(body: &'a [u8]) -> Result<Self, Error> {
        Self::of(body).ok_or(Error::Malformed("port id"))
    }

    /// The Option-shaped parse; the public boundary attaches the error.
    fn of(body: &'a [u8]) -> Option<Self> {
        let (subtype, value) = tagged(body)?;
        Some(match subtype {
            1 => Self::InterfaceAlias(value),
            2 => Self::PortComponent(value),
            3 => Self::MacAddress(parse_mac(value)?),
            4 => Self::NetworkAddress(parse_network_address(value)?),
            5 => Self::InterfaceName(value),
            6 => Self::AgentCircuitId(value),
            7 => Self::Local(value),
            subtype => Self::Other { subtype, value },
        })
    }

    /// Encode as a TLV body (subtype byte + identifier).
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::InterfaceAlias(v) => encode_tagged_id(1, v, out),
            Self::PortComponent(v) => encode_tagged_id(2, v, out),
            Self::MacAddress(m) => encode_tagged_id(3, m, out),
            Self::NetworkAddress(a) => encode_tagged_network_id(4, a, out),
            Self::InterfaceName(v) => encode_tagged_id(5, v, out),
            Self::AgentCircuitId(v) => encode_tagged_id(6, v, out),
            Self::Local(v) => encode_tagged_id(7, v, out),
            Self::Other { subtype, value } => encode_tagged_id(*subtype, value, out),
        }
    }
}

impl fmt::Display for PortId<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InterfaceAlias(v) => {
                f.write_str("interface-alias ")?;
                write_bytes(f, v)
            }
            Self::PortComponent(v) => {
                f.write_str("port-component ")?;
                write_bytes(f, v)
            }
            Self::MacAddress(m) => {
                f.write_str("mac ")?;
                write_mac(f, m)
            }
            Self::NetworkAddress(a) => {
                write!(f, "network-address({}) ", a.family)?;
                write_bytes(f, a.bytes)
            }
            Self::InterfaceName(v) => {
                f.write_str("interface-name ")?;
                write_bytes(f, v)
            }
            Self::AgentCircuitId(v) => {
                f.write_str("agent-circuit-id ")?;
                write_bytes(f, v)
            }
            Self::Local(v) => {
                f.write_str("local ")?;
                write_bytes(f, v)
            }
            Self::Other { subtype, value } => {
                write!(f, "other({subtype}) ")?;
                write_bytes(f, value)
            }
        }
    }
}

/// System Capabilities (§8.5.8): two 16-bit masks — what the device *can* do
/// and what is currently *enabled*. Bit positions per Table 8-4.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SystemCapabilities {
    /// Everything the system supports.
    pub capabilities: u16,
    /// The subset currently enabled.
    pub enabled: u16,
}

impl SystemCapabilities {
    /// Bit 0: other.
    pub const OTHER: u16 = 1 << 0;
    /// Bit 1: repeater.
    pub const REPEATER: u16 = 1 << 1;
    /// Bit 2: MAC bridge (switch).
    pub const BRIDGE: u16 = 1 << 2;
    /// Bit 3: 802.11 access point.
    pub const WLAN_ACCESS_POINT: u16 = 1 << 3;
    /// Bit 4: router.
    pub const ROUTER: u16 = 1 << 4;
    /// Bit 5: telephone.
    pub const TELEPHONE: u16 = 1 << 5;
    /// Bit 6: DOCSIS cable device.
    pub const DOCSIS: u16 = 1 << 6;
    /// Bit 7: station only.
    pub const STATION_ONLY: u16 = 1 << 7;
    /// Bit 8: C-VLAN component of a VLAN bridge.
    pub const C_VLAN: u16 = 1 << 8;
    /// Bit 9: S-VLAN component of a VLAN bridge.
    pub const S_VLAN: u16 = 1 << 9;
    /// Bit 10: two-port MAC relay.
    pub const TPMR: u16 = 1 << 10;

    /// Parse a System Capabilities TLV body (4 bytes).
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        let &[c1, c0, e1, e0] = body else {
            return Err(Error::Malformed("system capabilities"));
        };
        Ok(Self {
            capabilities: u16::from_be_bytes([c1, c0]),
            enabled: u16::from_be_bytes([e1, e0]),
        })
    }

    /// Encode as a TLV body.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.capabilities.to_be_bytes());
        out.extend_from_slice(&self.enabled.to_be_bytes());
    }

    /// True when `bit` (one of the associated constants) is enabled.
    pub fn is_enabled(&self, bit: u16) -> bool {
        self.enabled & bit != 0
    }
}

/// Management Address (§8.5.9): how to reach the device's management plane,
/// plus which interface the address lives on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagementAddress<'a> {
    /// The management address itself.
    pub address: NetworkAddress<'a>,
    /// Interface numbering subtype: 1 unknown, 2 ifIndex, 3 system port.
    pub interface_subtype: u8,
    /// The interface number in the scheme above.
    pub interface_number: u32,
    /// Object identifier of the hardware/protocol entity, often empty.
    pub oid: &'a [u8],
}

impl<'a> ManagementAddress<'a> {
    /// Parse a Management Address TLV body.
    ///
    /// Wire layout: address-string length (covering family + address), family
    /// byte, address bytes, interface subtype, 4-byte interface number, OID
    /// length, OID bytes.
    pub fn parse(body: &'a [u8]) -> Result<Self, Error> {
        Self::of(body).ok_or(Error::Malformed("management address"))
    }

    /// The Option-shaped parse; the public boundary attaches the error.
    fn of(body: &'a [u8]) -> Option<Self> {
        let (&addr_len, rest) = body.split_first()?;
        let (addr, rest) = take(rest, usize::from(addr_len))?;
        // `tagged` also enforces addr_len >= 2: family byte + real address.
        let (family, bytes) = tagged(addr)?;
        // The fixed middle, as a pattern: subtype, 4 number bytes, OID length.
        let &[interface_subtype, n0, n1, n2, n3, oid_len, ref rest @ ..] = rest else {
            return None;
        };
        let (oid, _) = take(rest, usize::from(oid_len))?;
        Some(Self {
            address: NetworkAddress { family, bytes },
            interface_subtype,
            interface_number: u32::from_be_bytes([n0, n1, n2, n3]),
            oid,
        })
    }

    /// Encode as a TLV body. Fails when the address or OID exceeds its
    /// one-byte length field.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let addr_len = self.address.bytes.len() + 1; // + family byte
        if addr_len > usize::from(u8::MAX) {
            return Err(Error::TooLong("management address"));
        }
        if self.oid.len() > usize::from(u8::MAX) {
            return Err(Error::TooLong("management address oid"));
        }
        out.push(addr_len as u8);
        out.push(self.address.family);
        out.extend_from_slice(self.address.bytes);
        out.push(self.interface_subtype);
        out.extend_from_slice(&self.interface_number.to_be_bytes());
        out.push(self.oid.len() as u8);
        out.extend_from_slice(self.oid);
        Ok(())
    }
}

/// An Organizationally Specific TLV (§8.6): a three-byte OUI names the org
/// (e.g. `00-12-BB` LLDP-MED, `00-80-C2` IEEE 802.1), a subtype names the
/// TLV within it, and the payload stays raw for the caller to interpret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrgTlv<'a> {
    /// Organizationally unique identifier.
    pub oui: [u8; 3],
    /// TLV subtype within that organization's numbering.
    pub subtype: u8,
    /// The organizationally defined payload.
    pub info: &'a [u8],
}

impl<'a> OrgTlv<'a> {
    /// Parse an Organizationally Specific TLV body (OUI + subtype + info).
    pub fn parse(body: &'a [u8]) -> Result<Self, Error> {
        let &[o0, o1, o2, subtype, ref info @ ..] = body else {
            return Err(Error::Malformed("organizationally specific tlv"));
        };
        Ok(Self {
            oui: [o0, o1, o2],
            subtype,
            info,
        })
    }

    /// Encode as a TLV body.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.oui);
        out.push(self.subtype);
        out.extend_from_slice(self.info);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec::Vec;

    #[test]
    fn chassis_id_mac_round_trips() {
        let id = ChassisId::MacAddress([0, 1, 2, 3, 4, 5]);
        let mut body = Vec::new();
        id.encode(&mut body);
        assert_eq!(ChassisId::parse(&body).unwrap(), id);
        assert_eq!(id.to_string(), "mac 00:01:02:03:04:05");
    }

    #[test]
    fn chassis_id_rejects_short_mac_and_empty_value() {
        assert_eq!(
            ChassisId::parse(&[4, 0, 1, 2]),
            Err(Error::Malformed("chassis id"))
        );
        assert_eq!(ChassisId::parse(&[6]), Err(Error::Malformed("chassis id")));
        assert_eq!(ChassisId::parse(&[]), Err(Error::Malformed("chassis id")));
    }

    #[test]
    fn unknown_subtype_is_preserved_not_rejected() {
        let id = ChassisId::parse(&[9, b'x']).unwrap();
        assert_eq!(
            id,
            ChassisId::Other {
                subtype: 9,
                value: b"x"
            }
        );
    }

    #[test]
    fn network_address_ip_accessor() {
        let v4 = NetworkAddress {
            family: 1,
            bytes: &[10, 0, 0, 1],
        };
        assert_eq!(v4.ip(), Some(IpAddr::from(Ipv4Addr::new(10, 0, 0, 1))));
        let bad = NetworkAddress {
            family: 1,
            bytes: &[10, 0],
        };
        assert_eq!(bad.ip(), None);
    }

    #[test]
    fn capabilities_round_trip_and_bits() {
        let caps = SystemCapabilities {
            capabilities: SystemCapabilities::BRIDGE | SystemCapabilities::ROUTER,
            enabled: SystemCapabilities::BRIDGE,
        };
        let mut body = Vec::new();
        caps.encode(&mut body);
        let parsed = SystemCapabilities::parse(&body).unwrap();
        assert_eq!(parsed, caps);
        assert!(parsed.is_enabled(SystemCapabilities::BRIDGE));
        assert!(!parsed.is_enabled(SystemCapabilities::ROUTER));
    }

    #[test]
    fn management_address_round_trips() {
        let ma = ManagementAddress {
            address: NetworkAddress {
                family: 1,
                bytes: &[192, 168, 1, 1],
            },
            interface_subtype: 2,
            interface_number: 7,
            oid: b"",
        };
        let mut body = Vec::new();
        ma.encode(&mut body).unwrap();
        let parsed = ManagementAddress::parse(&body).unwrap();
        assert_eq!(parsed, ma);
        assert_eq!(parsed.address.ip(), "192.168.1.1".parse().ok());
    }

    #[test]
    fn management_address_rejects_truncation_everywhere() {
        let ma = ManagementAddress {
            address: NetworkAddress {
                family: 1,
                bytes: &[192, 168, 1, 1],
            },
            interface_subtype: 2,
            interface_number: 7,
            oid: b"oid",
        };
        let mut body = Vec::new();
        ma.encode(&mut body).unwrap();
        // Every proper prefix must fail cleanly, never panic.
        for cut in 0..body.len() {
            assert!(ManagementAddress::parse(&body[..cut]).is_err(), "cut={cut}");
        }
    }

    #[test]
    fn org_tlv_round_trips() {
        let org = OrgTlv {
            oui: [0x00, 0x12, 0xBB],
            subtype: 1,
            info: b"\x00\x0f",
        };
        let mut body = Vec::new();
        org.encode(&mut body);
        assert_eq!(OrgTlv::parse(&body).unwrap(), org);
        assert!(OrgTlv::parse(&[0, 0x12]).is_err());
    }

    #[test]
    fn port_id_display_formats_interface_name() {
        let id = PortId::InterfaceName(b"Gi1/0/24");
        assert_eq!(id.to_string(), "interface-name Gi1/0/24");
    }
}
