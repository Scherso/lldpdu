//! Parse and build IEEE 802.1AB LLDP data units (LLDPDUs).
//!
//! LLDP (Link Layer Discovery Protocol) is how switches, routers, access
//! points, and phones announce who they are to their link neighbors: chassis
//! and port identity, system name and description, capabilities, and
//! management addresses, encoded as a sequence of TLVs inside an Ethernet
//! frame of EtherType `0x88CC`.
//!
//! This crate is deliberately small and layered:
//!
//! - [`tlv`] — the raw TLV wire layer: a bounds-checked iterator over
//!   type/length/value triples, and the corresponding encoder. Use this layer
//!   alone if you only need generic TLV walking.
//! - [`types`] — the typed vocabulary of 802.1AB §8.5: [`ChassisId`],
//!   [`PortId`], [`SystemCapabilities`], [`ManagementAddress`], [`OrgTlv`].
//! - [`pdu`] — [`Lldpdu`]: a whole data unit, parsed from bytes
//!   ([`Lldpdu::parse`], [`Lldpdu::parse_frame`]) or built back into bytes
//!   ([`Lldpdu::to_bytes`]).
//! - [`frame`] — Ethernet helpers: the LLDP EtherType, the three destination
//!   group addresses, and [`frame::lldpdu_of`] to locate the LLDPDU payload
//!   inside a captured frame (802.1Q-tagged, including Q-in-Q, or not).
//!
//! # Design rules
//!
//! - **No panics on untrusted input.** Every parser is total: malformed bytes
//!   yield an [`Error`], never an index out of bounds. There is no `unsafe`
//!   anywhere ([`forbid(unsafe_code)`]).
//! - **Zero dependencies, `no_std` + `alloc`.** The parser borrows from the
//!   input buffer (zero-copy); allocation is only used for the repeatable
//!   TLV collections on [`Lldpdu`] and for building.
//! - **One parsing rule.** The mandatory preamble (Chassis ID, Port ID, TTL —
//!   §8.2) must be right and TLV lengths must not lie; every other TLV either
//!   folds into a typed field or is preserved verbatim in
//!   [`Lldpdu::unknown`]. Real gear ships real bugs, so nothing optional is
//!   ever fatal — and nothing is ever silently dropped either.
//!
//! # Example
//!
//! ```
//! use lldpdu::{ChassisId, Lldpdu, PortId};
//!
//! // Build an announcement…
//! let mut pdu = Lldpdu::new(
//!     ChassisId::MacAddress([0x02, 0x00, 0x5e, 0x10, 0x00, 0x01]),
//!     PortId::InterfaceName(b"eth0"),
//!     120,
//! );
//! pdu.system_name = Some("core-sw-1");
//! let bytes = pdu.to_bytes().unwrap();
//!
//! // …and parse it back.
//! let parsed = Lldpdu::parse(&bytes).unwrap();
//! assert_eq!(parsed.system_name, Some("core-sw-1"));
//! assert_eq!(parsed.ttl, 120);
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod frame;
pub mod pdu;
pub mod tlv;
pub mod types;

pub use pdu::Lldpdu;
pub use tlv::{RawTlv, TlvIter};
pub use types::{ChassisId, ManagementAddress, NetworkAddress, OrgTlv, PortId, SystemCapabilities};

/// Everything that can go wrong parsing or building an LLDPDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The buffer ended in the middle of a TLV header or value.
    Truncated,
    /// A TLV's content is structurally invalid; the message names the field.
    Malformed(&'static str),
    /// A mandatory TLV (Chassis ID, Port ID, TTL) is absent; the message names
    /// the missing TLV.
    MissingMandatory(&'static str),
    /// A mandatory TLV slot held the wrong type; the message names the
    /// expected TLV and the type byte that was found instead.
    UnexpectedMandatory {
        /// The mandatory TLV that was expected (e.g. `"chassis id"`).
        expected: &'static str,
        /// The TLV type byte that appeared in that slot.
        got: u8,
    },
    /// Building: a value exceeds its wire field (e.g. a TLV value longer than
    /// the 9-bit length can carry); the message names the field.
    TooLong(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated LLDPDU"),
            Self::Malformed(what) => write!(f, "malformed {what}"),
            Self::MissingMandatory(what) => write!(f, "missing mandatory {what}"),
            Self::UnexpectedMandatory { expected, got } => {
                write!(f, "expected mandatory {expected}, got tlv type {got}")
            }
            Self::TooLong(what) => write!(f, "{what} too long to encode"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
