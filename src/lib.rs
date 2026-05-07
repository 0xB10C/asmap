mod interpret;
mod validate;

use std::fmt;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

/// Errors that can occur when loading asmap data.
#[derive(Debug)]
pub enum AsmapError {
    Io(std::io::Error),
    Invalid,
}

impl fmt::Display for AsmapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AsmapError::Io(e) => write!(f, "failed to read asmap file: {e}"),
            AsmapError::Invalid => write!(f, "asmap data failed validation"),
        }
    }
}

impl std::error::Error for AsmapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AsmapError::Io(e) => Some(e),
            AsmapError::Invalid => None,
        }
    }
}

impl From<std::io::Error> for AsmapError {
    fn from(e: std::io::Error) -> Self {
        AsmapError::Io(e)
    }
}

/// A validated asmap that maps IP addresses to Autonomous System Numbers (ASNs).
///
/// The asmap is validated on construction. Lookups are infallible — an unmapped
/// address returns ASN 0.
///
/// # Example
///
/// ```no_run
/// use asmap::Asmap;
/// use std::net::IpAddr;
///
/// let map = Asmap::from_file("path/to/asmap.dat").unwrap();
/// let asn = map.lookup("8.8.8.8".parse::<IpAddr>().unwrap());
/// println!("ASN: {asn}");
/// ```
#[derive(Debug)]
pub struct Asmap {
    data: Vec<u8>,
    /// Length of the actual asmap data (excluding the 7-byte read padding).
    len: usize,
}

impl Asmap {
    /// Load and validate an asmap from a file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, AsmapError> {
        let data = fs::read(path)?;
        Self::from_bytes(data)
    }

    /// Validate and wrap raw asmap bytes.
    pub fn from_bytes(mut data: Vec<u8>) -> Result<Self, AsmapError> {
        if !validate::sanity_check(&data, 128) {
            return Err(AsmapError::Invalid);
        }
        let len = data.len();
        // Pad with 7 zero bytes so the interpreter can always do aligned u64 loads
        // without bounds checking near the end of the data.
        data.extend_from_slice(&[0u8; 7]);
        Ok(Asmap { data, len })
    }

    /// Look up the ASN for an IP address. Returns 0 if unmapped.
    pub fn lookup(&self, addr: IpAddr) -> u32 {
        let ip6 = match addr {
            IpAddr::V4(v4) => v4.to_ipv6_mapped(),
            IpAddr::V6(v6) => v6,
        };
        interpret::interpret(&self.data, &ip6.octets())
    }

    /// Look up the ASN for an IPv4 address. Returns 0 if unmapped.
    pub fn lookup_v4(&self, addr: Ipv4Addr) -> u32 {
        self.lookup(IpAddr::V4(addr))
    }

    /// Look up the ASN for an IPv6 address. Returns 0 if unmapped.
    pub fn lookup_v6(&self, addr: Ipv6Addr) -> u32 {
        self.lookup(IpAddr::V6(addr))
    }

    /// Returns the raw asmap data (without internal padding).
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }
}
