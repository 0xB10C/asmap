//! IP to ASN lookup using Bitcoin Core's asmap binary trie format.
//!
//! An asmap file is a compact binary encoding of a mapping from IP prefixes to
//! Autonomous System Numbers (ASNs). This crate loads and validates asmap files,
//! then provides fast lookups for both IPv4 and IPv6 addresses.
//!
//! # Example
//!
//! ```
//! # let path = "fixtures/1772726400_asmap.dat";
//! use asmap::Asmap;
//! use std::net::IpAddr;
//!
//! let map = Asmap::from_file(path)?;
//! let asn = map.lookup("8.8.8.8".parse::<IpAddr>().unwrap());
//! assert_eq!(asn, 15169); // Google
//! # Ok::<(), asmap::AsmapError>(())
//! ```
//!
//! IPv4 addresses are automatically mapped to IPv6 (`::ffff:x.x.x.x`) before
//! lookup, matching how Bitcoin Core handles them internally.

mod interpret;
mod validate;

use std::fmt;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

/// Errors that can occur when loading asmap data.
///
/// # Example
///
/// ```
/// use asmap::{Asmap, AsmapError};
///
/// let result = Asmap::from_bytes(vec![0xFF; 16]);
/// assert!(matches!(result, Err(AsmapError::Invalid)));
///
/// let result = Asmap::from_file("/nonexistent");
/// assert!(matches!(result, Err(AsmapError::Io(_))));
/// ```
#[derive(Debug)]
pub enum AsmapError {
    /// An I/O error occurred while reading the asmap file.
    Io(std::io::Error),
    /// The asmap data failed structural validation.
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
/// # Loading from a file
///
/// ```
/// # let path = "fixtures/1772726400_asmap.dat";
/// use asmap::Asmap;
///
/// let map = Asmap::from_file(path)?;
/// # Ok::<(), asmap::AsmapError>(())
/// ```
///
/// # Loading from bytes
///
/// ```
/// # let path = "fixtures/1772726400_asmap.dat";
/// use asmap::Asmap;
///
/// let data = std::fs::read(path)?;
/// let map = Asmap::from_bytes(data)?;
/// # Ok::<(), asmap::AsmapError>(())
/// ```
///
/// # Looking up addresses
///
/// ```
/// # let map = asmap::Asmap::from_file("fixtures/1772726400_asmap.dat").unwrap();
/// use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
///
/// // Via IpAddr (accepts both v4 and v6)
/// let asn = map.lookup("8.8.8.8".parse::<IpAddr>().unwrap());
///
/// // Directly with typed addresses
/// let asn = map.lookup_v4(Ipv4Addr::new(1, 1, 1, 1));
/// let asn = map.lookup_v6(Ipv6Addr::LOCALHOST);
/// ```
#[derive(Debug)]
pub struct Asmap {
    data: Vec<u8>,
    /// Length of the actual asmap data (excluding the 7-byte read padding).
    len: usize,
}

impl Asmap {
    /// Load and validate an asmap from a file.
    ///
    /// # Errors
    ///
    /// Returns [`AsmapError::Io`] if the file cannot be read, or
    /// [`AsmapError::Invalid`] if the data fails validation.
    ///
    /// # Example
    ///
    /// ```
    /// # let path = "fixtures/1772726400_asmap.dat";
    /// use asmap::Asmap;
    ///
    /// let map = Asmap::from_file(path)?;
    /// # Ok::<(), asmap::AsmapError>(())
    /// ```
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, AsmapError> {
        let data = fs::read(path)?;
        Self::from_bytes(data)
    }

    /// Validate and wrap raw asmap bytes.
    ///
    /// # Errors
    ///
    /// Returns [`AsmapError::Invalid`] if the data fails validation.
    ///
    /// # Example
    ///
    /// ```
    /// use asmap::Asmap;
    ///
    /// let result = Asmap::from_bytes(vec![0xFF; 16]);
    /// assert!(result.is_err(), "garbage data should fail validation");
    /// ```
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
    ///
    /// IPv4 addresses are automatically mapped to their IPv6 representation
    /// (`::ffff:x.x.x.x`) before lookup.
    ///
    /// # Example
    ///
    /// ```
    /// # let map = asmap::Asmap::from_file("fixtures/1772726400_asmap.dat").unwrap();
    /// use std::net::IpAddr;
    ///
    /// let asn = map.lookup("8.8.8.8".parse::<IpAddr>().unwrap());
    /// assert_eq!(asn, 15169); // Google
    /// ```
    pub fn lookup(&self, addr: IpAddr) -> u32 {
        let ip6 = match addr {
            IpAddr::V4(v4) => v4.to_ipv6_mapped(),
            IpAddr::V6(v6) => v6,
        };
        interpret::interpret(&self.data, &ip6.octets())
    }

    /// Look up the ASN for an IPv4 address. Returns 0 if unmapped.
    ///
    /// # Example
    ///
    /// ```
    /// # let map = asmap::Asmap::from_file("fixtures/1772726400_asmap.dat").unwrap();
    /// use std::net::Ipv4Addr;
    ///
    /// let asn = map.lookup_v4(Ipv4Addr::new(1, 1, 1, 1));
    /// assert_eq!(asn, 13335); // Cloudflare
    /// ```
    pub fn lookup_v4(&self, addr: Ipv4Addr) -> u32 {
        self.lookup(IpAddr::V4(addr))
    }

    /// Look up the ASN for an IPv6 address. Returns 0 if unmapped.
    ///
    /// # Example
    ///
    /// ```
    /// # let map = asmap::Asmap::from_file("fixtures/1772726400_asmap.dat").unwrap();
    /// use std::net::Ipv6Addr;
    ///
    /// let asn = map.lookup_v6(Ipv6Addr::LOCALHOST);
    /// // Loopback is mapped in this fixture, but may not be in all asmaps
    /// let _ = asn;
    /// ```
    pub fn lookup_v6(&self, addr: Ipv6Addr) -> u32 {
        self.lookup(IpAddr::V6(addr))
    }

    /// Returns the raw asmap data (without internal padding).
    ///
    /// # Example
    ///
    /// ```
    /// # let map = asmap::Asmap::from_file("fixtures/1772726400_asmap.dat").unwrap();
    /// let bytes = map.as_bytes();
    /// assert!(!bytes.is_empty());
    /// ```
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }
}
