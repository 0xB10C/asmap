use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use asmap::{Asmap, AsmapError};

fn load_fixture() -> Asmap {
    Asmap::from_file("fixtures/asmap.raw").expect("failed to load fixtures/asmap.raw")
}

#[test]
fn validation_accepts_fixture() {
    load_fixture();
}

#[test]
fn validation_rejects_empty() {
    assert!(Asmap::from_bytes(vec![]).is_err());
}

#[test]
fn validation_rejects_garbage() {
    assert!(Asmap::from_bytes(vec![0xFF; 64]).is_err());
}

#[test]
fn validation_rejects_truncated() {
    let map = std::fs::read("fixtures/asmap.raw").unwrap();
    // Cut it in half
    let truncated = map[..map.len() / 2].to_vec();
    assert!(Asmap::from_bytes(truncated).is_err());
}

#[test]
fn lookup_250_0_0_0_as1000() {
    let map = load_fixture();
    // 250.0.0.0/8 -> AS1000, test several addresses in this range
    assert_eq!(map.lookup_v4(Ipv4Addr::new(250, 0, 0, 0)), 1000);
    assert_eq!(map.lookup_v4(Ipv4Addr::new(250, 1, 2, 3)), 1000);
    assert_eq!(map.lookup_v4(Ipv4Addr::new(250, 255, 255, 255)), 1000);
}

#[test]
fn lookup_101_x_subnets() {
    let map = load_fixture();
    // 101.1.0.0/16 AS1 through 101.8.0.0/16 AS8
    for asn in 1u32..=8 {
        let addr = Ipv4Addr::new(101, asn as u8, 0, 0);
        assert_eq!(map.lookup_v4(addr), asn, "101.{asn}.0.0 should be AS{asn}");

        let addr2 = Ipv4Addr::new(101, asn as u8, 128, 99);
        assert_eq!(
            map.lookup_v4(addr2),
            asn,
            "101.{asn}.128.99 should be AS{asn}"
        );
    }
}

#[test]
fn lookup_via_ipaddr() {
    let map = load_fixture();
    let addr: IpAddr = "250.0.0.1".parse().unwrap();
    assert_eq!(map.lookup(addr), 1000);
}

#[test]
fn lookup_unmapped_returns_zero() {
    let map = load_fixture();
    // 127.0.0.1 is unlikely to be mapped in a test asmap
    let asn = map.lookup_v4(Ipv4Addr::new(127, 0, 0, 1));
    assert_eq!(asn, 0, "unmapped address should return ASN 0");
}

#[test]
fn lookup_v6_mapped_ipv4() {
    let map = load_fixture();
    // ::ffff:250.0.0.1 is the IPv6-mapped form of 250.0.0.1
    let addr = Ipv4Addr::new(250, 0, 0, 1).to_ipv6_mapped();
    assert_eq!(map.lookup_v6(addr), 1000);
}

#[test]
fn lookup_v6_native() {
    let map = load_fixture();
    // Pure IPv6 address — likely unmapped in this fixture
    let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let asn = map.lookup_v6(addr);
    // Just verify it doesn't panic; result depends on fixture contents
    let _ = asn;
}

#[test]
fn as_bytes_matches_file() {
    let raw = std::fs::read("fixtures/asmap.raw").unwrap();
    let map = Asmap::from_bytes(raw.clone()).unwrap();
    assert_eq!(map.as_bytes(), &raw[..]);
}

#[test]
fn error_display_invalid() {
    let err = Asmap::from_bytes(vec![0x00]).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("validation"), "got: {msg}");
}

#[test]
fn error_display_io() {
    let err = Asmap::from_file("/nonexistent/path/asmap.raw").unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("read asmap file"), "got: {msg}");
    // Also test Error::source()
    let source = std::error::Error::source(&err);
    assert!(source.is_some());
}

#[test]
fn error_from_io() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
    let asmap_err: AsmapError = io_err.into();
    let msg = format!("{asmap_err}");
    assert!(msg.contains("gone"));
}

#[test]
fn validation_rejects_corrupted_first_byte() {
    let mut data = std::fs::read("fixtures/asmap.raw").unwrap();
    data[0] ^= 0xFF;
    assert!(Asmap::from_bytes(data).is_err());
}

#[test]
fn validation_rejects_corrupted_middle() {
    let mut data = std::fs::read("fixtures/asmap.raw").unwrap();
    let mid = data.len() / 2;
    data[mid] ^= 0xFF;
    assert!(Asmap::from_bytes(data).is_err());
}

#[test]
fn validation_rejects_appended_bytes() {
    let mut data = std::fs::read("fixtures/asmap.raw").unwrap();
    data.extend_from_slice(&[0xFF; 16]);
    assert!(Asmap::from_bytes(data).is_err());
}

#[test]
fn validation_rejects_single_byte() {
    assert!(Asmap::from_bytes(vec![0x00]).is_err());
    assert!(Asmap::from_bytes(vec![0x01]).is_err());
    assert!(Asmap::from_bytes(vec![0x80]).is_err());
}
