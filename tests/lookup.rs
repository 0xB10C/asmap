use std::net::{IpAddr, Ipv4Addr};

use asmap::Asmap;

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
