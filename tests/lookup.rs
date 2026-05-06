use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use asmap::{Asmap, AsmapError};

/// From https://github.com/bitcoin/bitcoin/blob/ec45646de9e62b3d42c85716bfeb06d8f2b507dc/src/test/data/asmap.raw
const SMALL_FIXTURE: &str = "fixtures/asmap.raw";
/// From https://github.com/bitcoin-core/asmap-data/commit/eadadb96818041ad1263e24895b85a689d9581d8
const REAL_FIXTURE: &str = "fixtures/1772726400_asmap.dat";

fn load_fixture() -> Asmap {
    Asmap::from_file(SMALL_FIXTURE).expect("failed to load small fixture")
}

fn load_real_fixture() -> Asmap {
    Asmap::from_file(REAL_FIXTURE).expect("failed to load real-world fixture")
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

// --- Real-world fixture tests (1772726400_asmap.dat) ---

#[test]
fn real_validation_accepts_fixture() {
    load_real_fixture();
}

#[test]
fn real_validation_rejects_truncated() {
    let data = std::fs::read(REAL_FIXTURE).unwrap();
    let truncated = data[..data.len() / 2].to_vec();
    assert!(Asmap::from_bytes(truncated).is_err());
}

#[test]
fn real_validation_rejects_corrupted() {
    let mut data = std::fs::read(REAL_FIXTURE).unwrap();
    // Zero out a large chunk to guarantee structural damage
    let mid = data.len() / 2;
    for b in &mut data[mid..mid + 256] {
        *b = 0x00;
    }
    assert!(Asmap::from_bytes(data).is_err());
}

#[test]
fn real_lookup_google_dns() {
    let map = load_real_fixture();
    // 8.8.8.8 is Google Public DNS, AS15169
    assert_eq!(map.lookup_v4(Ipv4Addr::new(8, 8, 8, 8)), 15169);
    assert_eq!(map.lookup_v4(Ipv4Addr::new(8, 8, 4, 4)), 15169);
}

#[test]
fn real_lookup_cloudflare() {
    let map = load_real_fixture();
    // 1.1.1.1 is Cloudflare, AS13335
    assert_eq!(map.lookup_v4(Ipv4Addr::new(1, 1, 1, 1)), 13335);
}

#[test]
fn real_lookup_quad9() {
    let map = load_real_fixture();
    // 9.9.9.9 is Quad9, AS19281
    assert_eq!(map.lookup_v4(Ipv4Addr::new(9, 9, 9, 9)), 19281);
}

#[test]
fn real_lookup_aws() {
    let map = load_real_fixture();
    // 52.0.0.1 is AWS, AS16509
    assert_eq!(map.lookup_v4(Ipv4Addr::new(52, 0, 0, 1)), 16509);
}

#[test]
fn real_lookup_hetzner() {
    let map = load_real_fixture();
    // 95.216.0.1 is Hetzner, AS24940
    assert_eq!(map.lookup_v4(Ipv4Addr::new(95, 216, 0, 1)), 24940);
}

#[test]
fn real_lookup_ovh() {
    let map = load_real_fixture();
    // 51.210.0.1 is OVH, AS16276
    assert_eq!(map.lookup_v4(Ipv4Addr::new(51, 210, 0, 1)), 16276);
}

#[test]
fn real_lookup_via_ipaddr() {
    let map = load_real_fixture();
    let addr: IpAddr = "8.8.8.8".parse().unwrap();
    assert_eq!(map.lookup(addr), 15169);
}

#[test]
fn real_lookup_v6_mapped_ipv4() {
    let map = load_real_fixture();
    // ::ffff:1.1.1.1 should give the same result as 1.1.1.1
    let v4_asn = map.lookup_v4(Ipv4Addr::new(1, 1, 1, 1));
    let v6_mapped = Ipv4Addr::new(1, 1, 1, 1).to_ipv6_mapped();
    assert_eq!(map.lookup_v6(v6_mapped), v4_asn);
}

#[test]
fn real_lookup_consistent_within_prefix() {
    let map = load_real_fixture();
    // Multiple addresses in Google's 8.8.8.0/24 should all map to the same ASN
    let asn = map.lookup_v4(Ipv4Addr::new(8, 8, 8, 0));
    for last_octet in 1..=255u8 {
        assert_eq!(
            map.lookup_v4(Ipv4Addr::new(8, 8, 8, last_octet)),
            asn,
            "8.8.8.{last_octet} should match 8.8.8.0"
        );
    }
}

#[test]
fn real_as_bytes_matches_file() {
    let raw = std::fs::read(REAL_FIXTURE).unwrap();
    let map = Asmap::from_bytes(raw.clone()).unwrap();
    assert_eq!(map.as_bytes(), &raw[..]);
}

#[test]
fn real_different_asns_for_different_providers() {
    let map = load_real_fixture();
    // These major providers should all have distinct ASNs
    let google = map.lookup_v4(Ipv4Addr::new(8, 8, 8, 8));
    let cloudflare = map.lookup_v4(Ipv4Addr::new(1, 1, 1, 1));
    let aws = map.lookup_v4(Ipv4Addr::new(52, 0, 0, 1));
    let hetzner = map.lookup_v4(Ipv4Addr::new(95, 216, 0, 1));

    let asns = [google, cloudflare, aws, hetzner];
    for i in 0..asns.len() {
        for j in (i + 1)..asns.len() {
            assert_ne!(asns[i], asns[j], "expected distinct ASNs");
        }
    }
}
