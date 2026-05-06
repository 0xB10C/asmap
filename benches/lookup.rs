use std::net::{IpAddr, Ipv4Addr};

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use asmap::Asmap;

const SMALL_FIXTURE: &str = "fixtures/asmap.raw";
const REAL_FIXTURE: &str = "fixtures/1772726400_asmap.dat";

fn bench_validation(c: &mut Criterion) {
    let small_data = std::fs::read(SMALL_FIXTURE).unwrap();
    let real_data = std::fs::read(REAL_FIXTURE).unwrap();

    c.bench_function("validate_small", |b| {
        b.iter(|| Asmap::from_bytes(black_box(small_data.clone())).unwrap())
    });

    c.bench_function("validate_real", |b| {
        b.iter(|| Asmap::from_bytes(black_box(real_data.clone())).unwrap())
    });
}

fn bench_lookup(c: &mut Criterion) {
    let small = Asmap::from_file(SMALL_FIXTURE).unwrap();
    let real = Asmap::from_file(REAL_FIXTURE).unwrap();

    c.bench_function("lookup_small_v4", |b| {
        b.iter(|| small.lookup_v4(black_box(Ipv4Addr::new(250, 1, 2, 3))))
    });

    c.bench_function("lookup_real_v4_google", |b| {
        b.iter(|| real.lookup_v4(black_box(Ipv4Addr::new(8, 8, 8, 8))))
    });

    c.bench_function("lookup_real_v4_cloudflare", |b| {
        b.iter(|| real.lookup_v4(black_box(Ipv4Addr::new(1, 1, 1, 1))))
    });

    c.bench_function("lookup_real_v4_aws", |b| {
        b.iter(|| real.lookup_v4(black_box(Ipv4Addr::new(52, 0, 0, 1))))
    });

    c.bench_function("lookup_real_ipaddr", |b| {
        let addr: IpAddr = "8.8.8.8".parse().unwrap();
        b.iter(|| real.lookup(black_box(addr)))
    });

    // Sweep through many different IPs to average over varying trie depths
    c.bench_function("lookup_real_v4_sweep", |b| {
        let addrs: Vec<Ipv4Addr> = (0..=255)
            .flat_map(|a| (0..=3).map(move |b| Ipv4Addr::new(a, b, 0, 1)))
            .collect();
        b.iter(|| {
            for &addr in &addrs {
                black_box(real.lookup_v4(addr));
            }
        })
    });
}

criterion_group!(benches, bench_validation, bench_lookup);
criterion_main!(benches);
