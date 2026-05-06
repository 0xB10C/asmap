# ASmap Interpreter in Rust

A Rust library for IP to ASN (Autonomous System Number) lookups using Bitcoin Core's asmap binary trie format.

## What is an ASmap?

An asmap file is a compact binary encoding of a mapping from IP prefixes to ASNs. The format was designed for Bitcoin Core to enable [AS-aware peer selection](https://github.com/bitcoin/bitcoin/pull/16702), improving resistance to eclipse attacks by diversifying connections across different autonomous systems.

The binary format uses a trie structure encoded as bytecode instructions, allowing efficient lookups without loading a full routing table into memory.

## Usage

```rust
use asmap::Asmap;
use std::net::IpAddr;

// Load from file (validates on construction)
let map = Asmap::from_file("path/to/asmap.dat")?;

// Look up any IP address
let asn = map.lookup("8.8.8.8".parse::<IpAddr>().unwrap());
println!("ASN: {asn}"); // 0 means unmapped

// Convenience methods for typed addresses
use std::net::Ipv4Addr;
let asn = map.lookup_v4(Ipv4Addr::new(1, 1, 1, 1));
```

IPv4 addresses are automatically mapped to IPv6 (`::ffff:x.x.x.x`) before lookup, matching how Bitcoin Core handles them internally.

## Obtaining asmap files

ASmap files are available from [bitcoin-core/asmap-data](https://github.com/bitcoin-core/asmap-data).

