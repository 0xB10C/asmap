const INVALID: u32 = 0xFFFFFFFF;

/// Extract a single bit from a byte slice using little-endian bit ordering (LSB first).
/// Used for reading asmap bytecode.
#[inline]
fn consume_bit_le(bitpos: &mut usize, bytes: &[u8]) -> bool {
    let bit = (bytes[*bitpos / 8] >> (*bitpos % 8)) & 1;
    *bitpos += 1;
    bit != 0
}

/// Extract a single bit from a byte slice using big-endian bit ordering (MSB first).
/// Used for reading IP address bits in network byte order.
#[inline]
fn consume_bit_be(bitpos: &mut u8, bytes: &[u8]) -> bool {
    let bit = (bytes[*bitpos as usize / 8] >> (7 - (*bitpos as usize % 8))) & 1;
    *bitpos += 1;
    bit != 0
}

/// Variable-length integer decoder.
///
/// Numbers are encoded in classes of increasing bit widths. Each class is prefixed
/// by continuation bits (1 = next class, 0 = decode value in current class).
/// The last class has no continuation bit.
///
/// Example with minval=100, bit_sizes=[4,2,2,3]:
///   - [100..115]: [0] + 4-bit BE value
///   - [116..119]: [1,0] + 2-bit BE value
///   - [120..123]: [1,1,0] + 2-bit BE value
///   - [124..131]: [1,1,1] + 3-bit BE value
fn decode_bits(bitpos: &mut usize, data: &[u8], minval: u32, bit_sizes: &[u8]) -> u32 {
    let end_bits = data.len() * 8;
    let mut val = minval;

    for (i, &size) in bit_sizes.iter().enumerate() {
        let is_last = i + 1 == bit_sizes.len();
        let bit = if !is_last {
            if *bitpos >= end_bits {
                return INVALID;
            }
            consume_bit_le(bitpos, data)
        } else {
            false
        };

        if bit {
            val += 1 << size;
        } else {
            for b in 0..size {
                if *bitpos >= end_bits {
                    return INVALID;
                }
                if consume_bit_le(bitpos, data) {
                    val += 1 << (size - 1 - b);
                }
            }
            return val;
        }
    }
    INVALID
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
enum Instruction {
    Return = 0,
    Jump = 1,
    Match = 2,
    Default = 3,
}

const TYPE_BIT_SIZES: &[u8] = &[0, 0, 1];
const ASN_BIT_SIZES: &[u8] = &[15, 16, 17, 18, 19, 20, 21, 22, 23, 24];
const MATCH_BIT_SIZES: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
const JUMP_BIT_SIZES: &[u8] = &[
    5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
    30,
];

fn decode_type(bitpos: &mut usize, data: &[u8]) -> Option<Instruction> {
    match decode_bits(bitpos, data, 0, TYPE_BIT_SIZES) {
        0 => Some(Instruction::Return),
        1 => Some(Instruction::Jump),
        2 => Some(Instruction::Match),
        3 => Some(Instruction::Default),
        _ => None,
    }
}

fn decode_asn(bitpos: &mut usize, data: &[u8]) -> u32 {
    decode_bits(bitpos, data, 1, ASN_BIT_SIZES)
}

fn decode_match(bitpos: &mut usize, data: &[u8]) -> u32 {
    decode_bits(bitpos, data, 2, MATCH_BIT_SIZES)
}

fn decode_jump(bitpos: &mut usize, data: &[u8]) -> u32 {
    decode_bits(bitpos, data, 17, JUMP_BIT_SIZES)
}

/// Interpret asmap bytecode to find the ASN for a 128-bit (IPv6) address.
///
/// Returns the ASN, or 0 if unmapped. Panics if the asmap data is malformed
/// (callers must validate with `sanity_check` first).
pub(crate) fn interpret(asmap: &[u8], ip: &[u8; 16]) -> u32 {
    let mut pos: usize = 0;
    let endpos = asmap.len() * 8;
    let mut ip_bit: u8 = 0;
    let ip_bits_end: u8 = 128;
    let mut default_asn: u32 = 0;

    while pos < endpos {
        let Some(opcode) = decode_type(&mut pos, asmap) else {
            break;
        };

        match opcode {
            Instruction::Return => {
                let asn = decode_asn(&mut pos, asmap);
                if asn == INVALID {
                    break;
                }
                return asn;
            }
            Instruction::Jump => {
                let jump = decode_jump(&mut pos, asmap);
                if jump == INVALID {
                    break;
                }
                if ip_bit == ip_bits_end {
                    break;
                }
                if jump as i64 >= (endpos - pos) as i64 {
                    break;
                }
                if consume_bit_be(&mut ip_bit, ip) {
                    pos += jump as usize;
                }
            }
            Instruction::Match => {
                let match_val = decode_match(&mut pos, asmap);
                if match_val == INVALID {
                    break;
                }
                let matchlen = (32 - match_val.leading_zeros()) as u8 - 1;
                if (ip_bits_end - ip_bit) < matchlen {
                    break;
                }
                for bit in 0..matchlen {
                    if consume_bit_be(&mut ip_bit, ip)
                        != ((match_val >> (matchlen - 1 - bit)) & 1 != 0)
                    {
                        return default_asn;
                    }
                }
            }
            Instruction::Default => {
                default_asn = decode_asn(&mut pos, asmap);
                if default_asn == INVALID {
                    break;
                }
            }
        }
    }

    panic!("asmap interpretation reached EOF without RETURN — data should have been validated");
}
