/// Read up to 32 bits from a byte slice starting at a bit position (LE bit order).
/// Returns the bits as a u32 in the low positions. Assumes sufficient data exists.
#[inline(always)]
fn read_bits_le(bitpos: usize, data: &[u8], count: u8) -> u32 {
    if count == 0 {
        return 0;
    }
    let byte_offset = bitpos / 8;
    let bit_offset = bitpos % 8;
    // Read up to 5 bytes to cover any bit-unaligned 32-bit span
    let mut raw: u64 = 0;
    let bytes_needed = (bit_offset + count as usize).div_ceil(8);
    for i in 0..bytes_needed {
        raw |= (data[byte_offset + i] as u64) << (i * 8);
    }
    ((raw >> bit_offset) & ((1u64 << count) - 1)) as u32
}

/// Decode a variable-length integer from the asmap bytecode.
/// Since data is pre-validated, no bounds checking is performed.
#[inline(always)]
fn decode_bits(pos: &mut usize, data: &[u8], minval: u32, bit_sizes: &[u8]) -> u32 {
    let mut val = minval;

    for (i, &size) in bit_sizes.iter().enumerate() {
        let is_last = i + 1 == bit_sizes.len();
        let bit = if !is_last {
            let b = read_bits_le(*pos, data, 1) != 0;
            *pos += 1;
            b
        } else {
            false
        };

        if bit {
            val += 1 << size;
        } else {
            // Read `size` bits at once and reverse their bit order (stored BE within class)
            let raw = read_bits_le(*pos, data, size);
            *pos += size as usize;
            // The bits are stored big-endian within the class value
            val += raw.reverse_bits() >> (32 - size);
            return val;
        }
    }
    unreachable!()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Instruction {
    Return = 0,
    Jump = 1,
    Match = 2,
    Default = 3,
}

const ASN_BIT_SIZES: &[u8] = &[15, 16, 17, 18, 19, 20, 21, 22, 23, 24];
const MATCH_BIT_SIZES: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
const JUMP_BIT_SIZES: &[u8] = &[
    5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
    30,
];

/// Decode instruction type directly from 1-3 bits:
///   0 = RETURN, 10 = JUMP, 110 = MATCH, 111 = DEFAULT
#[inline(always)]
fn decode_type(pos: &mut usize, data: &[u8]) -> Instruction {
    if read_bits_le(*pos, data, 1) == 0 {
        *pos += 1;
        Instruction::Return
    } else if read_bits_le(*pos + 1, data, 1) == 0 {
        *pos += 2;
        Instruction::Jump
    } else {
        let third = read_bits_le(*pos + 2, data, 1);
        *pos += 3;
        if third == 0 {
            Instruction::Match
        } else {
            Instruction::Default
        }
    }
}

#[inline(always)]
fn decode_asn(pos: &mut usize, data: &[u8]) -> u32 {
    decode_bits(pos, data, 1, ASN_BIT_SIZES)
}

#[inline(always)]
fn decode_match(pos: &mut usize, data: &[u8]) -> u32 {
    decode_bits(pos, data, 2, MATCH_BIT_SIZES)
}

#[inline(always)]
fn decode_jump(pos: &mut usize, data: &[u8]) -> u32 {
    decode_bits(pos, data, 17, JUMP_BIT_SIZES)
}

/// Interpret asmap bytecode to find the ASN for a 128-bit (IPv6) address.
///
/// Returns the ASN, or 0 if unmapped. Panics if the asmap data is malformed
/// (callers must validate with `sanity_check` first).
pub(crate) fn interpret(asmap: &[u8], ip: &[u8; 16]) -> u32 {
    let mut pos: usize = 0;
    let mut default_asn: u32 = 0;

    // Convert IP to u128 for fast bit extraction
    let ip_val = u128::from_be_bytes(*ip);
    let mut ip_bit: u8 = 0;

    loop {
        let opcode = decode_type(&mut pos, asmap);

        match opcode {
            Instruction::Return => {
                return decode_asn(&mut pos, asmap);
            }
            Instruction::Jump => {
                let jump = decode_jump(&mut pos, asmap);
                // Extract next IP bit (big-endian: MSB first)
                if (ip_val >> (127 - ip_bit as u32)) & 1 == 1 {
                    pos += jump as usize;
                }
                ip_bit += 1;
            }
            Instruction::Match => {
                let match_val = decode_match(&mut pos, asmap);
                let matchlen = (32 - match_val.leading_zeros()) - 1;
                // Compare IP bits against the match pattern
                for bit in 0..matchlen {
                    let ip_b = (ip_val >> (127 - ip_bit as u32)) & 1;
                    let pat_b = (match_val >> (matchlen - 1 - bit)) & 1;
                    if ip_b != pat_b as u128 {
                        return default_asn;
                    }
                    ip_bit += 1;
                }
            }
            Instruction::Default => {
                default_asn = decode_asn(&mut pos, asmap);
            }
        }
    }
}
