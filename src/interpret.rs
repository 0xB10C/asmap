/// Read up to 32 bits from a byte slice starting at a bit position (LE bit order).
/// Uses a single unaligned u64 load instead of a byte-at-a-time loop.
#[inline(always)]
fn read_bits_le(bitpos: usize, data: &[u8], count: u8) -> u32 {
    debug_assert!(count <= 32);
    if count == 0 {
        return 0;
    }
    let byte_offset = bitpos / 8;
    let bit_offset = bitpos % 8;
    // We need at most 5 bytes (bit_offset up to 7 + count up to 32 = 39 bits).
    // Read a u64 if we have enough bytes, otherwise fall back to byte loop.
    let raw: u64 = if byte_offset + 8 <= data.len() {
        // Fast path: single unaligned load
        let bytes: [u8; 8] = data[byte_offset..byte_offset + 8].try_into().unwrap();
        u64::from_le_bytes(bytes)
    } else {
        // Near end of data: read available bytes
        let mut buf = [0u8; 8];
        let avail = data.len() - byte_offset;
        buf[..avail].copy_from_slice(&data[byte_offset..]);
        u64::from_le_bytes(buf)
    };
    ((raw >> bit_offset) & ((1u64 << count) - 1)) as u32
}

/// Decode a variable-length integer from the asmap bytecode.
///
/// Uses bulk bit reads: reads a chunk of continuation bits at once and counts
/// trailing ones to determine the class, then reads the value bits in one go.
#[inline(always)]
fn decode_bits(pos: &mut usize, data: &[u8], minval: u32, bit_sizes: &[u8]) -> u32 {
    let n_classes = bit_sizes.len();

    // Read up to (n_classes - 1) continuation bits at once.
    // The class is determined by the number of leading 1-bits before the first 0
    // (or the last class if all are 1).
    let max_cont_bits = (n_classes - 1) as u8;
    let cont = read_bits_le(*pos, data, max_cont_bits);
    // trailing_ones tells us how many 1-bits before the first 0 (LE order)
    let class = cont.trailing_ones().min(max_cont_bits as u32) as usize;

    // Advance past continuation bits: `class` one-bits + 1 zero-bit, unless last class
    if class < n_classes - 1 {
        *pos += class + 1;
    } else {
        *pos += class;
    }

    // Accumulate the size of all skipped classes
    let mut val = minval;
    for &s in &bit_sizes[..class] {
        val += 1 << s;
    }

    // Read the value bits for this class
    let size = bit_sizes[class];
    let raw = read_bits_le(*pos, data, size);
    *pos += size as usize;

    // The value bits are stored big-endian within the class
    if size > 0 {
        val += raw.reverse_bits() >> (32 - size);
    }
    val
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

/// Decode instruction type from 1-3 bits with a single read:
///   0 = RETURN, 10 = JUMP, 110 = MATCH, 111 = DEFAULT
#[inline(always)]
fn decode_type(pos: &mut usize, data: &[u8]) -> Instruction {
    let bits = read_bits_le(*pos, data, 3);
    if bits & 1 == 0 {
        *pos += 1;
        Instruction::Return
    } else if bits & 2 == 0 {
        *pos += 2;
        Instruction::Jump
    } else if bits & 4 == 0 {
        *pos += 3;
        Instruction::Match
    } else {
        *pos += 3;
        Instruction::Default
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
    let mut ip_bit: u32 = 0;

    loop {
        let opcode = decode_type(&mut pos, asmap);

        match opcode {
            Instruction::Return => {
                return decode_asn(&mut pos, asmap);
            }
            Instruction::Jump => {
                let jump = decode_jump(&mut pos, asmap);
                if (ip_val >> (127 - ip_bit)) & 1 == 1 {
                    pos += jump as usize;
                }
                ip_bit += 1;
            }
            Instruction::Match => {
                let match_val = decode_match(&mut pos, asmap);
                let matchlen = 31 - match_val.leading_zeros();
                // Extract `matchlen` bits from IP starting at ip_bit (big-endian)
                let ip_bits =
                    ((ip_val >> (128 - ip_bit - matchlen)) & ((1u128 << matchlen) - 1)) as u32;
                // The pattern is the lower `matchlen` bits of match_val
                let pat_bits = match_val & ((1 << matchlen) - 1);
                if ip_bits != pat_bits {
                    return default_asn;
                }
                ip_bit += matchlen;
            }
            Instruction::Default => {
                default_asn = decode_asn(&mut pos, asmap);
            }
        }
    }
}
