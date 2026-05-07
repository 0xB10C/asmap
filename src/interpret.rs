// Precomputed cumulative offsets for each class in decode_bits.
// cumulative[i] = minval + sum(1 << bit_sizes[j] for j in 0..i)
// This avoids a loop on every decode call.
const fn precompute_cumulative(minval: u32, bit_sizes: &[u8]) -> [u32; 32] {
    let mut table = [0u32; 32];
    let mut acc = minval;
    let mut i = 0;
    while i < bit_sizes.len() {
        table[i] = acc;
        acc += 1 << bit_sizes[i];
        i += 1;
    }
    table
}

const ASN_BIT_SIZES: &[u8] = &[15, 16, 17, 18, 19, 20, 21, 22, 23, 24];
const MATCH_BIT_SIZES: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
const JUMP_BIT_SIZES: &[u8] = &[
    5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
    30,
];

const ASN_CUMULATIVE: [u32; 32] = precompute_cumulative(1, ASN_BIT_SIZES);
const MATCH_CUMULATIVE: [u32; 32] = precompute_cumulative(2, MATCH_BIT_SIZES);
const JUMP_CUMULATIVE: [u32; 32] = precompute_cumulative(17, JUMP_BIT_SIZES);

/// Read up to 32 bits from a padded byte slice starting at a bit position (LE bit order).
/// The data MUST have at least 7 bytes of padding beyond the logical end, so we can
/// always do a single u64 load without bounds checking.
#[inline(always)]
fn read_bits_le(bitpos: usize, data: &[u8]) -> u64 {
    let byte_offset = bitpos / 8;
    // Safety-equivalent: data is padded so byte_offset + 8 <= data.len() always holds.
    // We use safe code with the compiler able to elide the bounds check due to padding guarantee.
    let bytes: [u8; 8] = data[byte_offset..byte_offset + 8].try_into().unwrap();
    let raw = u64::from_le_bytes(bytes);
    raw >> (bitpos % 8)
}

/// Decode a variable-length integer from the asmap bytecode.
#[inline(always)]
fn decode_bits(pos: &mut usize, data: &[u8], bit_sizes: &[u8], cumulative: &[u32; 32]) -> u32 {
    let n_classes = bit_sizes.len();
    let max_cont_bits = (n_classes - 1) as u32;

    // Read continuation bits + potential value bits in one load
    let raw = read_bits_le(*pos, data);

    // Count trailing ones to find the class
    let class = (raw as u32).trailing_ones().min(max_cont_bits) as usize;

    // Advance past continuation bits: `class` one-bits + 1 zero-bit, unless last class
    let cont_len = if class < n_classes - 1 {
        class + 1
    } else {
        class
    };
    *pos += cont_len;

    // Base value from precomputed table
    let mut val = cumulative[class];

    // Read the value bits for this class
    let size = bit_sizes[class];
    if size > 0 {
        let value_raw = read_bits_le(*pos, data);
        let bits = (value_raw & ((1u64 << size) - 1)) as u32;
        *pos += size as usize;
        // The value bits are stored big-endian within the class
        val += bits.reverse_bits() >> (32 - size);
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

/// Decode instruction type from 1-3 bits with a single read:
///   0 = RETURN, 10 = JUMP, 110 = MATCH, 111 = DEFAULT
#[inline(always)]
fn decode_type(pos: &mut usize, data: &[u8]) -> Instruction {
    let bits = read_bits_le(*pos, data) as u32;
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
    decode_bits(pos, data, ASN_BIT_SIZES, &ASN_CUMULATIVE)
}

#[inline(always)]
fn decode_match(pos: &mut usize, data: &[u8]) -> u32 {
    decode_bits(pos, data, MATCH_BIT_SIZES, &MATCH_CUMULATIVE)
}

#[inline(always)]
fn decode_jump(pos: &mut usize, data: &[u8]) -> u32 {
    decode_bits(pos, data, JUMP_BIT_SIZES, &JUMP_CUMULATIVE)
}

/// Interpret asmap bytecode to find the ASN for a 128-bit (IPv6) address.
///
/// Returns the ASN, or 0 if unmapped. The data slice MUST be padded with at
/// least 7 extra bytes beyond the logical asmap data (done by Asmap on construction).
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
                let ip_bits =
                    ((ip_val >> (128 - ip_bit - matchlen)) & ((1u128 << matchlen) - 1)) as u32;
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
