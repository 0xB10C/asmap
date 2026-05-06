const INVALID: u32 = 0xFFFFFFFF;

#[inline]
fn consume_bit_le(bitpos: &mut usize, bytes: &[u8]) -> bool {
    let bit = (bytes[*bitpos / 8] >> (*bitpos % 8)) & 1;
    *bitpos += 1;
    bit != 0
}

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

const TYPE_BIT_SIZES: &[u8] = &[0, 0, 1];
const ASN_BIT_SIZES: &[u8] = &[15, 16, 17, 18, 19, 20, 21, 22, 23, 24];
const MATCH_BIT_SIZES: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
const JUMP_BIT_SIZES: &[u8] = &[
    5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
    30,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
enum Instruction {
    Return = 0,
    Jump = 1,
    Match = 2,
    Default = 3,
}

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

/// Validate an asmap by simulating all possible execution paths.
///
/// Checks for:
/// - Instructions not straddling EOF
/// - Jump targets within bounds and non-overlapping
/// - No unreachable code
/// - No redundant instruction sequences (consecutive DEFAULTs, DEFAULT then RETURN)
/// - Padding bits are zero and at most 7
/// - All paths terminate with RETURN
pub(crate) fn sanity_check(asmap: &[u8], mut bits: i32) -> bool {
    let mut pos: usize = 0;
    let endpos = asmap.len() * 8;
    let mut jumps: Vec<(u32, i32)> = Vec::with_capacity(bits as usize);
    let mut prevopcode = Instruction::Jump;
    let mut had_incomplete_match = false;

    while pos != endpos {
        // Check no jump landed in the middle of the previous instruction
        if let Some(&(target, _)) = jumps.last() {
            if pos >= target as usize {
                return false;
            }
        }

        let Some(opcode) = decode_type(&mut pos, asmap) else {
            return false;
        };

        match opcode {
            Instruction::Return => {
                if prevopcode == Instruction::Default {
                    return false;
                }
                let asn = decode_asn(&mut pos, asmap);
                if asn == INVALID {
                    return false;
                }
                if jumps.is_empty() {
                    // Final instruction — check padding
                    if endpos - pos > 7 {
                        return false;
                    }
                    while pos != endpos {
                        if consume_bit_le(&mut pos, asmap) {
                            return false;
                        }
                    }
                    return true;
                } else {
                    // Continue at the next jump target
                    let (target, saved_bits) = jumps.pop().unwrap();
                    if pos != target as usize {
                        return false;
                    }
                    bits = saved_bits;
                    prevopcode = Instruction::Jump;
                }
            }
            Instruction::Jump => {
                let jump = decode_jump(&mut pos, asmap);
                if jump == INVALID {
                    return false;
                }
                if (jump as i64) > (endpos - pos) as i64 {
                    return false;
                }
                if bits == 0 {
                    return false;
                }
                bits -= 1;
                let jump_offset = pos as u32 + jump;
                if let Some(&(last_target, _)) = jumps.last() {
                    if jump_offset >= last_target {
                        return false;
                    }
                }
                jumps.push((jump_offset, bits));
                prevopcode = Instruction::Jump;
            }
            Instruction::Match => {
                let match_val = decode_match(&mut pos, asmap);
                if match_val == INVALID {
                    return false;
                }
                let matchlen = (32 - match_val.leading_zeros()) as i32 - 1;
                if prevopcode != Instruction::Match {
                    had_incomplete_match = false;
                }
                if matchlen < 8 && had_incomplete_match {
                    return false;
                }
                had_incomplete_match = matchlen < 8;
                if bits < matchlen {
                    return false;
                }
                bits -= matchlen;
                prevopcode = Instruction::Match;
            }
            Instruction::Default => {
                if prevopcode == Instruction::Default {
                    return false;
                }
                let asn = decode_asn(&mut pos, asmap);
                if asn == INVALID {
                    return false;
                }
                prevopcode = Instruction::Default;
            }
        }
    }

    false // Reached EOF without RETURN
}
