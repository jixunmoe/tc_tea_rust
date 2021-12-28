use super::stream_ext::StreamExt;

const ROUNDS: u32 = 16;
const DELTA: u32 = 0x9e3779b9;

#[inline]
pub fn parse_key(key: &[u8]) -> Option<[u32; 4]> {
    if key.len() < 16 {
        return None;
    }

    let mut k = [0u32; 4];
    for (i, k) in k.iter_mut().enumerate() {
        *k = key.read_u32_be(i * 4);
    }
    return Some(k);
}

#[inline]
/// Perform a single round of encrypting/decrypting wrapping arithmetics
fn tc_tea_single_round_arithmetic(value: u32, sum: u32, key1: u32, key2: u32) -> u32 {
    // ((y << 4) + k[2]) ^ (y + sum) ^ ((y >> 5) + k[3]);

    value.wrapping_shl(4).wrapping_add(key1)
        ^ sum.wrapping_add(value)
        ^ value.wrapping_shr(5).wrapping_add(key2)
}

#[inline]
/// Perform a single operation of TEA ECB decryption.
pub fn ecb_decrypt(block: &mut [u8], k: &[u32; 4]) {
    let mut y = block.read_u32_be(0);
    let mut z = block.read_u32_be(4);
    let mut sum = DELTA.wrapping_mul(ROUNDS);

    for _ in 0..ROUNDS {
        z = z.wrapping_sub(tc_tea_single_round_arithmetic(y, sum, k[2], k[3]));
        y = y.wrapping_sub(tc_tea_single_round_arithmetic(z, sum, k[0], k[1]));

        sum = sum.wrapping_sub(DELTA);
    }

    block.write_u32_be(0, y);
    block.write_u32_be(4, z);
}

#[inline]
/// Perform a single operation of TEA ECB encryption.
pub fn ecb_encrypt(block: &mut [u8], k: &[u32; 4]) {
    let mut y = block.read_u32_be(0);
    let mut z = block.read_u32_be(4);
    let mut sum = 0_u32;

    for _ in 0..ROUNDS {
        sum = sum.wrapping_add(DELTA);

        y = y.wrapping_add(tc_tea_single_round_arithmetic(z, sum, k[0], k[1]));
        z = z.wrapping_add(tc_tea_single_round_arithmetic(y, sum, k[2], k[3]));
    }

    block.write_u32_be(0, y);
    block.write_u32_be(4, z);
}
