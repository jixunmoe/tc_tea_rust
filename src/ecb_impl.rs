// Tencent chooses 16 rounds instead of traditional 32 rounds.
const ROUNDS: u32 = 16;
const DELTA: u32 = 0x9e3779b9;

/// Perform a single round of encrypting/decrypting wrapping arithmetics
fn ecb_single_round(value: u32, sum: u32, key1: u32, key2: u32) -> u32 {
    let left = value.wrapping_shl(4).wrapping_add(key1);
    let right = value.wrapping_shr(5).wrapping_add(key2);
    let mid = sum.wrapping_add(value);

    left ^ mid ^ right
}

fn parse_tea_u64(state: u64) -> (u32, u32) {
    let y = (state >> 32) as u32;
    let z = state as u32;
    (y, z)
}

fn make_tea_u64(y: u32, z: u32) -> u64 {
    (y as u64) << 32 | (z as u64)
}

/// Perform a 16 round TEA ECB encryption.
pub fn encrypt(block: u64, key: &[u32; 4]) -> u64 {
    let (mut y, mut z) = parse_tea_u64(block);
    let mut sum = 0_u32;

    for _ in 0..ROUNDS {
        sum = sum.wrapping_add(DELTA);

        y = y.wrapping_add(ecb_single_round(z, sum, key[0], key[1]));
        z = z.wrapping_add(ecb_single_round(y, sum, key[2], key[3]));
    }

    make_tea_u64(y, z)
}

/// Perform a 16 round TEA ECB decryption.
pub fn decrypt(block: u64, key: &[u32; 4]) -> u64 {
    let (mut y, mut z) = parse_tea_u64(block);
    let mut sum = DELTA.wrapping_mul(ROUNDS);

    for _ in 0..ROUNDS {
        z = z.wrapping_sub(ecb_single_round(y, sum, key[2], key[3]));
        y = y.wrapping_sub(ecb_single_round(z, sum, key[0], key[1]));

        sum = sum.wrapping_sub(DELTA);
    }

    make_tea_u64(y, z)
}
