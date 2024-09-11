use byteorder::{ByteOrder, BE};

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

/// Perform a 16 round TEA ECB encryption.
pub fn encrypt(block: &mut [u8; 8], k: &[u32; 4]) {
    let mut y = BE::read_u32(&block[..4]);
    let mut z = BE::read_u32(&block[4..]);
    let mut sum = 0_u32;

    for _ in 0..ROUNDS {
        sum = sum.wrapping_add(DELTA);

        y = y.wrapping_add(ecb_single_round(z, sum, k[0], k[1]));
        z = z.wrapping_add(ecb_single_round(y, sum, k[2], k[3]));
    }

    BE::write_u32(&mut block[..4], y);
    BE::write_u32(&mut block[4..], z);
}

/// Perform a 16 round TEA ECB decryption.
pub fn decrypt(block: &mut [u8; 8], key: &[u32; 4]) {
    let mut y = BE::read_u32(&block[..4]);
    let mut z = BE::read_u32(&block[4..]);
    let mut sum = DELTA.wrapping_mul(ROUNDS);

    for _ in 0..ROUNDS {
        z = z.wrapping_sub(ecb_single_round(y, sum, key[2], key[3]));
        y = y.wrapping_sub(ecb_single_round(z, sum, key[0], key[1]));

        sum = sum.wrapping_sub(DELTA);
    }

    BE::write_u32(&mut block[..4], y);
    BE::write_u32(&mut block[4..], z);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decryption() {
        let mut data: [u8; 8] = [0x56, 0x27, 0x6b, 0xa9, 0x80, 0xb9, 0xec, 0x16];
        let key: [u32; 4] = [0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f00];
        let expected: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

        decrypt(&mut data, &key);
        assert_eq!(data, expected);
    }

    #[test]
    fn test_encryption() {
        let mut data: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let key: [u32; 4] = [0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f00];
        let expected: [u8; 8] = [0x56, 0x27, 0x6b, 0xa9, 0x80, 0xb9, 0xec, 0x16];

        encrypt(&mut data, &key);
        assert_eq!(data, expected);
    }
}
