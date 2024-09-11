use crate::ecb_impl;
use byteorder::{ByteOrder, BE};

/// Perform a 16 round TEA ECB encryption.
pub fn encrypt(block: &mut [u8; 8], key: &[u32; 4]) {
    let state = BE::read_u64(block);
    let state = ecb_impl::encrypt(state, key);
    BE::write_u64(block, state);
}

/// Perform a 16 round TEA ECB decryption.
pub fn decrypt(block: &mut [u8; 8], key: &[u32; 4]) {
    let state = BE::read_u64(block);
    let state = ecb_impl::decrypt(state, key);
    BE::write_u64(block, state);
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
