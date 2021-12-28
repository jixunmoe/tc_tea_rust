use rand::prelude::*;
use rand_chacha::ChaCha20Rng;

use super::stream_ext::StreamExt;
use super::tc_tea_internal::{ecb_decrypt, ecb_encrypt, parse_key};

const SALT_LEN: usize = 2;
const ZERO_LEN: usize = 7;
const FIXED_PADDING_LEN: usize = 1 + SALT_LEN + ZERO_LEN;

/// Calculate expected size of encrypted data.
///
/// `body_size` is the size of data you'd like to encrypt.
pub fn calc_encrypted_size(body_size: usize) -> usize {
    let len = FIXED_PADDING_LEN + body_size;
    let pad_len = (8 - (len & 0b0111)) & 0b0111;
    len + pad_len
}

/// Encrypts an arbitrary length sized data in the following way:
///
/// * PadLen  (1 byte)
/// * Padding (variable, 0-7byte)
/// * Salt    (2 bytes)
/// * Body    (? bytes)
/// * Zero    (7 bytes)
///
/// Returned bytes will always have a length multiple of 8.
///
/// PadLen/Padding/Salt are randomly bytes, with a minimum of 21 bits (3 * 8 - 3) randomness.
///
/// # Panics
///
/// If random number generator fails, it will panic.
pub fn encrypt<T: AsRef<[u8]>, K: AsRef<[u8]>>(plaintext: T, key: K) -> Option<Box<[u8]>> {
    let plaintext = plaintext.as_ref();
    let key = parse_key(key.as_ref())?;

    // buffer size calculation
    let len = FIXED_PADDING_LEN + plaintext.len();
    let pad_len = (8 - (len & 0b0111)) & 0b0111;
    let len = len + pad_len; // add our padding
    debug_assert_eq!(
        len,
        calc_encrypted_size(plaintext.len()),
        "encrypted size calculation mismatch"
    );
    let header_len = 1 + pad_len + SALT_LEN;

    // Setup buffer
    let mut encrypted = vec![0u8; len].into_boxed_slice();
    let mut iv1 = vec![0u8; len].into_boxed_slice();

    // Setup a header with random padding/salt
    #[cfg(feature = "secure_random")]
    ChaCha20Rng::from_entropy().fill_bytes(&mut encrypted[0..header_len]);

    #[cfg(not(feature = "secure_random"))]
    ChaCha20Rng::from_rng(thread_rng())
        .unwrap()
        .fill_bytes(&mut encrypted[0..header_len]);

    encrypted[0] = (encrypted[0] & 0b1111_1100) | ((pad_len as u8) & 0b0000_0111);

    // Copy input to destination buffer.
    encrypted[header_len..header_len + plaintext.len()]
        .as_mut()
        .copy_from_slice(plaintext);

    // First block
    iv1.copy_tea_block(0, &encrypted, 0); // preserve iv2 for first block
    ecb_encrypt(&mut encrypted[0..8], &key); // transform first block

    // Rest of the block
    for i in (8..len).step_by(8) {
        encrypted.xor_prev_tea_block(i); // XOR iv2
        iv1.copy_tea_block(i, &encrypted, i); // store iv1
        ecb_encrypt(&mut encrypted[i..i + 8], &key); // TEA ECB
        encrypted.xor_tea_block(i, &iv1, i - 8); // XOR iv1 (from prev block)
    }

    // Done.
    Some(encrypted)
}

/// Decrypts a byte array containing the following:
///
/// * PadLen  (1 byte)
/// * Padding (variable, 0-7byte)
/// * Salt    (2 bytes)
/// * Body    (? bytes)
/// * Zero    (7 bytes)
///
/// PadLen is taken from the last 3 bit of the first byte.
pub fn decrypt<T: AsRef<[u8]>, K: AsRef<[u8]>>(encrypted: T, key: K) -> Option<Box<[u8]>> {
    let encrypted = encrypted.as_ref();
    let key = parse_key(key.as_ref())?;
    let len = encrypted.len();
    if (len < FIXED_PADDING_LEN) || (len % 8 != 0) {
        return None;
    }

    let mut decrypted_buf = encrypted.to_vec();

    // First block
    ecb_decrypt(&mut decrypted_buf[0..8], &key);

    // Rest of the block
    for i in (8..len).step_by(8) {
        decrypted_buf.xor_prev_tea_block(i); // xor iv1
        ecb_decrypt(&mut decrypted_buf[i..i + 8], &key);
    }

    // Finalise: XOR iv2 (cipher text)
    decrypted_buf.xor_block(8, len - 8, encrypted, 0);

    let pad_size = usize::from(decrypted_buf[0] & 0b111);

    // Prefixed with "pad_size", "padding", "salt"
    let start_loc = 1 + pad_size + SALT_LEN;
    let end_loc = len - ZERO_LEN;

    if decrypted_buf[end_loc..].is_all_zeros() {
        Some(
            decrypted_buf[start_loc..end_loc]
                .to_vec()
                .into_boxed_slice(),
        )
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known good data, generated from its C++ implementation
    const GOOD_ENCRYPTED_DATA: [u8; 24] = [
        0x91, 0x09, 0x51, 0x62, 0xe3, 0xf5, 0xb6, 0xdc, //
        0x6b, 0x41, 0x4b, 0x50, 0xd1, 0xa5, 0xb8, 0x4e, //
        0xc5, 0x0d, 0x0c, 0x1b, 0x11, 0x96, 0xfd, 0x3c, //
    ];

    const ENCRYPTION_KEY: &'static str = "12345678ABCDEFGH";

    const GOOD_DECRYPTED_DATA: [u8; 8] = [1u8, 2, 3, 4, 5, 6, 7, 8];

    #[test]
    fn tc_tea_basic_decryption() {
        let result = decrypt(GOOD_ENCRYPTED_DATA, ENCRYPTION_KEY).unwrap();
        assert_eq!(result, GOOD_DECRYPTED_DATA.into());
    }

    #[test]
    fn tc_tea_decryption_reject_non_zero_byte() {
        let mut bad_data = GOOD_ENCRYPTED_DATA.clone();
        bad_data[23] ^= 0xff; // last byte
        assert!(decrypt(bad_data, ENCRYPTION_KEY).is_none());
    }

    #[test]
    fn tc_tea_basic_encryption() {
        let encrypted = encrypt(GOOD_DECRYPTED_DATA, ENCRYPTION_KEY).unwrap();
        assert_eq!(encrypted.len(), 24);

        // Since encryption utilises random numbers, we are just going to
        let decrypted = decrypt(encrypted, ENCRYPTION_KEY).unwrap();
        assert_eq!(decrypted, GOOD_DECRYPTED_DATA.into());
    }

    #[test]
    fn test_calc_encrypted_size() {
        assert_eq!(calc_encrypted_size(0), 16);
        assert_eq!(calc_encrypted_size(1), 16);
        assert_eq!(calc_encrypted_size(6), 16);

        assert_eq!(calc_encrypted_size(7), 24);
        assert_eq!(calc_encrypted_size(14), 24);
        assert_eq!(calc_encrypted_size(15), 32);
    }
}
