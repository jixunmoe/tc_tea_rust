//! _Tencent modified TEA_ (tc_tea) is a variant of the standard TEA (Tiny Encryption Algorithm).
//!
//! Notably, it uses a different round number and uses a "tweaked" CBC mode.

use byteorder::{ByteOrder, BE};
use thiserror::Error;

pub mod cbc;
pub mod ecb;
mod ecb_impl;

#[derive(Error, Debug, PartialEq)]
pub enum TcTeaError {
    #[error("Key size mismatch. Required 16 bytes, got {0} bytes")]
    KeyTooShort(usize),
    #[error("Cipher text size invalid. {0} mod 8 != 0.")]
    InvalidDataSize(usize),
    #[error("Decrypt buffer size too small, it should be at least {0} bytes (actual={1} bytes).")]
    DecryptBufferTooSmall(usize, usize),
    #[error("Encrypt buffer size too small, it should be at least {0} bytes (actual={1} bytes).")]
    EncryptBufferTooSmall(usize, usize),
    #[error("Invalid data padding")]
    InvalidPadding,
    #[error("Slice error.")]
    SliceError,
}

/// Calculate expected size of encrypted data.
///
/// `body_size` is the size of data you'd like to encrypt.
pub fn get_encrypted_size(body_size: usize) -> usize {
    let len = cbc::FIXED_PADDING_LEN + body_size;
    let pad_len = (8 - (len & 0b0111)) & 0b0111;
    len + pad_len
}

/// Parse key to u32 array
pub fn parse_key(key: &[u8]) -> Result<[u32; 4], TcTeaError> {
    let key_chunks = match key.len() {
        16 => key.chunks(4),
        key_length => Err(TcTeaError::KeyTooShort(key_length))?,
    };

    let mut parsed = [0u32; 4];
    for (key, key_chunk) in parsed.iter_mut().zip(key_chunks) {
        *key = BE::read_u32(key_chunk);
    }
    Ok(parsed)
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
pub fn encrypt<T: AsRef<[u8]>>(plaintext: T, key: &[u8]) -> Result<Vec<u8>, TcTeaError> {
    let key = parse_key(key)?;
    let plaintext = plaintext.as_ref();
    let cipher_len = get_encrypted_size(plaintext.len());
    let mut cipher = vec![0u8; cipher_len];
    cbc::encrypt(&mut cipher, plaintext, &key)?;
    Ok(cipher)
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
pub fn decrypt<T: AsRef<[u8]>>(encrypted: T, key: &[u8]) -> Result<Vec<u8>, TcTeaError> {
    let key = parse_key(key)?;
    let encrypted = encrypted.as_ref();
    let mut plain = vec![0u8; encrypted.len()];
    let result = cbc::decrypt(&mut plain, encrypted, &key)?;
    Ok(Vec::from(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calc_encrypted_size() {
        assert_eq!(get_encrypted_size(0), 16);
        assert_eq!(get_encrypted_size(1), 16);
        assert_eq!(get_encrypted_size(6), 16);

        assert_eq!(get_encrypted_size(7), 24);
        assert_eq!(get_encrypted_size(14), 24);
        assert_eq!(get_encrypted_size(15), 32);
    }

    #[test]
    fn test_sanity_test() -> Result<(), TcTeaError> {
        let key = b"43218765dcbahgfe";
        let message = b"this is a test message.";
        let cipher = encrypt(message, key)?;
        let plain = decrypt(cipher, key)?;
        assert_eq!(message, plain.as_slice());

        Ok(())
    }
}
