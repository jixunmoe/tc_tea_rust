//! _Tencent modified TEA_ (tc_tea) is a variant of the standard TEA (Tiny Encryption Algorithm).
//!
//! Notably, it uses a different round number and uses a "tweaked" CBC mode.

use byteorder::{ByteOrder, BE};
use thiserror::Error;

pub mod cbc;
pub mod ecb;

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
    let mut cipher = vec![0u8; plaintext.len()];
    let result = cbc::decrypt(&mut cipher, plaintext, &key)?;
    Ok(Vec::from(result))
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
