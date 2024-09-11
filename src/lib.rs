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

/// Generate salt for encryption function (or fixed salt if we are not using them)
fn generate_salt() -> [u8; 10] {
    #[cfg(not(feature = "random"))]
    {
        // Chosen by fair dice roll.
        // Guaranteed to be random.
        [0xA5, 0x6E, 0x35, 0xBC, 0x7C, 0x31, 0x04, 0x55, 0xA0, 0xBF]
    }

    #[cfg(feature = "random")]
    {
        use rand::RngCore;
        use rand::prelude::*;
        
        let mut salt = [0u8; 10];

        #[cfg(not(feature = "random_secure"))]
        rand_pcg::Pcg32::from_entropy().fill_bytes(&mut salt);

        #[cfg(feature = "random_secure")]
        rand_chacha::ChaCha20Rng::from_entropy().fill_bytes(&mut salt);

        salt
    }
}

/// Encrypts given plain text using tc_tea.
///
/// # Panics
///
/// If random number generator fails, it will panic.
pub fn encrypt<T, K>(plaintext: T, key: K) -> Result<Vec<u8>, TcTeaError>
where
    T: AsRef<[u8]>,
    K: AsRef<[u8]>,
{
    encrypt_with_salt(plaintext, key, &generate_salt())
}

/// Encrypts given plain text using tc_tea.
///
/// # Panics
///
/// If random number generator fails, it will panic.
pub fn encrypt_with_salt<T, K>(plaintext: T, key: K, salt: &[u8; 10]) -> Result<Vec<u8>, TcTeaError>
where
    T: AsRef<[u8]>,
    K: AsRef<[u8]>,
{
    let key = parse_key(key.as_ref())?;
    let plaintext = plaintext.as_ref();
    let cipher_len = get_encrypted_size(plaintext.len());
    let mut cipher = vec![0u8; cipher_len];
    cbc::encrypt(&mut cipher, plaintext, &key, &salt)?;
    Ok(cipher)
}

/// Decrypts tc_tea encrypted data.
pub fn decrypt<T, K>(encrypted: T, key: K) -> Result<Vec<u8>, TcTeaError>
where
    T: AsRef<[u8]>,
    K: AsRef<[u8]>,
{
    let key = parse_key(key.as_ref())?;
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
