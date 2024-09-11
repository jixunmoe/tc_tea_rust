use super::{ecb, TcTeaError};
use rand::prelude::*;
use std::cmp::min;

pub(crate) const SALT_LEN: usize = 2;
pub(crate) const ZERO_LEN: usize = 7;
pub(crate) const FIXED_PADDING_LEN: usize = 1 + SALT_LEN + ZERO_LEN;

fn xor_tea_block(a: &[u8; 8], b: &[u8; 8]) -> [u8; 8] {
    let mut dest = *a;
    dest.iter_mut().zip(b).for_each(|(a, b)| *a ^= *b);
    dest
}

#[inline(always)]
fn encrypt_round(
    cipher: &mut [u8],
    plain: &[u8],
    key: &[u32; 4],
    iv1: &mut [u8; 8],
    iv2: &mut [u8; 8],
) {
    let mut plain_block = [0u8; 8];
    plain_block.copy_from_slice(plain);

    let iv2_next = xor_tea_block(&plain_block, iv1);
    let mut result = iv2_next;
    ecb::encrypt(&mut result, key);

    let cipher_block = xor_tea_block(&result, iv2);
    *iv1 = cipher_block;
    *iv2 = iv2_next;
    cipher[..8].copy_from_slice(&cipher_block);
}

pub fn encrypt<'a>(
    cipher: &'a mut [u8],
    plain: &[u8],
    key: &[u32; 4],
) -> Result<&'a [u8], TcTeaError> {
    // buffer size calculation
    let len = FIXED_PADDING_LEN + plain.len();
    let pad_len = (8 - (len & 0b0111)) & 0b0111;
    let expected_output_len = len + pad_len; // add our padding
    if cipher.len() < expected_output_len {
        Err(TcTeaError::DecryptBufferTooSmall(
            expected_output_len,
            cipher.len(),
        ))?;
    }

    let header_len = 1 + pad_len + SALT_LEN;

    // Setup buffer
    let cipher = &mut cipher[..expected_output_len];
    let mut header = [0u8; 16];

    // Set up a header with random padding/salt
    #[cfg(feature = "secure_random")]
    rand_chacha::ChaCha20Rng::from_entropy().fill_bytes(&mut header[0..header_len]);
    #[cfg(not(feature = "secure_random"))]
    rand_pcg::Pcg32::from_entropy().fill_bytes(&mut header[0..header_len]);

    // Build header
    let copy_to_header_len = min(16 - header_len, plain.len());
    let (plain_header, plain) = plain.split_at(copy_to_header_len);

    header[0] = (header[0] & 0b1111_1000) | ((pad_len as u8) & 0b0000_0111);
    header[header_len..header_len + copy_to_header_len].copy_from_slice(plain_header);

    // Access to slice of "cipher" from inner scope
    {
        let mut iv1 = [0u8; 8];
        let mut iv2 = [0u8; 8];

        // Process whole blocks
        let plain_last_block_len = plain.len() % 8;
        let (plain, plain_last_block) = plain.split_at(plain.len() - plain_last_block_len);

        // Encrypt first 2 blocks from the header, then whole blocks
        // cbc_encrypt_round(cipher, &header, key, &mut iv1, &mut iv2);
        encrypt_round(cipher, &header[..8], key, &mut iv1, &mut iv2);
        let cipher = &mut cipher[8..];

        encrypt_round(cipher, &header[8..], key, &mut iv1, &mut iv2);
        let mut cipher = &mut cipher[8..];

        // Handle whole blocks
        for (plain, cipher) in plain.chunks_exact(8).zip(cipher.chunks_exact_mut(8)) {
            encrypt_round(cipher, plain, key, &mut iv1, &mut iv2);
        }
        cipher = &mut cipher[plain.len()..];

        // Handle last block, if there's any
        if plain_last_block_len != 0 {
            let mut last_block = [0u8; 8];
            last_block[..plain_last_block_len].copy_from_slice(plain_last_block);
            encrypt_round(cipher, &last_block, key, &mut iv1, &mut iv2);
        }
    }

    // Done.
    Ok(cipher)
}

#[inline(always)]
fn decrypt_round(
    plain: &mut [u8],
    cipher: &[u8],
    key: &[u32; 4],
    iv1: &mut [u8; 8],
    iv2: &mut [u8; 8],
) {
    let mut cipher_block = [0u8; 8];
    cipher_block.copy_from_slice(cipher);

    let mut result = xor_tea_block(&cipher_block, iv2);
    ecb::decrypt(&mut result, key);
    let plain_block = xor_tea_block(&result, iv1);

    *iv1 = cipher_block;
    *iv2 = result;

    plain[..8].copy_from_slice(&plain_block);
}

pub fn decrypt<'a>(
    plain: &'a mut [u8],
    cipher: &[u8],
    key: &[u32; 4],
) -> Result<&'a [u8], TcTeaError> {
    let input_len = cipher.len();
    if (input_len < FIXED_PADDING_LEN) || (input_len % 8 != 0) {
        Err(TcTeaError::InvalidDataSize(input_len))?;
    }
    let output_len = plain.len();
    if output_len < input_len {
        Err(TcTeaError::DecryptBufferTooSmall(input_len, output_len))?;
    }

    let plain = &mut plain[..input_len];
    let mut iv1 = [0u8; 8];
    let mut iv2 = [0u8; 8];
    for (cipher, plain) in cipher.chunks_exact(8).zip(plain.chunks_exact_mut(8)) {
        decrypt_round(plain, cipher, key, &mut iv1, &mut iv2);
    }

    let pad_size = usize::from(plain[0] & 0b111);

    // Prefixed with "pad_size", "padding", "salt"
    let start_loc = 1 + pad_size + SALT_LEN;
    let end_loc = input_len - ZERO_LEN;

    if plain[end_loc..].iter().fold(0u8, |acc, v| acc | v) != 0 {
        plain.fill(0);
        Err(TcTeaError::InvalidPadding)?
    }

    Ok(&plain[start_loc..end_loc])
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

    const ENCRYPTION_KEY: [u32; 4] = [0x31323334, 0x35363738, 0x41424344, 0x45464748];

    const EXPECTED_PLAIN_TEXT: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    #[test]
    fn tc_tea_basic_decryption() -> Result<(), TcTeaError> {
        let mut plain = vec![0u8; 24];
        let result = decrypt(&mut plain, &GOOD_ENCRYPTED_DATA, &ENCRYPTION_KEY)?;
        assert_eq!(result, &EXPECTED_PLAIN_TEXT);
        Ok(())
    }

    #[test]
    fn tc_tea_decryption_reject_non_zero_byte() {
        let mut bad_data = GOOD_ENCRYPTED_DATA;
        bad_data[23] ^= 0xff; // last byte
        let mut plain = vec![0xffu8; 24];
        assert_eq!(
            decrypt(&mut plain, &bad_data, &ENCRYPTION_KEY),
            Err(TcTeaError::InvalidPadding)
        );
    }

    #[test]
    fn tc_tea_encrypt_empty() -> Result<(), TcTeaError> {
        let mut cipher_buffer = [0xffu8; 100];
        let cipher = encrypt(&mut cipher_buffer, b"", &ENCRYPTION_KEY)?;
        assert_eq!(cipher.len(), 16);

        let mut plain = vec![0xffu8; 24];
        // Since encryption utilises random numbers, we are just going to
        let decrypted = decrypt(&mut plain, cipher, &ENCRYPTION_KEY)?;
        assert_eq!(decrypted, b"");

        Ok(())
    }

    #[test]
    fn tc_tea_basic_encryption() -> Result<(), TcTeaError> {
        let mut cipher_buffer = [0xffu8; 100];
        let cipher = encrypt(&mut cipher_buffer, &EXPECTED_PLAIN_TEXT, &ENCRYPTION_KEY)?;
        assert_eq!(cipher.len(), 24);

        let mut plain = vec![0xffu8; 24];
        // Since encryption utilises random numbers, we are just going to
        let decrypted = decrypt(&mut plain, cipher, &ENCRYPTION_KEY)?;
        assert_eq!(decrypted, &EXPECTED_PLAIN_TEXT);

        Ok(())
    }

    #[test]
    fn tc_tea_test_long_encryption() -> Result<(), TcTeaError> {
        let mut cipher_buffer = [0xffu8; 100];
        let input = b"...test data by Jixun ... ... test hello aaa";
        for _ in 0..16 {
            let cipher = encrypt(&mut cipher_buffer, input, &ENCRYPTION_KEY)?;
            assert_eq!(cipher.len() % 8, 0);
            assert!(cipher.len() > input.len());

            // Since encryption utilises random numbers, we are just going to
            let mut plain = vec![0xffu8; cipher.len()];
            let decrypted = decrypt(&mut plain, cipher, &ENCRYPTION_KEY)?;
            assert_eq!(decrypted, input);
        }

        Ok(())
    }

    #[test]
    fn tc_tea_test_various_len() -> Result<(), TcTeaError> {
        let mut cipher_buffer = [0xffu8; 100];
        let mut plain_buffer = [0xffu8; 100];

        let input = b"...test data by Jixun ... ... test hello aaa";
        for test_len in 0usize..input.len() {
            let input = &input[..test_len];
            let cipher = encrypt(&mut cipher_buffer, input, &ENCRYPTION_KEY)?;
            let decrypted = decrypt(&mut plain_buffer, cipher, &ENCRYPTION_KEY)?;
            assert_eq!(decrypted, input);
        }

        Ok(())
    }
}
