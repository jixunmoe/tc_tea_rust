use super::tc_tea_cbc;

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
    tc_tea_cbc::encrypt(plaintext.as_ref(), key.as_ref())
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
    tc_tea_cbc::decrypt(encrypted.as_ref(), key.as_ref())
}
