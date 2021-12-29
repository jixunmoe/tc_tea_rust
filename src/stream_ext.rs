use std::ops::BitOr;

pub trait StreamExt {
    fn read_u32_be(&self, offset: usize) -> u32;
    fn write_u32_be(&mut self, offset: usize, value: u32);
    fn xor_block(&mut self, dst_offset: usize, size: usize, src: &[u8], src_offset: usize);
    fn is_all_zeros(&self) -> bool;

    fn xor_prev_tea_block(&mut self, offset: usize);
    fn copy_tea_block(&mut self, offset: usize, src: &[u8], src_offset: usize);
    fn xor_tea_block(&mut self, dst_offset: usize, src: &[u8], src_offset: usize);
}

impl StreamExt for [u8] {
    #[inline]
    fn read_u32_be(&self, offset: usize) -> u32 {
        (u32::from(self[offset]) << 24)
            | (u32::from(self[offset + 1]) << 16)
            | (u32::from(self[offset + 2]) << 8)
            | (u32::from(self[offset + 3]))
    }

    #[inline]
    fn write_u32_be(&mut self, offset: usize, value: u32) {
        self[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    #[inline]
    fn xor_block(&mut self, dst_offset: usize, size: usize, src: &[u8], src_offset: usize) {
        for i in 0..size {
            self[dst_offset + i] ^= src[src_offset + i];
        }
    }

    /// Constant time all zero comparison
    /// Attempts to do constant time comparison,
    ///   but probably gets optimised away by llvm... lol
    fn is_all_zeros(&self) -> bool {
        self.iter().fold(0u8, |acc, b| acc.bitor(b)) == 0
    }

    #[inline]
    fn xor_prev_tea_block(&mut self, offset: usize) {
        for i in offset..offset + 8 {
            self[i] ^= self[i - 8];
        }
    }

    #[inline]
    fn copy_tea_block(&mut self, offset: usize, src: &[u8], src_offset: usize) {
        self[offset..offset + 8]
            .as_mut()
            .copy_from_slice(&src[src_offset..src_offset + 8]);
    }

    #[inline]
    fn xor_tea_block(&mut self, dst_offset: usize, src: &[u8], src_offset: usize) {
        self.xor_block(dst_offset, 8, src, src_offset);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_u32_be() {
        let v1 = [1, 2, 3, 4];
        let v2 = [0x7f, 0xff, 0xee, 0xdd, 0xcc];
        assert_eq!(v1.read_u32_be(0), 0x01020304);
        assert_eq!(v2.read_u32_be(1), 0xffeeddcc);
    }

    #[test]
    fn test_write_u32_be() {
        let v2 = &mut [0x7fu8, 0xff, 0xee, 0xdd, 0xcc];
        v2.write_u32_be(0, 0x01020304);
        assert_eq!(v2, &[1u8, 2, 3, 4, 0xcc]);
    }
}
