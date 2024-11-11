#![no_std]

use core::convert::TryInto;

/// Digest length in bytes (256-bits)
pub const DIGEST_LEN: usize = 32;

// Number of words used in block processing
const WORK_LEN: usize = 64;

// Length of a word in bytes
const WORD_BYTES_LEN: usize = 4;

// Length of message block in bytes
const BLOCK_BYTES_LEN: usize = 64;

// Number of words in the SHA-256 internal state
const STATE_LEN: usize = 8;

// Byte-length to represent the bit-length of the message
const MSG_BITS_LENGTH_LEN: usize = 8;

// Length of the minimum amount of padding bytes (0x80 || MSG_BITS_LEN(8))
const PAD_AND_LENGTH_LEN: usize = 9;

// Padding start byte
const PAD_START: u8 = 0x80;

// Word constants used during block processing
//
// Defined in FIPS-180-2, section 4.2.2
const K: [u32; WORK_LEN] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// Initial state words
const INITIAL_STATE: [u32; STATE_LEN] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const ZERO_BLOCK: [u8; BLOCK_BYTES_LEN] = [0_u8; BLOCK_BYTES_LEN];
const ZERO_WORK: [u32; WORK_LEN] = [0_u32; WORK_LEN];

/// SHA-256 Error types
#[derive(Debug)]
pub enum Error {
    InvalidLength,
}

/// Implementation of the SHA-256 transform
pub struct Sha256 {
    state: [u32; STATE_LEN],
    block: [u8; BLOCK_BYTES_LEN],
    index: usize,
    total_len: u64,
}

impl Sha256 {
    /// Create a newly initialized SHA-256 transform
    pub fn new() -> Self {
        Self {
            state: INITIAL_STATE,
            block: [0_u8; BLOCK_BYTES_LEN],
            index: 0,
            total_len: 0,
        }
    }

    /// Incrementally update the internal SHA-1 state with message bytes
    ///
    /// Total message length must be below UINT64_MAX:
    ///
    /// - 18_446_744_073_709_551_615 bits
    /// - 2_305_843_009_213_693_952 bytes
    pub fn input(&mut self, msg: &[u8]) -> Result<(), Error> {
        let len = (msg.len() * 8) as u64;

        if len + self.total_len > u64::MAX {
            return Err(Error::InvalidLength);
        }

        // increase the total length of the message
        self.total_len += len;

        for byte in msg.iter() {
            self.block[self.index] = *byte;
            self.index += 1;

            if self.index == BLOCK_BYTES_LEN {
                self.process_block();
            }
        }

        Ok(())
    }

    /// Compute the final digest
    ///
    /// Resets the internal state to the initial state
    pub fn finalize(&mut self) -> Result<[u8; DIGEST_LEN], Error> {
        if self.index < BLOCK_BYTES_LEN {
            let old_len = self.index;

            // pad and process the padded block
            self.pad()?;
            self.process_block();

            if old_len > BLOCK_BYTES_LEN - PAD_AND_LENGTH_LEN {
                // there wasn't enough room to include the message bit-length
                // process a full block of padding
                self.full_pad();
                self.process_block();
            }
        }

        let mut res = [0_u8; DIGEST_LEN];

        for (i, word) in self.state.iter().enumerate() {
            res[i * WORD_BYTES_LEN..(i + 1) * WORD_BYTES_LEN]
                .copy_from_slice(word.to_be_bytes().as_ref());
        }

        self.reset();

        Ok(res)
    }

    /// Convenience function to calculate the SHA-256 digest of the given input
    pub fn digest(input: &[u8]) -> Result<[u8; DIGEST_LEN], Error> {
        let mut sha = Self::new();
        sha.input(&input)?;
        sha.finalize()
    }

    /// Reset the internal state to the initial state
    pub fn reset(&mut self) {
        Self::zero_block(&mut self.block);
        self.index = 0;
        self.total_len = 0;
        self.state.copy_from_slice(INITIAL_STATE.as_ref());
    }

    fn process_block(&mut self) {
        let mut w = [0_u32; WORK_LEN];

        // initialize first 16 working words from the message block
        for (t, word) in self.block.chunks_exact(WORD_BYTES_LEN).enumerate() {
            // unwrap safe here, because word guaranteed 4 bytes long
            w[t] = u32::from_be_bytes(word.try_into().unwrap());
        }

        // initialize remaining working words
        for t in 16..64 {
            w[t] = (Self::lil_sigma1(w[t - 2]) as u64
                + w[t - 7] as u64
                + Self::lil_sigma0(w[t - 15]) as u64
                + w[t - 16] as u64
                & 0xffff_ffff) as u32;
        }

        // initialize working variables from current state
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        // perform main transformations
        for t in 0..WORK_LEN {
            let temp1 = ((h as u64
                + Self::big_sigma1(e) as u64
                + Self::ch(e, f, g) as u64
                + K[t] as u64
                + w[t] as u64)
                & 0xffff_ffff) as u32;

            let temp2 =
                ((Self::big_sigma0(a) as u64 + Self::maj(a, b, c) as u64) & 0xffff_ffff) as u32;

            h = g;
            g = f;
            f = e;
            e = ((d as u64 + temp1 as u64) & 0xffff_ffff) as u32;
            d = c;
            c = b;
            b = a;
            a = ((temp1 as u64 + temp2 as u64) & 0xffff_ffff) as u32;
        }

        // add the temporary values back to the state words
        for (i, word) in self.state.iter_mut().enumerate() {
            let temp = match i {
                0 => a as u64,
                1 => b as u64,
                2 => c as u64,
                3 => d as u64,
                4 => e as u64,
                5 => f as u64,
                6 => g as u64,
                7 => h as u64,
                _ => unreachable!("invalid state index"),
            };

            *word = ((*word as u64 + temp) & 0xffff_ffff) as u32;
        }

        // zero the working words
        Self::zero_work(&mut w);
        // zero the message block
        Self::zero_block(&mut self.block);
        // reset the index
        self.index = 0;
    }

    // Corresponds to SHA_Ch from RFC 4634
    fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ ((!x) & z)
    }

    // Corresponds to SHA_Maj from RFC 4634
    fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    // Corresponds to SHA256_SIGMA0 from RFC 4634
    fn big_sigma0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    // Corresponds to SHA256_SIGMA1 from RFC 4634
    fn big_sigma1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    // Corresponds to SHA256_sigma0 from RFC 4634
    fn lil_sigma0(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }

    // Corresponds to SHA256_sigma1 from RFC 4634
    fn lil_sigma1(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }

    // Pad a message to next block-length bytes
    fn pad(&mut self) -> Result<(), Error> {
        Self::inner_pad(&mut self.block, self.index, self.total_len)
    }

    // Perform inner padding
    fn inner_pad(
        block: &mut [u8; BLOCK_BYTES_LEN],
        index: usize,
        total_len: u64,
    ) -> Result<(), Error> {
        let pad_len = BLOCK_BYTES_LEN - index;

        // check that we are not padding a full block
        // total_len is a u64, so can't be more than u64::MAX
        if pad_len == 0 {
            return Err(Error::InvalidLength);
        }

        block[index] = PAD_START;

        // the end position of zero-byte padding
        let zero_pad_end = if pad_len > PAD_AND_LENGTH_LEN {
            // enough room for message bit length to follow
            BLOCK_BYTES_LEN - MSG_BITS_LENGTH_LEN
        } else {
            // only enough room for zeros
            BLOCK_BYTES_LEN
        };

        if pad_len > 1 {
            // will pad with zeroes, or a no-op if index + 1 == zero_pad_end
            Self::zero_bytes(&mut block[index + 1..zero_pad_end]);
        }

        if pad_len >= PAD_AND_LENGTH_LEN {
            // add the message bits length
            block[BLOCK_BYTES_LEN - MSG_BITS_LENGTH_LEN..]
                .copy_from_slice(total_len.to_be_bytes().as_ref());
        }

        Ok(())
    }

    // Add a full block of padding
    fn full_pad(&mut self) {
        Self::inner_full_pad(&mut self.block, self.total_len);
    }

    // Perform full padding
    fn inner_full_pad(block: &mut [u8; BLOCK_BYTES_LEN], total_len: u64) {
        Self::zero_bytes(&mut block[..BLOCK_BYTES_LEN - MSG_BITS_LENGTH_LEN]);
        block[BLOCK_BYTES_LEN - MSG_BITS_LENGTH_LEN..]
            .copy_from_slice(total_len.to_be_bytes().as_ref());
    }

    // Zero a work word buffer potentially containing sensitive data
    fn zero_work(work: &mut [u32; WORK_LEN]) {
        work.copy_from_slice(ZERO_WORK.as_ref());
    }

    // Zero a block potentially containing sensitive data
    fn zero_block(block: &mut [u8; BLOCK_BYTES_LEN]) {
        block.copy_from_slice(ZERO_BLOCK.as_ref());
    }

    // Zero a byte buffer
    //
    // Buffer length guaranteed less or equal to a block length at compile time
    fn zero_bytes(buf: &mut [u8]) {
        buf.copy_from_slice(&ZERO_BLOCK[..buf.len()]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_vector1() {
        let input = b"abc";
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];

        let mut sha = Sha256::new();

        sha.input(input.as_ref()).unwrap();

        let digest = sha.finalize().unwrap();

        assert_eq!(digest, expected);
    }

    #[test]
    fn rfc_vector2() {
        let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let expected = [
            0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e,
            0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4,
            0x19, 0xdb, 0x06, 0xc1,
        ];

        let mut sha = Sha256::new();

        sha.input(input.as_ref()).unwrap();

        let digest = sha.finalize().unwrap();

        assert_eq!(digest, expected);
    }

    #[test]
    fn rfc_vector3() {
        let input = b"a";
        let expected = [
            0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92, 0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7,
            0x3e, 0x67, 0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e, 0x04, 0x6d, 0x39, 0xcc,
            0xc7, 0x11, 0x2c, 0xd0,
        ];

        let mut sha = Sha256::new();

        for _i in 0..1_000_000 {
            sha.input(input.as_ref()).unwrap();
        }

        let digest = sha.finalize().unwrap();

        assert_eq!(digest, expected);
    }

    #[test]
    fn rfc_vector4() {
        let input = b"0123456701234567012345670123456701234567012345670123456701234567";
        let expected = [
            0x59, 0x48, 0x47, 0x32, 0x84, 0x51, 0xbd, 0xfa, 0x85, 0x05, 0x62, 0x25, 0x46, 0x2c,
            0xc1, 0xd8, 0x67, 0xd8, 0x77, 0xfb, 0x38, 0x8d, 0xf0, 0xce, 0x35, 0xf2, 0x5a, 0xb5,
            0x56, 0x2b, 0xfb, 0xb5,
        ];

        let mut sha = Sha256::new();

        for _i in 0..10 {
            sha.input(input.as_ref()).unwrap();
        }

        let digest = sha.finalize().unwrap();

        assert_eq!(digest, expected);
    }

    // FIXME: skip vector 5, 7, and 9 since the `final_bits` API is unimplemented

    #[test]
    fn rfc_vector6() {
        let input = b"\x19";
        let expected = [
            0x68, 0xaa, 0x2e, 0x2e, 0xe5, 0xdf, 0xf9, 0x6e, 0x33, 0x55, 0xe6, 0xc7, 0xee, 0x37,
            0x3e, 0x3d, 0x6a, 0x4e, 0x17, 0xf7, 0x5f, 0x95, 0x18, 0xd8, 0x43, 0x70, 0x9c, 0x0c,
            0x9b, 0xc3, 0xe3, 0xd4,
        ];

        let mut sha = Sha256::new();

        sha.input(input.as_ref()).unwrap();

        let digest = sha.finalize().unwrap();

        assert_eq!(digest, expected);
    }

    #[test]
    fn rfc_vector8() {
        let input = b"\xe3\xd7\x25\x70\xdc\xdd\x78\x7c\xe3\x88\x7a\xb2\xcd\x68\x46\x52";
        let expected = [
            0x17, 0x5e, 0xe6, 0x9b, 0x02, 0xba, 0x9b, 0x58, 0xe2, 0xb0, 0xa5, 0xfd, 0x13, 0x81,
            0x9c, 0xea, 0x57, 0x3f, 0x39, 0x40, 0xa9, 0x4f, 0x82, 0x51, 0x28, 0xcf, 0x42, 0x09,
            0xbe, 0xab, 0xb4, 0xe8,
        ];

        let mut sha = Sha256::new();

        sha.input(input.as_ref()).unwrap();

        let digest = sha.finalize().unwrap();

        assert_eq!(digest, expected);
    }

    #[test]
    fn rfc_vector10() {
        let input = [
            0x83, 0x26, 0x75, 0x4e, 0x22, 0x77, 0x37, 0x2f, 0x4f, 0xc1, 0x2b, 0x20, 0x52, 0x7a,
            0xfe, 0xf0, 0x4d, 0x8a, 0x05, 0x69, 0x71, 0xb1, 0x1a, 0xd5, 0x71, 0x23, 0xa7, 0xc1,
            0x37, 0x76, 0x00, 0x00, 0xd7, 0xbe, 0xf6, 0xf3, 0xc1, 0xf7, 0xa9, 0x08, 0x3a, 0xa3,
            0x9d, 0x81, 0x0d, 0xb3, 0x10, 0x77, 0x7d, 0xab, 0x8b, 0x1e, 0x7f, 0x02, 0xb8, 0x4a,
            0x26, 0xc7, 0x73, 0x32, 0x5f, 0x8b, 0x23, 0x74, 0xde, 0x7a, 0x4b, 0x5a, 0x58, 0xcb,
            0x5c, 0x5c, 0xf3, 0x5b, 0xce, 0xe6, 0xfb, 0x94, 0x6e, 0x5b, 0xd6, 0x94, 0xfa, 0x59,
            0x3a, 0x8b, 0xeb, 0x3f, 0x9d, 0x65, 0x92, 0xec, 0xed, 0xaa, 0x66, 0xca, 0x82, 0xa2,
            0x9d, 0x0c, 0x51, 0xbc, 0xf9, 0x33, 0x62, 0x30, 0xe5, 0xd7, 0x84, 0xe4, 0xc0, 0xa4,
            0x3f, 0x8d, 0x79, 0xa3, 0x0a, 0x16, 0x5c, 0xba, 0xbe, 0x45, 0x2b, 0x77, 0x4b, 0x9c,
            0x71, 0x09, 0xa9, 0x7d, 0x13, 0x8f, 0x12, 0x92, 0x28, 0x96, 0x6f, 0x6c, 0x0a, 0xdc,
            0x10, 0x6a, 0xad, 0x5a, 0x9f, 0xdd, 0x30, 0x82, 0x57, 0x69, 0xb2, 0xc6, 0x71, 0xaf,
            0x67, 0x59, 0xdf, 0x28, 0xeb, 0x39, 0x3d, 0x54, 0xd6,
        ];
        let expected = [
            0x97, 0xdb, 0xca, 0x7d, 0xf4, 0x6d, 0x62, 0xc8, 0xa4, 0x22, 0xc9, 0x41, 0xdd, 0x7e,
            0x83, 0x5b, 0x8a, 0xd3, 0x36, 0x17, 0x63, 0xf7, 0xe9, 0xb2, 0xd9, 0x5f, 0x4f, 0x0d,
            0xa6, 0xe1, 0xcc, 0xbc,
        ];

        let mut sha = Sha256::new();

        sha.input(input.as_ref()).unwrap();

        let digest = sha.finalize().unwrap();

        assert_eq!(digest, expected);
    }
}
