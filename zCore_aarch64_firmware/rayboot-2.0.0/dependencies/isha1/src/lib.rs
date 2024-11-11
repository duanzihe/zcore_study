#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use core::convert::TryInto;

/// SHA-1 Errors
#[derive(Debug)]
pub enum Error {
    InvalidLength,
    FullPad,
}

/// Digest length in bytes (160-bits)
pub const DIGEST_LEN: usize = 20;

// Word length in bits
pub const WORD_BITS_LEN: usize = 32;

// Word length in bytes
pub const WORD_BYTES_LEN: usize = 4;

// Number of 32-bit words used to process blocks
const W_LEN: usize = 80;

// Block length in bytes
const BLOCK_BYTES_LEN: usize = 64;

// Byte-length to represent the Bit-length of the message
const MSG_BITS_LENGTH_LEN: usize = 8;

// Length of the minimum amount of padding bytes (0x80 || MSG_BITS_LEN(8))
const PAD_AND_LENGTH_LEN: usize = 9;

// Number of intermdiate state blocks (DIGEST_LEN / 4)
const INTERMEDIATE_BLOCKS: usize = 5;

const PAD_START: u8 = 0x80;

// Zero-filled block
const ZERO_BLOCK: [u8; BLOCK_BYTES_LEN] = [0_u8; BLOCK_BYTES_LEN];

// Zero-filled work buffer
const ZERO_WORK: [u32; W_LEN] = [0_u32; W_LEN];

// Initial state of the SHA-1 digest
const INITIAL_STATE: [u32; INTERMEDIATE_BLOCKS] =
    [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

/// SHA-1 digest implementation
pub struct Sha1 {
    /// Internal SHA-1 state, updated every block
    state: [u32; INTERMEDIATE_BLOCKS],
    /// Current message block
    block: [u8; BLOCK_BYTES_LEN],
    /// Index into the current block
    index: usize,
    /// Total bit length of the message
    total_len: u64,
}

impl Sha1 {
    /// Create a newly initialized SHA-1 hasher
    pub fn new() -> Self {
        Self {
            state: INITIAL_STATE,
            block: [0_u8; BLOCK_BYTES_LEN],
            index: 0,
            total_len: 0,
        }
    }

    /// Interface for custom initialization of the SHA-1 state
    ///
    /// Only used for convenience in Cryptopals challenge #29
    ///
    /// NEVER actually do this in practice
    pub fn from_digest(mac: &[u8; DIGEST_LEN]) -> Self {
        let mut state = [0_u32; INTERMEDIATE_BLOCKS];

        for (i, w) in mac.chunks_exact(WORD_BYTES_LEN).enumerate() {
            state[i] = u32::from_be_bytes(w.try_into().unwrap());
        }

        Self {
            state: state,
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

    /// Convenience function to compute the SHA-1 digest of the given message
    pub fn digest(msg: &[u8]) -> Result<[u8; DIGEST_LEN], Error> {
        let mut sha = Self::new();
        sha.input(&msg)?;
        sha.finalize()
    }

    // Process a block, updating the internal state
    // FIXME: also implement the queued version mentioned in the RFC for space-constrained devices
    fn process_block(&mut self) {
        let mut w = [0_u32; W_LEN];

        // initialize the first 16 words from the message block
        for (t, b) in self.block.chunks_exact(WORD_BYTES_LEN).enumerate() {
            // unwrap is safe, since b will always be exactly four bytes
            w[t] = u32::from_be_bytes(b.try_into().unwrap());
        }

        // initialize the remaining words
        // perform an XOR and circular shift on four previous words
        for t in 16..80 {
            w[t] = Self::circular_shift(1, w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];

        for t in 0..80 {
            let temp = ((Self::circular_shift(5, a) as u64
                + Self::f(t, b, c, d) as u64
                + e as u64
                + w[t] as u64
                + Self::k(t) as u64)
                & 0xffff_ffff) as u32;
            e = d;
            d = c;
            c = Self::circular_shift(30, b);
            b = a;
            a = temp;
        }

        for (i, word) in self.state.iter_mut().enumerate() {
            let temp = match i {
                0 => a as u64,
                1 => b as u64,
                2 => c as u64,
                3 => d as u64,
                4 => e as u64,
                _ => unreachable!("invalid state index: {}", i),
            };
            *word = ((*word as u64 + temp) & 0xffff_ffff) as u32;
        }

        // clear any potentially sensitive material
        Self::zero_work(&mut w);
        Self::zero_block(&mut self.block);

        self.index = 0;
    }

    // Rotate a given 32-bit word by s bits
    // Equivalent to: (word << s) | (word >> (32 - s))
    #[inline(always)]
    fn circular_shift(s: u32, word: u32) -> u32 {
        word.rotate_left(s)
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

    /// Compute the final digest using a forged value for the total message length
    ///
    /// NEVER actually do this, only for Cryptopals challenge #29
    pub fn finalize_insecure(&mut self, forged_total_len: u64) -> Result<[u8; DIGEST_LEN], Error> {
        if self.index < BLOCK_BYTES_LEN {
            let old_len = self.index;

            // forge the total message length
            self.total_len = forged_total_len;

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

    /// Reset the internal state to the initial state
    pub fn reset(&mut self) {
        Self::zero_block(&mut self.block);
        self.state.copy_from_slice(INITIAL_STATE.as_ref());
        self.index = 0;
        self.total_len = 0;
    }

    // Pad a message to next block-length bytes
    fn pad(&mut self) -> Result<(), Error> {
        Self::inner_pad(&mut self.block, self.index, self.total_len)
    }

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

    /// Pad a message using SHA-1 formatting
    ///
    /// Only return the padding
    pub fn pad_message(msg: &[u8]) -> Result<Vec<u8>, Error> {
        let msg_len = msg.len();

        if msg_len == 0 || msg_len * 8 > core::u64::MAX as usize {
            return Err(Error::InvalidLength);
        }

        let total_len = (msg_len * 8) as u64;
        let mut pad_block = [0_u8; BLOCK_BYTES_LEN];

        let end_len = if msg_len % BLOCK_BYTES_LEN == 0 {
            // add full block of padding
            Self::inner_pad(&mut pad_block, 0, total_len)?;
            0
        } else if msg_len < BLOCK_BYTES_LEN {
            // copy message to padding block
            Self::inner_pad(&mut pad_block, msg_len, total_len)?;
            msg_len
        } else {
            // message is larger than a full block
            // non-modulo the block length
            let last_len = msg_len % BLOCK_BYTES_LEN;
            Self::inner_pad(&mut pad_block, last_len, total_len)?;
            last_len
        };

        let mut res: Vec<u8> = Vec::with_capacity(BLOCK_BYTES_LEN * 2);

        // add the padding block to the result
        res.extend_from_slice(&pad_block[end_len..]);

        if end_len > BLOCK_BYTES_LEN - PAD_AND_LENGTH_LEN {
            // not enough space to write the total bit length
            // add a block full of zeroes + total bit length
            Self::inner_full_pad(&mut pad_block, total_len);
            res.extend_from_slice(&pad_block);
        }

        Ok(res)
    }

    // Add a full block of padding
    fn full_pad(&mut self) {
        Self::inner_full_pad(&mut self.block, self.total_len);
    }

    fn inner_full_pad(block: &mut [u8; BLOCK_BYTES_LEN], total_len: u64) {
        Self::zero_bytes(&mut block[..BLOCK_BYTES_LEN - MSG_BITS_LENGTH_LEN]);
        block[BLOCK_BYTES_LEN - MSG_BITS_LENGTH_LEN..]
            .copy_from_slice(total_len.to_be_bytes().as_ref());
    }

    // Constant bitwise operations over b, c, and d
    // Operations performed depends on t
    fn f(t: usize, b: u32, c: u32, d: u32) -> u32 {
        match t {
            // (B AND C) OR ((NOT B) AND D)
            0..=19 => (b & c) | ((!b) & d),
            // B XOR C XOR D
            20..=39 => b ^ c ^ d,
            // (B AND C) OR (B AND D) OR (C AND D)
            40..=59 => (b & c) | (b & d) | (c & d),
            // B XOR C XOR D
            60..=79 => b ^ c ^ d,
            _ => unreachable!("invalid value of t: {}", t),
        }
    }

    // K constants depending on the value of t
    //
    // t must be between 0..=79
    fn k(t: usize) -> u32 {
        match t {
            0..=19 => 0x5a82_7999,
            20..=39 => 0x6ed_9eba1,
            40..=59 => 0x8f1b_bcdc,
            60..=79 => 0xca62_c1d6,
            _ => unreachable!("invalid value of t: {}", t),
        }
    }

    // Zero a block that potentially contains sensitive material
    #[inline(always)]
    fn zero_block(block: &mut [u8; BLOCK_BYTES_LEN]) {
        block.copy_from_slice(ZERO_BLOCK.as_ref());
    }

    // Zero a work buffer that potentially contains sensitive material
    #[inline(always)]
    fn zero_work(work: &mut [u32; W_LEN]) {
        work.copy_from_slice(ZERO_WORK.as_ref());
    }

    // Fill a slice with zeroes
    //
    // Guaranteed less or equal to block length at compile time
    #[inline(always)]
    fn zero_bytes(buf: &mut [u8]) {
        buf.copy_from_slice(&ZERO_BLOCK[..buf.len()]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_pad() {
        let test_bytes = [0x61, 0x62, 0x63, 0x64, 0x65];
        let test_bytes_len = test_bytes.len();

        let expected_block = [
            0x61, 0x62, 0x63, 0x64, 0x65, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28,
        ];

        let mut sha = Sha1::new();

        sha.block[..test_bytes_len].copy_from_slice(test_bytes.as_ref());
        sha.index = test_bytes_len;
        sha.total_len = (test_bytes_len * 8) as u64;

        sha.pad().unwrap();

        assert_eq!(sha.block, expected_block);
    }

    #[test]
    fn check_pad_message() {
        let test_bytes = [0x61, 0x62, 0x63, 0x64, 0x65];

        let expected_block = [
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x28,
        ];

        let mut padded_block = Sha1::pad_message(test_bytes.as_ref()).unwrap();

        assert_eq!(padded_block[..], expected_block[..]);
        assert_eq!(expected_block.len(), 59);

        let expected_block_lg = [
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xd8,
        ];

        let padded_block_lg = Sha1::pad_message(&padded_block).unwrap();

        assert_eq!(padded_block_lg[..], expected_block_lg[..]);

        // pad a block larger than full block, non-modulo the block length
        // still has enough room to write padding start and total bit length in one padding block
        padded_block.extend_from_slice([0x61; 60].as_ref());

        let expected_block_lg_non_mod = [0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xb8];

        let padded_block_lg_non_mod = Sha1::pad_message(&padded_block).unwrap();

        assert_eq!(padded_block_lg_non_mod[..], expected_block_lg_non_mod[..]);

        let expected_block_lg_non_mod_full_pad = [
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, 0xc0,
        ];

        // add one extra byte to require a full padding block of zeroes
        padded_block.push(0x61);

        let padded_block_lg_non_mod_full_pad = Sha1::pad_message(&padded_block).unwrap();

        assert_eq!(
            padded_block_lg_non_mod_full_pad[..],
            expected_block_lg_non_mod_full_pad[..]
        );

        let a_block = [0x61; 93];
        let expected_a_pad = [
            0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xe8,
        ];

        let pad_a = Sha1::pad_message(a_block.as_ref()).unwrap();

        assert_eq!(pad_a[..], expected_a_pad[..]);
        assert_eq!(pad_a.len(), 35);
    }

    #[test]
    fn check_digest_one() {
        let input = b"abc".to_vec();
        let expected = [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
            0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
        ];

        let digest = Sha1::digest(&input).unwrap();

        assert_eq!(digest, expected);
    }

    #[test]
    fn check_digest_two() {
        let inputs = [
            b"abcdbcdecdefdefgefghfghighijhi".to_vec(),
            b"jkijkljklmklmnlmnomnopnopq".to_vec(),
        ];
        let expected = [
            0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae, 0x4a, 0xa1, 0xf9, 0x51,
            0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1,
        ];

        let mut sha = Sha1::new();

        for input in inputs.iter() {
            sha.input(&input).unwrap();
        }

        let digest = sha.finalize().unwrap();

        assert_eq!(digest, expected);
        assert_eq!(sha.block, [0_u8; BLOCK_BYTES_LEN]);
    }

    #[test]
    fn check_digest_three() {
        let input = 0x61;
        let expected = [
            0x34, 0xaa, 0x97, 0x3c, 0xd4, 0xc4, 0xda, 0xa4, 0xf6, 0x1e, 0xeb, 0x2b, 0xdb, 0xad,
            0x27, 0x31, 0x65, 0x34, 0x01, 0x6f,
        ];

        let mut sha = Sha1::new();

        for _i in 0..1_000_000 {
            sha.input(&[input]).unwrap();

            if sha.index % BLOCK_BYTES_LEN == 0 {
                assert_eq!(sha.block, [0_u8; BLOCK_BYTES_LEN]);
            }
        }

        let digest = sha.finalize().unwrap();

        assert_eq!(digest, expected);
        assert_eq!(sha.block, [0_u8; BLOCK_BYTES_LEN]);
    }

    #[test]
    fn check_digest_four() {
        let inputs = [
            b"01234567012345670123456701234567",
            b"01234567012345670123456701234567",
        ];
        let expected = [
            0xde, 0xa3, 0x56, 0xa2, 0xcd, 0xdd, 0x90, 0xc7, 0xa7, 0xec, 0xed, 0xc5, 0xeb, 0xb5,
            0x63, 0x93, 0x4f, 0x46, 0x04, 0x52,
        ];

        let mut sha = Sha1::new();

        for _i in 0..10 {
            for input in inputs.iter() {
                sha.input(input.as_ref()).unwrap();
            }
        }

        assert_eq!(sha.block, [0_u8; BLOCK_BYTES_LEN]);

        let digest = sha.finalize().unwrap();

        assert_eq!(digest, expected);
    }
}
