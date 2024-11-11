use crate::{hash, Error, Hash};
use alloc::vec::Vec;
use num::traits::float::FloatCore;

/// Mask Generation Function 1 from RFC8017 Appendix B
///
/// Outputs the mask of mask_len bytes using the input seed
///
/// Returns error if mask_len > 2**32 * Hash Digest Length
pub fn mgf1(seed: &[u8], mask_len: usize, hash: Hash) -> Result<Vec<u8>, Error> {
    let hash_len = hash::hash_len(hash)?;
    // 1. If mask_len > 2**32 * hLen, output "mask too long"
    if mask_len > 0x1_0000_0000 * hash_len {
        return Err(Error::InvalidMaskLength);
    }

    // prepare input for step 3B
    let seed_len = seed.len();
    let mut input = seed.to_vec();
    // add room for C encoding
    input.extend_from_slice([0_u8; 4].as_ref());

    let lim = (mask_len as f64 / hash_len as f64).ceil() as usize;
    // 2. Let T be the empty octet string
    let mut t: Vec<u8> = Vec::with_capacity(lim * hash_len);

    // 3. For counter from 0 to ceil(mask_len / hLen) - 1
    for i in 0..lim {
        // 3A. Convert counter to an octet string C of length 4 octets
        let c = (i as u32).to_be_bytes();
        // 3B. Concatenate the hash of the seed and C to the octet string T
        input[seed_len..].copy_from_slice(c.as_ref());
        t.extend_from_slice(&hash::digest(&input, hash)?);
    }

    // 4. Output the leading mask_len octets of T
    Ok(t[..mask_len].to_vec())
}
