use alloc::vec::Vec;

use crate::{constant_compare, der, hash, Error, Hash, Verification};

pub fn encode(message: &[u8], em_len: usize, hash: Hash) -> Result<Vec<u8>, Error> {
    // RFC8017 9.2 Steps 1. H = Hash(M) If th e hash function outputs message too long", output
    //   "message too long" and stop
    let h = hash::digest(&message, hash)?;

    // RFC8017 9.2 Steps 2. Encode the algorithm ID for the hash function and the hash value
    //   into an ASN.1 value
    let mut t = der::encoding(hash)?;
    t.extend_from_slice(&h);

    let t_len = t.len();
    if em_len < t_len + 11 {
        // RFC8017 9.2 Steps 3. If emLen < tLen + 11, output "intended encoded message length
        //   too short" and stop
        Err(Error::InvalidMessage)
    } else {
        // RFC8017 9.2 Steps 4. Generate an octet string PS consisting of
        //   emLen - tLen - 3 octets with hexadecimal value 0xff
        let ps_len = em_len - t_len - 3;
        let mut ps: Vec<u8> = Vec::with_capacity(ps_len);
        ps.resize(ps_len, 0xff);

        // RFC8017 9.2 Steps 5. EM = 0x00 || 0x01 || PS || 0x00 || T
        let mut em: Vec<u8> = Vec::with_capacity(em_len);
        em.extend_from_slice([0x00, 0x01].as_ref());
        em.extend_from_slice(&ps);
        em.push(0x00);
        em.extend_from_slice(&t);

        Ok(em)
    }
}

/// Comparison a PKCS1-v1.5 encoded message according to RFC8017
///
/// Encodes the given message according to RFC8017 9.2 PCKS1_v1.5 encoding
///
/// Checks (in constant-time) that the provided encoded message matches
///
/// Function has not been checked for constant-time evaluation
pub fn verify(
    message: &[u8],
    encoded_message: &[u8],
    hash: Hash,
) -> Result<Verification, Verification> {
    let res = encode(&message, encoded_message.len(), hash).map_err(|_| Verification::Inconsistent);

    let err_num = match res {
        Ok(ref em) => constant_compare(em, &encoded_message),
        Err(_) => constant_compare(&encoded_message, &encoded_message),
    };

    if err_num == 0 && res.is_ok() {
        Ok(Verification::Consistent)
    } else {
        Err(Verification::Inconsistent)
    }
}

/// INSECURE verification of PKCS1-v1.5 encoded message according to RFC8017
///
/// Only checks the leading bytes, trailing pad/delimiter, and the DER encoded hash
///
/// Used for RSA(e=3, m) broadcast attack in Cryptopals challenge #42
///
/// Please for the love of fuck, never actually do this
pub fn verify_insecure(
    message: &[u8],
    encoded_message: &[u8],
    hash: Hash,
) -> Result<Verification, Verification> {
    // Right at the start, early exit on hash failure (opens timing side-channels)
    let h = hash::digest(&message, hash).map_err(|_| Verification::Inconsistent)?;

    // Another early exit timing side-channel, and only partial comparison of PS bytes
    // Also, non-constant-time comparison
    if encoded_message[..3] != [0x00, 0x01, 0xff] {
        return Err(Verification::Inconsistent);
    }

    // Get DER encoding of the hash function, another early exit timing side-channel...
    let mut t = der::encoding(hash).map_err(|_| Verification::Inconsistent)?;
    t.extend_from_slice(&h);

    // Who needs to check all those 0xff bytes anyways?
    let mut prev_len = 3;
    for &b in encoded_message[3..].iter() {
        if b == 0 {
            break;
        };
        prev_len += 1;
    }

    // Check that DER encoding is preceeded by 0xff || 0x00
    // Trying to do things right, at least we're using constant-time comparison, right?
    let mut err_num = constant_compare(
        &encoded_message[prev_len - 1..prev_len + 1],
        [0xff, 0x00].as_ref(),
    );

    // Check the DER encoding in the encoded message matches the one we calculated
    err_num |= constant_compare(&encoded_message[prev_len + 1..], &t);

    if err_num == 0 {
        Ok(Verification::Consistent)
    } else {
        Err(Verification::Inconsistent)
    }
}

#[cfg(test)]
mod tests {
    use crate::RSA_1024_LEN;

    use super::*;

    const MSG: &[u8; 33] = b"This may be the last thing I type";

    #[test]
    fn check_pkcs1_v1_5_encoding() {
        let em = encode(MSG.as_ref(), RSA_1024_LEN / 8, Hash::Sha256).unwrap();
        let res = verify(MSG.as_ref(), &em, Hash::Sha256).unwrap();
        assert_eq!(res, Verification::Consistent);
    }

    #[test]
    fn check_pkcs1_v1_5_insecure_verification() {
        let em = encode(MSG.as_ref(), RSA_1024_LEN / 8, Hash::Sha256).unwrap();
        let res = verify_insecure(MSG.as_ref(), &em, Hash::Sha256).unwrap();
        assert_eq!(res, Verification::Consistent);
    }
}
