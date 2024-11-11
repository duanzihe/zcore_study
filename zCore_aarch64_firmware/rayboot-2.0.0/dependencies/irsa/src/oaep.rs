use crate::{hash, mask, xor_assign};
use crate::{Error, Hash};
use crate::{RSA_1024_LEN, RSA_2048_LEN, RSA_3072_LEN, RSA_4096_LEN};
use alloc::vec::Vec;
use rand::Rng;
use rand::SeedableRng;

const ZERO_BYTES: [u8; RSA_4096_LEN / 8] = [0_u8; RSA_4096_LEN / 8];

/// OAEP encode a message using an optional label according to RFC8017 7.1.1 Steps 2
///
/// Returns an error on invalid message and/or label length
pub fn encode(
    message: &[u8],
    label: Option<&[u8]>,
    n_len: usize,
    hash: Hash,
) -> Result<Vec<u8>, Error> {
    check_n_len(n_len)?;
    let hash_len = hash::hash_len(hash)?;
    let k = n_len / 8;
    check_message_len(message.len(), k - (2 * hash_len) - 2)?;

    let label = match label {
        Some(l) => l,
        None => &[],
    };

    check_label_len(label.len(), hash)?;

    let db_len = db_len(k, hash)?;
    let mut db: Vec<u8> = Vec::with_capacity(db_len);
    db.resize(db_len, 0);

    let mut seed = Vec::with_capacity(hash_len);
    seed.resize(hash_len, 0);

    let mut res: Vec<u8> = Vec::with_capacity(k);
    res.resize(k, 0);

    oaep_encode_inner(
        &message,
        &label,
        &mut seed[..],
        &mut db[..],
        &mut res[..],
        hash,
    )?;

    Ok(res)
}

/// OAEP decode an encoded message with an optional label according to RFC8017 7.1.2 Steps 3
///
/// Returns error on invalid message and/or label length, and any decoding errors
///
/// Care has been taken to not allow an attacker to distinguish, via timing or error type, what
/// decoding errors occurred, if any.
///
/// Currently, there has been no validation of constant-time evaluation
pub fn decode(
    encoded: &[u8],
    label: Option<&[u8]>,
    n_len: usize,
    hash: Hash,
) -> Result<Vec<u8>, Error> {
    check_n_len(n_len).map_err(|_| Error::InvalidCiphertext)?;
    check_message_len(encoded.len(), n_len).map_err(|_| Error::InvalidCiphertext)?;

    let k = n_len / 8;

    let label = match label {
        Some(l) => l,
        None => &[],
    };

    check_label_len(label.len(), hash).map_err(|_| Error::InvalidCiphertext)?;

    let db_len = db_len(k, hash).map_err(|_| Error::InvalidCiphertext)?;
    let mut db: Vec<u8> = Vec::with_capacity(db_len);
    db.resize(db_len, 0);

    let hash_len = hash::hash_len(hash).map_err(|_| Error::InvalidCiphertext)?;
    let mut seed: Vec<u8> = Vec::with_capacity(hash_len);
    seed.resize(hash_len, 0);

    let mut msg_idx = 0_usize;

    oaep_decode_inner(
        &encoded,
        &label,
        &mut seed[..],
        &mut db[..],
        &mut msg_idx,
        k,
        hash,
    )?;

    // no decoding errors, copy message to the result
    let mut res: Vec<u8> = Vec::with_capacity(db.len() - msg_idx);
    res.extend_from_slice(&db[msg_idx..]);

    Ok(res)
}

// Perform OAEP encoding for the various lengths of k (1024, 2048, 3072, 4096)
//
// Caller performs validity checks on message, label, seed, and db
fn oaep_encode_inner(
    message: &[u8],
    label: &[u8],
    seed: &mut [u8],
    db: &mut [u8],
    res: &mut [u8],
    hash: Hash,
) -> Result<(), Error> {
    // 7.1.1 Steps 2.a Let lHash = Hash(L)
    let hash_len = hash::hash_len(hash)?;
    let lhash = hash::digest(label, hash)?;

    // 7.1.1 Steps 2.b Generate a padding string PS consisting of k - mLen - 2hLen - 2 zero octets
    let k = res.len();
    let ps_len = k - message.len() - (2 * hash_len) - 2;

    // 7.1.1 Steps 2.c Concatenate lHash, PS, a single octet with hexadecimal value 0x01,
    //     and the message M
    //
    //     DB = lHash || PS || 0x01 || M
    db[..hash_len].copy_from_slice(&lhash);
    db[hash_len..hash_len + ps_len].copy_from_slice(&ZERO_BYTES[..ps_len]);
    db[hash_len + ps_len] = 0x01;
    db[hash_len + ps_len + 1..].copy_from_slice(message);

    // 7.1.1. Steps 2.d Generate a random octet string seed of length hLen
    let mut rng = rand::rngs::StdRng::seed_from_u64(0);
    rng.fill(&mut seed[..]);

    // 7.1.1. Steps 2.e Let dbMask = MGF(seed, k - hLen - 1)
    let mut db_mask = mask::mgf1(&seed, k - hash_len - 1, hash)?;

    // 7.1.1. Steps 2.f Let maskedDB = DB \xor dbMask
    xor_assign(&mut db[..], &db_mask);

    // 7.1.1. Steps 2.g Let seedMask = MGF(maskedDB, hLen)
    let mut seed_mask = mask::mgf1(&db, hash_len, hash)?;

    // 7.1.1. Steps 2.h Let maskedSeed = seed \xor seedMask
    xor_assign(&mut seed[..], &seed_mask);

    // 7.1.1. Steps 2.i EM = 0x00 || maskedSeed || maskedDB
    res[1..1 + hash_len].copy_from_slice(seed.as_ref());
    res[hash_len + 1..].copy_from_slice(db.as_ref());

    // clear temporary variables
    let db_len = db.len();
    db.copy_from_slice(&ZERO_BYTES[..db_len]);

    let db_mask_len = db_mask.len();
    db_mask[..].copy_from_slice(&ZERO_BYTES[..db_mask_len]);

    let seed_len = seed.len();
    seed.copy_from_slice(&ZERO_BYTES[..seed_len]);

    let seed_mask_len = seed_mask.len();
    seed_mask[..].copy_from_slice(&ZERO_BYTES[..seed_mask_len]);

    Ok(())
}

// Perform OAEP decoding for the various lengths of k (1024, 2048, 3072, 4096)
//
// Caller performs validity checks on encoded message, label, seed, and db
fn oaep_decode_inner(
    encoded: &[u8],
    label: &[u8],
    seed: &mut [u8],
    db: &mut [u8],
    db_idx: &mut usize,
    k: usize,
    hash: Hash,
) -> Result<(), Error> {
    // 7.1.2 Steps 3.a Let lHash = Hash(L)
    let hash_len = hash::hash_len(hash).map_err(|_| Error::InvalidCiphertext)?;
    let lhash = hash::digest(label, hash).map_err(|_| Error::InvalidCiphertext)?;

    // 7.1.2 Steps 3.b EM = Y || maskedSeed || maskedDB
    let y = encoded[0];
    seed.copy_from_slice(&encoded[1..1 + hash_len]);
    db.copy_from_slice(&encoded[1 + hash_len..]);

    // 7.1.2 Steps 3.c let seedMask = MGF(maskedDB, hLen)
    let mut seed_mask = mask::mgf1(&db, hash_len, hash).map_err(|_| Error::InvalidCiphertext)?;

    // 7.1.2 Steps 3.d let seed = maskedSeed \xor seedMask
    xor_assign(seed, &seed_mask);

    // 7.1.2 Steps 3.e let dbMask = MGF(seed, k - hLen -1)
    let mut db_mask =
        mask::mgf1(&seed, k - hash_len - 1, hash).map_err(|_| Error::InvalidCiphertext)?;

    // 7.1.2 Steps 3.f let DB = maskedDB \xor dbMask
    xor_assign(db, &db_mask);

    // 7.1.2 Steps 3.g DB = lHash' || PS || 0x01 || M
    let lhash_prime = &db[..hash_len];
    let mut ps_len = hash_len;

    // Get the length of PS padding zero bytes (possibly zero)
    for &b in db[hash_len..].iter() {
        if b != 0 {
            break;
        };
        ps_len += 1;
    }

    /* 7.1.2 Steps 4 Output the message M
     *
     * Note: Care must be taken to ensure that an opponent cannot
     * distinguish the different error conditions in Step 3.g, whether by
     * error message or timing, and, more generally, that an opponent
     * cannot learn partial information about the encoded message EM.
     * Otherwise, an opponent may be able to obtain useful information
     * about the decryption of the ciphertext C, leading to a chosen-
     * ciphertext attack such as the one observed by Manger [MANGER].
     */
    let mut err_num = y;

    // constant-time compare equality of lHash and lHash'
    for (el, ar) in lhash.iter().zip(lhash_prime.iter()) {
        err_num |= el ^ ar;
    }

    // constant-time check 0x01 separates PS and M
    err_num |= db[ps_len] ^ 0x01;

    // Set index in DB to the start of the message
    *db_idx = ps_len + 1;

    // clear temporary variables
    let seed_len = seed.len();
    seed.copy_from_slice(&ZERO_BYTES[..seed_len]);

    let seed_mask_len = seed_mask.len();
    seed_mask[..].copy_from_slice(&ZERO_BYTES[..seed_mask_len]);

    let db_mask_len = db_mask.len();
    db_mask[..].copy_from_slice(&ZERO_BYTES[..db_mask_len]);

    if err_num == 0 {
        Ok(())
    } else {
        Err(Error::InvalidCiphertext)
    }
}

fn db_len(k: usize, hash: Hash) -> Result<usize, Error> {
    Ok(k - hash::hash_len(hash)? - 1)
}

fn max_label_len(hash: Hash) -> Result<usize, Error> {
    match hash {
        // OAEP label length limit from RFC8017 7.1.1 Steps 1.a (2^61 - 1)
        Hash::Sha1 => Ok(0x1fff_ffff_ffff_ffff_usize),
        // OAEP label length limit from RFC8017 7.1.1 Steps 1.a (2^61 + 2^12 - 1)
        // Note: 2^12 represents difference in output bit-length of SHA-1 and SHA-256
        //     should multiply, but even 2^61 - 1 is too large to construct on x86/64
        Hash::Sha256 => Ok(0x2000_0000_0000_0fff_usize),
        Hash::Sha224 | Hash::Sha384 | Hash::Sha512 | Hash::Sha512_224 | Hash::Sha512_256 => {
            Err(Error::UnimplementedHash)
        }
        Hash::Md2 | Hash::Md5 => Err(Error::DeprecatedHash),
    }
}

fn check_n_len(n_len: usize) -> Result<(), Error> {
    match n_len {
        RSA_1024_LEN => Ok(()),
        RSA_2048_LEN => Ok(()),
        RSA_3072_LEN => Ok(()),
        RSA_4096_LEN => Ok(()),
        _ => Err(Error::InvalidSize),
    }
}

fn check_message_len(len: usize, expected_len: usize) -> Result<(), Error> {
    if len > expected_len {
        Err(Error::InvalidMessage)
    } else {
        Ok(())
    }
}

fn check_label_len(len: usize, hash: Hash) -> Result<(), Error> {
    if len > max_label_len(hash)? {
        Err(Error::InvalidLabelLength)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OAEP_1024_SHA1_MESSAGE_LIMIT: usize = RSA_1024_LEN / 8 - (2 * isha1::DIGEST_LEN) - 2;
    const OAEP_2048_SHA1_MESSAGE_LIMIT: usize = RSA_2048_LEN / 8 - (2 * isha1::DIGEST_LEN) - 2;
    const OAEP_3072_SHA1_MESSAGE_LIMIT: usize = RSA_3072_LEN / 8 - (2 * isha1::DIGEST_LEN) - 2;
    const OAEP_4096_SHA1_MESSAGE_LIMIT: usize = RSA_4096_LEN / 8 - (2 * isha1::DIGEST_LEN) - 2;

    const OAEP_1024_SHA256_MESSAGE_LIMIT: usize = RSA_1024_LEN / 8 - (2 * isha256::DIGEST_LEN) - 2;
    const OAEP_2048_SHA256_MESSAGE_LIMIT: usize = RSA_2048_LEN / 8 - (2 * isha256::DIGEST_LEN) - 2;
    const OAEP_3072_SHA256_MESSAGE_LIMIT: usize = RSA_3072_LEN / 8 - (2 * isha256::DIGEST_LEN) - 2;
    const OAEP_4096_SHA256_MESSAGE_LIMIT: usize = RSA_4096_LEN / 8 - (2 * isha256::DIGEST_LEN) - 2;

    const MSG: &[u8; 16] = b"some message yeh";
    const LABEL: &[u8; 16] = b"my badass LABEL?";

    #[test]
    fn check_oaep_1024_sha1() {
        // test encoding and decoding with no LABEL
        let encoded = encode(MSG.as_ref(), None, RSA_2048_LEN, Hash::Sha1).unwrap();
        let decoded = decode(encoded.as_ref(), None, RSA_2048_LEN, Hash::Sha1).unwrap();

        assert_eq!(decoded[..], MSG[..]);

        // test encoding and decoding with a LABEL
        let encoded = encode(MSG.as_ref(), Some(LABEL.as_ref()), RSA_2048_LEN, Hash::Sha1).unwrap();
        let decoded = decode(
            encoded.as_ref(),
            Some(LABEL.as_ref()),
            RSA_2048_LEN,
            Hash::Sha1,
        )
        .unwrap();

        assert_eq!(decoded[..], MSG[..]);
    }

    #[test]
    fn check_oaep_2048_sha1() {
        // test encoding and decoding with no LABEL
        let encoded = encode(MSG.as_ref(), None, RSA_2048_LEN, Hash::Sha1).unwrap();
        let decoded = decode(encoded.as_ref(), None, RSA_2048_LEN, Hash::Sha1).unwrap();

        assert_eq!(decoded[..], MSG[..]);

        // test encoding and decoding with a LABEL
        let encoded = encode(MSG.as_ref(), Some(LABEL.as_ref()), RSA_2048_LEN, Hash::Sha1).unwrap();
        let decoded = decode(
            encoded.as_ref(),
            Some(LABEL.as_ref()),
            RSA_2048_LEN,
            Hash::Sha1,
        )
        .unwrap();

        assert_eq!(decoded[..], MSG[..]);
    }

    #[test]
    fn check_oaep_3072_sha1() {
        // test encoding and decoding with no LABEL
        let encoded = encode(MSG.as_ref(), None, RSA_3072_LEN, Hash::Sha1).unwrap();
        let decoded = decode(encoded.as_ref(), None, RSA_3072_LEN, Hash::Sha1).unwrap();

        assert_eq!(decoded[..], MSG[..]);

        // test encoding and decoding with a LABEL
        let encoded = encode(MSG.as_ref(), Some(LABEL.as_ref()), RSA_3072_LEN, Hash::Sha1).unwrap();
        let decoded = decode(
            encoded.as_ref(),
            Some(LABEL.as_ref()),
            RSA_3072_LEN,
            Hash::Sha1,
        )
        .unwrap();

        assert_eq!(decoded[..], MSG[..]);
    }

    #[test]
    fn check_oaep_4096_sha1() {
        // test encoding and decoding with no LABEL
        let encoded = encode(MSG.as_ref(), None, RSA_4096_LEN, Hash::Sha1).unwrap();
        let decoded = decode(encoded.as_ref(), None, RSA_4096_LEN, Hash::Sha1).unwrap();

        assert_eq!(decoded[..], MSG[..]);

        // test encoding and decoding with a LABEL
        let encoded = encode(MSG.as_ref(), Some(LABEL.as_ref()), RSA_4096_LEN, Hash::Sha1).unwrap();
        let decoded = decode(
            encoded.as_ref(),
            Some(LABEL.as_ref()),
            RSA_4096_LEN,
            Hash::Sha1,
        )
        .unwrap();

        assert_eq!(decoded[..], MSG[..]);
    }

    #[test]
    fn check_oaep_1024_sha256() {
        // test encoding and decoding with no LABEL
        let encoded = encode(MSG.as_ref(), None, RSA_1024_LEN, Hash::Sha256).unwrap();
        let decoded = decode(encoded.as_ref(), None, RSA_1024_LEN, Hash::Sha256).unwrap();

        assert_eq!(decoded[..], MSG[..]);

        // test encoding and decoding with a LABEL
        let encoded = encode(
            MSG.as_ref(),
            Some(LABEL.as_ref()),
            RSA_1024_LEN,
            Hash::Sha256,
        )
        .unwrap();
        let decoded = decode(
            encoded.as_ref(),
            Some(LABEL.as_ref()),
            RSA_1024_LEN,
            Hash::Sha256,
        )
        .unwrap();

        assert_eq!(decoded[..], MSG[..]);
    }

    #[test]
    fn check_oaep_2048_sha256() {
        // test encoding and decoding with no LABEL
        let encoded = encode(MSG.as_ref(), None, RSA_2048_LEN, Hash::Sha256).unwrap();
        let decoded = decode(encoded.as_ref(), None, RSA_2048_LEN, Hash::Sha256).unwrap();

        assert_eq!(decoded[..], MSG[..]);

        // test encoding and decoding with a LABEL
        let encoded = encode(
            MSG.as_ref(),
            Some(LABEL.as_ref()),
            RSA_2048_LEN,
            Hash::Sha256,
        )
        .unwrap();
        let decoded = decode(
            encoded.as_ref(),
            Some(LABEL.as_ref()),
            RSA_2048_LEN,
            Hash::Sha256,
        )
        .unwrap();

        assert_eq!(decoded[..], MSG[..]);
    }

    #[test]
    fn check_oaep_3072_sha256() {
        // test encoding and decoding with no LABEL
        let encoded = encode(MSG.as_ref(), None, RSA_3072_LEN, Hash::Sha256).unwrap();
        let decoded = decode(encoded.as_ref(), None, RSA_3072_LEN, Hash::Sha256).unwrap();

        assert_eq!(decoded[..], MSG[..]);

        // test encoding and decoding with a LABEL
        let encoded = encode(
            MSG.as_ref(),
            Some(LABEL.as_ref()),
            RSA_3072_LEN,
            Hash::Sha256,
        )
        .unwrap();
        let decoded = decode(
            encoded.as_ref(),
            Some(LABEL.as_ref()),
            RSA_3072_LEN,
            Hash::Sha256,
        )
        .unwrap();

        assert_eq!(decoded[..], MSG[..]);
    }

    #[test]
    fn check_oaep_4096_sha256() {
        // test encoding and decoding with no LABEL
        let encoded = encode(MSG.as_ref(), None, RSA_4096_LEN, Hash::Sha256).unwrap();
        let decoded = decode(encoded.as_ref(), None, RSA_4096_LEN, Hash::Sha256).unwrap();

        assert_eq!(decoded[..], MSG[..]);

        // test encoding and decoding with a LABEL
        let encoded = encode(
            MSG.as_ref(),
            Some(LABEL.as_ref()),
            RSA_4096_LEN,
            Hash::Sha256,
        )
        .unwrap();
        let decoded = decode(
            encoded.as_ref(),
            Some(LABEL.as_ref()),
            RSA_4096_LEN,
            Hash::Sha256,
        )
        .unwrap();

        assert_eq!(decoded[..], MSG[..]);
    }

    #[test]
    fn check_oaep_sha1_invalid_message() {
        assert!(encode(
            [0_u8; OAEP_1024_SHA1_MESSAGE_LIMIT + 1].as_ref(),
            None,
            RSA_1024_LEN,
            Hash::Sha1,
        )
        .is_err());
        assert!(encode(
            [0_u8; OAEP_2048_SHA1_MESSAGE_LIMIT + 1].as_ref(),
            None,
            RSA_2048_LEN,
            Hash::Sha1,
        )
        .is_err());
        assert!(encode(
            [0_u8; OAEP_3072_SHA1_MESSAGE_LIMIT + 1].as_ref(),
            None,
            RSA_3072_LEN,
            Hash::Sha1
        )
        .is_err());
        assert!(encode(
            [0_u8; OAEP_4096_SHA1_MESSAGE_LIMIT + 1].as_ref(),
            None,
            RSA_4096_LEN,
            Hash::Sha1
        )
        .is_err());
    }

    #[test]
    fn check_oaep_sha256_invalid_message() {
        assert!(encode(
            [0_u8; OAEP_1024_SHA256_MESSAGE_LIMIT + 1].as_ref(),
            None,
            RSA_1024_LEN,
            Hash::Sha256,
        )
        .is_err());
        assert!(encode(
            [0_u8; OAEP_2048_SHA256_MESSAGE_LIMIT + 1].as_ref(),
            None,
            RSA_2048_LEN,
            Hash::Sha256,
        )
        .is_err());
        assert!(encode(
            [0_u8; OAEP_3072_SHA256_MESSAGE_LIMIT + 1].as_ref(),
            None,
            RSA_3072_LEN,
            Hash::Sha256,
        )
        .is_err());
        assert!(encode(
            [0_u8; OAEP_4096_SHA256_MESSAGE_LIMIT + 1].as_ref(),
            None,
            RSA_4096_LEN,
            Hash::Sha256,
        )
        .is_err());
    }

    // FIXME: label max is too large for x86 and x86_64 architectures
    // so max size labels can't even be constructed
    // research which architectures support max label size, and write tests for them

    #[test]
    fn check_oaep_sha1_invalid_decoding() {
        let mut enc_1024 = encode(MSG.as_ref(), None, RSA_1024_LEN, Hash::Sha1).unwrap();

        // make Y non-zero
        enc_1024[0] = 0xff;
        assert!(decode(enc_1024.as_ref(), None, RSA_1024_LEN, Hash::Sha1).is_err());

        // make Y zero, screw up seed
        enc_1024[0] = 0x00;
        enc_1024[1] ^= 1;
        assert!(decode(enc_1024.as_ref(), None, RSA_1024_LEN, Hash::Sha1).is_err());

        // restore the seed, screw up the lHash in the DB
        enc_1024[1] ^= 1;
        enc_1024[1 + isha1::DIGEST_LEN + 1] ^= 1;
        assert!(decode(enc_1024.as_ref(), None, RSA_1024_LEN, Hash::Sha1).is_err());

        // restore the lHash, screw up the PS padding
        enc_1024[1 + isha1::DIGEST_LEN + 1] ^= 1;
        enc_1024[1 + (isha1::DIGEST_LEN * 2) + 1] ^= 1;
        assert!(decode(enc_1024.as_ref(), None, RSA_1024_LEN, Hash::Sha1).is_err());

        // restore the PS padding, screw up the padding delimiter
        enc_1024[1 + (isha1::DIGEST_LEN * 2) + 1] ^= 1;
        enc_1024[RSA_1024_LEN / 8 - MSG.len() - 1] ^= 1;
        assert!(decode(enc_1024.as_ref(), None, RSA_1024_LEN, Hash::Sha1).is_err());

        // restore the padding delimiter, ensure valid decoding
        enc_1024[RSA_1024_LEN / 8 - MSG.len() - 1] ^= 1;
        let dec = decode(enc_1024.as_ref(), None, RSA_1024_LEN, Hash::Sha1).unwrap();
        assert_eq!(dec[..], MSG[..]);

        let mut enc_2048 = encode(MSG.as_ref(), None, RSA_2048_LEN, Hash::Sha1).unwrap();

        // make Y non-zero
        enc_2048[0] = 0xff;
        assert!(decode(enc_2048.as_ref(), None, RSA_2048_LEN, Hash::Sha1).is_err());

        let mut enc_3072 = encode(MSG.as_ref(), None, RSA_3072_LEN, Hash::Sha1).unwrap();

        // make Y non-zero
        enc_3072[0] = 0xff;
        assert!(decode(enc_3072.as_ref(), None, RSA_3072_LEN, Hash::Sha1).is_err());

        let mut enc_4096 = encode(MSG.as_ref(), None, RSA_4096_LEN, Hash::Sha1).unwrap();

        // make Y non-zero
        enc_4096[0] = 0xff;
        assert!(decode(enc_4096.as_ref(), None, RSA_4096_LEN, Hash::Sha1).is_err());
    }

    #[test]
    fn check_oaep_sha256_invalid_decoding() {
        let mut enc_1024 = encode(MSG.as_ref(), None, RSA_1024_LEN, Hash::Sha256).unwrap();

        // make Y non-zero
        enc_1024[0] = 0xff;
        assert!(decode(enc_1024.as_ref(), None, RSA_1024_LEN, Hash::Sha256).is_err());

        // make Y zero, screw up seed
        enc_1024[0] = 0x00;
        enc_1024[1] ^= 1;
        assert!(decode(enc_1024.as_ref(), None, RSA_1024_LEN, Hash::Sha256).is_err());

        // restore the seed, screw up the lHash in the DB
        enc_1024[1] ^= 1;
        enc_1024[1 + isha256::DIGEST_LEN + 1] ^= 1;
        assert!(decode(enc_1024.as_ref(), None, RSA_1024_LEN, Hash::Sha256).is_err());

        // restore the lHash, screw up the PS padding
        enc_1024[1 + isha256::DIGEST_LEN + 1] ^= 1;
        enc_1024[1 + (isha256::DIGEST_LEN * 2) + 1] ^= 1;
        assert!(decode(enc_1024.as_ref(), None, RSA_1024_LEN, Hash::Sha256).is_err());

        // restore the PS padding, screw up the padding delimiter
        enc_1024[1 + (isha256::DIGEST_LEN * 2) + 1] ^= 1;
        enc_1024[RSA_1024_LEN / 8 - MSG.len() - 1] ^= 1;
        assert!(decode(enc_1024.as_ref(), None, RSA_1024_LEN, Hash::Sha256).is_err());

        // restore the padding delimiter, ensure valid decoding
        enc_1024[RSA_1024_LEN / 8 - MSG.len() - 1] ^= 1;
        let dec = decode(enc_1024.as_ref(), None, RSA_1024_LEN, Hash::Sha256).unwrap();
        assert_eq!(dec[..], MSG[..]);

        let mut enc_2048 = encode(MSG.as_ref(), None, RSA_2048_LEN, Hash::Sha256).unwrap();

        // make Y non-zero
        enc_2048[0] = 0xff;
        assert!(decode(enc_2048.as_ref(), None, RSA_2048_LEN, Hash::Sha256).is_err());

        let mut enc_3072 = encode(MSG.as_ref(), None, RSA_3072_LEN, Hash::Sha256).unwrap();

        // make Y non-zero
        enc_3072[0] = 0xff;
        assert!(decode(enc_3072.as_ref(), None, RSA_3072_LEN, Hash::Sha256).is_err());

        let mut enc_4096 = encode(MSG.as_ref(), None, RSA_4096_LEN, Hash::Sha256).unwrap();

        // make Y non-zero
        enc_4096[0] = 0xff;
        assert!(decode(enc_4096.as_ref(), None, RSA_4096_LEN, Hash::Sha256).is_err());
    }
}
