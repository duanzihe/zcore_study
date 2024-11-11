use alloc::vec::Vec;

use crate::{Error, Hash};

pub fn hash_len(hash: Hash) -> Result<usize, Error> {
    match hash {
        Hash::Sha1 => Ok(isha1::DIGEST_LEN),
        Hash::Sha256 => Ok(isha256::DIGEST_LEN),
        Hash::Sha224 | Hash::Sha384 | Hash::Sha512 | Hash::Sha512_224 | Hash::Sha512_256 => {
            Err(Error::UnimplementedHash)
        }
        Hash::Md2 | Hash::Md5 => Err(Error::DeprecatedHash),
    }
}

/// Calculate the message's digest using a given hash function
///
/// Returns error on hashing error
///
/// Panics on unimplemented hashing algorithms
pub fn digest(message: &[u8], hash: Hash) -> Result<Vec<u8>, Error> {
    match hash {
        Hash::Sha1 => Ok(isha1::Sha1::digest(&message)
            .map_err(|e| Error::Sha1(e))?
            .to_vec()),
        Hash::Sha256 => Ok(isha256::Sha256::digest(&message)
            .map_err(|e| Error::Sha256(e))?
            .to_vec()),
        Hash::Sha224 | Hash::Sha384 | Hash::Sha512 | Hash::Sha512_224 | Hash::Sha512_256 => {
            Err(Error::UnimplementedHash)
        }
        Hash::Md2 | Hash::Md5 => Err(Error::DeprecatedHash),
    }
}
