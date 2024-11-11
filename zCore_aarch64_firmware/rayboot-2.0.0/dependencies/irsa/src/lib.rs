#![no_std]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use num::bigint::{BigInt, BigUint};
use num::{Integer, One, Zero};

mod der;
mod hash;
mod mask;
mod oaep;
pub mod pkcs1v1_5;
mod primes;

pub use isha256::Sha256;
pub use prime_math::InvMod;
use rand::SeedableRng;

/// Default RSA public exponent (from wolfSSL: wolfssl/wolfssl/wolfcrypt/rsa.h)
pub const E: u32 = 65537;

/// Length of RSA 1024-bit modulus
pub const RSA_1024_LEN: usize = 1024;

/// Length of RSA 2048-bit modulus
pub const RSA_2048_LEN: usize = 2048;

/// Length of RSA 3072-bit modulus
pub const RSA_3072_LEN: usize = 3072;

/// Length of RSA 4096-bit modulus
pub const RSA_4096_LEN: usize = 4096;

/// RSA errors
#[derive(Debug)]
pub enum Error {
    CiphertextOutOfRange,
    IntegerOutOfRange,
    MessageOutOfRange,
    InvalidCiphertext,
    DeprecatedHash,
    InvalidHash,
    UnimplementedHash,
    InvalidLabelLength,
    InvalidMaskLength,
    InvalidMessage,
    InvalidModulus,
    InvalidPrime,
    InvalidRsaKey,
    InvalidSize,
    InvalidXorLength,
    Sha1(isha1::Error),
    Sha256(isha256::Error),
}

/// RSA Verification states
#[derive(Debug, PartialEq)]
pub enum Verification {
    Consistent,
    Inconsistent,
}

/// Hash function to use with RSA encoding schemes (PKCS1_1.5, PSS, OAEP, MGF1)
#[derive(Clone, Copy, PartialEq)]
pub enum Hash {
    /// MD2: deprecated hash function, too weak for modern use. See RFC8017 9.2 Notes for details
    Md2,
    /// MD5: deprecated hash function, too weak for modern use. See RFC8017 9.2 Notes for details
    Md5,
    /// SHA1: too weak for modern use, here for backwards compatibility. May be deprecated in the future. See RFC8017 9.2 Notes for details
    Sha1,
    /// SHA224: SHA2-224 considered safe for modern use (unimplemented)
    Sha224,
    /// SHA2256: SHA2-256 considered safe for modern use
    Sha256,
    /// SHA384: SHA2-384 considered safe for modern use (unimplemented)
    Sha384,
    /// SHA512: SHA2-512 considered safe for modern use (unimplemented)
    Sha512,
    /// SHA512_224: SHA2-512_224 considered safe for modern use (unimplemented)
    Sha512_224,
    /// SHA512_256: SHA2-512_256 considered safe for modern use (unimplemented)
    Sha512_256,
}

// Zero bytes for front-padding BigUint byte representation
const ZERO_BYTES: [u8; RSA_4096_LEN / 8] = [0_u8; RSA_4096_LEN / 8];
const END_MAGIC_NUM: [u8; 8] = [
    'I' as u8, 't' as u8, 'i' as u8, 's' as u8, 'e' as u8, 'n' as u8, 'd' as u8, 'h' as u8,
];

/// RSA public key
#[derive(Debug)]
pub struct RsaPublicKey {
    /// RSA public modulus, composite of private primes p and q
    pub n: BigUint,
    /// Bit-length of the RSA public modulus
    pub n_len: usize,
    /// RSA public exponent
    pub e: BigUint,
}

impl RsaPublicKey {
    /// Create a new RSA public key from a private key
    ///
    /// Alias for from_private_key
    pub fn new(key: &RsaPrivateKey) -> Result<Self, Error> {
        Self::from_private_key(&key)
    }

    /// Judge whether is magic number or not
    fn judge_magic_number(raw_data: &Vec<u8>, i: usize) -> bool {
        if i + 7 >= raw_data.len() {
            return false;
        }
        raw_data[i] == 'I' as u8
            && raw_data[i + 1] == 't' as u8
            && raw_data[i + 2] == 'i' as u8
            && raw_data[i + 3] == 's' as u8
            && raw_data[i + 4] == 'e' as u8
            && raw_data[i + 5] == 'n' as u8
            && raw_data[i + 6] == 'd' as u8
            && raw_data[i + 7] == 'h' as u8
    }

    /// vec to usize
    fn vec_to_usize_le(data: Vec<u8>) -> usize {
        assert_eq!(data.len(), core::mem::size_of::<usize>());
        let mut ans = 0 as usize;
        for i in 0..8 {
            let j = data[i] as usize;
            ans |= j << (i << 3);
        }
        ans
    }

    /// Dump to raw data
    pub fn to_raw(&self) -> Vec<u8> {
        let mut ans = vec![];
        let mut n_bytes = self.n.to_bytes_le();
        let mut n_len_bytes = self.n_len.to_le_bytes().to_vec();
        let mut e_bytes = self.e.to_bytes_le();
        ans.append(&mut n_bytes);
        ans.append(&mut END_MAGIC_NUM.to_vec());
        ans.append(&mut n_len_bytes);
        ans.append(&mut END_MAGIC_NUM.to_vec());
        ans.append(&mut e_bytes);
        ans
    }

    /// create from Vec<u8> raw data
    pub fn from_raw(raw: Vec<u8>) -> Self {
        let mut group = vec![];
        let mut tmp = vec![];

        let raw_len = raw.len();
        let mut magic_num_start = vec![];

        for i in 0..raw_len {
            if raw[i] == 'I' as u8 && Self::judge_magic_number(&raw, i) {
                magic_num_start.push(i);
            }
        }
        assert_eq!(magic_num_start.len(), 2);

        for i in 0..magic_num_start[0] {
            tmp.push(raw[i]);
        }
        group.push(tmp.clone());

        tmp.clear();
        for i in (magic_num_start[0] + 8)..magic_num_start[1] {
            tmp.push(raw[i]);
        }
        group.push(tmp.clone());

        tmp.clear();

        for i in (magic_num_start[1] + 8)..raw_len {
            tmp.push(raw[i]);
        }
        group.push(tmp);

        assert_eq!(group.len(), 3);
        let n = BigUint::from_bytes_le(group[0].as_slice());
        let n_len = Self::vec_to_usize_le(group[1].clone());
        let e = BigUint::from_bytes_le(group[2].as_slice());
        Self { n, n_len, e }
    }

    /// Create a new RSA public key from a private key
    pub fn from_private_key(key: &RsaPrivateKey) -> Result<Self, Error> {
        // if in debug mode, check the private key for validity
        if cfg!(debug_assertions) {
            check_key(&key)?;
        }

        Ok(Self {
            n: key.n.clone(),
            n_len: key.n_len,
            e: key.e.clone(),
        })
    }

    /// INSECURE create a new RSA public key from a private key with no checks
    pub fn from_private_key_insecure(key: &RsaPrivateKey) -> Self {
        Self {
            n: key.n.clone(),
            n_len: key.n_len,
            e: key.e.clone(),
        }
    }

    /// Encrypt a message under the public key
    ///
    /// Interprets the bytes in big-endian byte order
    ///
    /// The resulting ciphertext is a BigUint in big-endian byte order
    pub fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        if message.len() > self.n_len {
            return Err(Error::InvalidMessage);
        }

        let msg_bn = BigUint::from_bytes_be(&message);

        if msg_bn >= self.n {
            return Err(Error::InvalidMessage);
        }

        let e = msg_bn.modpow(&self.e, &self.n).to_bytes_be();

        // Front-pad the result with zeroes, if necessary
        // no-op if e is n_len / 8 bytes
        // let mut res = ZERO_BYTES[..(self.n_len / 8) - e.len()].to_vec();
        // res.extend_from_slice(&e);

        Ok(e)
    }

    /// Encrypt a message under the public key using OAEP-SHA1 encoding
    pub fn oaep_encrypt(
        &self,
        message: &[u8],
        label: Option<&[u8]>,
        hash: Hash,
    ) -> Result<Vec<u8>, Error> {
        let msg = oaep::encode(&message, label, self.n_len, hash)?;
        self.encrypt(&msg)
    }

    /// Apply RSAVP1 verification primitive from RFC8017 5.2.2
    pub fn verify(&self, signature: &[u8]) -> Result<Vec<u8>, Verification> {
        self.encrypt(signature)
            .map_err(|_| Verification::Inconsistent)
    }

    /// Verify a signed message using RSASSA-PKCS1-V1_5-VERIFY from RFC8017 8.2.2
    pub fn verify_pkcs1_v1_5(
        &self,
        message: &[u8],
        signature: &[u8],
        hash: Hash,
    ) -> Result<Verification, Verification> {
        //  Steps 2a+b. Convert signature to an integer, and apply RSAVP1
        //  Steps 3. EM' = EMSA-PKCS1-V1_5-ENCODE(M, k)
        //  Steps 4. Compare the encoded message and EM', if they are the same
        //  output "valid signature", otherwise "invalid signature"
        //
        //  Early exit presents no risk, since verification does not rely on secret material
        let em = self.verify(signature)?;
        pkcs1v1_5::verify(&message, &em, hash)
    }

    /// INSECURELY verify a signed message for Cryptopals challenge #42
    pub fn verify_pkcs1_v1_5_insecure(
        &self,
        message: &[u8],
        signature: &[u8],
        hash: Hash,
    ) -> Result<Verification, Verification> {
        let em = self.verify(signature)?;
        pkcs1v1_5::verify_insecure(&message, &em, hash)
    }
}

impl From<&RsaPrivateKey> for RsaPublicKey {
    /// Implements the From trait for RsaPublicKey
    ///
    /// Panics in debug mode when RsaPrivateKey is invalid
    fn from(key: &RsaPrivateKey) -> Self {
        RsaPublicKey::from_private_key(&key).unwrap()
    }
}

/// RSA private key
#[derive(Debug)]
pub struct RsaPrivateKey {
    /// RSA public modulus, composite of private primes p and q
    n: BigUint,
    /// Bit-length of the RSA public modulus
    n_len: usize,
    /// RSA public exponent
    e: BigUint,
    /// RSA private exponent
    d: BigUint,
    /// RSA prime 1
    p: BigUint,
    /// RSA prime 2
    q: BigUint,
    /// RSA exponent 1: d mod (p - 1)
    dp: BigUint,
    /// RSA exponent 2: d mod (q - 1)
    dq: BigUint,
    /// RSA coefficient: (inverse of q) mod p
    invq: BigUint,
}

impl RsaPrivateKey {
    /// Create a new RSA private key of a given bit-length
    ///
    /// Uses default value from wolfSSL for public exponent
    ///
    /// Size must be one of: 1024, 2048, 3072, 4096
    ///
    /// 512 is not supported, because it's way too short
    ///
    /// Based on wolfSSL implementation wc_MakeRsaKey: wolfssl/wolfcrypt/src/rsa.c
    pub fn new(size: usize) -> Result<Self, Error> {
        Self::from_exponent(E, size)
    }

    /// Create a new RSA private key from a given public exponent and bit-length
    ///
    /// Size must be one of: 1024, 2048, 3072, 4096
    ///
    /// 512 is not supported, because it's way too short
    ///
    /// Based on wolfSSL implementation wc_MakeRsaKey: wolfssl/wolfcrypt/src/rsa.c
    pub fn from_exponent(e: u32, size: usize) -> Result<Self, Error> {
        let mut e = BigUint::from_bytes_le(e.to_le_bytes().as_ref());

        length_check(size)?;

        // let seed: SeedableRng = rand::SeedableRng::seed_from_u64(0);
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);

        let mut p = primes::generate_prime(size, &e, None, &mut rng)?;
        let mut q = primes::generate_prime(size, &e, Some(&p), &mut rng)?;

        // P must be larger than Q
        if p < q {
            // swap if P is smaller
            let mut tmp = p.clone();
            p.clone_from(&q);
            q.clone_from(&tmp);

            // clear the temporary variable
            tmp.set_zero();
        }

        let mut p1 = p.clone();
        p1 -= 1_u32;

        let mut q1 = q.clone();
        q1 -= 1_u32;

        let mut lcm = p1.lcm(&q1);

        // d = (1 / e) mod lcm(p - 1, q - 1)
        let mut d = e.invmod(&lcm);
        let mut n = p.clone();
        n *= &q;

        let res = Self {
            n: n.clone(),
            n_len: size,
            e: e.clone(),
            d: d.clone(),
            p: p.clone(),
            q: q.clone(),
            dp: d.mod_floor(&p1),
            dq: d.mod_floor(&q1),
            // u = 1 / q mod p
            invq: q.invmod(&p),
        };

        // clear temporary variables
        n.set_zero();
        e.set_zero();
        d.set_zero();
        p.set_zero();
        p1.set_zero();
        q.set_zero();
        q1.set_zero();
        lcm.set_zero();

        // Perform the pair-wise consistency test on the new key
        if cfg!(debug_assertions) {
            check_key(&res)?;
        }

        Ok(res)
    }

    /// INSECURE construct an RSA private key with a 256-bit modulus
    ///
    /// Part of Cryptopals challenge #47
    pub fn from_exponent_insecure(e: u32, size: usize) -> Result<Self, Error> {
        let mut e = BigUint::from_bytes_le(e.to_le_bytes().as_ref());

        let mut rng = rand::rngs::StdRng::seed_from_u64(0);

        let mut p = primes::generate_prime_insecure(size, &e, None, &mut rng)?;
        let mut q = primes::generate_prime_insecure(size, &e, Some(&p), &mut rng)?;

        // P must be larger than Q
        if p < q {
            // swap if P is smaller
            let mut tmp = p.clone();
            p.clone_from(&q);
            q.clone_from(&tmp);

            // clear the temporary variable
            tmp.set_zero();
        }

        let mut p1 = p.clone();
        p1 -= 1_u32;

        let mut q1 = q.clone();
        q1 -= 1_u32;

        let mut lcm = p1.lcm(&q1);

        // d = (1 / e) mod lcm(p - 1, q - 1)
        let mut d = e.invmod(&lcm);
        let mut n = p.clone();
        n *= &q;

        let res = Self {
            n: n.clone(),
            n_len: size,
            e: e.clone(),
            d: d.clone(),
            p: p.clone(),
            q: q.clone(),
            dp: d.mod_floor(&p1),
            dq: d.mod_floor(&q1),
            // u = 1 / q mod p
            invq: q.invmod(&p),
        };

        // clear temporary variables
        n.set_zero();
        e.set_zero();
        d.set_zero();
        p.set_zero();
        p1.set_zero();
        q.set_zero();
        q1.set_zero();
        lcm.set_zero();

        Ok(res)
    }

    /// Clear the internal variables
    pub fn clear(&mut self) {
        self.n.set_zero();
        self.n_len = 0;
        self.e.set_zero();
        self.d.set_zero();
        self.p.set_zero();
        self.q.set_zero();
        self.dp.set_zero();
        self.dq.set_zero();
        self.invq.set_zero();
    }

    /// Decrypt a ciphertext under this private key
    ///
    /// Interprets the ciphertext as BigUint bytes in big-endian order
    ///
    /// The resulting message is in big-endian byte order
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        if ciphertext.len() > self.n_len {
            return Err(Error::InvalidCiphertext);
        }

        let ciph_bn = BigUint::from_bytes_be(&ciphertext);

        if ciph_bn >= self.n {
            return Err(Error::InvalidCiphertext);
        }

        // m_1 = c**dP mod P
        let mut m1: BigInt = ciph_bn.modpow(&self.dp, &self.p).into();
        // m_2 = c**dQ mod Q
        let mut m2 = ciph_bn.modpow(&self.dq, &self.q);

        // h = ((m_1 - m_2) * qInv) mod p
        let mut m2_bi: BigInt = m2.clone().into();
        m1 -= &m2_bi;

        // clear the temp m2
        m2_bi.set_zero();

        let mut qinv: BigInt = self.invq.clone().into();
        m1 *= &qinv;

        // clear the temp qinv
        qinv.set_zero();

        let mut p: BigInt = self.p.clone().into();
        let mut h = BigUint::from_bytes_be(&m1.mod_floor(&p).to_bytes_be().1);

        // clear the temp p + m1
        p.set_zero();
        m1.set_zero();

        // m = m_2 + q * h
        h *= &self.q;
        h += &m2;

        // clear the temp m2
        m2.set_zero();

        let res = h.to_bytes_be();

        // clear the temp h
        h.set_zero();

        Ok(res)
    }

    /// Decrypt a OAEP encoded ciphertext under this private key
    pub fn oaep_decrypt(
        &self,
        ciphertext: &[u8],
        label: Option<&[u8]>,
        hash: Hash,
    ) -> Result<Vec<u8>, Error> {
        let mut dec = self.decrypt(&ciphertext)?;

        let mut enc_msg = ZERO_BYTES[..(self.n_len / 8) - dec.len()].to_vec();
        enc_msg.extend_from_slice(&dec);

        dec.clear();

        let res = oaep::decode(&enc_msg, label, self.n_len, hash)?;

        enc_msg.clear();

        Ok(res)
    }

    /// Apply RSASP1 signature primitive
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        // RFC8017 5.2 Apply the signature primitive (i.e. decryption)
        self.decrypt(message)
    }

    /// Sign a message using RSASSA-PKCS1_v1_5-SIGN from RFC8017 8.2
    pub fn sign_pkcs1_v1_5(&self, message: &[u8], hash: Hash) -> Result<Vec<u8>, Error> {
        // Steps 1. EM = EMSA-PKCS1-V1_5-ENCODE(m, k)
        // Steps 2. Apply RSASP1 signature primitive
        // Steps 3. Output S
        self.sign(&pkcs1v1_5::encode(message, self.n_len / 8, hash)?)
    }
}

impl Drop for RsaPrivateKey {
    fn drop(&mut self) {
        self.clear();
    }
}

/* From wolfSSL: wolfssl/wolfcrypt/src/rsa.c
 *
 * Check the pair-wise consistency of the RSA key.
 * From NIST SP 800-56B, section 6.4.1.1.
 * Verify that k = (k^e)^d, for some k: 1 < k < n-1. */
pub fn check_key(key: &RsaPrivateKey) -> Result<(), Error> {
    length_check(key.n_len)?;

    let mut k = BigUint::from_bytes_le(0x2342_u16.to_le_bytes().as_ref());
    let mut temp = k.modpow(&key.e, &key.n);
    temp = temp.modpow(&key.d, &key.n);

    let mut res = Ok(());

    if k != temp {
        res = Err(Error::InvalidRsaKey);
    }

    // clear the temporary K value
    k.set_zero();

    // check d <= N
    if key.d > key.n {
        res = Err(Error::InvalidRsaKey);
    }

    // check P * Q == N
    temp = key.p.clone();
    temp *= &key.q;
    if temp != key.n {
        res = Err(Error::InvalidRsaKey);
    }

    let mut p1 = key.p.clone();
    p1 -= 1_u32;

    // check dP <= P - 1
    if key.dp > p1 {
        res = Err(Error::InvalidRsaKey);
    }

    // check e*dP % (P - 1) == 1
    temp = key.e.clone();
    temp *= &key.dp;
    temp = temp.mod_floor(&p1);
    if !temp.is_one() {
        res = Err(Error::InvalidRsaKey);
    }

    // clear temp P - 1
    p1.set_zero();

    let mut q1 = key.q.clone();
    q1 -= 1_u32;

    // check dQ <= Q - 1
    if key.dq > q1 {
        res = Err(Error::InvalidRsaKey);
    }

    // check e*dQ % (Q - 1) == 1
    temp = key.e.clone();
    temp *= &key.dq;
    temp = temp.mod_floor(&q1);
    if !temp.is_one() {
        res = Err(Error::InvalidRsaKey);
    }

    // clear temp Q - 1
    q1.set_zero();

    // check 1 / Q <= P
    if key.invq > key.p {
        res = Err(Error::InvalidRsaKey);
    }

    // check ((1/Q) * Q) % p == 1
    temp = key.invq.clone();
    temp *= &key.q;
    temp = temp.mod_floor(&key.p);
    if !temp.is_one() {
        res = Err(Error::InvalidRsaKey);
    }

    // clear the temporary variable
    temp.set_zero();

    res
}

/// Check the provided size is a valid RSA public modulus bit-length
#[inline(always)]
pub(crate) fn length_check(size: usize) -> Result<(), Error> {
    match size {
        RSA_1024_LEN => Ok(()),
        RSA_2048_LEN => Ok(()),
        RSA_3072_LEN => Ok(()),
        RSA_4096_LEN => Ok(()),
        _ => return Err(Error::InvalidSize),
    }
}

/// Bitwise exlusive-OR of two byte slices
#[inline(always)]
pub fn xor(el: &[u8], ar: &[u8]) -> Vec<u8> {
    let el_len = el.len();
    let ar_len = ar.len();
    let len = if el_len < ar_len { el_len } else { ar_len };

    el[..len]
        .iter()
        .zip(ar[..len].iter())
        .map(|(&e, &r)| e ^ r)
        .collect()
}

/// Bitwise exlusive-OR of two byte slices, assiging result to left byte slice
#[inline(always)]
pub fn xor_assign(el: &mut [u8], ar: &[u8]) {
    let el_len = el.len();
    let ar_len = ar.len();
    let len = if el_len < ar_len { el_len } else { ar_len };

    for (e, &r) in el[..len].iter_mut().zip(ar[..len].iter()) {
        *e ^= r;
    }
}

/// Constant-time compare two byte slices
///
/// If slices are unequal length, the shortest length of bytes is compared
#[inline(always)]
pub fn constant_compare(el: &[u8], ar: &[u8]) -> u8 {
    let mut res = 0;
    let len = if el.len() > ar.len() {
        ar.len()
    } else {
        el.len()
    };
    for (e, a) in el[..len].iter().zip(ar[..len].iter()) {
        res |= e ^ a;
    }
    res
}

#[cfg(test)]
mod tests {
    use core::convert::{TryFrom, TryInto};
    use rand::thread_rng;

    use prime_math::rand_biguint;

    use super::*;

    #[test]
    fn check_invmod() {
        let e = BigUint::from_bytes_le(E.to_le_bytes().as_ref());
        let mut rng = thread_rng();
        let one = One::one();

        // check E's inverse modulo random integers
        for _ in 0..10 {
            for &rsa_len in [RSA_1024_LEN, RSA_2048_LEN, RSA_3072_LEN, RSA_4096_LEN].iter() {
                let k = rand_biguint(rsa_len, &mut rng);

                let mut inv_e = e.invmod(&k);

                inv_e *= &e;
                inv_e = inv_e.mod_floor(&k);

                assert_eq!(inv_e, one);

                // test against the lcm(k - 1, k)
                let mut k_lcm = k.clone();

                k_lcm -= 1_u32;
                k_lcm = k_lcm.lcm(&k);

                inv_e = e.invmod(&k_lcm);

                inv_e *= &e;
                inv_e = inv_e.mod_floor(&k_lcm);

                assert_eq!(inv_e, one);
            }
        }
    }

    #[test]
    // the extra checking of inv_mod_slow against primes
    // takes a really long time in debug mode
    //
    // run in release mode: cargo test --release
    // or comment the following annotation to run in debug mode
    #[cfg(not(debug_assertions))]
    fn check_inv_mod_slow_1024() {
        let e = BigUint::from_bytes_le(E.to_le_bytes().as_ref());
        let mut rng = thread_rng();
        let one = One::one();

        // check E's inverse modulo random primes
        let k = primes::generate_prime(RSA_1024_LEN, &e, None, &mut rng).unwrap();

        let mut inv_e = e.invmod(&k);

        inv_e *= &e;
        inv_e = inv_e.mod_floor(&k);

        assert_eq!(inv_e, one);

        // test against the lcm(k - 1, k)
        let mut k_lcm = k.clone();

        k_lcm -= 1_u32;
        k_lcm = k_lcm.pow(2_u32);

        inv_e = e.invmod(&k_lcm);

        inv_e *= &e;
        inv_e = inv_e.mod_floor(&k_lcm);

        assert_eq!(inv_e, one);
    }

    #[test]
    // the extra checking of inv_mod_slow against primes
    // takes a really long time in debug mode
    //
    // run in release mode: cargo test --release
    // or comment the following annotation to run in debug mode
    #[cfg(not(debug_assertions))]
    fn check_inv_mod_slow_2048() {
        let e = BigUint::from_bytes_le(E.to_le_bytes().as_ref());
        let mut rng = thread_rng();
        let one = One::one();

        // check E's inverse modulo random primes
        let k = primes::generate_prime(RSA_2048_LEN, &e, None, &mut rng).unwrap();

        let mut inv_e = e.invmod(&k);

        inv_e *= &e;
        inv_e = inv_e.mod_floor(&k);

        assert_eq!(inv_e, one);

        // test against the (k - 1)**2
        let mut k_lcm = k.clone();

        k_lcm -= 1_u32;
        k_lcm = k_lcm.pow(2_u32);

        inv_e = e.invmod(&k_lcm);

        inv_e *= &e;
        inv_e = inv_e.mod_floor(&k_lcm);

        assert_eq!(inv_e, one);
    }

    #[test]
    // the extra checking of inv_mod_slow against primes
    // takes a really long time in debug mode
    //
    // run in release mode: cargo test --release
    // or comment the following annotation to run in debug mode
    #[cfg(not(debug_assertions))]
    fn check_inv_mod_slow_3072() {
        let e = BigUint::from_bytes_le(E.to_le_bytes().as_ref());
        let mut rng = thread_rng();
        let one = One::one();

        // check E's inverse modulo random primes
        let k = primes::generate_prime(RSA_3072_LEN, &e, None, &mut rng).unwrap();

        let mut inv_e = e.invmod(&k);

        inv_e *= &e;
        inv_e = inv_e.mod_floor(&k);

        assert_eq!(inv_e, one);

        // test against (k - 1)**2
        let mut k_lcm = k.clone();

        k_lcm -= 1_u32;
        k_lcm = k_lcm.pow(2_u32);

        inv_e = e.invmod(&k_lcm);

        inv_e *= &e;
        inv_e = inv_e.mod_floor(&k_lcm);

        assert_eq!(inv_e, one);
    }

    #[test]
    // the extra checking of inv_mod_slow against primes
    // takes a really long time in debug mode
    //
    // run in release mode: cargo test --release
    // or comment the following annotation to run in debug mode
    #[cfg(not(debug_assertions))]
    fn check_invmod_4096() {
        let e = BigUint::from_bytes_le(E.to_le_bytes().as_ref());
        let mut rng = thread_rng();
        let one = One::one();

        // check E's inverse modulo random primes
        let k = primes::generate_prime(RSA_4096_LEN, &e, None, &mut rng).unwrap();
        let mut inv_e = e.invmod(&k);

        inv_e *= &e;
        inv_e = inv_e.mod_floor(&k);

        assert_eq!(inv_e, one);

        // test against the (k - 1)**2
        assert_eq!(inv_e, one);

        let mut k_lcm = k.clone();
        k_lcm -= 1_u32;
        k_lcm = k_lcm.pow(2_u32);

        inv_e = e.invmod(&k_lcm);

        inv_e *= &e;
        inv_e = inv_e.mod_floor(&k_lcm);

        assert_eq!(inv_e, one);
    }

    #[test]
    fn check_rsa_1024_keygen() {
        let key = RsaPrivateKey::new(RSA_1024_LEN).unwrap();

        // in debug mode, this check is internal to key generation
        if !cfg!(debug_assertions) {
            check_key(&key).unwrap();
        }
    }

    #[test]
    fn check_rsa_2048_keygen() {
        let key = RsaPrivateKey::new(RSA_2048_LEN).unwrap();
        // in debug mode, this check is internal to key generation
        if !cfg!(debug_assertions) {
            check_key(&key).unwrap();
        }
    }

    #[test]
    fn check_rsa_3072_keygen() {
        let key = RsaPrivateKey::new(RSA_3072_LEN).unwrap();
        // in debug mode, this check is internal to key generation
        if !cfg!(debug_assertions) {
            check_key(&key).unwrap();
        }
    }

    #[test]
    fn check_rsa_4096_keygen() {
        let key = RsaPrivateKey::new(RSA_4096_LEN).unwrap();
        // in debug mode, this check is internal to key generation
        if !cfg!(debug_assertions) {
            check_key(&key).unwrap();
        }
    }

    #[test]
    fn check_rsa_1024_public_key() {
        let pvt_key = RsaPrivateKey::new(RSA_1024_LEN).unwrap();

        let _pub_key = RsaPublicKey::try_from(&pvt_key).unwrap();
        let _pub_key = RsaPublicKey::from(&pvt_key);

        let _pub_key: RsaPublicKey = (&pvt_key).try_into().unwrap();
        let _pub_key: RsaPublicKey = (&pvt_key).into();
    }

    #[test]
    fn check_encryption_1024() {
        let pvt_key = RsaPrivateKey::new(RSA_1024_LEN).unwrap();
        let pub_key = RsaPublicKey::from(&pvt_key);

        let orig_msg = [42];

        let ciphertext = pub_key.encrypt(&orig_msg).unwrap();
        let msg = pvt_key.decrypt(&ciphertext).unwrap();

        assert_eq!(&msg, &orig_msg);
    }

    #[test]
    fn check_encryption_2048() {
        let pvt_key = RsaPrivateKey::new(RSA_2048_LEN).unwrap();
        let pub_key = RsaPublicKey::from(&pvt_key);

        let orig_msg = [42];

        let ciphertext = pub_key.encrypt(&orig_msg).unwrap();
        let msg = pvt_key.decrypt(&ciphertext).unwrap();

        assert_eq!(&msg, &orig_msg);
    }

    #[test]
    fn check_encryption_3072() {
        let pvt_key = RsaPrivateKey::new(RSA_3072_LEN).unwrap();
        let pub_key = RsaPublicKey::from(&pvt_key);

        let orig_msg = [42];

        let ciphertext = pub_key.encrypt(&orig_msg).unwrap();
        let msg = pvt_key.decrypt(&ciphertext).unwrap();

        assert_eq!(&msg, &orig_msg);
    }

    #[test]
    fn check_encryption_4096() {
        let pvt_key = RsaPrivateKey::new(RSA_4096_LEN).unwrap();
        let pub_key = RsaPublicKey::from(&pvt_key);

        let orig_msg = [42];

        let ciphertext = pub_key.encrypt(&orig_msg).unwrap();
        let msg = pvt_key.decrypt(&ciphertext).unwrap();

        assert_eq!(&msg, &orig_msg);
    }

    #[test]
    fn check_modulus_len() {
        let pvt_key_1024 = RsaPrivateKey::new(RSA_1024_LEN).unwrap();
        let n_bytes_len = pvt_key_1024.n.to_bytes_be().len() * 8;
        assert_eq!(n_bytes_len, RSA_1024_LEN);

        let pvt_key_2048 = RsaPrivateKey::new(RSA_2048_LEN).unwrap();
        let n_bytes_len = pvt_key_2048.n.to_bytes_be().len() * 8;
        assert_eq!(n_bytes_len, RSA_2048_LEN);

        let pvt_key_3072 = RsaPrivateKey::new(RSA_3072_LEN).unwrap();
        let n_bytes_len = pvt_key_3072.n.to_bytes_be().len() * 8;
        assert_eq!(n_bytes_len, RSA_3072_LEN);

        let pvt_key_4096 = RsaPrivateKey::new(RSA_4096_LEN).unwrap();
        let n_bytes_len = pvt_key_4096.n.to_bytes_be().len() * 8;
        assert_eq!(n_bytes_len, RSA_4096_LEN);
    }

    #[test]
    fn check_oaep_sha1_encryption() {
        let pvt_key = RsaPrivateKey::from_exponent(3, RSA_1024_LEN).unwrap();
        let pub_key = RsaPublicKey::from(&pvt_key);

        let orig_msg = [42];

        let ciphertext = pub_key.oaep_encrypt(&orig_msg, None, Hash::Sha1).unwrap();
        let msg = pvt_key.oaep_decrypt(&ciphertext, None, Hash::Sha1).unwrap();

        assert_eq!(&msg[..], &orig_msg);
    }

    #[test]
    fn check_oaep_sha256_encryption() {
        let pvt_key = RsaPrivateKey::from_exponent(3, RSA_1024_LEN).unwrap();
        let pub_key = RsaPublicKey::from(&pvt_key);

        let orig_msg = [42];

        let ciphertext = pub_key.oaep_encrypt(&orig_msg, None, Hash::Sha256).unwrap();
        let msg = pvt_key
            .oaep_decrypt(&ciphertext, None, Hash::Sha256)
            .unwrap();

        assert_eq!(&msg[..], &orig_msg);
    }

    #[test]
    fn check_pkcs1_v1_5_signing() {
        let pvt_key = RsaPrivateKey::from_exponent(3, RSA_1024_LEN).unwrap();
        let pub_key = RsaPublicKey::from(&pvt_key);

        let msg = b"don't let them scare you";

        let sig = pvt_key.sign_pkcs1_v1_5(msg.as_ref(), Hash::Sha1).unwrap();
        let res = pub_key
            .verify_pkcs1_v1_5(msg.as_ref(), &sig, Hash::Sha1)
            .unwrap();

        assert_eq!(res, Verification::Consistent);
    }

    #[test]
    fn check_pkcs1_v1_5_signing_insecure() {
        let pvt_key = RsaPrivateKey::from_exponent(3, RSA_1024_LEN).unwrap();
        let pub_key = RsaPublicKey::from(&pvt_key);

        let msg = b"not even a little";

        let sig = pvt_key.sign_pkcs1_v1_5(msg.as_ref(), Hash::Sha1).unwrap();
        let res = pub_key
            .verify_pkcs1_v1_5_insecure(msg.as_ref(), &sig, Hash::Sha1)
            .unwrap();

        assert_eq!(res, Verification::Consistent);
    }
}

#[no_mangle]
pub fn fmod(a: f64, b: f64) -> f64 {
    a % b
}
