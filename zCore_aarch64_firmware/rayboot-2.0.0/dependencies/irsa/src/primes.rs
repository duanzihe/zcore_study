/// From wolfSSL and TomsFastMath 0.10 by Tom St Denis:
///
/// https://github.com/wolfssl/wolfssl/blob/master/wolfssl/wolfcrypt/src/tfm.c
///
/// http://math.libtomcrypt.com
///
/// original C edited by Moises Guimaraes (moises@wolfssl.com)
/// to fit wolfSSL's needs.
///
/// Ported to Rust by Nym Seddon
use alloc::vec::Vec;
use num::bigint::BigUint;
use num::{Integer, One, Zero};

use rand::rngs::StdRng;
use rand::Rng;

use prime_math::is_prime;

use crate::{length_check, Error};

const PRIME_BOUND_LEN: usize = 256;

/* From wolfSSL: wolfssl/wolfcrypt/src/rsa.c
 *
 * The lower_bound value is floor(2^(0.5) * 2^((nlen/2)-1)) where nlen is 4096.
 * This number was calculated using a small test tool written with a common
 * large number math library. Other values of nlen may be checked with a subset
 * of lower_bound. */
const LOWER_PRIME_BOUND: [u8; PRIME_BOUND_LEN] = [
    0xb5, 0x04, 0xf3, 0x33, 0xf9, 0xde, 0x64, 0x84, 0x59, 0x7d, 0x89, 0xb3, 0x75, 0x4a, 0xbe, 0x9f,
    0x1d, 0x6f, 0x60, 0xba, 0x89, 0x3b, 0xa8, 0x4c, 0xed, 0x17, 0xac, 0x85, 0x83, 0x33, 0x99, 0x15,
    /* 512 */
    0x4a, 0xfc, 0x83, 0x04, 0x3a, 0xb8, 0xa2, 0xc3, 0xa8, 0xb1, 0xfe, 0x6f, 0xdc, 0x83, 0xdb, 0x39,
    0x0f, 0x74, 0xa8, 0x5e, 0x43, 0x9c, 0x7b, 0x4a, 0x78, 0x04, 0x87, 0x36, 0x3d, 0xfa, 0x27, 0x68,
    /* 1024 */
    0xd2, 0x20, 0x2e, 0x87, 0x42, 0xaf, 0x1f, 0x4e, 0x53, 0x05, 0x9c, 0x60, 0x11, 0xbc, 0x33, 0x7b,
    0xca, 0xb1, 0xbc, 0x91, 0x16, 0x88, 0x45, 0x8a, 0x46, 0x0a, 0xbc, 0x72, 0x2f, 0x7c, 0x4e, 0x33,
    0xc6, 0xd5, 0xa8, 0xa3, 0x8b, 0xb7, 0xe9, 0xdc, 0xcb, 0x2a, 0x63, 0x43, 0x31, 0xf3, 0xc8, 0x4d,
    0xf5, 0x2f, 0x12, 0x0f, 0x83, 0x6e, 0x58, 0x2e, 0xea, 0xa4, 0xa0, 0x89, 0x90, 0x40, 0xca, 0x4a,
    /* 2048 */
    0x81, 0x39, 0x4a, 0xb6, 0xd8, 0xfd, 0x0e, 0xfd, 0xf4, 0xd3, 0xa0, 0x2c, 0xeb, 0xc9, 0x3e, 0x0c,
    0x42, 0x64, 0xda, 0xbc, 0xd5, 0x28, 0xb6, 0x51, 0xb8, 0xcf, 0x34, 0x1b, 0x6f, 0x82, 0x36, 0xc7,
    0x01, 0x04, 0xdc, 0x01, 0xfe, 0x32, 0x35, 0x2f, 0x33, 0x2a, 0x5e, 0x9f, 0x7b, 0xda, 0x1e, 0xbf,
    0xf6, 0xa1, 0xbe, 0x3f, 0xca, 0x22, 0x13, 0x07, 0xde, 0xa0, 0x62, 0x41, 0xf7, 0xaa, 0x81, 0xc2,
    /* 3072 */
    0xc1, 0xfc, 0xbd, 0xde, 0xa2, 0xf7, 0xdc, 0x33, 0x18, 0x83, 0x8a, 0x2e, 0xaf, 0xf5, 0xf3, 0xb2,
    0xd2, 0x4f, 0x4a, 0x76, 0x3f, 0xac, 0xb8, 0x82, 0xfd, 0xfe, 0x17, 0x0f, 0xd3, 0xb1, 0xf7, 0x80,
    0xf9, 0xac, 0xce, 0x41, 0x79, 0x7f, 0x28, 0x05, 0xc2, 0x46, 0x78, 0x5e, 0x92, 0x95, 0x70, 0x23,
    0x5f, 0xcf, 0x8f, 0x7b, 0xca, 0x3e, 0xa3, 0x3b, 0x4d, 0x7c, 0x60, 0xa5, 0xe6, 0x33, 0xe3,
    0xe1,
    /* 4096 */
];

// Check the difference of P and Q is in valid range
//
// Caller must validate size
fn compare_diff_pq(p: &BigUint, q: &BigUint, size: usize) -> bool {
    // c = 2^((size/2) - 100)
    let mut c = BigUint::from_bytes_le(&[2]).pow((size as u32 / 2) - 100);

    // d = |p - q|
    let mut d = if p > q { p - q } else { q - p };

    let ret = d > c;

    // clear temporary variables
    c.set_zero();
    d.set_zero();

    ret
}

/// Generate prime for use in RSA private keys
pub fn generate_prime(
    size: usize,
    e: &BigUint,
    p: Option<&BigUint>,
    rng: &mut StdRng,
) -> Result<BigUint, Error> {
    length_check(size)?;
    generate_prime_inner(size, e, p, rng)
}

/// INSECURE generate 128-bit prime for use in RSA private keys
///
/// Part of Cryptopals challenge #47
pub(crate) fn generate_prime_insecure(
    size: usize,
    e: &BigUint,
    p: Option<&BigUint>,
    rng: &mut StdRng,
) -> Result<BigUint, Error> {
    generate_prime_inner(size, e, p, rng)
}

fn generate_prime_inner(
    size: usize,
    e: &BigUint,
    p: Option<&BigUint>,
    rng: &mut StdRng,
) -> Result<BigUint, Error> {
    /* size is the size of n in bits
     * prime_size is in bytes
     *
     * divide by 16 to ensure P * Q results in N <= size bits
     */
    let prime_size = size / 16;
    let mut prime_buf: Vec<u8> = Vec::with_capacity(prime_size);
    prime_buf.resize(prime_size, 0);

    /* The fail_count value comes from NIST FIPS 186-4, section B.3.3,
     * process steps 4.7 and 5.8.
     * */
    let fail_count = 5 * (size / 2);
    let mut i = 0;

    while i < fail_count {
        rng.fill(prime_buf.as_mut_slice());

        // prime lower bound has the MSB set, set it in the candidate
        prime_buf[0] |= 0x80;

        // make candidate odd
        prime_buf[prime_size - 1] |= 0x01;

        // convert to BigUint
        let prime = BigUint::from_bytes_be(&prime_buf);

        if check_probable_prime(&prime, &e, size, rng) {
            match p {
                Some(p_ref) => {
                    if compare_diff_pq(p_ref, &prime, size) {
                        return Ok(prime);
                    }
                }
                None => return Ok(prime),
            }
        }

        i += 1;
    }

    Err(Error::InvalidPrime)
}

// From wolfSSL: wolfssl/wolfcrypt/src/rsa.c
//
// Port of wc_CheckProbablePrime_ex
fn check_probable_prime(p: &BigUint, e: &BigUint, size: usize, rng: &mut StdRng) -> bool {
    /* 4.4,5.5 - Check that prime >= (2^(1/2))(2^((nlen/2)-1))
     *           This is a comparison against lowerBound */
    let tmp1 = BigUint::from_bytes_be(&LOWER_PRIME_BOUND[..size / 16]);
    if p < &tmp1 {
        return false;
    }

    /* 4.5,5.6 - Check that GCD(p-1, e) == 1 */
    if !(p - 1_u32).gcd(&e).is_one() {
        // e divides p - 1
        return false;
    }

    /* NOTE: M-R is Miller-Rabin
     *
     * 4.5.1,5.6.1 - Check primality of p with 8 rounds of M-R.
     * mp_prime_is_prime_ex() performs test divisions against the first 256
     * prime numbers. After that it performs 8 rounds of M-R using random
     * bases between 2 and n-2.
     * mp_prime_is_prime() performs the same test divisions and then does
     * M-R with the first 8 primes. Both functions set isPrime as a
     * side-effect. */
    is_prime(&p, 8, size, rng)
}
