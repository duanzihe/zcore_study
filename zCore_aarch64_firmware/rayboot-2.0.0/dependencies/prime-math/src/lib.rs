#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::ops::Neg;
use num::bigint::Sign::Minus;
use num::bigint::{BigInt, BigUint};
use num::{Integer, One, Signed, Zero};
use rand::rngs::StdRng;
use rand::{Rng, RngCore};

const PRIMES_LEN: usize = 256;

// First 256 primes
//
// From wolfSSL:
// https://github.com/wolfssl/wolfssl/blob/master/wolfssl/wolfcrypt/src/tfm.c
const PRIMES: [u16; PRIMES_LEN] = [
    0x0002, 0x0003, 0x0005, 0x0007, 0x000b, 0x000d, 0x0011, 0x0013, 0x0017, 0x001d, 0x001f, 0x0025,
    0x0029, 0x002b, 0x002f, 0x0035, 0x003b, 0x003d, 0x0043, 0x0047, 0x0049, 0x004f, 0x0053, 0x0059,
    0x0061, 0x0065, 0x0067, 0x006b, 0x006d, 0x0071, 0x007f, 0x0083, 0x0089, 0x008b, 0x0095, 0x0097,
    0x009d, 0x00a3, 0x00a7, 0x00ad, 0x00b3, 0x00b5, 0x00bf, 0x00c1, 0x00c5, 0x00c7, 0x00d3, 0x00df,
    0x00e3, 0x00e5, 0x00e9, 0x00ef, 0x00f1, 0x00fb, 0x0101, 0x0107, 0x010d, 0x010f, 0x0115, 0x0119,
    0x011b, 0x0125, 0x0133, 0x0137, 0x0139, 0x013d, 0x014b, 0x0151, 0x015b, 0x015d, 0x0161, 0x0167,
    0x016f, 0x0175, 0x017b, 0x017f, 0x0185, 0x018d, 0x0191, 0x0199, 0x01a3, 0x01a5, 0x01af, 0x01b1,
    0x01b7, 0x01bb, 0x01c1, 0x01c9, 0x01cd, 0x01cf, 0x01d3, 0x01df, 0x01e7, 0x01eb, 0x01f3, 0x01f7,
    0x01fd, 0x0209, 0x020b, 0x021d, 0x0223, 0x022d, 0x0233, 0x0239, 0x023b, 0x0241, 0x024b, 0x0251,
    0x0257, 0x0259, 0x025f, 0x0265, 0x0269, 0x026b, 0x0277, 0x0281, 0x0283, 0x0287, 0x028d, 0x0293,
    0x0295, 0x02a1, 0x02a5, 0x02ab, 0x02b3, 0x02bd, 0x02c5, 0x02cf, 0x02d7, 0x02dd, 0x02e3, 0x02e7,
    0x02ef, 0x02f5, 0x02f9, 0x0301, 0x0305, 0x0313, 0x031d, 0x0329, 0x032b, 0x0335, 0x0337, 0x033b,
    0x033d, 0x0347, 0x0355, 0x0359, 0x035b, 0x035f, 0x036d, 0x0371, 0x0373, 0x0377, 0x038b, 0x038f,
    0x0397, 0x03a1, 0x03a9, 0x03ad, 0x03b3, 0x03b9, 0x03c7, 0x03cb, 0x03d1, 0x03d7, 0x03df, 0x03e5,
    0x03f1, 0x03f5, 0x03fb, 0x03fd, 0x0407, 0x0409, 0x040f, 0x0419, 0x041b, 0x0425, 0x0427, 0x042d,
    0x043f, 0x0443, 0x0445, 0x0449, 0x044f, 0x0455, 0x045d, 0x0463, 0x0469, 0x047f, 0x0481, 0x048b,
    0x0493, 0x049d, 0x04a3, 0x04a9, 0x04b1, 0x04bd, 0x04c1, 0x04c7, 0x04cd, 0x04cf, 0x04d5, 0x04e1,
    0x04eb, 0x04fd, 0x04ff, 0x0503, 0x0509, 0x050b, 0x0511, 0x0515, 0x0517, 0x051b, 0x0527, 0x0529,
    0x052f, 0x0551, 0x0557, 0x055d, 0x0565, 0x0577, 0x0581, 0x058f, 0x0593, 0x0595, 0x0599, 0x059f,
    0x05a7, 0x05ab, 0x05ad, 0x05b3, 0x05bf, 0x05c9, 0x05cb, 0x05cf, 0x05d1, 0x05d5, 0x05db, 0x05e7,
    0x05f3, 0x05fb, 0x0607, 0x060d, 0x0611, 0x0617, 0x061f, 0x0623, 0x062b, 0x062f, 0x063d, 0x0641,
    0x0647, 0x0649, 0x064d, 0x0653,
];

const MIN_RAND_PRIME_LEN: usize = 2;
const MAX_RAND_PRIME_LEN: usize = 512;

const ZEROES: [u8; MAX_RAND_PRIME_LEN] = [0_u8; MAX_RAND_PRIME_LEN];

#[derive(PartialEq)]
pub enum RngType {
    /// Blum-Blum-Shub prime generation:
    /// https://en.wikipedia.org/wiki/Blum_Blum_Shub
    Bbs,
    /// Normal prime generation
    Normal,
}

/// Generate a random prime with given byte length
///
/// Port of fp_rand_prime_ex from wolfSSL:
///
/// https://github.com/wolfssl/wolfssl/blob/master/wolfssl/wolfcrypt/src/tfm.c
///
/// Panics if len is out-of-range (2 <= len <= 512)
pub fn rand_prime(len: usize, rng: &mut StdRng, rng_type: RngType) -> BigUint {
    if len < MIN_RAND_PRIME_LEN || len > MAX_RAND_PRIME_LEN {
        panic!(
            "invalid prime byte length: {}, min: {}, max: {}",
            len, MIN_RAND_PRIME_LEN, MAX_RAND_PRIME_LEN
        );
    }

    let mut buf: Vec<u8> = Vec::with_capacity(len);
    buf.resize(len, 0);

    let len_bits = len * 8;
    let zeroes = &ZEROES[..len];

    loop {
        /* generate value */
        rng.fill(buf.as_mut_slice());

        /* munge bits */
        buf[0] |= 0x80 | 0x40;
        buf[len - 1] |= 0x01 | if rng_type == RngType::Bbs { 0x02 } else { 0x00 };

        let prime = BigUint::from_bytes_be(&buf);

        // zero the temporary buffer
        buf.copy_from_slice(zeroes);

        /* From wolfSSL: */
        /* test */
        /* Running Miller-Rabin up to 3 times gives us a 2^{-80} chance
         * of a 1024-bit candidate being a false positive, when it is our
         * prime candidate. (Note 4.49 of Handbook of Applied Cryptography.)
         * Using 8 because we've always used 8 */
        if is_prime(&prime, 8, len_bits, rng) {
            return prime;
        }
    }
}

/// Test candidate primacy using multiple rounds of the Miller-Rabin algorithm
///
/// Port of mp_prime_is_prime_ex from wolfSSL:
///
/// https://github.com/wolfssl/wolfssl/blob/master/wolfssl/wolfcrypt/src/tfm.c
pub fn is_prime(p: &BigUint, t: u32, size: usize, rng: &mut StdRng) -> bool {
    for prime in PRIMES.iter() {
        let bn_p = BigUint::from_bytes_be(prime.to_be_bytes().as_ref());
        // check against primes table
        if *p == bn_p {
            return true;
        }

        // do trial division
        if p.mod_floor(&bn_p).is_zero() {
            return false;
        }
    }

    let two = BigUint::from_bytes_le(&[2]);
    let c = p - &two;

    for _t in 0..t {
        let mut b = rand_biguint(size, rng);

        // divergence from wolfSSL, get a random number in range
        // wolfSSL uses a while loop, and iterates without modifying the counter
        if b < two {
            b += rng.next_u32();
        } else if b > c {
            b = &c - rng.next_u32();
        }

        if !miller_rabin(&p, &b) {
            return false;
        }
    }

    true
}

/// Port of fp_prime_miller_rabin_ex from wolfSSL:
///
/// https://github.com/wolfssl/wolfssl/blob/master/wolfssl/wolfcrypt/src/tfm.c
///
/// Miller-Rabin test of "a" to the base of "b" as described in
/// HAC pp. 139 Algorithm 4.24
///
/// Sets result to 0 if definitely composite or 1 if probably prime.
/// Randomly the chance of error is no more than 1/4 and often
/// very much lower.
pub fn miller_rabin(a: &BigUint, b: &BigUint) -> bool {
    if b <= &One::one() {
        return false;
    }

    let n1: BigUint = a - 1_u32;

    // count the number of least significant bits that are zero
    let s = match n1.trailing_zeros() {
        Some(n) => n,
        None => n1.bits(),
    };
    assert!(s <= u32::MAX as u64);

    let two = BigUint::from_bytes_le(&[2]);

    // compute 2**s
    let two_s = two.pow(s as u32);

    // set r = n1 / 2**s
    let r = n1.clone() / two_s;

    // compute y = b**r mod a
    let mut y = b.modpow(&r, &a);

    if !y.is_one() && y != n1 {
        let mut j = 1;

        while j <= (s - 1) && y != n1 {
            // y = a**2 mod y
            y = a.modpow(&two, &y);

            // if y == 1, then a is composite
            if y.is_one() {
                return false;
            }

            j += 1;
        }

        // if y != n1, then a is composite
        if y != n1 {
            return false;
        }
    }

    return true;
}

/// Create a random BigUint of the given bit size
///
/// Caller must validate size
pub fn rand_biguint(size: usize, rng: &mut StdRng) -> BigUint {
    let size_bytes = size / 8;

    let mut buf: Vec<u8> = Vec::with_capacity(size_bytes);
    buf.resize(size_bytes, 0);

    rng.fill(buf.as_mut_slice());

    BigUint::from_bytes_le(&buf)
}

pub trait InvMod {
    /// Calculate the inverse of self % modulus
    ///
    /// For odd modulus
    fn invmod(&self, modulus: &Self) -> Self;

    /// Calculate the inverse of self % modulus
    ///
    /// For even modulus
    fn invmod_slow(&self, modulus: &Self) -> Self;
}

impl InvMod for BigInt {
    /// Returns `(1 / self) % modulus` using Extended Euclidean Algorithm
    ///
    /// Panics if self and modulus are both even, either is zero, |self| == modulus, or no inverse is found
    ///
    /// From wolfSSL implementation: fp_invmod, fp_invmod_slow
    /// https://github.com/wolfSSL/wolfssl/blob/master/wolfcrypt/src/tfm.c
    fn invmod(&self, modulus: &Self) -> Self {
        if modulus.is_even() {
            return self.invmod_slow(modulus);
        }

        if self.is_zero() || modulus.is_zero() {
            panic!("base and/or modulus cannot be zero");
        }

        if self.abs() == *modulus {
            panic!("cannot invert |a| == modulus");
        }

        let x = modulus;
        let y = if self > modulus {
            self.mod_floor(modulus)
        } else {
            self.clone()
        };

        /* 3. u=x, v=y, B=0, D=1 */

        /* x == modulus, y == value to invert */
        let mut u = x.clone();
        /* we need y = |a| */
        let mut v = y.abs();

        let mut bb = Self::zero();
        let mut bd = Self::one();

        // here an infinite loop takes the place of `goto top`
        // where a condition calls for `goto top`, simply continue
        //
        // NOTE: need to be cautious to always break/return, else infinite loop
        loop {
            /* 4. while u is even do */
            while u.is_even() {
                /* 4.1 u = u / 2 */
                u /= 2_u32;

                /* 4.2 if B is odd then */
                if bb.is_odd() {
                    /* B = (B-x)/2 */
                    bb -= x;
                }

                /* B = B/2 */
                bb /= 2_u32;
            }

            /* 5. while v is even do */
            while v.is_even() {
                /* 5.1 v = v/2 */
                v /= 2_u32;

                /* 5.2 if D is odd then */
                if bd.is_odd() {
                    /* D = (D-x)/2 */
                    bd -= x;
                }

                /* D = D/2 */
                bd /= 2_u32;
            }

            /* 6. if u >= v then */
            if u >= v {
                /* u = u - v, B = B - D */
                u -= &v;
                bb -= &bd;
            } else {
                /* v = v - u, D = D - B */
                v -= &u;
                bd -= &bb;
            }

            /* if u != 0, goto step 4 */
            if !u.is_zero() {
                continue;
            }

            /* now a = B, b = D, gcd == g*v */
            if !v.is_one() {
                // if v != 1, there is no inverse
                panic!("no inverse, GCD != 1");
            }

            /* while D is too low */
            while bd.sign() == Minus {
                bd += modulus;
            }

            /* while D is too big */
            let mod_mag = modulus.magnitude();
            while bd.magnitude() >= mod_mag {
                bd -= modulus;
            }

            if self.sign() == Minus {
                bd = bd.neg();
            }

            /* D is now the inverse */
            break;
        }

        bd
    }

    /// Port of fp_invmod_slow from wolfSSL: wolfssl/wolfcrypt/src/tfm.c
    fn invmod_slow(&self, modulus: &Self) -> Self {
        if self.is_even() && modulus.is_even() {
            panic!("base and modulus are both even");
        }

        if self.is_zero() || modulus.is_zero() {
            panic!("base and/or modulus cannot be zero");
        }

        let x = self.mod_floor(modulus);
        let y = modulus;

        /* 3. u=x, v=y, A=1, B=0, C=0, D-1 */
        let mut u = x.clone();
        let mut v = y.clone();
        let mut ba = Self::one();
        let mut bb = Self::zero();
        let mut bc = Self::zero();
        let mut bd = Self::one();

        // here an infinite loop takes the place of `goto top`
        // where a condition calls for `goto top`, simply continue
        //
        // NOTE: need to be cautious to always break/return, else infinite loop
        loop {
            /* 4. while u is even do */
            while u.is_even() {
                /* 4.1 u = u / 2 */
                u /= 2_u32;

                /* 4.2 if A or B is odd then */
                if ba.is_odd() || bb.is_odd() {
                    /* A = (A+y)/2, B = (B-x)/2*/
                    // div 2 happens unconditionally below
                    ba += y;
                    bb -= &x;
                }

                ba /= 2_u32;
                bb /= 2_u32;
            }

            /* 5. while v is even do */
            while v.is_even() {
                /* 5.1 v = v / 2 */
                v /= 2_u32;

                /* 5.2 if C or D is odd then */
                if bc.is_odd() || bd.is_odd() {
                    /* C = (C+y)/2, D = (D-x)/2 */
                    // div 2 happens unconditionally below
                    bc += y;
                    bd -= &x;
                }

                /* C = C/2, D = D/2 */
                bc /= 2_u32;
                bd /= 2_u32;
            }

            /* 6. if u >= v then */
            if u >= v {
                /* u = u - v, A = A - C, B = B - D */
                u -= &v;
                ba -= &bc;
                bb -= &bd;
            } else {
                /* v = v - u, C = C - A, D = D - B */
                v -= &u;
                bc -= &ba;
                bd -= &bb;
            }

            /* if u != 0, goto step 4 */
            if !u.is_zero() {
                continue;
            }

            /* now a = C, b = D, gcd == g*v */
            if !v.is_one() {
                // if v != 1, there is no inverse
                panic!("no inverse, GCD != 1");
            }

            /* while C is too low */
            while bc.sign() == Minus {
                bc += y;
            }

            /* while C is too big */
            let mod_mag = y.magnitude();
            while bc.magnitude() > mod_mag {
                bc -= y;
            }

            /* C is now the inverse */
            break;
        }

        bc
    }
}

impl InvMod for BigUint {
    fn invmod(&self, modulus: &Self) -> Self {
        let bi: BigInt = self.clone().into();
        bi.invmod(&modulus.clone().into()).into_parts().1
    }

    fn invmod_slow(&self, modulus: &Self) -> Self {
        let bi: BigInt = self.clone().into();
        bi.invmod_slow(&modulus.clone().into()).into_parts().1
    }
}
