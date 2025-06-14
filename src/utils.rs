// BabyJubJub elliptic curve implementation in Rust.
// For LICENSE check https://github.com/arnaucube/babyjubjub-rs

use ark_bn254::Fr;
use ark_ff::*;
use num::BigUint;
use num_bigint::{BigInt, ToBigInt};
use num_traits::{One, Zero};
use poseidon_rust::poseidon::Poseidon;
use std::{iter::once, str::FromStr};

use crate::{
    params::{
        circom_t13::POSEIDON_CIRCOM_BN_13_PARAMS, circom_t17::POSEIDON_CIRCOM_BN_17_PARAMS,
        circom_t3::POSEIDON_CIRCOM_BN_3_PARAMS,
    },
    SUBORDER,
};

pub fn modulus(a: &BigInt, m: &BigInt) -> BigInt {
    ((a % m) + m) % m
}

pub fn get_msg_hash(msg_bytes: Vec<u8>) -> Result<BigInt, String> {
    let msg_bytes_fr = msg_bytes
        .into_iter()
        .map(|x| Fr::from_str(&x.to_string()).unwrap())
        .collect::<Vec<Fr>>();

    let msg_hash: BigUint = compute_hash_298_bytes(msg_bytes_fr).into_bigint().into();

    let msg_hash_big = msg_hash.to_bigint().unwrap();
    let msg_hash = modulus(&msg_hash_big, &SUBORDER);
    Ok(msg_hash)
}

// Poseidon(16) -- 18 rounds ==>  18 * 16 = 288 , output 18 Fr
// total preimage left ==> 18 + 10 = 28 , use poseidon(16) and poseidon(12)
// output poseidon(2) ==> 1
// TODO: revist to check correct params are used
fn compute_hash_298_bytes(input: Vec<Fr>) -> Fr {
    assert!(input.len() == 298, "Input lenght must be 298 bytes");

    let poseidon_hash_16 = Poseidon::new(&POSEIDON_CIRCOM_BN_17_PARAMS);
    let mut inter_pos_1_16 = Vec::<Fr>::with_capacity(18);

    for chunk in input[..288].chunks(16) {
        inter_pos_1_16.push(
            poseidon_hash_16
                .permutation(
                    once(Fr::zero())
                        .chain(chunk.iter().cloned())
                        .collect::<Vec<Fr>>(),
                )
                .unwrap()[0],
        )
    }

    let inter_pos_2_16 = poseidon_hash_16
        .permutation(
            once(Fr::zero())
                .chain(inter_pos_1_16[0..16].iter().cloned())
                .collect::<Vec<Fr>>(),
        )
        .unwrap()[0];

    //Replace params with 12
    let poseidon_hash_12 = Poseidon::new(&POSEIDON_CIRCOM_BN_13_PARAMS);
    let inter_pos_2_12 = poseidon_hash_12
        .permutation(
            once(Fr::zero())
                .chain(
                    inter_pos_1_16[16..]
                        .iter()
                        .chain(input[18 * 16..].iter())
                        .cloned(),
                )
                .collect::<Vec<Fr>>(),
        )
        .unwrap()[0];

    //Replace params with 2
    let poseidon_hash_2 = Poseidon::new(&POSEIDON_CIRCOM_BN_3_PARAMS);

    poseidon_hash_2
        .permutation([Fr::zero(), inter_pos_2_16, inter_pos_2_12].to_vec())
        .unwrap()[0]
}

pub fn modinv(a: &BigInt, q: &BigInt) -> Result<BigInt, String> {
    let big_zero: BigInt = Zero::zero();
    if a == &big_zero {
        return Err("no mod inv of Zero".to_string());
    }

    let mut mn = (q.clone(), a.clone());
    let mut xy: (BigInt, BigInt) = (Zero::zero(), One::one());

    while mn.1 != big_zero {
        xy = (xy.1.clone(), xy.0 - (mn.0.clone() / mn.1.clone()) * xy.1);
        mn = (mn.1.clone(), modulus(&mn.0, &mn.1));
    }

    while xy.0 < Zero::zero() {
        xy.0 = modulus(&xy.0, q);
    }
    Ok(xy.0)
}

/*
pub fn modinv_v2(a0: &BigInt, m0: &BigInt) -> BigInt {
    if m0 == &One::one() {
        return One::one();
    }

    let (mut a, mut m, mut x0, mut inv): (BigInt, BigInt, BigInt, BigInt) =
        (a0.clone(), m0.clone(), Zero::zero(), One::one());

    while a > One::one() {
        inv = inv - (&a / m.clone()) * x0.clone();
        a = a % m.clone();
        std::mem::swap(&mut a, &mut m);
        std::mem::swap(&mut x0, &mut inv);
    }

    if inv < Zero::zero() {
        inv += m0.clone()
    }
    inv
}

pub fn modinv_v3(a: &BigInt, q: &BigInt) -> BigInt {
    let mut aa: BigInt = a.clone();
    let mut qq: BigInt = q.clone();
    if qq < Zero::zero() {
        qq = -qq;
    }
    if aa < Zero::zero() {
        aa = -aa;
    }
    let d = num::Integer::gcd(&aa, &qq);
    if d != One::one() {
        println!("ERR no mod_inv");
    }
    let res: BigInt;
    if d < Zero::zero() {
        res = d + qq;
    } else {
        res = d;
    }
    res
}
pub fn modinv_v4(x: &BigInt, q: &BigInt) -> BigInt {
    let (gcd, inverse, _) = extended_gcd(x.clone(), q.clone());
    let one: BigInt = One::one();
    if gcd == one {
        modulus(&inverse, q)
    } else {
        panic!("error: gcd!=one")
    }
}
pub fn extended_gcd(a: BigInt, b: BigInt) -> (BigInt, BigInt, BigInt) {
    let (mut s, mut old_s) = (BigInt::zero(), BigInt::one());
    let (mut t, mut old_t) = (BigInt::one(), BigInt::zero());
    let (mut r, mut old_r) = (b, a);

    while r != BigInt::zero() {
        let quotient = &old_r / &r;
        old_r -= &quotient * &r;
        std::mem::swap(&mut old_r, &mut r);
        old_s -= &quotient * &s;
        std::mem::swap(&mut old_s, &mut s);
        old_t -= quotient * &t;
        std::mem::swap(&mut old_t, &mut t);
    }

    let _quotients = (t, s); // == (a, b) / gcd

    (old_r, old_s, old_t)
}
*/

pub fn concatenate_arrays<T: Clone>(x: &[T], y: &[T]) -> Vec<T> {
    x.iter().chain(y).cloned().collect()
}

#[allow(clippy::many_single_char_names)]
pub fn modsqrt(a: &BigInt, q: &BigInt) -> Result<BigInt, String> {
    // Tonelli-Shanks Algorithm (https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm)
    //
    // This implementation is following the Go lang core implementation https://golang.org/src/math/big/int.go?s=23173:23210#L859
    // Also described in https://www.maa.org/sites/default/files/pdf/upload_library/22/Polya/07468342.di020786.02p0470a.pdf
    // -> section 6

    let zero: BigInt = Zero::zero();
    let one: BigInt = One::one();
    if legendre_symbol(a, q) != 1 || a == &zero || q == &2.to_bigint().unwrap() {
        return Err("not a mod p square".to_string());
    } else if q % 4.to_bigint().unwrap() == 3.to_bigint().unwrap() {
        let r = a.modpow(&((q + one) / 4), q);
        return Ok(r);
    }

    let mut s = q - &one;
    let mut e: BigInt = Zero::zero();
    while &s % 2 == zero {
        s >>= 1;
        e += &one;
    }

    let mut n: BigInt = 2.to_bigint().unwrap();
    while legendre_symbol(&n, q) != -1 {
        n = &n + &one;
    }

    let mut y = a.modpow(&((&s + &one) >> 1), q);
    let mut b = a.modpow(&s, q);
    let mut g = n.modpow(&s, q);
    let mut r = e;

    loop {
        let mut t = b.clone();
        let mut m: BigInt = Zero::zero();
        while t != one {
            t = modulus(&(&t * &t), q);
            m += &one;
        }

        if m == zero {
            return Ok(y);
        }

        t = g.modpow(&(2.to_bigint().unwrap().modpow(&(&r - &m - 1), q)), q);
        g = g.modpow(&(2.to_bigint().unwrap().modpow(&(r - &m), q)), q);
        y = modulus(&(y * t), q);
        b = modulus(&(b * &g), q);
        r = m.clone();
    }
}

#[allow(dead_code)]
#[allow(clippy::many_single_char_names)]
pub fn modsqrt_v2(a: &BigInt, q: &BigInt) -> Result<BigInt, String> {
    // Tonelli-Shanks Algorithm (https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm)
    //
    // This implementation is following this Python implementation by Dusk https://github.com/dusk-network/dusk-zerocaf/blob/master/tools/tonelli.py

    let zero: BigInt = Zero::zero();
    let one: BigInt = One::one();
    if legendre_symbol(a, q) != 1 || a == &zero || q == &2.to_bigint().unwrap() {
        return Err("not a mod p square".to_string());
    } else if q % 4.to_bigint().unwrap() == 3.to_bigint().unwrap() {
        let r = a.modpow(&((q + one) / 4), q);
        return Ok(r);
    }

    let mut p = q - &one;
    let mut s: BigInt = Zero::zero();
    while &p % 2.to_bigint().unwrap() == zero {
        s += &one;
        p >>= 1;
    }

    let mut z: BigInt = One::one();
    while legendre_symbol(&z, q) != -1 {
        z = &z + &one;
    }
    let mut c = z.modpow(&p, q);

    let mut x = a.modpow(&((&p + &one) >> 1), q);
    let mut t = a.modpow(&p, q);
    let mut m = s;

    while t != one {
        let mut i: BigInt = One::one();
        let mut e: BigInt = 2.to_bigint().unwrap();
        while i < m {
            if t.modpow(&e, q) == one {
                break;
            }
            e *= 2.to_bigint().unwrap();
            i += &one;
        }

        let b = c.modpow(&(2.to_bigint().unwrap().modpow(&(&m - &i - 1), q)), q);
        x = modulus(&(x * &b), q);
        t = modulus(&(t * &b * &b), q);
        c = modulus(&(&b * &b), q);
        m = i.clone();
    }
    Ok(x)
}

pub fn legendre_symbol(a: &BigInt, q: &BigInt) -> i32 {
    // returns 1 if has a square root modulo q
    let one: BigInt = One::one();
    let ls: BigInt = a.modpow(&((q - &one) >> 1), q);
    if ls == q - one {
        return -1;
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    #[test]
    fn test_mod_inverse() {
        let a = BigInt::parse_bytes(b"123456789123456789123456789123456789123456789", 10).unwrap();
        let b = BigInt::parse_bytes(b"12345678", 10).unwrap();
        assert_eq!(
            modinv(&a, &b).unwrap(),
            BigInt::parse_bytes(b"641883", 10).unwrap()
        );
    }

    #[test]
    fn test_sqrtmod() {
        let a = BigInt::parse_bytes(
            b"6536923810004159332831702809452452174451353762940761092345538667656658715568",
            10,
        )
        .unwrap();
        let q = BigInt::parse_bytes(
            b"7237005577332262213973186563042994240857116359379907606001950938285454250989",
            10,
        )
        .unwrap();

        assert_eq!(
            (modsqrt(&a, &q).unwrap()).to_string(),
            "5464794816676661649783249706827271879994893912039750480019443499440603127256"
        );
        assert_eq!(
            (modsqrt_v2(&a, &q).unwrap()).to_string(),
            "5464794816676661649783249706827271879994893912039750480019443499440603127256"
        );
    }
    #[test]
    fn test_get_msg_hash() {
        let mut rng = rand::thread_rng();
        let random_input: Vec<Fr> = (0..298)
            .map(|_| Fr::from_str(&rng.gen::<u8>().to_string()).unwrap())
            .collect();
        let msg_hash = compute_hash_298_bytes(random_input);
        println!("hash : {:?}", msg_hash);
    }
}
