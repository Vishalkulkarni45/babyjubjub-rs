// BabyJubJub elliptic curve implementation in Rust.
// For LICENSE check https://github.com/arnaucube/babyjubjub-rs

use ark_bn254::Fr;
use ark_ff::*;
use num::BigUint;
use num_bigint::{BigInt, Sign, ToBigInt};
use num_traits::{One, Zero};
use poseidon_rust::poseidon::Poseidon;
use serde::{Deserialize, Serialize};
use std::{fs::OpenOptions, io::Write, str::FromStr};

use crate::{
    curve::Point,
    params::{
        circom_t10::POSEIDON_CIRCOM_BN_10_PARAMS, circom_t11::POSEIDON_CIRCOM_BN_11_PARAMS,
        circom_t12::POSEIDON_CIRCOM_BN_12_PARAMS, circom_t13::POSEIDON_CIRCOM_BN_13_PARAMS,
        circom_t14::POSEIDON_CIRCOM_BN_14_PARAMS, circom_t15::POSEIDON_CIRCOM_BN_15_PARAMS,
        circom_t16::POSEIDON_CIRCOM_BN_16_PARAMS, circom_t17::POSEIDON_CIRCOM_BN_17_PARAMS,
        circom_t2::POSEIDON_CIRCOM_BN_2_PARAMS, circom_t3::POSEIDON_CIRCOM_BN_3_PARAMS,
        circom_t4::POSEIDON_CIRCOM_BN_4_PARAMS, circom_t5::POSEIDON_CIRCOM_BN_5_PARAMS,
        circom_t6::POSEIDON_CIRCOM_BN_6_PARAMS, circom_t7::POSEIDON_CIRCOM_BN_7_PARAMS,
        circom_t8::POSEIDON_CIRCOM_BN_8_PARAMS, circom_t9::POSEIDON_CIRCOM_BN_9_PARAMS,
    },
    signature::Signature,
};
use lazy_static::lazy_static;

#[cfg(not(feature = "aarch64"))]
use blake_hash::Digest;

#[cfg(feature = "aarch64")]
extern crate blake;

//TODO: Replace BigInt with BigUint
lazy_static! {
    pub static ref D: Fr = Fr::from_str("168696").unwrap();
    pub static ref D_BIG: BigInt = BigInt::from(168696_u64 );
    pub static ref A: Fr = Fr::from_str("168700").unwrap();
    pub static ref A_BIG: BigInt = BigInt::from(168700_u64);
    pub static ref Q: BigInt = BigInt::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",10
    )
        .unwrap();
    pub static ref B8: Point = Point {
        x: Fr::from_str(
               "5299619240641551281634865583518297030282874472190772894086521144482721001553",
           )
            .unwrap(),
            y: Fr::from_str(
                "16950150798460657717958625567821834550301663161624707787222815936182638968203",
            )
                .unwrap(),
    };
    pub static ref ORDER: Fr = Fr::from_str(
        "21888242871839275222246405745257275088614511777268538073601725287587578984328",
    )
        .unwrap();

    // SUBORDER = ORDER >> 3
    pub static ref SUBORDER:BigInt = &BigInt::parse_bytes(
        b"21888242871839275222246405745257275088614511777268538073601725287587578984328",
        10,
    )
        .unwrap()
        >> 3;
    pub static ref MAX_BYTES_IN_FIELD: usize = 31_usize;
}

pub fn modulus(a: &BigInt, m: &BigInt) -> BigInt {
    ((a % m) + m) % m
}

pub fn get_msg_hash(msg_bytes: Vec<u8>) -> Result<BigInt, String> {
    let msg_hash: Fr = pack_bytes_and_poseidon(&msg_bytes)?;
    let msg_hash_bu: BigUint = msg_hash.into_bigint().into();
    Ok(modulus(&msg_hash_bu.to_bigint().unwrap(), &SUBORDER))
}

fn compute_int_chunk_length(byte_len: usize) -> usize {
    let pack_size = *MAX_BYTES_IN_FIELD;
    let remain = byte_len % pack_size;
    let mut num_chunks = (byte_len - remain) / pack_size;
    if remain > 0 {
        num_chunks += 1;
    }
    num_chunks
}

pub fn pack_bytes_array(unpacked: Vec<u8>) -> Vec<BigInt> {
    let pack_size = *MAX_BYTES_IN_FIELD;
    let max_bytes = unpacked.len();
    let max_ints = compute_int_chunk_length(max_bytes);
    let mut out: Vec<BigInt> = vec![BigInt::zero(); max_ints];

    for i in 0..max_ints {
        let mut sum = BigInt::zero();
        for j in 0..pack_size {
            let idx = pack_size * i + j;

            // Copy previous value if out of bounds
            if idx >= max_bytes {
                continue;
            }
            // First item of chunk is byte itself
            else if j == 0 {
                sum = BigInt::from(unpacked[idx]);
            }
            // Every other item is 256^j * byte
            else {
                sum += (BigInt::from(1) << (8 * j)) * BigInt::from(unpacked[idx]);
            }
        }
        out[i] = sum;
    }

    out
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub struct EcdsaInput {
    pub SmileId_data: Vec<String>,
    pub s: String,
    pub Tx: String,
    pub Ty: String,
    pub Ux: String,
    pub Uy: String,
    pub pubKeyX: String,
    pub pubKeyY: String,
    pub r_inv: Vec<String>,
}
fn fr_to_string(input: &Fr) -> String {
    let in_bu: BigUint = input.into_bigint().into();
    in_bu.to_string()
}

pub fn create_output_json(sig: &Signature, t: &Point, u: &Point, pk: &Point, data: Vec<u8>) {
    let r_sclar: BigUint = sig.r_b8.x.into_bigint().into();
    let r = modulus(&r_sclar.to_bigint().unwrap(), &SUBORDER);

    // Compute the modular inverse of r modulo the subgroup order
    let mut r_inv = r.modinv(&SUBORDER).unwrap();
    r_inv = modulus(&(-r_inv), &SUBORDER);
    let (r_inv_sign, r_inv_limbs) = r_inv.to_u64_digits();
    println!("r_inv limbs {:?}", r_inv_limbs);
    assert_eq!(r_inv_sign, Sign::Plus);
    let data_str: Vec<String> = data.iter().map(u8::to_string).collect();
    assert_eq!(data_str.len(), 298);
    let out = EcdsaInput {
        SmileId_data: data.iter().map(u8::to_string).collect(),
        s: sig.s.clone().to_string(),
        Tx: fr_to_string(&t.x),
        Ty: fr_to_string(&t.y),
        Ux: fr_to_string(&u.x),
        Uy: fr_to_string(&u.y),
        pubKeyX: fr_to_string(&pk.x),
        pubKeyY: fr_to_string(&pk.y),
        r_inv: (0..4).map(|i| r_inv_limbs[i].to_string()).collect(),
    };
    let json = serde_json::to_string_pretty(&out).unwrap();
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open("output.json")
        .unwrap();
    file.write_all(json.as_bytes()).unwrap();
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

#[cfg(not(feature = "aarch64"))]
pub fn blh(b: &[u8]) -> Vec<u8> {
    let hash = blake_hash::Blake512::digest(b);
    hash.to_vec()
}

#[cfg(feature = "aarch64")]
pub fn blh(b: &[u8]) -> Vec<u8> {
    let mut hash = [0; 64];
    blake::hash(512, b, &mut hash).unwrap();
    hash.to_vec()
}

#[allow(non_snake_case)]
pub fn get_eff_ecdsa_args(msg: Vec<u8>, sig: Signature) -> (Point, Point) {
    // Compute the hash of the message as a scalar
    let msg_hash = get_msg_hash(msg).unwrap();

    // Recover r from the signature's R point x-coordinate, reduced modulo the subgroup order
    let r_sclar: BigUint = sig.r_b8.x.into_bigint().into();
    let r = modulus(&r_sclar.to_bigint().unwrap(), &SUBORDER);

    // Compute the modular inverse of r modulo the subgroup order
    let r_inv = r.modinv(&SUBORDER).unwrap();

    // T = R * r_inv, where R is the signature's R point
    let T = sig.r_b8.mul_scalar(&r_inv);

    // U = G * (-r_inv * msg_hash mod n), where G is the generator
    let U = B8.mul_scalar(&(modulus(&(-r_inv * msg_hash), &SUBORDER)));

    // Return the two points (T, U) for efficient ECDSA verification
    (T, U)
}

pub fn concatenate_arrays<T: Clone>(x: &[T], y: &[T]) -> Vec<T> {
    x.iter().chain(y).cloned().collect()
}

fn get_poseidon_hasher(k: usize) -> Poseidon<Fr> {
    match k {
        2 => Poseidon::new(&POSEIDON_CIRCOM_BN_2_PARAMS),
        3 => Poseidon::new(&POSEIDON_CIRCOM_BN_3_PARAMS),
        4 => Poseidon::new(&POSEIDON_CIRCOM_BN_4_PARAMS),
        5 => Poseidon::new(&POSEIDON_CIRCOM_BN_5_PARAMS),
        6 => Poseidon::new(&POSEIDON_CIRCOM_BN_6_PARAMS),
        7 => Poseidon::new(&POSEIDON_CIRCOM_BN_7_PARAMS),
        8 => Poseidon::new(&POSEIDON_CIRCOM_BN_8_PARAMS),
        9 => Poseidon::new(&POSEIDON_CIRCOM_BN_9_PARAMS),
        10 => Poseidon::new(&POSEIDON_CIRCOM_BN_10_PARAMS),
        11 => Poseidon::new(&POSEIDON_CIRCOM_BN_11_PARAMS),
        12 => Poseidon::new(&POSEIDON_CIRCOM_BN_12_PARAMS),
        13 => Poseidon::new(&POSEIDON_CIRCOM_BN_13_PARAMS),
        14 => Poseidon::new(&POSEIDON_CIRCOM_BN_14_PARAMS),
        15 => Poseidon::new(&POSEIDON_CIRCOM_BN_15_PARAMS),
        16 => Poseidon::new(&POSEIDON_CIRCOM_BN_16_PARAMS),
        17 => Poseidon::new(&POSEIDON_CIRCOM_BN_17_PARAMS),
        _ => panic!("Unsupported input length: {}", k),
    }
}

/// Custom hasher function that mimics the Circom CustomHasher template
/// If k < 16, uses a single Poseidon hash
/// If k >= 16, chunks inputs into groups of 16, hashes each chunk, then hashes the results
pub fn custom_hasher(inputs: &[Fr]) -> Result<Fr, String> {
    let k = inputs.len();

    if k < 16 {
        let hasher = get_poseidon_hasher(k + 1);

        // If k is less than 16, use a single poseidon hash
        let mut hash_inputs = vec![Fr::zero()]; // Poseidon typically needs a capacity element
        hash_inputs.extend_from_slice(inputs);

        let result = hasher
            .permutation(hash_inputs)
            .map_err(|e| format!("Poseidon hashing failed: {:?}", e))?;
        Ok(result[0])
    } else {
        // Do up to 16 rounds of poseidon
        let rounds = k.div_ceil(16);
        if rounds >= 17 {
            return Err("Too many rounds (>= 17)".to_string());
        }

        let mut chunk_hashes = Vec::new();
        let hasher = Poseidon::new(&POSEIDON_CIRCOM_BN_17_PARAMS);

        // Hash each chunk of 16 elements
        for i in 0..rounds {
            // Build the 17-element input vector: 1 capacity + up to 16 data elements, padded with zeros.
            let start = i * 16;
            let end = usize::min(start + 16, k);

            // Pre-allocate exact capacity to avoid reallocations.
            let mut chunk_inputs = Vec::with_capacity(17);
            chunk_inputs.push(Fr::zero()); // Capacity element
            chunk_inputs.extend_from_slice(&inputs[start..end]);

            // Pad the remaining slots (if any) with zeros so we always hash exactly 17 elements.
            chunk_inputs.resize(17, Fr::zero());

            let chunk_result = hasher
                .permutation(chunk_inputs)
                .map_err(|e| format!("Poseidon chunk hashing failed: {:?}", e))?;
            chunk_hashes.push(chunk_result[0]);
        }

        // Hash all chunk results together
        let mut final_inputs = vec![Fr::zero()]; // Capacity element
        final_inputs.extend(chunk_hashes);

        let final_hasher = get_poseidon_hasher(rounds + 1);

        let final_result = final_hasher
            .permutation(final_inputs)
            .map_err(|e| format!("Poseidon final hashing failed: {:?}", e))?;
        Ok(final_result[0])
    }
}

/// Packs a byte array and hashes it with Poseidon, mirroring the Circom
/// `PackBytesAndPoseidon` template.
///
/// * `bytes` – raw bytes to be packed.
///
/// Returns the Poseidon hash of the packed field elements or an error if the
/// hashing fails.
pub fn pack_bytes_and_poseidon(bytes: &[u8]) -> Result<Fr, String> {
    // Convert the incoming bytes into field‐sized integers.
    let packed_bigints = pack_bytes_array(bytes.to_vec());

    // Convert each BigInt chunk into a field element.
    let mut packed_fr = Vec::with_capacity(packed_bigints.len());
    for big in packed_bigints {
        let fr = Fr::from_str(&big.to_string())
            .map_err(|_| "Failed to convert chunk into field element".to_string())?;
        packed_fr.push(fr);
    }

    // Hash using the same custom hasher employed by the Circom template.
    custom_hasher(&packed_fr)
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
