use crate::{
    curve::Point,
    params::circom_t6::POSEIDON_CIRCOM_BN_6_PARAMS,
    signature::{schnorr_hash, Signature},
    utils::{blh, concatenate_arrays, get_msg_hash, modulus, B8, Q, SUBORDER},
};
use ark_bn254::Fr;
use ark_ff::*;
use generic_array::GenericArray;
use num::{BigInt, BigUint};
use num_bigint::{RandBigInt, Sign, ToBigInt};
use poseidon_rust::poseidon::Poseidon;
use std::str::FromStr;
pub struct EdDSAPrivateKey {
    pub key: [u8; 32],
}

impl EdDSAPrivateKey {
    pub fn import(b: Vec<u8>) -> Result<EdDSAPrivateKey, String> {
        if b.len() != 32 {
            return Err(String::from("imported key can not be bigger than 32 bytes"));
        }
        let mut sk: [u8; 32] = [0; 32];
        sk.copy_from_slice(&b[..32]);
        Ok(EdDSAPrivateKey { key: sk })
    }
    pub fn new_key() -> Self {
        // https://tools.ietf.org/html/rfc8032#section-5.1.5
        let mut rng = rand::thread_rng();
        let sk_raw = rng.gen_bigint(1024);
        let (_, sk_raw_bytes) = sk_raw.to_bytes_be();
        EdDSAPrivateKey::import(sk_raw_bytes[..32].to_vec()).unwrap()
    }

    pub fn scalar_key(&self) -> BigInt {
        // not-compatible with circomlib implementation, but using Blake2b
        // let mut hasher = Blake2b::new();
        // hasher.update(sk_raw_bytes);
        // let mut h = hasher.finalize();

        // compatible with circomlib implementation
        let hash: Vec<u8> = blh(&self.key);
        let mut h: Vec<u8> = hash[..32].to_vec();

        // prune buffer following RFC 8032
        // https://tools.ietf.org/html/rfc8032#page-13
        h[0] &= 0xF8;
        h[31] &= 0x7F;
        h[31] |= 0x40;

        let sk = BigInt::from_bytes_le(Sign::Plus, &h[..]);
        sk >> 3
    }

    pub fn public_key(&self) -> Point {
        B8.mul_scalar(&self.scalar_key())
    }

    pub fn sign(&self, msg: BigInt) -> Result<Signature, String> {
        if msg > Q.clone() {
            return Err("msg outside the Finite Field".to_string());
        }
        // let (_, sk_bytes) = self.key.to_bytes_le();
        // let mut hasher = Blake2b::new();
        // hasher.update(sk_bytes);
        // let mut h = hasher.finalize(); // h: hash(sk), s: h[32:64]
        let mut h: Vec<u8> = blh(&self.key);

        let (_, msg_bytes) = msg.to_bytes_le();
        let mut msg32: [u8; 32] = [0; 32];
        msg32[..msg_bytes.len()].copy_from_slice(&msg_bytes[..]);
        let msg_fr: Fr = Fr::from_str(&msg.to_string()).unwrap();

        // https://tools.ietf.org/html/rfc8032#section-5.1.6
        let s = GenericArray::<u8, generic_array::typenum::U32>::from_mut_slice(&mut h[32..64]);
        let r_bytes = concatenate_arrays(s, &msg32);
        let r_hashed: Vec<u8> = blh(&r_bytes);
        let mut r = BigInt::from_bytes_le(Sign::Plus, &r_hashed[..]);
        r = modulus(&r, &SUBORDER);
        let r_b8: Point = B8.mul_scalar(&r);
        let a = &self.public_key();

        let hm_input = vec![Fr::zero(), r_b8.x, r_b8.y, a.x, a.y, msg_fr];
        //TODO: Check the param
        let poseidon_hash_5 = Poseidon::new(&POSEIDON_CIRCOM_BN_6_PARAMS);
        let hm: Fr = poseidon_hash_5.permutation(hm_input).unwrap()[0];

        let mut s = &self.scalar_key() << 3;
        let hm_bu: BigUint = hm.into_bigint().into();
        let hm_b = hm_bu.to_bigint().unwrap();
        s = hm_b * s;
        s = r + s;
        s %= &SUBORDER.clone();

        Ok(Signature { r_b8, s })
    }

    #[allow(clippy::many_single_char_names)]
    pub fn sign_schnorr(&self, m: BigInt) -> Result<(Point, BigInt), String> {
        // random r
        let mut rng = rand::thread_rng();
        let k = rng.gen_biguint(1024).to_bigint().unwrap();

        // r = k·G
        let r = B8.mul_scalar(&k);

        // h = H(x, r, m)
        let pk = self.public_key();
        let h = schnorr_hash(&pk, m, &r)?;

        // s= k+x·h
        let sk_scalar = self.scalar_key();
        let s = k + &sk_scalar * &h;
        Ok((r, s))
    }
}

#[derive(Clone, Debug)]
pub struct ECDSAPrivateKey {
    pub key: BigInt,
}
impl ECDSAPrivateKey {
    pub fn new_key() -> Self {
        let mut rng = rand::thread_rng();
        Self {
            key: modulus(
                &rng.gen_bigint_range(&BigInt::from(21341253), &SUBORDER.clone()),
                &SUBORDER,
            ),
        }
    }
    pub fn import(key: BigInt) -> Self {
        Self { key }
    }

    pub fn public_key(&self) -> Point {
        B8.mul_scalar(&self.key)
    }

    // Cur built to support only msg of len 298 bytes
    #[allow(non_snake_case)]
    pub fn sign_ecdsa(&self, msg: Vec<u8>) -> Result<Signature, String> {
        // Convert the message and key to byte arrays
        let (_, key_bytes) = self.key.to_bytes_le();

        // Hash the message bytes
        let h: Vec<u8> = blh(&msg);

        // Concatenate key bytes and message hash to form the preimage for k
        let k_preimage = concatenate_arrays(&key_bytes, &h);

        // Deterministically generate the nonce k and reduce it modulo the subgroup order
        let k = modulus(
            &BigInt::from_bytes_le(Sign::Plus, &blh(&k_preimage)),
            &SUBORDER,
        );

        // Calculate the curve point R = k * G
        let R = B8.mul_scalar(&k);

        // Use the x-coordinate of R as r (after conversion and reduction)
        let r: BigUint = R.x.into_bigint().into();
        let r_scalar = modulus(&r.to_bigint().unwrap(), &SUBORDER);

        // Reject signatures where r is zero (invalid per ECDSA spec)
        if r_scalar == BigInt::from(0) {
            return Err("r is zero, invalid signature".to_string());
        }

        // Compute the modular inverse of k
        let k_inv = match k.modinv(&SUBORDER) {
            Some(k_inv) => k_inv,
            None => return Err("k inverse not found".to_string()),
        };

        // Sanity check: k * k_inv mod n == 1
        assert_eq!(modulus(&(k_inv.clone() * k), &SUBORDER), BigInt::one());

        // Hash the message to a scalar
        let msg_hash = get_msg_hash(msg)?;

        // Compute s = k_inv * (msg_hash + r * key) mod n
        let s = modulus(
            &(k_inv * (msg_hash + r_scalar * self.key.clone())),
            &SUBORDER,
        );

        // Reject signatures where s is zero (invalid per ECDSA spec)
        if s == BigInt::from(0) {
            return Err("s is zero, invalid signature".to_string());
        }

        // Return the signature (R point and scalar s)
        Ok(Signature { r_b8: R, s })
    }
}
pub fn verify_ecdsa(msg: Vec<u8>, sig: Signature, pk: Point) -> bool {
    let msg_hash = get_msg_hash(msg).unwrap();

    let s_inv = match sig.s.modinv(&SUBORDER) {
        Some(s_inv) => s_inv,
        None => return false,
    };

    let r_sclar: BigUint = sig.r_b8.x.into_bigint().into();
    let r = modulus(&r_sclar.to_bigint().unwrap(), &SUBORDER);

    // u1 = msg_hash * s_inv mod n
    let u1 = modulus(&(msg_hash * &s_inv), &SUBORDER);
    // u2 = r * s_inv mod n
    let u2 = modulus(&(r.clone() * &s_inv), &SUBORDER);

    // R = u1*G + u2*pk
    let u1_g = B8.mul_scalar(&u1);
    let u2_pk = pk.mul_scalar(&u2);
    let r_point = u1_g.projective().add(&u2_pk.projective()).affine();

    // Check if R.x mod n == r
    let r_x_sclar: BigUint = r_point.x.into_bigint().into();
    let r_x = modulus(&r_x_sclar.to_bigint().unwrap(), &SUBORDER);
    r_x == r
}

pub fn verify_eff_ecdsa(sig: Signature, t: Point, u: Point, pk: Point) {
    // Efficient ECDSA verification using precomputed points T and U:
    // Check if s*T + U == pk
    let lhs = t
        .mul_scalar(&sig.s)
        .projective()
        .add(&u.projective())
        .affine();
    assert!(lhs.equals(pk), "Efficient ECDSA verification failed");
}

pub fn verify(pk: Point, sig: Signature, msg: BigInt) -> bool {
    if msg > Q.clone() {
        return false;
    }
    let msg_fr: Fr = Fr::from_str(&msg.to_string()).unwrap();
    let hm_input = vec![Fr::zero(), sig.r_b8.x, sig.r_b8.y, pk.x, pk.y, msg_fr];
    let poseidon_hash_5 = Poseidon::new(&POSEIDON_CIRCOM_BN_6_PARAMS);
    let hm: Fr = poseidon_hash_5.permutation(hm_input).unwrap()[0];
    let hm_bu: BigUint = hm.into_bigint().into();
    let l = B8.mul_scalar(&sig.s);
    let hm_b = hm_bu.to_bigint().unwrap();
    let r = sig
        .r_b8
        .projective()
        .add(&pk.mul_scalar(&(8.to_bigint().unwrap() * hm_b)).projective());
    l.equals(r.affine())
}
