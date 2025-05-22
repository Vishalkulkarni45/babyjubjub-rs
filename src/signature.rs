use crate::{
    curve::{decompress_point, Point},
    params::circom_t6::POSEIDON_CIRCOM_BN_6_PARAMS,
    utils::{B8, Q},
};
use ark_bn254::Fr;
use ark_ff::*;
use arrayref::array_ref;
use num::{BigInt, BigUint};
use num_bigint::{Sign, ToBigInt};
use poseidon_rust::poseidon::Poseidon;
use std::cmp::min;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct Signature {
    pub r_b8: Point,
    pub s: BigInt,
}

impl Signature {
    pub fn compress(&self) -> [u8; 64] {
        let mut b: Vec<u8> = Vec::new();
        b.append(&mut self.r_b8.compress().to_vec());
        let (_, s_bytes) = self.s.to_bytes_le();
        let mut s_32bytes: [u8; 32] = [0; 32];
        let len = min(s_bytes.len(), s_32bytes.len());
        s_32bytes[..len].copy_from_slice(&s_bytes[..len]);
        b.append(&mut s_32bytes.to_vec());
        let mut r: [u8; 64] = [0; 64];
        r[..].copy_from_slice(&b[..]);
        r
    }
}

pub fn decompress_signature(b: &[u8; 64]) -> Result<Signature, String> {
    let r_b8_bytes: [u8; 32] = *array_ref!(b[..32], 0, 32);
    let s: BigInt = BigInt::from_bytes_le(Sign::Plus, &b[32..]);
    let r_b8 = decompress_point(r_b8_bytes);
    match r_b8 {
        Result::Err(err) => Err(err),
        Result::Ok(res) => Ok(Signature { r_b8: res, s }),
    }
}

pub fn schnorr_hash(pk: &Point, msg: BigInt, c: &Point) -> Result<BigInt, String> {
    if msg > Q.clone() {
        return Err("msg outside the Finite Field".to_string());
    }
    let msg_fr: Fr = Fr::from_str(&msg.to_string()).unwrap();
    let hm_input = vec![Fr::zero(), pk.x, pk.y, c.x, c.y, msg_fr];
    let poseidon_hash_5 = Poseidon::new(&POSEIDON_CIRCOM_BN_6_PARAMS);
    let hm: Fr = poseidon_hash_5.permutation(hm_input).unwrap()[0];

    let hm_bu: BigUint = hm.into_bigint().into();
    Ok(hm_bu.to_bigint().unwrap())
}

pub fn verify_schnorr(pk: Point, m: BigInt, r: Point, s: BigInt) -> Result<bool, String> {
    // sG = s·G
    let sg = B8.mul_scalar(&s);

    // r + h · x
    let h = schnorr_hash(&pk, m, &r)?;
    let pk_h = pk.mul_scalar(&h);
    let right = r.projective().add(&pk_h.projective());

    Ok(sg.equals(right.affine()))
}
