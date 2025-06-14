// BabyJubJub elliptic curve implementation in Rust.
// For LICENSE check https://github.com/arnaucube/babyjubjub-rs
use ark_bn254::Fr;
use num::BigUint;
use params::circom_t6::POSEIDON_CIRCOM_BN_6_PARAMS;
use poseidon_rust::poseidon::Poseidon;
use std::str::FromStr;

use ark_ff::*;

//pub type ArkBigInt = <ark_bn254::Fr as ark_ff::PrimeField>::BigInt;
use arrayref::array_ref;

#[cfg(not(feature = "aarch64"))]
use blake_hash::Digest;
use utils::{get_msg_hash, modulus}; // compatible version with Blake used at circomlib

#[cfg(feature = "aarch64")]
extern crate blake; // compatible version with Blake used at circomlib

use std::cmp::min;

use num_bigint::{BigInt, RandBigInt, Sign, ToBigInt};
use num_traits::One;

use generic_array::GenericArray;

pub mod params;
pub mod utils;

use lazy_static::lazy_static;
//TODO: Replace BigInt with BigUint
lazy_static! {
    static ref D: Fr = Fr::from_str("168696").unwrap();
    static ref D_BIG: BigInt = BigInt::from(168696 as u64 );
    static ref A: Fr = Fr::from_str("168700").unwrap();
    static ref A_BIG: BigInt = BigInt::from(168700 as u64);
    pub static ref Q: BigInt = BigInt::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",10
    )
        .unwrap();
    static ref B8: Point = Point {
        x: Fr::from_str(
               "5299619240641551281634865583518297030282874472190772894086521144482721001553",
           )
            .unwrap(),
            y: Fr::from_str(
                "16950150798460657717958625567821834550301663161624707787222815936182638968203",
            )
                .unwrap(),
    };
    static ref ORDER: Fr = Fr::from_str(
        "21888242871839275222246405745257275088614511777268538073601725287587578984328",
    )
        .unwrap();

    // SUBORDER = ORDER >> 3
    static ref SUBORDER:BigInt = &BigInt::parse_bytes(
        b"21888242871839275222246405745257275088614511777268538073601725287587578984328",
        10,
    )
        .unwrap()
        >> 3;
}

#[derive(Clone, Debug)]
pub struct PointProjective {
    pub x: Fr,
    pub y: Fr,
    pub z: Fr,
}

impl PointProjective {
    pub fn affine(&self) -> Point {
        if self.z == Fr::ZERO {
            return Point {
                x: Fr::zero(),
                y: Fr::zero(),
            };
        }

        let zinv = self.z.inverse().unwrap();
        let mut x = self.x;
        x = x * zinv;

        let mut y = self.y;
        y = y * zinv;

        Point { x, y }
    }

    #[allow(clippy::many_single_char_names)]
    pub fn add(&self, q: &PointProjective) -> PointProjective {
        // add-2008-bbjlp https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#addition-add-2008-bbjlp
        let mut a = self.z;
        a = a * q.z;
        let mut b = a;
        b = b.square();
        let mut c = self.x;
        c = c * q.x;
        let mut d = self.y;
        d = d * q.y;
        let mut e = *D;
        e = e * c;
        e = e * d;
        let mut f = b;
        f = f - e;
        let mut g = b;
        g = g + e;
        // let mut x1y1 = self.x;
        // x1y1 = x1y1 * self.y;
        // let mut x2y2 = q.x;
        // x2y2 = x2y2 + q.y;
        let mut x1py1 = self.x;
        x1py1 = x1py1 + self.y;
        let mut x2py2 = q.x;
        x2py2 = x2py2 + q.y;
        let mut aux = x1py1;
        aux = aux * x2py2;
        aux = aux - c;
        aux = aux - d;
        let mut x3 = a;
        x3 = x3 * f;
        x3 = x3 * aux;
        let mut ac = *A;
        ac = ac * c;
        let mut dac = d;
        dac = dac - ac;
        let mut y3 = a;
        y3 = y3 * g;
        y3 = y3 * dac;
        let mut z3 = f;
        z3 = z3 * g;

        PointProjective {
            x: x3,
            y: y3,
            z: z3,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Point {
    pub x: Fr,
    pub y: Fr,
}

impl Point {
    pub fn projective(&self) -> PointProjective {
        PointProjective {
            x: self.x,
            y: self.y,
            z: Fr::one(),
        }
    }

    pub fn mul_scalar(&self, n: &BigInt) -> Point {
        let mut r: PointProjective = PointProjective {
            x: Fr::zero(),
            y: Fr::one(),
            z: Fr::one(),
        };
        let mut exp: PointProjective = self.projective();
        let (_, b) = n.to_bytes_le();
        for i in 0..n.bits() {
            if test_bit(&b, i.try_into().unwrap()) {
                r = r.add(&exp);
            }
            exp = exp.add(&exp);
        }
        r.affine()
    }

    pub fn compress(&self) -> [u8; 32] {
        let p = &self;
        let mut r: [u8; 32] = [0; 32];
        let x_biguint: BigUint = p.x.into_bigint().into();
        let x_big = x_biguint.to_bigint().unwrap();
        let y_biguint: BigUint = p.y.into_bigint().into();
        let y_big = y_biguint.to_bigint().unwrap();
        let (_, y_bytes) = y_big.to_bytes_le();
        let len = min(y_bytes.len(), r.len());
        r[..len].copy_from_slice(&y_bytes[..len]);

        let q_shift: BigUint = Q.clone().to_biguint().unwrap() >> 1;
        if x_big > q_shift.try_into().unwrap() {
            r[31] |= 0x80;
        }
        r
    }

    pub fn equals(&self, p: Point) -> bool {
        if self.x == p.x && self.y == p.y {
            return true;
        }
        false
    }
}

pub fn test_bit(b: &[u8], i: usize) -> bool {
    b[i / 8] & (1 << (i % 8)) != 0
}

pub fn decompress_point(bb: [u8; 32]) -> Result<Point, String> {
    // https://tools.ietf.org/html/rfc8032#section-5.2.3
    let mut sign: bool = false;
    let mut b = bb;
    if b[31] & 0x80 != 0x00 {
        sign = true;
        b[31] &= 0x7F;
    }
    let y: BigInt = BigInt::from_bytes_le(Sign::Plus, &b[..]);
    if y >= Q.clone() {
        return Err("y outside the Finite Field over R".to_string());
    }
    let one: BigInt = One::one();

    // x^2 = (1 - y^2) / (a - d * y^2) (mod p)
    let den = utils::modinv(
        &utils::modulus(
            &(&A_BIG.clone() - utils::modulus(&(&D_BIG.clone() * (&y * &y)), &Q)),
            &Q,
        ),
        &Q,
    )?;
    let mut x: BigInt = utils::modulus(&((one - utils::modulus(&(&y * &y), &Q)) * den), &Q);
    x = utils::modsqrt(&x, &Q)?;

    if sign && (x <= (&Q.clone() >> 1)) || (!sign && (x > (&Q.clone() >> 1))) {
        x *= -(1.to_bigint().unwrap());
    }
    x = utils::modulus(&x, &Q);
    let x_fr: Fr = Fr::from_str(&x.to_string()).unwrap();
    let y_fr: Fr = Fr::from_str(&y.to_string()).unwrap();
    Ok(Point { x: x_fr, y: y_fr })
}

#[cfg(not(feature = "aarch64"))]
fn blh(b: &[u8]) -> Vec<u8> {
    let hash = blake_hash::Blake512::digest(b);
    hash.to_vec()
}

#[cfg(feature = "aarch64")]
fn blh(b: &[u8]) -> Vec<u8> {
    let mut hash = [0; 64];
    blake::hash(512, b, &mut hash).unwrap();
    hash.to_vec()
}

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

pub struct PrivateKey {
    pub key: [u8; 32],
}

impl PrivateKey {
    pub fn import(b: Vec<u8>) -> Result<PrivateKey, String> {
        if b.len() != 32 {
            return Err(String::from("imported key can not be bigger than 32 bytes"));
        }
        let mut sk: [u8; 32] = [0; 32];
        sk.copy_from_slice(&b[..32]);
        Ok(PrivateKey { key: sk })
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

    pub fn public(&self) -> Point {
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
        let r_bytes = utils::concatenate_arrays(s, &msg32);
        let r_hashed: Vec<u8> = blh(&r_bytes);
        let mut r = BigInt::from_bytes_le(Sign::Plus, &r_hashed[..]);
        r = utils::modulus(&r, &SUBORDER);
        let r_b8: Point = B8.mul_scalar(&r);
        let a = &self.public();

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
        let pk = self.public();
        let h = schnorr_hash(&pk, m, &r)?;

        // s= k+x·h
        let sk_scalar = self.scalar_key();
        let s = k + &sk_scalar * &h;
        Ok((r, s))
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

// Cur built to support only msg of len 298 bytes
#[allow(non_snake_case)]
pub fn sign_ecdsa(msg: Vec<u8>, key: BigInt) -> Result<Signature, String> {
    // Convert the message and key to byte arrays
    let (_, key_bytes) = key.to_bytes_le();

    // Hash the message bytes
    let h: Vec<u8> = blh(&msg);

    // Concatenate key bytes and message hash to form the preimage for k
    let k_preimage = utils::concatenate_arrays(&key_bytes, &h);

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
    let s = modulus(&(k_inv * (msg_hash + r_scalar * key)), &SUBORDER);

    // Reject signatures where s is zero (invalid per ECDSA spec)
    if s == BigInt::from(0) {
        return Err("s is zero, invalid signature".to_string());
    }

    // Return the signature (R point and scalar s)
    Ok(Signature { r_b8: R, s })
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

pub fn new_key() -> PrivateKey {
    // https://tools.ietf.org/html/rfc8032#section-5.1.5
    let mut rng = rand::thread_rng();
    let sk_raw = rng.gen_biguint(1024).to_bigint().unwrap();
    let (_, sk_raw_bytes) = sk_raw.to_bytes_be();
    PrivateKey::import(sk_raw_bytes[..32].to_vec()).unwrap()
}

pub fn new_ecdsa_key() -> BigInt {
    let mut rng = rand::thread_rng();
    modulus(
        &rng.gen_bigint_range(&BigInt::from(21341253), &SUBORDER.clone()),
        &SUBORDER,
    )
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

#[cfg(test)]
mod tests {
    use super::*;
    use ::hex;
    use rand::Rng;

    #[test]
    fn test_add_same_point() {
        let p: PointProjective = PointProjective {
            x: Fr::from_str(
                "17777552123799933955779906779655732241715742912184938656739573121738514868268",
            )
            .unwrap(),
            y: Fr::from_str(
                "2626589144620713026669568689430873010625803728049924121243784502389097019475",
            )
            .unwrap(),
            z: Fr::one(),
        };
        let q: PointProjective = PointProjective {
            x: Fr::from_str(
                "17777552123799933955779906779655732241715742912184938656739573121738514868268",
            )
            .unwrap(),
            y: Fr::from_str(
                "2626589144620713026669568689430873010625803728049924121243784502389097019475",
            )
            .unwrap(),
            z: Fr::one(),
        };
        let res = p.add(&q).affine();
        assert_eq!(
            res.x,
            Fr::from_str(
                "6890855772600357754907169075114257697580319025794532037257385534741338397365"
            )
            .unwrap()
        );
        assert_eq!(
            res.y,
            Fr::from_str(
                "4338620300185947561074059802482547481416142213883829469920100239455078257889"
            )
            .unwrap()
        );
    }
    #[test]
    fn test_add_different_points() {
        let p: PointProjective = PointProjective {
            x: Fr::from_str(
                "17777552123799933955779906779655732241715742912184938656739573121738514868268",
            )
            .unwrap(),
            y: Fr::from_str(
                "2626589144620713026669568689430873010625803728049924121243784502389097019475",
            )
            .unwrap(),
            z: Fr::one(),
        };
        let q: PointProjective = PointProjective {
            x: Fr::from_str(
                "16540640123574156134436876038791482806971768689494387082833631921987005038935",
            )
            .unwrap(),
            y: Fr::from_str(
                "20819045374670962167435360035096875258406992893633759881276124905556507972311",
            )
            .unwrap(),
            z: Fr::one(),
        };
        let res = p.add(&q).affine();
        assert_eq!(
            res.x,
            Fr::from_str(
                "7916061937171219682591368294088513039687205273691143098332585753343424131937"
            )
            .unwrap()
        );
        assert_eq!(
            res.y,
            Fr::from_str(
                "14035240266687799601661095864649209771790948434046947201833777492504781204499"
            )
            .unwrap()
        );
    }

    #[test]
    fn test_mul_scalar() {
        let p: Point = Point {
            x: Fr::from_str(
                "17777552123799933955779906779655732241715742912184938656739573121738514868268",
            )
            .unwrap(),
            y: Fr::from_str(
                "2626589144620713026669568689430873010625803728049924121243784502389097019475",
            )
            .unwrap(),
        };
        let res_m = p.mul_scalar(&3.to_bigint().unwrap());
        let res_a = p.projective().add(&p.projective());
        let res_a = res_a.add(&p.projective()).affine();
        assert_eq!(res_m.x, res_a.x);
        assert_eq!(
            res_m.x,
            Fr::from_str(
                "19372461775513343691590086534037741906533799473648040012278229434133483800898"
            )
            .unwrap()
        );
        assert_eq!(
            res_m.y,
            Fr::from_str(
                "9458658722007214007257525444427903161243386465067105737478306991484593958249"
            )
            .unwrap()
        );

        let n = BigInt::parse_bytes(
            b"14035240266687799601661095864649209771790948434046947201833777492504781204499",
            10,
        )
        .unwrap();
        let res2 = p.mul_scalar(&n);
        assert_eq!(
            res2.x,
            Fr::from_str(
                "17070357974431721403481313912716834497662307308519659060910483826664480189605"
            )
            .unwrap()
        );
        assert_eq!(
            res2.y,
            Fr::from_str(
                "4014745322800118607127020275658861516666525056516280575712425373174125159339"
            )
            .unwrap()
        );
    }

    #[test]
    fn test_new_key_sign_verify_0() {
        let sk = new_key();
        let pk = sk.public();
        let msg = 5.to_bigint().unwrap();
        let sig = sk.sign(msg.clone()).unwrap();
        let v = verify(pk, sig, msg);
        assert_eq!(v, true);
    }

    #[test]
    fn test_new_key_sign_verify_1() {
        let sk = new_key();
        let pk = sk.public();
        let msg = BigInt::parse_bytes(b"123456789012345678901234567890", 10).unwrap();
        let sig = sk.sign(msg.clone()).unwrap();
        let v = verify(pk, sig, msg);
        assert_eq!(v, true);
    }

    #[test]
    fn test_new_key_sign_verify_1_ecdsa() {
        for _ in 0..100 {
            let sk = new_ecdsa_key();
            let pk = B8.mul_scalar(&sk);

            let mut rng = rand::thread_rng();
            let msg: Vec<u8> = (0..298).map(|_| rng.gen::<u8>()).collect();

            let sig = sign_ecdsa(msg.clone(), sk).unwrap();
            verify_ecdsa(msg.clone(), sig.clone(), pk.clone());
        }
    }

    #[test]
    fn test_new_key_sign_verify_1_eff_ecdsa() {
        for _ in 0..100 {
            let sk = new_ecdsa_key();
            let pk = B8.mul_scalar(&sk);

            let mut rng = rand::thread_rng();
            let msg: Vec<u8> = (0..298).map(|_| rng.gen::<u8>()).collect();
            let sig = sign_ecdsa(msg.clone(), sk).unwrap();
            let (t, u) = get_eff_ecdsa_args(msg, sig.clone());
            verify_eff_ecdsa(sig, t, u, pk);
        }
    }

    #[test]
    fn test_point_compress_decompress() {
        let p: Point = Point {
            x: Fr::from_str(
                "17777552123799933955779906779655732241715742912184938656739573121738514868268",
            )
            .unwrap(),
            y: Fr::from_str(
                "2626589144620713026669568689430873010625803728049924121243784502389097019475",
            )
            .unwrap(),
        };
        let p_comp = p.compress();
        assert_eq!(
            hex::encode(p_comp),
            "53b81ed5bffe9545b54016234682e7b2f699bd42a5e9eae27ff4051bc698ce85"
        );
        let p2 = decompress_point(p_comp).unwrap();
        assert_eq!(p.x, p2.x);
        assert_eq!(p.y, p2.y);
    }

    #[test]
    fn test_point_decompress0() {
        let y_bytes_raw =
            hex::decode("b5328f8791d48f20bec6e481d91c7ada235f1facf22547901c18656b6c3e042f")
                .unwrap();
        let mut y_bytes: [u8; 32] = [0; 32];
        y_bytes.copy_from_slice(&y_bytes_raw);
        let p = decompress_point(y_bytes).unwrap();

        let expected_px_raw =
            hex::decode("b86cc8d9c97daef0afe1a4753c54fb2d8a530dc74c7eee4e72b3fdf2496d2113")
                .unwrap();
        let mut e_px_bytes: [u8; 32] = [0; 32];
        e_px_bytes.copy_from_slice(&expected_px_raw);
        let expected_px: Fr =
            Fr::from_str(&BigInt::from_bytes_le(Sign::Plus, &e_px_bytes).to_string()).unwrap();
        assert_eq!(&p.x, &expected_px);
    }

    #[test]
    fn test_point_decompress1() {
        let y_bytes_raw =
            hex::decode("70552d3ff548e09266ded29b33ce75139672b062b02aa66bb0d9247ffecf1d0b")
                .unwrap();
        let mut y_bytes: [u8; 32] = [0; 32];
        y_bytes.copy_from_slice(&y_bytes_raw);
        let p = decompress_point(y_bytes).unwrap();

        let expected_px_raw =
            hex::decode("30f1635ba7d56f9cb32c3ffbe6dca508a68c7f43936af11a23c785ce98cb3404")
                .unwrap();
        let mut e_px_bytes: [u8; 32] = [0; 32];
        e_px_bytes.copy_from_slice(&expected_px_raw);
        let expected_px: Fr =
            Fr::from_str(&BigInt::from_bytes_le(Sign::Plus, &e_px_bytes).to_string()).unwrap();
        assert_eq!(&p.x, &expected_px);
    }

    #[test]
    fn test_point_decompress_loop() {
        for _ in 0..5 {
            let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
            let sk_raw: BigInt = BigInt::from_bytes_le(Sign::Plus, &random_bytes[..]);
            let (_, sk_raw_bytes) = sk_raw.to_bytes_be();
            let mut h: Vec<u8> = blh(&sk_raw_bytes);

            h[0] = h[0] & 0xF8;
            h[31] = h[31] & 0x7F;
            h[31] = h[31] | 0x40;

            let sk = BigInt::from_bytes_le(Sign::Plus, &h[..]);
            let point = B8.mul_scalar(&sk);
            let cmp_point = point.compress();
            let dcmp_point = decompress_point(cmp_point).unwrap();

            assert_eq!(&point.x, &dcmp_point.x);
            assert_eq!(&point.y, &dcmp_point.y);
        }
    }

    #[test]
    fn test_signature_compress_decompress() {
        let sk = new_key();
        let pk = sk.public();

        for i in 0..5 {
            let msg_raw = "123456".to_owned() + &i.to_string();
            let msg = BigInt::parse_bytes(msg_raw.as_bytes(), 10).unwrap();
            let sig = sk.sign(msg.clone()).unwrap();

            let compressed_sig = sig.compress();
            let decompressed_sig = decompress_signature(&compressed_sig).unwrap();
            assert_eq!(&sig.r_b8.x, &decompressed_sig.r_b8.x);
            assert_eq!(&sig.r_b8.y, &decompressed_sig.r_b8.y);
            assert_eq!(&sig.s, &decompressed_sig.s);

            let v = verify(pk.clone(), decompressed_sig, msg);
            assert_eq!(v, true);
        }
    }

    #[test]
    fn test_schnorr_signature() {
        let sk = new_key();
        let pk = sk.public();

        let msg = BigInt::parse_bytes(b"123456789012345678901234567890", 10).unwrap();
        let (s, e) = sk.sign_schnorr(msg.clone()).unwrap();
        let verification = verify_schnorr(pk, msg, s, e).unwrap();
        assert_eq!(true, verification);
    }

    #[test]
    fn test_circomlib_testvector() {
        let sk_raw_bytes =
            hex::decode("0001020304050607080900010203040506070809000102030405060708090001")
                .unwrap();

        // test blake compatible with circomlib implementation
        let h: Vec<u8> = blh(&sk_raw_bytes);
        assert_eq!(hex::encode(h), "c992db23d6290c70ffcc02f7abeb00b9d00fa8b43e55d7949c28ba6be7545d3253882a61bd004a236ef1cdba01b27ba0aedfb08eefdbfb7c19657c880b43ddf1");

        // test private key
        let sk = PrivateKey::import(
            hex::decode("0001020304050607080900010203040506070809000102030405060708090001")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            sk.scalar_key().to_string(),
            "6466070937662820620902051049739362987537906109895538826186780010858059362905"
        );

        // test public key
        let pk = sk.public();
        assert_eq!(
            pk.x.to_string(),
            "13277427435165878497778222415993513565335242147425444199013288855685581939618"
        );
        assert_eq!(
            pk.y.to_string(),
            "13622229784656158136036771217484571176836296686641868549125388198837476602820"
        );

        // test signature & verification
        let msg = BigInt::from_bytes_le(Sign::Plus, &hex::decode("00010203040506070809").unwrap());
        println!("msg {:?}", msg.to_string());
        let sig = sk.sign(msg.clone()).unwrap();
        assert_eq!(
            sig.r_b8.x.to_string(),
            "11384336176656855268977457483345535180380036354188103142384839473266348197733"
        );
        assert_eq!(
            sig.r_b8.y.to_string(),
            "15383486972088797283337779941324724402501462225528836549661220478783371668959"
        );
        assert_eq!(
            sig.s.to_string(),
            "1672775540645840396591609181675628451599263765380031905495115170613215233181"
        );
        let v = verify(pk, sig, msg);
        assert_eq!(v, true);
    }
}
