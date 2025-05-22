use crate::utils::{modinv, modsqrt, modulus, A, A_BIG, D, D_BIG, Q};
use ark_bn254::Fr;
use ark_ff::*;
use num::BigUint;
use num_bigint::{BigInt, Sign, ToBigInt};
use num_traits::One;
use std::cmp::min;
use std::str::FromStr;

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
        x *= zinv;

        let mut y = self.y;
        y *= zinv;

        Point { x, y }
    }

    #[allow(clippy::many_single_char_names)]
    pub fn add(&self, q: &PointProjective) -> PointProjective {
        // add-2008-bbjlp https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#addition-add-2008-bbjlp
        let mut a = self.z;
        a *= q.z;
        let mut b = a;
        b = b.square();
        let mut c = self.x;
        c *= q.x;
        let mut d = self.y;
        d *= q.y;
        let mut e = *D;
        e *= c;
        e *= d;
        let mut f = b;
        f -= e;
        let mut g = b;
        g += e;
        let mut x1py1 = self.x;
        x1py1 += self.y;
        let mut x2py2 = q.x;
        x2py2 += q.y;
        let mut aux = x1py1;
        aux *= x2py2;
        aux -= c;
        aux -= d;
        let mut x3 = a;
        x3 *= f;
        x3 *= aux;
        let mut ac = *A;
        ac *= c;
        let mut dac = d;
        dac -= ac;
        let mut y3 = a;
        y3 *= g;
        y3 *= dac;
        let mut z3 = f;
        z3 *= g;

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
        if x_big > q_shift.into() {
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
    let den = modinv(
        &modulus(
            &(A_BIG.clone() - modulus(&(D_BIG.clone() * (&y * &y)), &Q)),
            &Q,
        ),
        &Q,
    )?;
    let mut x: BigInt = modulus(&((one - modulus(&(&y * &y), &Q)) * den), &Q);
    x = modsqrt(&x, &Q)?;

    if sign && (x <= (&Q.clone() >> 1)) || (!sign && (x > (&Q.clone() >> 1))) {
        x *= -(1.to_bigint().unwrap());
    }
    x = modulus(&x, &Q);
    let x_fr: Fr = Fr::from_str(&x.to_string()).unwrap();
    let y_fr: Fr = Fr::from_str(&y.to_string()).unwrap();
    Ok(Point { x: x_fr, y: y_fr })
}
