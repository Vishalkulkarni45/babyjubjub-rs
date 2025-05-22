#[cfg(test)]
mod tests {
    use babyjubjub_rs::{
        key::{verify, EdDSAPrivateKey},
        signature::decompress_signature,
        utils::{get_msg_hash, modinv, modsqrt, modsqrt_v2, modulus, EcdsaInput, SUBORDER},
    };
    use num::BigInt;
    use num_bigint::Sign;

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
    fn test_output_json_ecdsa() {
        //read data from output.json
        let data = std::fs::read_to_string("output.json").unwrap();
        let input: EcdsaInput = serde_json::from_str(&data).unwrap();

        let msg: Vec<u8> = input
            .SmileId_data
            .iter()
            .map(|x| x.parse::<u8>().unwrap())
            .collect();
        //   println!("msg: {:?}", msg);
        let msg_hash = get_msg_hash(msg).unwrap();
        println!("msg_hash_limbs:{:?}", msg_hash.to_u64_digits());
        let r_inv: Vec<u64> = input
            .r_inv
            .iter()
            .map(|x| x.parse::<u64>().unwrap())
            .collect();
        let mut bytes = Vec::with_capacity(r_inv.len() * 8);
        for limb in &r_inv {
            bytes.extend_from_slice(&limb.to_le_bytes());
        }

        let r_inv = BigInt::from_bytes_le(Sign::Plus, &bytes[..]);
        let res = modulus(&(msg_hash * r_inv), &SUBORDER);

        println!("res: {:?}", res.to_u64_digits());
    }
    #[test]
    fn test_signature_compress_decompress() {
        let sk = EdDSAPrivateKey::new_key();
        let pk = sk.public_key();

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
}
