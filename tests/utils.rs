#[cfg(test)]
mod tests {
    use babyjubjub_rs::{
        key::{verify, ECDSAPrivateKey, EdDSAPrivateKey},
        signature::decompress_signature,
        utils::{
            create_output_json, get_eff_ecdsa_args, get_msg_hash, modinv, modsqrt, modsqrt_v2,
            modulus, EcdsaInput, SUBORDER,
        },
    };
    use num::BigInt;
    use num_bigint::Sign;
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
    fn test_creat_output_json_ecdsa() {
        let sk = ECDSAPrivateKey::new_key();
        let pk = sk.public_key();
        let mut rng = rand::thread_rng();
        let msg: Vec<u8> = (0..298).map(|_| rng.gen::<u8>() % 128).collect();
        let sig = sk.sign_ecdsa(msg.clone()).unwrap();
        let (t, u) = get_eff_ecdsa_args(msg.clone(), sig.clone());
        create_output_json(&sig, &t, &u, &pk, msg);
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
