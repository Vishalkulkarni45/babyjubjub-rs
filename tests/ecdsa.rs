#[cfg(test)]
mod tests {
    use babyjubjub_rs::{
        key::{verify, EdDSAPrivateKey},
        signature::verify_schnorr,
        utils::blh,
    };
    use num::BigInt;
    use num_bigint::{Sign, ToBigInt};

    #[test]
    fn test_new_key_sign_verify_0() {
        let sk = EdDSAPrivateKey::new_key();
        let pk = sk.public_key();
        let msg = 5.to_bigint().unwrap();
        let sig = sk.sign(msg.clone()).unwrap();
        let v = verify(pk, sig, msg);
        assert_eq!(v, true);
    }

    #[test]
    fn test_new_key_sign_verify_1() {
        let sk = EdDSAPrivateKey::new_key();
        let pk = sk.public_key();
        let msg = BigInt::parse_bytes(b"123456789012345678901234567890", 10).unwrap();
        let sig = sk.sign(msg.clone()).unwrap();
        let v = verify(pk, sig, msg);
        assert_eq!(v, true);
    }

    #[test]
    fn test_schnorr_signature() {
        let sk = EdDSAPrivateKey::new_key();
        let pk = sk.public_key();

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
        let sk = EdDSAPrivateKey::import(
            hex::decode("0001020304050607080900010203040506070809000102030405060708090001")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            sk.scalar_key().to_string(),
            "6466070937662820620902051049739362987537906109895538826186780010858059362905"
        );

        // test public key
        let pk = sk.public_key();
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
