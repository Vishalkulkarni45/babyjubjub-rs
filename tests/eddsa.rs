#[cfg(test)]
mod tests {

    use babyjubjub_rs::{
        key::{verify_ecdsa, verify_eff_ecdsa, ECDSAPrivateKey},
        utils::get_eff_ecdsa_args,
    };
    use rand::Rng;

    #[test]
    fn test_new_key_sign_verify_1_ecdsa() {
        for _ in 0..100 {
            let sk = ECDSAPrivateKey::new_key();
            let pk = sk.public_key();

            let mut rng = rand::thread_rng();
            let msg: Vec<u8> = (0..298).map(|_| rng.gen::<u8>()).collect();

            let sig = sk.sign_ecdsa(msg.clone()).unwrap();
            verify_ecdsa(msg.clone(), sig.clone(), pk.clone());
        }
    }

    #[test]
    fn test_new_key_sign_verify_1_eff_ecdsa() {
        let sk = ECDSAPrivateKey::new_key();
        let pk = sk.public_key();

        let mut rng = rand::thread_rng();
        let msg: Vec<u8> = (0..298).map(|_| rng.gen::<u8>() % 128).collect();
        let sig = sk.sign_ecdsa(msg.clone()).unwrap();
        let (t, u) = get_eff_ecdsa_args(msg.clone(), sig.clone());
        verify_eff_ecdsa(sig, t, u, pk);
    }
}
