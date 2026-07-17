#![no_main]
use crypto::Crypto;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    let (priv_key_bytes, plaintext_bytes) = data.split_at(32);

    let Ok(plain_text) = std::str::from_utf8(plaintext_bytes) else {
        return;
    };

    let mut priv_array = [0u8; 32];
    priv_array.copy_from_slice(priv_key_bytes);

    let secret = x25519_dalek::StaticSecret::from(priv_array);
    let public = x25519_dalek::PublicKey::from(&secret);

    let crypto = Crypto::new_native(public.as_bytes(), secret.to_bytes().as_ref())
        .expect("Crypto initialization failed");

    if let Ok(encrypted_base64) = crypto.encrypt_native(plain_text) {
        let decrypt_result = crypto.decrypt_native(&encrypted_base64, 300_000);

        assert!(
            decrypt_result.is_ok(),
            "Valid encrypted data failed to decrypt"
        );

        assert_eq!(
            decrypt_result.unwrap().plain_text,
            plain_text,
            "Decrypted text does not match original"
        );
    }
});
