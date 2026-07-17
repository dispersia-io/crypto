#![no_main]
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use crypto::Crypto;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    let (priv_key_bytes, garbage_bytes) = data.split_at(32);

    let mut priv_array = [0u8; 32];
    priv_array.copy_from_slice(priv_key_bytes);

    let secret = x25519_dalek::StaticSecret::from(priv_array);
    let public = x25519_dalek::PublicKey::from(&secret);

    if let Ok(crypto) = Crypto::new_native(public.as_bytes(), secret.to_bytes().as_ref()) {
        if let Ok(invalid_b64_str) = std::str::from_utf8(garbage_bytes) {
            let _ = crypto.decrypt_native(invalid_b64_str, 60_000);
        }

        let b64_garbage = BASE64.encode(garbage_bytes);
        let _ = crypto.decrypt_native(&b64_garbage, 60_000);
    }
});
