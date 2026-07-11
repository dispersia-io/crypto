use base64::Engine;
use crypto::Crypto;
use wasm_bindgen_test::*;

const TEST_PUBLIC_KEY: &str = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=";
const TEST_PRIVATE_KEY: &str = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=";

#[wasm_bindgen_test]
fn test_valid_encryption_decryption() {
    let crypto = Crypto::new(TEST_PUBLIC_KEY, TEST_PRIVATE_KEY).unwrap();
    let plain_text = "Secret message rust";

    let encrypted = crypto.encrypt(plain_text).unwrap();
    assert_ne!(plain_text, encrypted);

    let decrypted = crypto.decrypt(&encrypted, 5000).unwrap().plain_text;
    assert_eq!(plain_text, decrypted);
}

#[wasm_bindgen_test]
fn test_short_payload() {
    let crypto = Crypto::new(TEST_PUBLIC_KEY, TEST_PRIVATE_KEY).unwrap();
    let plain_text = "A";

    let encrypted = crypto.encrypt(plain_text).unwrap();
    let decrypted = crypto.decrypt(&encrypted, 5000).unwrap().plain_text;

    assert_eq!(plain_text, decrypted);
}

#[wasm_bindgen_test]
fn test_long_payload_hybrid_success() {
    let crypto = Crypto::new(TEST_PUBLIC_KEY, TEST_PRIVATE_KEY).unwrap();
    let long_text = "A".repeat(100_000); // ~100 KB

    let encrypted = crypto.encrypt(&long_text).unwrap();
    let decrypted = crypto.decrypt(&encrypted, 5000).unwrap().plain_text;

    assert_eq!(long_text.len(), decrypted.len());
    assert_eq!(long_text, decrypted);
}

#[wasm_bindgen_test]
fn test_tamper_resistance_integrity() {
    let crypto = Crypto::new(TEST_PUBLIC_KEY, TEST_PRIVATE_KEY).unwrap();
    let plain_text = "Crucial financial data: $1000";

    let encrypted_base64 = crypto.encrypt(plain_text).unwrap();
    let mut raw_bytes = base64::engine::general_purpose::STANDARD
        .decode(&encrypted_base64)
        .unwrap();

    let last_idx = raw_bytes.len() - 1;
    raw_bytes[last_idx] ^= 0x01;

    let tampered_base64 = base64::engine::general_purpose::STANDARD.encode(&raw_bytes);
    let result = crypto.decrypt(&tampered_base64, 5000);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .as_string()
        .unwrap()
        .contains("AES decryption failed"));
}

#[wasm_bindgen_test]
fn test_corrupted_base64() {
    let crypto = Crypto::new(TEST_PUBLIC_KEY, TEST_PRIVATE_KEY).unwrap();
    let result = crypto.decrypt("Not_A_Valid_Base64_!!!", 5000);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .as_string()
        .unwrap()
        .contains("Base64 decoding failed"));
}

#[wasm_bindgen_test]
fn test_max_age_expiration() {
    let crypto = Crypto::new(TEST_PUBLIC_KEY, TEST_PRIVATE_KEY).unwrap();
    let encrypted = crypto.encrypt("timeout test").unwrap();

    let result = crypto.decrypt(&encrypted, 0);

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .as_string()
        .unwrap()
        .contains("Payload expired"));
}

#[wasm_bindgen_test]
fn test_invalid_keys_handling() {
    let bad_base64_result = Crypto::new("invalid_base64", TEST_PRIVATE_KEY);
    assert!(bad_base64_result.is_err());
    assert!(bad_base64_result
        .unwrap_err()
        .as_string()
        .unwrap()
        .contains("Public key base64 decoding failed"));

    let bad_length_result = Crypto::new(TEST_PUBLIC_KEY, "AQID");
    assert!(bad_length_result.is_err());
    assert!(bad_length_result
        .unwrap_err()
        .as_string()
        .unwrap()
        .contains("Invalid key length (must be 32 bytes)"));
}

#[wasm_bindgen_test]
fn test_performance() {
    let crypto = Crypto::new(TEST_PUBLIC_KEY, TEST_PRIVATE_KEY).unwrap();
    let plain_text = "Standard message for routing and delivery.";

    let start = js_sys::Date::now();

    let iterations = 200;
    for _ in 0..iterations {
        let encrypted = crypto.encrypt(plain_text).unwrap();
        let _decrypted = crypto.decrypt(&encrypted, 5000).unwrap();
    }

    let elapsed_ms = js_sys::Date::now() - start;

    assert!(
        elapsed_ms < 5000.0,
        "Performance degradation: {} iterations took {} ms",
        iterations,
        elapsed_ms
    );
}
