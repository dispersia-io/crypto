use base64::Engine;
use crypto::Crypto;
use wasm_bindgen_test::*;

const PUBLIC_KEY_BASE64: &str = "HFgjF7vWprdXpDt3W4QJXX382auktMbEzHdZTCt2PTk=";
const PRIVATE_KEY_BASE64: &str = "wZ6RKIt5VTVAvcLHS2vf3qXYs0teYsMj2welcJvAb6Y=";

fn get_test_keys() -> (Vec<u8>, Vec<u8>) {
    (
        base64::engine::general_purpose::STANDARD
            .decode(PUBLIC_KEY_BASE64)
            .unwrap(),
        base64::engine::general_purpose::STANDARD
            .decode(PRIVATE_KEY_BASE64)
            .unwrap(),
    )
}

#[wasm_bindgen_test]
fn test_generate_key_pair() {
    let keys = Crypto::generate_key_pair();

    assert!(!keys.public_key.is_empty());
    assert!(!keys.private_key.is_empty());

    let pub_bytes = base64::engine::general_purpose::STANDARD
        .decode(&keys.public_key)
        .unwrap();
    let priv_bytes = base64::engine::general_purpose::STANDARD
        .decode(&keys.private_key)
        .unwrap();

    assert_eq!(pub_bytes.len(), 32);
    assert_eq!(priv_bytes.len(), 32);

    let crypto = Crypto::new(&pub_bytes, &priv_bytes).unwrap();
    let encrypted = crypto.encrypt("test").unwrap();
    assert!(crypto.decrypt(&encrypted, 5000).is_ok());
}

#[wasm_bindgen_test]
fn test_valid_encryption_decryption() {
    let (pub_bytes, priv_bytes) = get_test_keys();
    let crypto = Crypto::new(&pub_bytes, &priv_bytes).unwrap();
    let plain_text = "Secret message rust";

    let encrypted = crypto.encrypt(plain_text).unwrap();
    assert_ne!(plain_text, encrypted);

    let decrypted = crypto.decrypt(&encrypted, 5000).unwrap();
    assert_eq!(plain_text, decrypted.plain_text);
    assert!(!decrypted.message_id.is_empty());
}

#[wasm_bindgen_test]
fn test_short_payload() {
    let (pub_bytes, priv_bytes) = get_test_keys();
    let crypto = Crypto::new(&pub_bytes, &priv_bytes).unwrap();
    let plain_text = "A";

    let encrypted = crypto.encrypt(plain_text).unwrap();
    let decrypted = crypto.decrypt(&encrypted, 5000).unwrap().plain_text;

    assert_eq!(plain_text, decrypted);
}

#[wasm_bindgen_test]
fn test_long_payload_hybrid_success() {
    let (pub_bytes, priv_bytes) = get_test_keys();
    let crypto = Crypto::new(&pub_bytes, &priv_bytes).unwrap();
    let long_text = "A".repeat(100_000); // ~100 KB

    let encrypted = crypto.encrypt(&long_text).unwrap();
    let decrypted = crypto.decrypt(&encrypted, 5000).unwrap().plain_text;

    assert_eq!(long_text.len(), decrypted.len());
    assert_eq!(long_text, decrypted);
}

#[wasm_bindgen_test]
fn test_tamper_resistance_integrity() {
    let (pub_bytes, priv_bytes) = get_test_keys();
    let crypto = Crypto::new(&pub_bytes, &priv_bytes).unwrap();
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
fn test_corrupted_base64_payload() {
    let (pub_bytes, priv_bytes) = get_test_keys();
    let crypto = Crypto::new(&pub_bytes, &priv_bytes).unwrap();
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
    let (pub_bytes, priv_bytes) = get_test_keys();
    let crypto = Crypto::new(&pub_bytes, &priv_bytes).unwrap();
    let encrypted = crypto.encrypt("timeout test").unwrap();

    let result = crypto.decrypt(&encrypted, 0); // 0 ms max age -> протух моментально

    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .as_string()
        .unwrap()
        .contains("Payload expired"));
}

#[wasm_bindgen_test]
fn test_invalid_keys_handling() {
    let bad_length_pub = vec![0u8; 15];
    let bad_length_priv = vec![0u8; 15];

    let bad_length_result = Crypto::new(&bad_length_pub, &bad_length_priv);

    assert!(bad_length_result.is_err());
    assert!(bad_length_result
        .unwrap_err()
        .as_string()
        .unwrap()
        .contains("Invalid key length"));
}

#[wasm_bindgen_test]
fn test_private_key_redacted_in_debug() {
    let pub_bytes = vec![0u8; 32];
    let priv_bytes = vec![1u8; 32];

    let crypto =
        Crypto::new(&pub_bytes, &priv_bytes).expect("Crypto should initialize with 32-byte keys");

    let debug_str = format!("{:?}", crypto);

    assert!(
        debug_str.contains("public_key"),
        "Debug output should contain public_key field"
    );

    assert!(
        debug_str.contains("private_key: \"[REDACTED]\""),
        "Debug output MUST redact the private key"
    );

    assert!(
        !debug_str.contains("1, 1, 1"),
        "CRITICAL: Actual private key bytes leaked into Debug output!"
    );
}

#[wasm_bindgen_test]
fn test_performance() {
    let (pub_bytes, priv_bytes) = get_test_keys();
    let crypto = Crypto::new(&pub_bytes, &priv_bytes).unwrap();
    let plain_text = "Standard message for routing and delivery.";

    let start = js_sys::Date::now();

    let iterations = 200;
    for _ in 0..iterations {
        let encrypted = crypto.encrypt(plain_text).unwrap();
        let _decrypted = crypto.decrypt(&encrypted, 5000).unwrap();
    }

    let elapsed_ms = js_sys::Date::now() - start;

    assert!(
        elapsed_ms < 1000.0,
        "Performance degradation: {} iterations took {} ms",
        iterations,
        elapsed_ms
    );
}
