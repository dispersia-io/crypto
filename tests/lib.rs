use base64::Engine;
use crypto::Crypto;
use wasm_bindgen_test::*;

const TEST_PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7fSACXW6R4i1yrCGbZjOMEPEz
UnRXV6ziC/TBFQc6l4hky2JN9usMFgIoWTXbZNI1VTkXIqbzrTQp+CVrNLwlFveP
d3U5g/V1maORezp1pkCLSPIgdO7XA+Mr5mSYS5S6Ic/tXfU7y62bFGsjwwDwFJsF
Qjq4MqWFSsorzK0W7QIDAQAB
-----END PUBLIC KEY-----"#;

const TEST_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALt9IAJdbpHiLXKs
IZtmM4wQ8TNSdFdXrOIL9MEVBzqXiGTLYk326wwWAihZNdtk0jVVORcipvOtNCn4
JWs0vCUW9493dTmD9XWZo5F7OnWmQItI8iB07tcD4yvmZJhLlLohz+1d9TvLrZsU
ayPDAPAUmwVCOrgypYVKyivMrRbtAgMBAAECgYAEGARV6OJcLxsc8OM++GlRuqD5
pOhDa/era+VpPeNNhTeGM+aumyCgv+5GIUSKyNXKMlUvyyLoGTUVYYS3pYwiHZGk
rViayZwWOkCkR3JF7VIWdwaV4INLxYK6kgLvmQSawwOpC+J9vofCIbXjkUn4EEIX
LX+cwSBRX5cOaza45QJBAPQds64BQy1xU4D+IUdot3CmlxVb26UOpivBmAWcTB7z
5dZXmQW0MtXpAsy8zvLLlDpdvmztz9Pu9heD5P1aPzcCQQDEnbScUiCE32Yx5Nnq
A/Ipbw6oZaBjnOAEljQJTRuzqI+qvvuDzvc+2LEQCmm2WfgqtwbcrDbF7FFRnCUh
DcT7AkAaou8LKooY+EejSJd7AjsZ6KONqhNCZGHPXnVnD1HjArvucmp5C9uMKbur
eWKfbYVEBRyVKDHIL0fc8wBWgLVrAkAxRS/oaHA7u9vZLvcovHpnxavPqT/rFnnQ
zG8X0ZnaiKgP6rIOksPEnPqqAWICT0NwONNgY0uKh7DNGar4QIIXAkEA11w64v4v
SM0HB6DVzSn9BJmJP5iziSO7LidmC+EZD2neOEM5IX8xuytlLFcoZZdbKVI6TRzG
psWxW49+Me+bww==
-----END PRIVATE KEY-----"#;

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
    let public_key_result = Crypto::new("invalid_public_key", TEST_PRIVATE_KEY);
    assert!(public_key_result.is_err());
    assert!(public_key_result
        .unwrap_err()
        .as_string()
        .unwrap()
        .contains("Public key decoding failed"));

    let private_key_result = Crypto::new(TEST_PUBLIC_KEY, "invalid_private_key");
    assert!(private_key_result.is_err());
    assert!(private_key_result
        .unwrap_err()
        .as_string()
        .unwrap()
        .contains("Private key decoding failed"));
}

#[wasm_bindgen_test]
fn test_performance() {
    let crypto = Crypto::new(TEST_PUBLIC_KEY, TEST_PRIVATE_KEY).unwrap();
    let plain_text = "Standard message for routing and delivery.";

    let start = js_sys::Date::now();

    let iterations = 50;
    for _ in 0..iterations {
        let encrypted = crypto.encrypt(plain_text).unwrap();
        let _decrypted = crypto.decrypt(&encrypted, 5000).unwrap();
    }

    let elapsed_ms = js_sys::Date::now() - start;

    assert!(
        elapsed_ms < 10000.0,
        "Performance degradation: {} iterations took {} ms",
        iterations,
        elapsed_ms
    );
}
