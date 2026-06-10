use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::rngs::OsRng;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use wasm_bindgen::prelude::*;

#[derive(Serialize)]
struct PayloadRef<'a> {
    timestamp: u64,
    data: &'a str,
}

#[derive(Deserialize)]
struct PayloadOwned {
    timestamp: u64,
    data: String,
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct Crypto {
    public_key: Option<RsaPublicKey>,
    private_key: Option<RsaPrivateKey>,
}

fn format_error(context: &str, error: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&format!("CryptoError: {} - {}", context, error))
}

#[wasm_bindgen]
impl Crypto {
    #[wasm_bindgen(constructor)]
    pub fn new(public_key_pem: &str, private_key_pem: &str) -> Result<Crypto, JsValue> {
        let public_key = if public_key_pem.trim().is_empty() {
            None
        } else {
            Some(
                RsaPublicKey::from_public_key_pem(public_key_pem)
                    .map_err(|error| format_error("Public key decoding failed", error))?,
            )
        };

        let private_key = if private_key_pem.trim().is_empty() {
            None
        } else {
            Some(
                RsaPrivateKey::from_pkcs8_pem(private_key_pem)
                    .map_err(|error| format_error("Private key decoding failed", error))?,
            )
        };

        Ok(Crypto {
            public_key,
            private_key,
        })
    }

    pub fn encrypt(&self, plain_text: &str) -> Result<String, JsValue> {
        let public_key = self
            .public_key
            .as_ref()
            .ok_or_else(|| format_error("Encryption failed", "Missing public key"))?;

        let now = js_sys::Date::now() as u64;

        let payload = PayloadRef {
            timestamp: now,
            data: plain_text,
        };

        let payload_bytes = serde_json::to_vec(&payload)
            .map_err(|error| format_error("Payload serialization failed", error))?;

        let encrypted_bytes = public_key
            .encrypt(&mut OsRng, Oaep::new::<Sha256>(), &payload_bytes)
            .map_err(|error| format_error("RSA encryption failed", error))?;

        Ok(BASE64.encode(encrypted_bytes))
    }

    pub fn decrypt(&self, encrypted_base64: &str, max_age_ms: u64) -> Result<String, JsValue> {
        let private_key = self
            .private_key
            .as_ref()
            .ok_or_else(|| format_error("Decryption failed", "Missing private key"))?;

        let encrypted_bytes = BASE64
            .decode(encrypted_base64)
            .map_err(|error| format_error("Base64 decoding failed", error))?;

        let decrypted_bytes = private_key
            .decrypt(Oaep::new::<Sha256>(), &encrypted_bytes)
            .map_err(|error| format_error("RSA decryption failed", error))?;

        let payload: PayloadOwned = serde_json::from_slice(&decrypted_bytes)
            .map_err(|error| format_error("Payload deserialization failed", error))?;

        let now = js_sys::Date::now() as u64;

        let is_expired = payload
            .timestamp
            .checked_add(max_age_ms)
            .map_or(true, |expiry_time| now > expiry_time);

        if is_expired {
            return Err(format_error(
                "Validation failed",
                "Payload expired (exceeds max age limit)",
            ));
        }

        let is_future = now
            .checked_add(10000)
            .map_or(true, |future_limit| payload.timestamp > future_limit);

        if is_future {
            return Err(format_error(
                "Validation failed",
                "Payload timestamp is from the future",
            ));
        }

        Ok(payload.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert_ne!(
            plain_text, encrypted,
            "Encrypted text should not equal plain text"
        );

        let decoded_base64 = base64::engine::general_purpose::STANDARD.decode(&encrypted);
        assert!(
            decoded_base64.is_ok(),
            "Encrypted text must be valid Base64"
        );

        let decrypted = crypto.decrypt(&encrypted, 5000).unwrap();
        assert_eq!(plain_text, decrypted, "Decrypted text must match original");
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
}
