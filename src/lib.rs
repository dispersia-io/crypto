use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use sha2::Sha256;
use rsa::{RsaPublicKey, RsaPrivateKey, Oaep};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::rngs::OsRng;

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
            Some(RsaPublicKey::from_public_key_pem(public_key_pem)
                .map_err(|error| format_error("Public key decoding failed", error))?)
        };

        let private_key = if private_key_pem.trim().is_empty() {
            None
        } else {
            Some(RsaPrivateKey::from_pkcs8_pem(private_key_pem)
                .map_err(|error| format_error("Private key decoding failed", error))?)
        };

        Ok(Crypto { public_key, private_key })
    }

    pub fn encrypt(&self, plain_text: &str) -> Result<String, JsValue> {
        let public_key = self.public_key.as_ref().ok_or_else(|| {
            format_error("Encryption failed", "Missing public key")
        })?;

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
        let private_key = self.private_key.as_ref().ok_or_else(|| {
            format_error("Decryption failed", "Missing private key")
        })?;

        let encrypted_bytes = BASE64.decode(encrypted_base64)
            .map_err(|error| format_error("Base64 decoding failed", error))?;

        let decrypted_bytes = private_key
            .decrypt(Oaep::new::<Sha256>(), &encrypted_bytes)
            .map_err(|error| format_error("RSA decryption failed", error))?;

        let payload: PayloadOwned = serde_json::from_slice(&decrypted_bytes)
            .map_err(|error| format_error("Payload deserialization failed", error))?;

        let now = js_sys::Date::now() as u64;

        if now > payload.timestamp + max_age_ms {
            return Err(format_error("Validation failed", "Payload expired (exceeds max age limit)"));
        }

        if payload.timestamp > now + 10000 {
            return Err(format_error("Validation failed", "Payload timestamp is from the future"));
        }

        Ok(payload.data)
    }
}
