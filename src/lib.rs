use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bincode::Options;
use rand::{rngs::OsRng, RngCore};
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    traits::PublicKeyParts,
    Oaep, RsaPrivateKey, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::borrow::Cow;
use wasm_bindgen::prelude::*;

#[derive(Serialize, Deserialize)]
struct Payload<'a> {
    timestamp: u64,
    #[serde(borrow)]
    data: Cow<'a, str>,
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Debug)]
pub struct DecryptedMessage {
    pub plain_text: String,
    pub message_id: String,
}

#[wasm_bindgen]
#[derive(Debug)]
pub struct Crypto {
    public_key: Option<RsaPublicKey>,
    private_key: Option<RsaPrivateKey>,
}

const MAX_PAYLOAD_SIZE: u64 = 10 * 1024 * 1024;

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

        let mut aes_key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut aes_key_bytes);
        let aes_key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let now = js_sys::Date::now() as u64;

        let payload = Payload {
            timestamp: now,
            data: Cow::Borrowed(plain_text),
        };

        let payload_bytes = bincode::options()
            .with_limit(MAX_PAYLOAD_SIZE)
            .serialize(&payload)
            .map_err(|error| format_error("Bincode serialization failed", error))?;

        let cipher = Aes256Gcm::new(aes_key);
        let ciphertext = cipher
            .encrypt(nonce, payload_bytes.as_ref())
            .map_err(|error| format_error("AES encryption failed", error))?;

        let rsa_encrypted_key = public_key
            .encrypt(&mut OsRng, Oaep::new::<Sha256>(), &aes_key_bytes)
            .map_err(|error| format_error("RSA encryption failed", error))?;

        let mut final_bytes =
            Vec::with_capacity(rsa_encrypted_key.len() + nonce_bytes.len() + ciphertext.len());

        final_bytes.extend_from_slice(&rsa_encrypted_key);
        final_bytes.extend_from_slice(&nonce_bytes);
        final_bytes.extend_from_slice(&ciphertext);

        Ok(BASE64.encode(final_bytes))
    }

    pub fn decrypt(
        &self,
        encrypted_base64: &str,
        max_age_ms: u64,
    ) -> Result<DecryptedMessage, JsValue> {
        let private_key = self
            .private_key
            .as_ref()
            .ok_or_else(|| format_error("Decryption failed", "Missing private key"))?;

        let final_bytes = BASE64
            .decode(encrypted_base64)
            .map_err(|error| format_error("Base64 decoding failed", error))?;

        let rsa_len = private_key.size();

        if final_bytes.len() < rsa_len + 12 {
            return Err(format_error("Decryption failed", "Invalid payload length"));
        }

        let (rsa_encrypted_key, rest) = final_bytes.split_at(rsa_len);
        let (nonce_bytes, ciphertext) = rest.split_at(12);

        let aes_key_bytes = private_key
            .decrypt(Oaep::new::<Sha256>(), rsa_encrypted_key)
            .map_err(|error| format_error("RSA decryption failed", error))?;

        if aes_key_bytes.len() != 32 {
            return Err(format_error(
                "Decryption failed",
                "Invalid AES key size extracted",
            ));
        }

        let aes_key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);
        let cipher = Aes256Gcm::new(aes_key);
        let nonce = Nonce::from_slice(nonce_bytes);

        let decrypted_bytes = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|error| format_error("AES decryption failed", error))?;

        let payload: Payload = bincode::options()
            .with_limit(MAX_PAYLOAD_SIZE)
            .deserialize(&decrypted_bytes)
            .map_err(|error| format_error("Bincode deserialization failed", error))?;

        let now = js_sys::Date::now() as u64;

        let is_expired = payload
            .timestamp
            .checked_add(max_age_ms)
            .is_none_or(|expiry_time| now > expiry_time);

        if is_expired {
            return Err(format_error(
                "Validation failed",
                "Payload expired (exceeds max age limit)",
            ));
        }

        let is_future = now
            .checked_add(10000)
            .is_none_or(|future_limit| payload.timestamp > future_limit);

        if is_future {
            return Err(format_error(
                "Validation failed",
                "Payload timestamp is from the future",
            ));
        }

        Ok(DecryptedMessage {
            plain_text: payload.data.into_owned(),
            message_id: BASE64.encode(nonce_bytes),
        })
    }
}
