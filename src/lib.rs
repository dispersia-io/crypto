use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bincode::Options;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use wasm_bindgen::prelude::*;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Serialize, Deserialize)]
struct Payload<'a> {
    timestamp: u64,
    #[serde(borrow)]
    data: Cow<'a, str>,
}

#[wasm_bindgen(getter_with_clone)]
pub struct KeyPair {
    pub public_key: String,
    pub private_key: String,
}

#[wasm_bindgen(getter_with_clone)]
#[derive(Debug)]
pub struct DecryptedMessage {
    pub plain_text: String,
    pub message_id: String,
}

#[wasm_bindgen]
pub struct Crypto {
    public_key: Option<PublicKey>,
    private_key: Option<StaticSecret>,
}

const MAX_PAYLOAD_SIZE: u64 = 10 * 1024 * 1024;

fn format_error(context: &str, error: impl std::fmt::Display) -> String {
    format!("CryptoError: {context} - {error}")
}

fn bincode_config() -> impl bincode::Options {
    bincode::options()
        .with_limit(MAX_PAYLOAD_SIZE)
        .with_fixint_encoding()
        .with_little_endian()
}

#[inline]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn get_current_time_ms() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now() as u64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }
}

impl std::fmt::Debug for Crypto {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Crypto")
            .field("public_key", &self.public_key)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

impl Crypto {
    /// Initializes a new native `Crypto` instance using byte slices for the public and private keys.
    ///
    /// Both keys are optional from a functional perspective but must conform to cryptographic constraints if provided.
    ///
    /// # Errors
    ///
    /// Returns a `String` error representation if:
    /// - The provided `public_key_bytes` slice is populated but its length is not exactly 32 bytes.
    /// - The provided `private_key_bytes` slice is populated but its length is not exactly 32 bytes.
    /// - Fixed-size cryptographic array conversion fails due to anomalous internal constraints.
    pub fn new_native(public_key_bytes: &[u8], private_key_bytes: &[u8]) -> Result<Crypto, String> {
        let valid_pub = public_key_bytes.is_empty() || public_key_bytes.len() == 32;
        let valid_priv = private_key_bytes.is_empty() || private_key_bytes.len() == 32;

        if !valid_pub || !valid_priv {
            return Err(format_error(
                "Initialization failed",
                "Keys must be exactly 32 bytes or empty",
            ));
        }

        let public_key = match public_key_bytes.len() {
            0 => None,
            32 => {
                let array: [u8; 32] = public_key_bytes
                    .try_into()
                    .map_err(|_| "Public key must be exactly 32 bytes".to_string())?;

                Some(PublicKey::from(array))
            }
            _ => unreachable!(),
        };

        let private_key = match private_key_bytes.len() {
            0 => None,
            32 => {
                let array: [u8; 32] = private_key_bytes
                    .try_into()
                    .map_err(|_| "Private key must be exactly 32 bytes".to_string())?;

                Some(StaticSecret::from(array))
            }
            _ => unreachable!(),
        };

        Ok(Crypto {
            public_key,
            private_key,
        })
    }

    /// Encrypts a plaintext string slice using an asymmetric X25519 Diffie-Hellman key exchange and symmetric AES-256-GCM authenticated encryption.
    ///
    /// # Errors
    ///
    /// Returns a `String` error representation if:
    /// - The `public_key` field is missing from the current `Crypto` context.
    /// - Binary serialization of the structural payload fails due to encoding bounds.
    /// - The underlying hardware or software cryptographic layer fails to execute AES-256-GCM encryption.
    pub fn encrypt_native(&self, plain_text: &str) -> Result<String, String> {
        let public_key = self
            .public_key
            .as_ref()
            .ok_or_else(|| format_error("Encryption failed", "Missing public key"))?;

        let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);
        let shared_secret = ephemeral_secret.diffie_hellman(public_key);

        let mut hasher = Sha256::new();
        hasher.update(shared_secret.as_bytes());
        let aes_key_bytes = hasher.finalize();
        let aes_key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let payload = Payload {
            timestamp: get_current_time_ms(),
            data: Cow::Borrowed(plain_text),
        };

        let payload_bytes = bincode_config()
            .serialize(&payload)
            .map_err(|error| format_error("Bincode serialization failed", error))?;

        let cipher = Aes256Gcm::new(aes_key);
        let ciphertext = cipher
            .encrypt(nonce, payload_bytes.as_ref())
            .map_err(|error| format_error("AES encryption failed", error))?;

        let mut final_bytes = Vec::with_capacity(32 + nonce_bytes.len() + ciphertext.len());

        final_bytes.extend_from_slice(ephemeral_public.as_bytes());
        final_bytes.extend_from_slice(&nonce_bytes);
        final_bytes.extend_from_slice(&ciphertext);

        Ok(BASE64.encode(final_bytes))
    }

    /// Decrypts a Base64-encoded encrypted payload using the local asymmetric private key, and validates integrity constraints along with expiration bounds.
    ///
    /// # Errors
    ///
    /// Returns a `String` error representation if:
    /// - The `private_key` field is missing from the current `Crypto` context.
    /// - The input string is not a syntactically valid Base64 sequence.
    /// - The decoded byte array is truncated and lacks the minimum required structure length (44 bytes).
    /// - The symmetric AES-256-GCM authenticated decryption fails (e.g., due to data tampering or key mismatch).
    /// - Deserialization of the decrypted payload bytes fails.
    /// - The message epoch timestamp has exceeded the allowed time-to-live delta bounded by `max_age_ms`.
    /// - The message clock state originates from an invalid temporal future offset.
    pub fn decrypt_native(
        &self,
        encrypted_base64: &str,
        max_age_ms: u64,
    ) -> Result<DecryptedMessage, String> {
        let private_key = self
            .private_key
            .as_ref()
            .ok_or_else(|| format_error("Decryption failed", "Missing private key"))?;

        let final_bytes = BASE64
            .decode(encrypted_base64)
            .map_err(|error| format_error("Base64 decoding failed", error))?;

        if final_bytes.len() < 32 + 12 {
            return Err(format_error("Decryption failed", "Invalid payload length"));
        }

        let (ephemeral_public_bytes, rest) = final_bytes.split_at(32);
        let (nonce_bytes, ciphertext) = rest.split_at(12);

        let ephemeral_public_array: [u8; 32] = ephemeral_public_bytes
            .try_into()
            .map_err(|_| format_error("Decryption failed", "Malformed ephemeral public key"))?;
        let ephemeral_public = PublicKey::from(ephemeral_public_array);

        let shared_secret = private_key.diffie_hellman(&ephemeral_public);

        let mut hasher = Sha256::new();
        hasher.update(shared_secret.as_bytes());
        let aes_key_bytes = hasher.finalize();

        let aes_key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);
        let cipher = Aes256Gcm::new(aes_key);
        let nonce = Nonce::from_slice(nonce_bytes);

        let decrypted_bytes = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|error| format_error("AES decryption failed", error))?;

        let payload: Payload = bincode_config()
            .deserialize(&decrypted_bytes)
            .map_err(|error| format_error("Bincode deserialization failed", error))?;

        let now = get_current_time_ms();

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
            .checked_add(10_000)
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

#[wasm_bindgen]
impl Crypto {
    /// WebAssembly-compatible constructor creating an instance of `Crypto` using key byte arrays.
    ///
    /// # Errors
    ///
    /// Returns a JavaScript string primitive wrapping the initialization failure context if the byte layouts are incorrect.
    #[wasm_bindgen(constructor)]
    pub fn new(public_key_bytes: &[u8], private_key_bytes: &[u8]) -> Result<Crypto, JsValue> {
        Self::new_native(public_key_bytes, private_key_bytes).map_err(|e| JsValue::from_str(&e))
    }

    /// Generates a randomized, cryptographically secure X25519 asymmetric key pair.
    ///
    /// Both keys within the returned structure are serialized as Base64-encoded strings.
    #[must_use]
    #[wasm_bindgen]
    pub fn generate_key_pair() -> KeyPair {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);

        KeyPair {
            private_key: BASE64.encode(secret.to_bytes()),
            public_key: BASE64.encode(public.as_bytes()),
        }
    }

    /// JavaScript binding interacting with `encrypt_native` to process a plaintext payload string.
    ///
    /// # Errors
    ///
    /// Throws a JavaScript exception string if runtime encryption constraints or serialization targets fail.
    pub fn encrypt(&self, plain_text: &str) -> Result<String, JsValue> {
        self.encrypt_native(plain_text)
            .map_err(|e| JsValue::from_str(&e))
    }

    /// JavaScript binding interacting with `decrypt_native` to isolate and decrypt structural targets.
    ///
    /// # Errors
    ///
    /// Throws a JavaScript exception string if signature matching, temporal validations, or decoding pipelines drop errors.
    pub fn decrypt(
        &self,
        encrypted_base64: &str,
        max_age_ms: u64,
    ) -> Result<DecryptedMessage, JsValue> {
        self.decrypt_native(encrypted_base64, max_age_ms)
            .map_err(|e| JsValue::from_str(&e))
    }
}
