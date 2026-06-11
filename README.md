<div align="center">

# @dispersiajs/crypto

[![Latest Release](https://badgen.net/github/release/dispersia-io/crypto?icon=github&cache=240)](https://github.com/dispersia-io/crypto/releases)
[![CodeQL](https://github.com/dispersia-io/crypto/actions/workflows/codeql.yml/badge.svg)](https://github.com/dispersia-io/crypto/actions/workflows/codeql.yml)
[![Install Size](https://badgen.net/packagephobia/install/@dispersiajs/crypto?color=purple&cache=240)](https://www.npmjs.com/package/@dispersiajs/crypto)
[![License](https://badgen.net/npm/license/@dispersiajs/crypto?color=black&cache=240)](https://github.com/dispersia-io/crypto/blob/main/LICENSE.md)

</div>

A high-performance, isomorphic WebAssembly (WASM) cryptography module responsible for End-to-End (E2E) encryption within the **[Dispersia](https://github.com/dispersia-io)** ecosystem.

Designed specifically for developer-focused API integrations, this library ensures that sensitive message templates, routing data, and delivery payloads (across messengers and task managers) are encrypted client-side and can only be decrypted by authorized endpoints.

## ✨ Core Features

- **Isomorphic Architecture**: Runs seamlessly in both Node.js (CommonJS) and browser environments (ESM) using a unified API.
- **WebAssembly Powered**: Core cryptographic algorithms are written in Rust and compiled to WASM for near-native performance and memory safety.
- **Robust E2E Encryption**: Utilizes industry-standard asymmetric cryptography (RSA-2048/4096) combined with fast symmetric payload encryption.
- **Time-based Validation**: Built-in temporal security to prevent replay attacks and expire old payloads automatically.
- **Zero-Dependency Core**: The compiled WASM binary is self-contained, minimizing the JavaScript bundle size and reducing the attack surface.

## 📦 Installation

```bash
npm install @dispersiajs/crypto
# or
yarn add @dispersiajs/crypto
# or
pnpm add @dispersiajs/crypto
```

## 🚀 Usage

Because the core engine relies on WebAssembly, initialization in modern environments is asynchronous to allow the browser or Node.js to fetch and instantiate the `.wasm` binary properly.

### 1. Initialization & Environment Responsibility Separation

You initialize the crypto instance by providing your PKCS#8 PEM-formatted keys via an options object.

The library is specifically designed to support **environment responsibility separation**. You only need to provide the keys required for the specific environment's role:

- **Encryption-only (`publicKey` only):** Use this in public-facing clients, frontends, or data-ingestion services where payloads are created but should never be read.
- **Decryption-only (`privateKey` only):** Use this in secure, internal background workers or isolated backend services responsible for parsing and routing messages.
- **Bi-directional (`publicKey` & `privateKey`):** Use this when an environment needs full read/write capabilities.

If a method is called without its corresponding key being provided during initialization, a `CryptoError` will be thrown immediately.

```typescript
import { Crypto } from '@dispersiajs/crypto';

// Keys should be securely loaded from your environment variables or key vault
const publicKey = `-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----`;
const privateKey = `-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----`;

async function main() {
  // Example 1: Full bi-directional context
  const crypto = await Crypto.init({ publicKey, privateKey });

  // Example 2: Encryption-only context (Safe for public clients)
  const encryptor = await Crypto.init({ publicKey });
  // encryptor.decrypt(...) -> throws CryptoError: Missing private key

  // Example 3: Decryption-only context (Internal secure workers)
  const decryptor = await Crypto.init({ privateKey });
  // decryptor.encrypt(...) -> throws CryptoError: Missing public key
}
main();
```

### 2. Encrypting Data

Encrypting data requires a valid public key to be present during initialization.

```typescript
const secretPayload = JSON.stringify({
  message: 'Critical system alert',
  timestamp: Date.now(),
});

// Returns a secure, base64-encoded ciphertext string
const encrypted = crypto.encrypt(secretPayload);

console.log('Encrypted:', encrypted);
```

### 3. Decrypting & Validating Data

Decryption requires a valid private key. You must also specify a `max_age_ms` parameter. If the payload is older than this threshold, the decryption will strictly fail, throwing a `CryptoError`.

```typescript
try {
  const decrypted = crypto.decrypt(encrypted, {
    // Allow payloads no older than 60 seconds (60,000 ms)
    maxAgeMs: 60_000,
  });

  console.log('Decrypted:', decrypted);
} catch (error) {
  console.error('Decryption failed:', error.message);
}
```

## 🏗️ Architecture

This repository is split into two main layers:

1. **Rust Core (`/src`)**: Handles the raw mathematical operations, key parsing, and temporal validation. Compiled using `wasm-pack`.
2. **TypeScript Translator (`/translator`)**: A lightweight interoperability layer that provides strong typings, handles the async loading of the WASM binary, and converts Rust `JsValue` panics into standard JavaScript `Error` objects.

## 🛠️ Development & Contributing

We welcome contributions from the community! Please review our standard guidelines before opening a Pull Request.

- **[CONTRIBUTING.md](./CONTRIBUTING.md)**: Detailed instructions on setting up the environment, branching strategy, and conventional commits.
- **[SECURITY.md](./SECURITY.md)**: Guidelines for reporting vulnerabilities.

### Quick Start for Contributors

```bash
# Initialize environment, install deps, and fetch Cargo crates
yarn setup

# Run the full build pipeline (Rust WASM + TypeScript)
yarn build

# Run the test suite (Jest Integration Tests + Rust Unit Tests)
yarn test
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE.md) file for details.
