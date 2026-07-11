import { CryptoError } from './model/error.js';
import {
  type InitOptions,
  type DecryptOptions,
  type ICrypto,
  type DecryptedResult,
  type KeyPairResult,
} from './model/interface.js';
import initWasmModule, { Crypto as WasmCrypto } from './crypto.js';

let wasmInitPromise: Promise<void> | null = null;

export class Crypto implements ICrypto {
  private _wasm: WasmCrypto | null = null;

  private constructor() {}

  private static _initWasm(): Promise<void> {
    return (wasmInitPromise ??= (async () => {
      let wasmModule: BufferSource | undefined = undefined;

      const isNode =
        typeof process !== 'undefined' && !!process.versions && !!process.versions.node;

      if (isNode) {
        try {
          const fs = await import('node:fs/promises');
          const { default: path } = await import('node:path');
          const { fileURLToPath } = await import('node:url');

          const __filename = fileURLToPath(import.meta.url);
          const __dirname = path.dirname(__filename);

          const wasmPath = path.resolve(__dirname, 'crypto_bg.wasm');

          wasmModule = await fs.readFile(wasmPath);
        } catch (error) {
          throw new CryptoError('Failed to read file "crypto_bg.wasm" in Node.js', error);
        }
      }

      await initWasmModule({ module_or_path: wasmModule });
    })());
  }

  public static async init(options: InitOptions): Promise<Crypto> {
    const { publicKey, privateKey } = options;

    if (!publicKey && !privateKey) {
      throw new CryptoError('At least one of the keys is required');
    }

    // eslint-disable-next-line no-console
    if (!publicKey) console.warn('[Crypto.init]: Public key missing. Encryption unavailable');
    // eslint-disable-next-line no-console
    if (!privateKey) console.warn('[Crypto.init]: Private key missing. Decryption unavailable');

    await Crypto._initWasm();

    const crypto = new Crypto();
    crypto._wasm = new WasmCrypto(
      options.publicKey ?? new Uint8Array(0),
      options.privateKey ?? new Uint8Array(0),
    );

    return crypto;
  }

  public static async generateKeyPair(): Promise<KeyPairResult> {
    await Crypto._initWasm();

    const keyPair = WasmCrypto.generate_key_pair();
    const result: KeyPairResult = {
      publicKey: keyPair.public_key,
      privateKey: keyPair.private_key,
    };

    keyPair.free();

    return result;
  }

  public encrypt(data: string): string {
    if (!this._wasm) throw new CryptoError('Crypto is not initialized');
    if (typeof data !== 'string') throw new TypeError('The encrypted data must be stringified');
    return this._wasm.encrypt(data);
  }

  public decrypt(data: string, options: DecryptOptions): DecryptedResult {
    if (!this._wasm) throw new CryptoError('Crypto is not initialized');
    if (typeof data !== 'string') throw new TypeError('The decrypted data must be stringified');
    if (typeof options.maxAgeMs !== 'bigint') throw new TypeError('The max age should be BigInt');

    const decrypted = this._wasm.decrypt(data, options.maxAgeMs);
    const result: DecryptedResult = {
      plainText: decrypted.plain_text,
      messageId: decrypted.message_id,
    };

    decrypted.free();

    return result;
  }
}
