import { CryptoError } from './model/error.js';
import { type InitOptions, type DecryptOptions, type ICrypto } from './model/interface.js';
import initWasm, { Crypto as WasmCrypto } from './wasm.js';

export class Crypto implements ICrypto {
  private _wasm: WasmCrypto | null = null;

  constructor() {}

  public static async init(options: InitOptions): Promise<Crypto> {
    const { publicKey, privateKey } = options;

    if (!publicKey && !privateKey) {
      throw new CryptoError('At least one of the keys is required - public or private.');
    }

    let wasmBytes: BufferSource | undefined = undefined;

    const isNode = typeof process !== 'undefined' && !!process.versions && !!process.versions.node;

    if (isNode) {
      try {
        const fs = await import('node:fs/promises');
        const path = await import('node:path');
        const { fileURLToPath } = await import('node:url');

        const __filename = fileURLToPath(import.meta.url);
        const __dirname = path.dirname(__filename);

        const wasmPath = path.resolve(__dirname, 'wasm_bg.wasm');

        wasmBytes = await fs.readFile(wasmPath);
      } catch (error) {
        throw new CryptoError('Failed to read local WASM file in Node.js environment.');
      }
    }

    // @ts-ignore
    await initWasm(wasmBytes);

    if (!publicKey) {
      console.warn('[Crypto.init]: Public key missing. Encryption unavailable.');
    }

    if (!privateKey) {
      console.warn('[Crypto.init]: Private key missing. Decryption unavailable.');
    }

    const crypto = new Crypto();
    crypto._wasm = new WasmCrypto(publicKey ?? '', privateKey ?? '');

    return crypto;
  }

  public encrypt(data: string): string {
    if (!this._wasm) {
      throw new CryptoError('Crypto is not initialized');
    }

    if (typeof data !== 'string') {
      throw new TypeError('The encrypted data must be stringified');
    }

    return this._wasm.encrypt(data);
  }

  public decrypt(data: string, options: DecryptOptions): string {
    const { maxAgeMs } = options;

    if (!this._wasm) {
      throw new CryptoError('Crypto is not initialized');
    }

    if (typeof data !== 'string') {
      throw new TypeError('The decrypted data must be stringified');
    }

    if (typeof maxAgeMs !== 'bigint') {
      throw new TypeError('The max age should be BigInt');
    }

    return this._wasm.decrypt(data, maxAgeMs);
  }
}
