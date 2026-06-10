import { CryptoError } from './model/error.cjs';
import { type InitOptions, type DecryptOptions, type ICrypto } from './model/interface.cjs';
import initWasm, { Crypto as WasmCrypto } from './wasm.js';

export class Crypto implements ICrypto {
  private _wasm: WasmCrypto | null = null;

  constructor() {}

  public static async init(options: InitOptions): Promise<ICrypto> {
    const { publicKey, privateKey } = options;

    if (!publicKey && !privateKey) {
      throw new CryptoError('At least one of the keys is required - public or private.');
    }

    // @ts-ignore
    await initWasm();

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
