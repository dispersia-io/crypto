import { CryptoError } from './model/error.js';
import {
  type InitOptions,
  type DecryptOptions,
  type ICrypto,
  type KeyPairResult,
  type DecryptedResult,
} from './model/interface.js';
import { Crypto as WasmCrypto } from './crypto.js';

export class Crypto implements ICrypto {
  private _wasm: WasmCrypto | null = null;

  private constructor() {}

  public static init(options: InitOptions): Crypto {
    const { publicKey, privateKey } = options;

    if (!publicKey && !privateKey) {
      throw new CryptoError('At least one of the keys is required');
    }

    // eslint-disable-next-line no-console
    if (!publicKey) console.warn('[Crypto.init]: Public key missing. Encryption unavailable');
    // eslint-disable-next-line no-console
    if (!privateKey) console.warn('[Crypto.init]: Private key missing. Decryption unavailable');

    const crypto = new Crypto();
    crypto._wasm = new WasmCrypto(
      options.publicKey ?? new Uint8Array(0),
      options.privateKey ?? new Uint8Array(0),
    );

    return crypto;
  }

  public static generateKeyPair(): KeyPairResult {
    const keyPair = WasmCrypto.generate_key_pair();
    const result = {
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
