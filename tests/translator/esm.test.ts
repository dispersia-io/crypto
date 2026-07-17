/* eslint-disable @typescript-eslint/no-unsafe-return */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unsafe-argument */
import { Buffer } from 'node:buffer';
import { Crypto } from '../../dist/esm/index.js';

describe('Crypto Translator (ESM)', () => {
  const PUBLIC_KEY_BASE64 = 'HFgjF7vWprdXpDt3W4QJXX382auktMbEzHdZTCt2PTk=';
  const PRIVATE_KEY_BASE64 = 'wZ6RKIt5VTVAvcLHS2vf3qXYs0teYsMj2welcJvAb6Y=';

  const PUBLIC_KEY = new Uint8Array(Buffer.from(PUBLIC_KEY_BASE64, 'base64'));
  const PRIVATE_KEY = new Uint8Array(Buffer.from(PRIVATE_KEY_BASE64, 'base64'));

  describe('Key Generation & Initialization', () => {
    it('generates valid key pair', async () => {
      const keys = await Crypto.generateKeyPair();

      expect(keys.publicKey).toBeDefined();
      expect(keys.privateKey).toBeDefined();
    });

    it('initializes from bytes properly and keeps them immutable', async () => {
      const mockPublicKey = new Uint8Array(32).fill(1);
      const mockPrivateKey = new Uint8Array(32).fill(2);

      const crypto = await Crypto.init({
        publicKey: mockPublicKey,
        privateKey: mockPrivateKey,
      });

      expect(crypto).toBeInstanceOf(Crypto);

      expect(mockPublicKey[0]).toBe(1);
      expect(mockPrivateKey[0]).toBe(2);
    });
  });

  describe('Initialization checks', () => {
    it('throws if both keys are completely missing', async () => {
      const crypto = Crypto.init({ publicKey: undefined, privateKey: undefined });
      await expect(crypto).rejects.toThrow('At least one of the keys is required');
    });

    it('throws when trying to encrypt without initialization', () => {
      const crypto = new (Crypto as any)();
      expect(() => crypto.encrypt('test')).toThrow('Crypto is not initialized');
    });

    it('prevents multiple Wasm initializations', async () => {
      const config = { publicKey: PUBLIC_KEY, privateKey: PRIVATE_KEY };

      const promise1 = Crypto.init(config);
      const promise2 = Crypto.init(config);

      expect(promise1).toEqual(promise2);

      await Promise.all([promise1, promise2]);
    });
  });

  describe('Type Validation', () => {
    let crypto: Crypto;

    beforeAll(async () => {
      crypto = await Crypto.init({
        publicKey: PUBLIC_KEY,
        privateKey: PRIVATE_KEY,
      });
    });

    it('throws if data for encryption is not a string', () => {
      expect(() => crypto.encrypt(123 as any)).toThrow(TypeError);
      expect(() => crypto.encrypt({ foo: 'bar' } as any)).toThrow(TypeError);
    });

    it('throws if data for decryption is not a string', () => {
      expect(() => crypto.decrypt(123 as any, { maxAgeMs: 1000n })).toThrow(TypeError);
    });

    it('throws if maxAgeMs is not a BigInt', () => {
      expect(() => crypto.decrypt('some_data', { maxAgeMs: 1000 as any })).toThrow(TypeError);
    });
  });

  describe('Integration & Output Formatting', () => {
    it('encrypts to base64, verifies inequality, and decrypts returning plainText and messageId', async () => {
      const crypto = await Crypto.init({
        publicKey: PUBLIC_KEY,
        privateKey: PRIVATE_KEY,
      });

      const plainText = 'ESM Test Message';
      const encrypted = crypto.encrypt(plainText);

      expect(encrypted).not.toEqual(plainText);
      expect(encrypted.includes(plainText)).toBe(false);

      const base64Regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
      expect(base64Regex.test(encrypted)).toBe(true);

      const decrypted = crypto.decrypt(encrypted, { maxAgeMs: 5000n });
      expect(decrypted.plainText).toEqual(plainText);
      expect(typeof decrypted.messageId).toBe('string');
      expect(decrypted.messageId.length).toBeGreaterThan(0);
    });
  });
});
