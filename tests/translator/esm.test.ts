import { Crypto } from '../../dist/esm/index.js';

const TEST_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7fSACXW6R4i1yrCGbZjOMEPEz
UnRXV6ziC/TBFQc6l4hky2JN9usMFgIoWTXbZNI1VTkXIqbzrTQp+CVrNLwlFveP
d3U5g/V1maORezp1pkCLSPIgdO7XA+Mr5mSYS5S6Ic/tXfU7y62bFGsjwwDwFJsF
Qjq4MqWFSsorzK0W7QIDAQAB
-----END PUBLIC KEY-----`;

const TEST_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----`;

describe('Crypto Translator (ESM)', () => {
  describe('Initialization checks', () => {
    it('throws if both keys are completely missing', async () => {
      await expect(Crypto.init({ publicKey: '', privateKey: '' })).rejects.toThrow(
        'At least one of the keys is required',
      );
    });

    it('throws when trying to encrypt without initialization', () => {
      const crypto = new Crypto();
      expect(() => crypto.encrypt('test')).toThrow('Crypto is not initialized');
    });
  });

  describe('Type Validation', () => {
    let crypto: Crypto;

    beforeAll(async () => {
      crypto = await Crypto.init({
        publicKey: TEST_PUBLIC_KEY,
        privateKey: TEST_PRIVATE_KEY,
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
    it('encrypts to base64 and verifies inequality with plaintext', async () => {
      const crypto = await Crypto.init({
        publicKey: TEST_PUBLIC_KEY,
        privateKey: TEST_PRIVATE_KEY,
      });

      const plainText = 'ESM Test Message';
      const encrypted = crypto.encrypt(plainText);

      expect(encrypted).not.toEqual(plainText);
      expect(encrypted.includes(plainText)).toBe(false);

      const base64Regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
      expect(base64Regex.test(encrypted)).toBe(true);
    });
  });
});
