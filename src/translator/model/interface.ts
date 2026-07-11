export type InitOptions = {
  publicKey?: Uint8Array;
  privateKey?: Uint8Array;
};

export type KeyPairResult = {
  publicKey: string;
  privateKey: string;
};

export type DecryptOptions = {
  maxAgeMs: bigint;
};

export type DecryptedResult = {
  plainText: string;
  messageId: string;
};

export interface ICrypto {
  encrypt(data: string): string;
  decrypt(data: string, options: DecryptOptions): DecryptedResult;
}
