export type InitOptions = {
  publicKey?: string;
  privateKey?: string;
};

export type DecryptOptions = {
  maxAgeMs: bigint;
};

export interface ICrypto {
  encrypt(data: string): string;
  decrypt(data: string, options: DecryptOptions): string;
}
