export class CryptoError extends Error {
  constructor(error: string) {
    super(error);

    this.name = 'CryptoError';
  }
}
