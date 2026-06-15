export class CryptoError extends Error {
  constructor(reason: string, original?: unknown) {
    let details: string | undefined;

    if (original instanceof Error) {
      details = original.message;
    } else if (typeof original === 'string') {
      details = original;
    }

    super(details ? `${reason} (${details})` : reason);

    this.name = 'CryptoError';
  }
}
