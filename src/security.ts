export class ToolError extends Error {
  constructor(readonly code: string, message: string) { super(message); }
}

export class Redactor {
  private readonly values = new Set<string>();

  register(secret: string): void {
    for (const value of [secret, JSON.stringify(secret).slice(1, -1), encodeURIComponent(secret)]) {
      if (value) this.values.add(value);
    }
  }

  text(text: string): string {
    for (const value of [...this.values].sort((a, b) => b.length - a.length)) text = text.split(value).join('[REDACTED]');
    return text;
  }

  payload(value: unknown): unknown {
    if (typeof value === 'string') return this.text(value).replace(/-----BEGIN [\s\S]*?-----END [^-]+-----/g, '[REDACTED]')
      .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[REDACTED]')
      .replace(/(?:AccountKey|sig)=[^\s;&]+/gi, '[REDACTED]');
    if (Array.isArray(value)) return value.map(item => this.payload(item));
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) =>
      [key, /^(?:api[-_]?key|authorization|password|passphrase|token|accessToken|refreshToken|clientSecret|privateKey)$/i.test(key) ? '[REDACTED]' : this.payload(item)]));
    return value;
  }
}
