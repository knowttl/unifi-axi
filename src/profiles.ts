import { homedir } from 'node:os';
import { isAbsolute, join, win32 } from 'node:path';
import { isIP } from 'node:net';
import { X509Certificate } from 'node:crypto';
import { PrivateFiles } from './private-file.js';
import { Redactor, ToolError } from './security.js';

export type SecretRef = { env: string } | { file: string };
export interface Profile {
  origin: string;
  apiKey: SecretRef;
  siteId?: string;
  apiContract?: string;
  tls?: { trustedCertificatePem: string; peerFingerprintSha256: string; connectAddress?: string };
  writes?: { allowWrites: boolean; operations: string[] };
}
interface Config { version: 1; defaultProfile?: string; profiles: Record<string, Profile> }
export interface Selection { name: string; source: string; profile: Profile }
const profileName = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const fields = ['origin', 'apiKey', 'siteId', 'apiContract', 'tls', 'writes'];

function invalid(message: string): never { throw new ToolError('CONFIG_INVALID', message); }
function object(value: unknown, keys: string[], label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !keys.includes(key))) invalid(`Invalid ${label} object or unknown field.`);
  return value as Record<string, unknown>;
}
function json(text: string): unknown {
  try { return JSON.parse(text.replace(/^\uFEFF/, '')); } catch { return invalid('Invalid configuration JSON.'); }
}

export function validateProfile(value: unknown, platform = process.platform): Profile {
  const data = object(value, fields, 'profile');
  if (typeof data.origin !== 'string') invalid('origin must be an HTTPS origin.');
  let origin: URL;
  try { origin = new URL(data.origin); } catch { return invalid('origin must be an HTTPS origin.'); }
  if (origin.protocol !== 'https:' || origin.username || origin.password || origin.pathname !== '/' || origin.search || origin.hash ||
      !/^https:\/\/[^/?#]+\/?$/.test(data.origin)) invalid('origin must be an HTTPS origin without user information, path, query or fragment.');
  const ref = object(data.apiKey === undefined ? { env: 'UNIFI_AXI_API_KEY' } : data.apiKey, ['env', 'file'], 'apiKey SecretRef');
  if (Object.keys(ref).length !== 1) invalid('apiKey must be exactly one env or file SecretRef.');
  if ('env' in ref) {
    if (typeof ref.env !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(ref.env)) invalid('Invalid apiKey environment reference.');
  } else if (typeof ref.file !== 'string' || (platform === 'win32' ? !/^[A-Za-z]:[\\/]/.test(ref.file) || !win32.isAbsolute(ref.file) : !isAbsolute(ref.file))) {
    invalid('apiKey file must be an absolute local path; Windows UNC and device paths are refused.');
  }
  if (data.siteId !== undefined && (typeof data.siteId !== 'string' || !data.siteId)) invalid('siteId must be a nonempty string.');
  if (data.apiContract !== undefined && (typeof data.apiContract !== 'string' || !['10.6.109', '11.0.97'].includes(data.apiContract))) invalid('Unsupported apiContract.');
  if (data.writes !== undefined) {
    const writes = object(data.writes, ['allowWrites', 'operations'], 'writes');
    if (typeof writes.allowWrites !== 'boolean' || !Array.isArray(writes.operations) || writes.operations.some(op => typeof op !== 'string' || !/^OP-\d{3}$/.test(op))) invalid('writes requires allowWrites and an operations array of operation IDs.');
  }
  if (data.tls !== undefined) {
    const tls = object(data.tls, ['trustedCertificatePem', 'peerFingerprintSha256', 'connectAddress'], 'tls');
    if (typeof tls.trustedCertificatePem !== 'string' || typeof tls.peerFingerprintSha256 !== 'string' ||
        !/^[a-fA-F0-9]{64}$/.test(tls.peerFingerprintSha256) ||
        !/^\s*-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*$/.test(tls.trustedCertificatePem)) invalid('tls requires one public certificate and a SHA-256 fingerprint.');
    let certificate: X509Certificate;
    try { certificate = new X509Certificate(tls.trustedCertificatePem); } catch { return invalid('Invalid TLS certificate.'); }
    if (certificate.fingerprint256.replaceAll(':', '').toLowerCase() !== tls.peerFingerprintSha256.toLowerCase()) invalid('TLS certificate fingerprint does not match.');
    if (tls.connectAddress !== undefined && (typeof tls.connectAddress !== 'string' || !isIP(tls.connectAddress))) invalid('tls.connectAddress must be an IP address.');
  }
  return { ...data, origin: origin.origin, apiKey: ref } as unknown as Profile;
}

export function configPath(explicit?: string, env = process.env, platform = process.platform): string {
  const supplied = explicit ?? env.UNIFI_AXI_CONFIG;
  if (supplied) {
    if (!isAbsolute(supplied)) invalid('Configuration path must be absolute.');
    return supplied;
  }
  if (platform === 'win32') {
    if (!env.APPDATA || !win32.isAbsolute(env.APPDATA)) invalid('APPDATA must be an absolute path.');
    return win32.join(env.APPDATA, 'unifi-axi', 'config.json');
  }
  return join(env.XDG_CONFIG_HOME && isAbsolute(env.XDG_CONFIG_HOME) ? env.XDG_CONFIG_HOME : join(homedir(), '.config'), 'unifi-axi', 'config.json');
}

export class Profiles {
  constructor(readonly path: string, private readonly files = new PrivateFiles(), private readonly env = process.env) {}

  private async load(verifyAcl = false): Promise<Config> {
    let text: string;
    try { text = await this.files.read(this.path, false, verifyAcl); } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { version: 1, profiles: {} };
      throw error;
    }
    const data = object(json(text), ['version', 'defaultProfile', 'profiles'], 'config');
    if (data.version !== 1) invalid('Configuration version must be 1.');
    if (!data.profiles || typeof data.profiles !== 'object' || Array.isArray(data.profiles)) invalid('profiles must be an object.');
    const profiles = Object.fromEntries(Object.entries(data.profiles).map(([name, profile]) => {
      if (!profileName.test(name)) invalid('Invalid profile name.');
      return [name, validateProfile(profile)];
    }));
    if (data.defaultProfile !== undefined && (typeof data.defaultProfile !== 'string' || !Object.hasOwn(profiles, data.defaultProfile))) invalid('defaultProfile must name an existing profile.');
    return { version: 1, profiles, ...(data.defaultProfile !== undefined ? { defaultProfile: data.defaultProfile as string } : {}) };
  }

  async list(): Promise<string[]> { return Object.keys((await this.load()).profiles); }

  async select(explicit?: string, verifyAcl = false): Promise<Selection> {
    const readOnly = this.env.UNIFI_AXI_READ_ONLY;
    if (readOnly !== undefined && !/^(1|0|true|false)$/i.test(readOnly)) invalid('UNIFI_AXI_READ_ONLY must be 1, 0, true or false.');
    const named = explicit ?? this.env.UNIFI_AXI_PROFILE;
    // Named file profiles never inspect competing environment profile fields.
    if (named !== undefined) {
      const config = await this.load(verifyAcl);
      if (!Object.hasOwn(config.profiles, named)) throw new ToolError('PROFILE_NOT_FOUND', 'Selected profile does not exist.');
      return { name: named, source: 'file', profile: config.profiles[named]! };
    }
    const names = ['ORIGIN', 'API_KEY', 'SITE_ID', 'API_CONTRACT', 'TLS', 'WRITES'];
    if (names.some(name => this.env[`UNIFI_AXI_${name}`] !== undefined)) {
      if (!this.env.UNIFI_AXI_ORIGIN || !this.env.UNIFI_AXI_API_KEY) invalid('Partial environment profile: origin and API key are required.');
      const profile: Record<string, unknown> = { origin: this.env.UNIFI_AXI_ORIGIN };
      for (const [field, name] of [['siteId', 'SITE_ID'], ['apiContract', 'API_CONTRACT'], ['tls', 'TLS'], ['writes', 'WRITES']]) {
        const value = this.env[`UNIFI_AXI_${name}`];
        if (value !== undefined) profile[field!] = ['tls', 'writes'].includes(field!) ? json(value) : value;
      }
      return { name: 'env', source: 'environment', profile: validateProfile(profile) };
    }
    const config = await this.load(verifyAcl);
    const name = config.defaultProfile ?? (Object.keys(config.profiles).length === 1 ? Object.keys(config.profiles)[0] : undefined);
    if (!name) throw new ToolError(Object.keys(config.profiles).length ? 'PROFILE_AMBIGUOUS' : 'PROFILE_REQUIRED', 'Select a profile with --profile or configure a complete environment profile.');
    return { name, source: 'file', profile: config.profiles[name]! };
  }

  async secret(profile: Profile, redactor: Redactor, verifyAcl = false): Promise<string> {
    let value: string | undefined;
    if ('env' in profile.apiKey) value = this.env[profile.apiKey.env];
    else {
      try { value = (await this.files.read(profile.apiKey.file, true, verifyAcl)).replace(/^\uFEFF/, '').trimEnd(); } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      }
    }
    if (!value) throw new ToolError('AUTH_REQUIRED', 'Selected profile has no available API key.');
    redactor.register(value);
    if (/[^\t\x20-\x7e\x80-\xff]/.test(value)) invalid('API key cannot be used as an HTTP header.');
    return value;
  }

  async configure(name: string, input: string): Promise<void> {
    if (!profileName.test(name)) invalid('Invalid profile name.');
    const profile = validateProfile(json(await this.files.read(input)));
    const config = await this.load(true);
    config.profiles[name] = profile;
    await this.files.write(this.path, `${JSON.stringify(config, null, 2)}\n`);
  }
}
