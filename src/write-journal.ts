import { homedir } from 'node:os';
import { dirname, isAbsolute, join } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { PrivateFiles } from './private-file.js';
import { ToolError } from './security.js';

export function digest(value: unknown): string {
  function canonical(item: unknown): unknown {
    if (Array.isArray(item)) return item.map(canonical);
    if (item && typeof item === 'object') return Object.fromEntries(Object.entries(item).sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => [key, canonical(value)]));
    return item;
  }
  return createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
}

export interface Intent {
  version: 1;
  auditId: string;
  binding: string;
  identity: string;
  confirmation: string;
  operation: 'OP-049' | 'OP-050' | 'OP-052';
  site: string;
  target: string | null;
  outcome: 'not-sent' | 'unknown' | 'accepted' | 'verified' | 'no-op';
  bodyHash: string;
  bodyKeys: string[];
}

const hash = /^[a-f0-9]{64}$/;
const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
function corrupt(): never { throw new ToolError('WRITE_JOURNAL_INVALID', 'Incomplete or corrupt request ownership. Never retry this ID with a mutation.'); }

export class WriteJournal {
  private readonly files = new PrivateFiles();
  readonly directory: string;

  constructor(config: string, profile: string, readonly requestId: string) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(requestId)) throw new ToolError('INVALID_ARGUMENT', 'request-id must contain 1-128 letters, digits, dots, underscores or hyphens.');
    const base = process.env.UNIFI_AXI_WRITE_LOG ?? join(process.env.XDG_STATE_HOME && isAbsolute(process.env.XDG_STATE_HOME)
      ? process.env.XDG_STATE_HOME : join(homedir(), '.local/state'), 'unifi-axi', 'writes.log');
    if (!isAbsolute(base)) throw new ToolError('CONFIG_INVALID', 'UNIFI_AXI_WRITE_LOG must be an absolute private directory.');
    this.directory = join(base, digest({ config, profile }), digest(requestId));
  }

  async read(): Promise<Intent | undefined> {
    let text: string;
    try {
      for (const path of [dirname(dirname(this.directory)), dirname(this.directory), this.directory]) await this.files.verifyDirectory(path);
      text = await this.files.read(join(this.directory, 'intent.json'), true);
    }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      // An empty claim left by an interrupted owner is never permission to retry.
      const { lstat } = await import('node:fs/promises');
      try { await lstat(this.directory); } catch (missing) {
        if ((missing as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
        throw missing;
      }
      return corrupt();
    }
    let value: Intent;
    try { value = JSON.parse(text) as Intent; } catch { return corrupt(); }
    if (!value || value.version !== 1 || !uuid.test(value.auditId) ||
        ![value.binding, value.identity, value.confirmation, value.bodyHash].every(item => typeof item === 'string' && hash.test(item)) ||
        !['OP-049', 'OP-050', 'OP-052'].includes(value.operation) || typeof value.site !== 'string' || !uuid.test(value.site) ||
        (value.target !== null && (typeof value.target !== 'string' || !uuid.test(value.target))) ||
        !['not-sent', 'unknown', 'accepted', 'verified', 'no-op'].includes(value.outcome) ||
        !Array.isArray(value.bodyKeys) || value.bodyKeys.some(key => typeof key !== 'string' || !['name', 'enabled', 'management', 'vlanId', 'dhcpGuarding',
          'cellularBackupEnabled', 'internetAccessEnabled', 'ipv4Configuration', 'ipv6Configuration', 'isolationEnabled', 'mdnsForwardingEnabled', 'zoneId', 'deviceId'].includes(key)) ||
        Object.keys(value).sort().join() !== 'auditId,binding,bodyHash,bodyKeys,confirmation,identity,operation,outcome,site,target,version') return corrupt();
    value.site = value.site.toLowerCase();
    value.target = value.target?.toLowerCase() ?? null;
    return value;
  }

  async claim(intent: Omit<Intent, 'version' | 'auditId' | 'outcome'>): Promise<Intent> {
    if (process.platform === 'win32') throw new ToolError('WRITE_UNSUPPORTED', 'Durable native Windows writes are pending verification.');
    const namespace = dirname(this.directory);
    await this.files.directory(dirname(namespace));
    await this.files.directory(namespace);
    try { await this.files.directory(this.directory, true); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'EEXIST') throw new ToolError('WRITE_OWNED', 'This request ID is already owned. Use write show or write reconcile.');
      throw error;
    }
    const record: Intent = { version: 1, auditId: randomUUID(), outcome: 'not-sent', ...intent };
    await this.save(record);
    return record;
  }

  async save(intent: Intent): Promise<void> {
    await this.files.write(join(this.directory, 'intent.json'), JSON.stringify(intent) + '\n');
    await this.files.syncDirectory(this.directory);
  }

  async observe(outcome: Intent['outcome']): Promise<void> {
    await this.files.write(join(this.directory, 'observation.json'), JSON.stringify({ outcome, checkedAt: new Date().toISOString() }) + '\n');
    await this.files.syncDirectory(this.directory);
  }
}
