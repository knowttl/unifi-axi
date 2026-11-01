import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import catalogue from './fixtures/catalogue.json' with { type: 'json' };
import data from './fixtures/variant-obligations.json' with { type: 'json' };

type Value = null | boolean | number | string | Value[] | { [key: string]: Value };
type RecordValue = { [key: string]: Value };
interface Condition { pointer: string; property: string; value: Value; schema: string }
interface Position {
  operation: string; method: string; path: string; direction: string; schema: string;
  pointer: string; conditions: Condition[]; status?: number;
}
interface Variant {
  id: string; kind: string; schema?: string; versions: string[]; positions: string[];
  tag?: { property: string; value: Value }; value?: Value;
}
interface Manifest {
  ledgerSha256: string; sources: Record<string, string>; cases: Variant[]; positions: Record<string, Position>;
}
export interface Exchange { method: string; path: string; request: string; response: string; status: number }
interface Obligation { variant: Variant; version: string; position: Position; positionId: string; operation: string; key: string; sourceReason: string }

export const obligations = data as unknown as Manifest;
const names: Record<string, string> = {
  'OP-001': 'information', 'OP-002': 'sites', 'OP-003': 'countries', 'OP-004': 'applications', 'OP-005': 'categories',
  'OP-006': 'pendingDevices', 'OP-007': 'aclRules', 'OP-009': 'aclRuleOrder', 'OP-012': 'aclRule',
  'OP-014': 'clients', 'OP-015': 'client', 'OP-017': 'deviceTags', 'OP-018': 'devices', 'OP-021': 'device',
  'OP-024': 'statistics', 'OP-025': 'dnsPolicies', 'OP-028': 'dnsPolicy', 'OP-030': 'firewallPolicies',
  'OP-032': 'firewallPolicyOrder', 'OP-035': 'firewallPolicy', 'OP-038': 'firewallZones', 'OP-041': 'firewallZone',
  'OP-044': 'vouchers', 'OP-047': 'voucher', 'OP-048': 'networks', 'OP-051': 'network', 'OP-053': 'references',
  'OP-054': 'radiusProfiles', 'OP-055': 'lags', 'OP-056': 'lag', 'OP-057': 'mcLagDomains', 'OP-058': 'mcLagDomain',
  'OP-059': 'switchStacks', 'OP-060': 'switchStack', 'OP-061': 'trafficLists', 'OP-064': 'trafficList',
  'OP-066': 'vpnServers', 'OP-067': 'vpnTunnels', 'OP-068': 'wans', 'OP-069': 'wifiBroadcasts', 'OP-072': 'wifiBroadcast',
};
const confidential = new Set(['apiKey', 'api-key', 'api_key', 'authorization', 'password', 'passphrase', 'token',
  'accessToken', 'refreshToken', 'clientSecret', 'privateKey']);
const object = (value: unknown): RecordValue | undefined =>
  value !== null && typeof value === 'object' && !Array.isArray(value) ? value as RecordValue : undefined;
const parts = (pointer: string) => pointer === '' ? [] : pointer.slice(1).split('/').map(part => part.replaceAll('~1', '/').replaceAll('~0', '~'));
function at(value: Value | undefined, path: string[]): Value | undefined {
  for (const part of path) value = value !== null && typeof value === 'object' ? (value as RecordValue)[part] : undefined;
  return value;
}
function witnesses(value: Value | undefined, path: string[], location: string[] = []): { value: Value; location: string[] }[] {
  if (value === undefined) return [];
  if (!path.length) return [{ value, location }];
  const [first, ...rest] = path;
  if (first === '*' && value !== null && typeof value === 'object') return Object.entries(value)
    .flatMap(([key, child]) => witnesses(child, rest, [...location, key]));
  return witnesses(at(value, [first!]), rest, [...location, first!]);
}
function json(bytes: string): Value | undefined {
  if (!bytes) return undefined;
  try { return JSON.parse(bytes) as Value; }
  catch { return undefined; }
}

export class VariantCoverage {
  private readonly secret: string;
  private readonly entries: Obligation[] = [];
  private readonly observed = new Set<string>();
  private readonly previews = new Map<string, Value>();

  constructor(secret: string, installed: string) {
    this.secret = secret;
    const sources: Record<string, Value> = {};
    for (const [version, hash] of Object.entries(obligations.sources)) {
      const bytes = readFileSync(join(installed, `evidence/sources/network-${version}-openapi.json`));
      assert.equal(createHash('sha256').update(bytes).digest('hex'), hash);
      sources[version] = JSON.parse(bytes.toString()) as Value;
    }
    assert.equal(obligations.cases.length, 1251);
    obligations.cases.forEach((variant, index) => {
      assert.equal(variant.id, `VAR-${String(index + 1).padStart(3, '0')}`);
      for (const version of variant.versions) for (const positionId of variant.positions) {
        const position = obligations.positions[positionId];
        assert.ok(position, positionId);
        const operation = catalogue.find(operation => operation.vendorOperationId === position.operation);
        assert.ok(operation, position.operation);
        const schema = variant.schema ? object(at(sources[version], parts(variant.schema.slice(1)))) : undefined;
        let sourceReason = '';
        if (schema?.type === 'integer' && typeof variant.value === 'string') {
          sourceReason = 'The recorded enum value is a string at an integer field; the exact ledger value has no valid positive wire witness.';
        }
        const protocol = variant.tag?.value ?? variant.value;
        if (variant.schema?.includes('named protocol') && typeof protocol === 'string') {
          const parent = object(at(sources[version], parts(variant.schema.replace('/properties/name', '').slice(1))));
          const mapping = object(object(parent?.discriminator)?.mapping);
          if (mapping && !mapping[protocol.toUpperCase().replaceAll('-', '_').replaceAll('.', '_')]) {
            sourceReason = 'The recorded enum value has no branch in its enclosing named-protocol discriminator.';
          }
        }
        this.entries.push({ variant, version, position, positionId, operation: operation.id,
          key: `${variant.id}:${version}:${positionId}`, sourceReason });
      }
    });
  }

  private redact(value: Value, operation: string): Value {
    if (typeof value === 'string') {
      for (const secret of [this.secret, JSON.stringify(this.secret).slice(1, -1), encodeURIComponent(this.secret)]) {
        if (secret) value = value.split(secret).join('[REDACTED]');
      }
      return value;
    }
    if (Array.isArray(value)) return value.map(child => this.redact(child, operation));
    if (value !== null && typeof value === 'object') {
      let fields = Object.entries(value);
      if (value.id && ['OP-066', 'OP-067', 'OP-068'].includes(operation)) {
        const allowed = operation === 'OP-068' ? ['id', 'name'] : ['id', 'name', 'type', 'metadata', ...(operation === 'OP-066' ? ['enabled'] : [])];
        fields = fields.filter(([key]) => allowed.includes(key)).map(([key, child]) => [key,
          key === 'metadata' && object(child) ? Object.fromEntries(Object.entries(child as RecordValue)
            .filter(([field]) => field === 'origin' || (field === 'source' && operation === 'OP-067' && object(child)!.origin === 'DERIVED'))) : child]);
      }
      return Object.fromEntries(fields.map(([key, child]) =>
        [key, confidential.has(key) || (key === 'code' && ['OP-044', 'OP-047'].includes(operation))
          ? '[REDACTED]' : this.redact(child, operation)]));
    }
    return value;
  }

  observe(args: string[], output: unknown, exchanges: Exchange[]): void {
    const result = object(output);
    if (!result || result.error) return;
    const operation = catalogue.find(operation => operation.command.split(' ').every((word, index) => args[index] === word));
    if (!operation) return;
    const version = exchanges.map(exchange => object(json(exchange.response))?.applicationVersion)
      .find(value => typeof value === 'string');
    if (typeof version !== 'string') return;
    const preview = object(result.preview);
    const previewKey = `${operation.id}:${version}`;
    if (preview) { this.previews.set(previewKey, preview.body!); return; }
    const write = object(result.write);
    if (write && write.outcome !== (['OP-016', 'OP-022', 'OP-023'].includes(operation.id) ? 'accepted' : 'verified')) return;
    const path = new RegExp(`^/proxy/network/integration${operation.path.replace(/\{[^}]+\}/g, '[^/]+')}$`);
    const matching = exchanges.filter(exchange => exchange.method === operation.method && path.test(new URL(exchange.path, 'https://synthetic.invalid').pathname));
    for (const entry of this.entries.filter(entry => entry.operation === operation.id && entry.version === version && !this.observed.has(entry.key))) {
      const { variant, position } = entry;
      if (position.direction === 'parameter') continue;
      for (const exchange of matching) {
        if (position.direction === 'response' && exchange.status !== position.status) continue;
        const wire = json(position.direction === 'request' ? exchange.request : exchange.response);
        if (variant.kind === 'bodyless_success') {
          if (write && exchange.status === 200 && exchange.response === '') {
            assert.equal(write.operation, operation.id);
            this.observed.add(entry.key);
          }
          continue;
        }
        if (write && position.direction === 'response') assert.equal(write.operation, operation.id);
        let published = write ? this.previews.get(previewKey) : result[names[operation.id]!];
        const page = object(wire);
        if (!write && Array.isArray(page?.data)) {
          const start = Number(new URL(exchange.path, 'https://synthetic.invalid').searchParams.get('offset') ?? 0) - Number(result.offset ?? 0);
          published = { ...page, data: (published as Value[]).slice(start, start + page.data.length) };
        }
        for (const witness of witnesses(wire, parts(position.pointer))) {
          if (!position.conditions.every(condition => {
            const location = parts(condition.pointer).map((part, index) => part === '*' ? witness.location[index]! : part);
            const expected = position.direction === 'request' && condition.schema.includes('named protocol') &&
              condition.property === 'name' && typeof condition.value === 'string' ? condition.value.toLowerCase() : condition.value;
            return isDeepStrictEqual(at(wire, [...location, condition.property]), expected);
          })) continue;
          let expected = variant.tag?.value ?? variant.value;
          if (position.direction === 'request' && variant.schema?.includes('named protocol') && typeof expected === 'string') expected = expected.toLowerCase();
          const selected = variant.tag ? object(witness.value)?.[variant.tag.property] : witness.value;
          if ((variant.tag || Object.hasOwn(variant, 'value')) && !isDeepStrictEqual(selected, expected)) continue;
          const record = object(witness.value);
          if (variant.kind === 'schema_root' && (!record || !Object.keys(record).length)) continue;
          if (!write || position.direction === 'request') {
            const visible = at(published, witness.location);
            const redacted = this.redact(witness.value, operation.id);
            if (visible === undefined) continue;
            if (variant.kind === 'schema_root' && Array.isArray(page?.data)) {
              const pages = matching.map(exchange => object(json(exchange.response))).filter(page => Array.isArray(page?.data));
              const records = pages.flatMap(page => page!.data as Value[]);
              assert.deepEqual(result[names[operation.id]!], this.redact(records, operation.id));
              assert.equal(result.count, records.length);
              assert.equal(result.offset, pages[0]?.offset);
              assert.equal(result.totalCount, page.totalCount);
              const last = pages.at(-1)!;
              assert.equal(result.complete, Number(last.offset) + Number(last.count) >= Number(last.totalCount));
            } else if (!isDeepStrictEqual(visible, redacted)) continue;
            assert.deepEqual(visible, redacted);
          } else if (object(wire)?.id !== undefined) assert.equal(write.target, String(object(wire)!.id).toLowerCase());
          this.observed.add(entry.key);
          break;
        }
        if (this.observed.has(entry.key)) break;
      }
    }
  }

  rows() {
    return this.entries.map(entry => ({ task: 'B4.11', acceptance: 'STEP-B4.11', case: entry.variant.id,
      version: entry.version, operation: entry.operation, position: entry.positionId,
      direction: entry.position.direction, pointer: entry.position.pointer,
      status: this.observed.has(entry.key) ? 'passed' : 'pending-obligation',
      ...(!this.observed.has(entry.key) ? { reason: entry.version === '11.0.97' && ['OP-006', 'OP-018', 'OP-019', 'OP-020', 'OP-021', 'OP-022', 'OP-023', 'OP-024'].includes(entry.operation)
        ? 'CF-007 (issue #33): device contract refusal prevents this assertion.'
        : process.platform === 'win32' && entry.position.method !== 'GET'
          ? 'Native Windows durable mutations are deferred to the live list.'
        : entry.position.direction === 'parameter'
          ? 'The retained parameter schema describes filter grammar metadata; no concrete wire-value witness is supplied.'
          : entry.sourceReason || `No matching offline public assertion observed at ${entry.position.pointer || '/'} with the required enclosing tags and exact variant value.` } : {}) }));
  }
}
