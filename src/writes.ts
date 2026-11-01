import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { application, sites, selectSite } from './application.js';
import { catalogue, parameterFlag, writeOperations, type Operation } from './catalogue.js';
import { Profiles, writeAllowed, type Selection } from './profiles.js';
import { readOperation } from './reads.js';
import { ToolError, type Redactor } from './security.js';
import { contractValidator } from './validation.js';
import { sendMutation, type PeerIdentity } from './transport.js';
import { digest, WriteJournal, type Intent } from './write-journal.js';
import { PrivateFiles } from './private-file.js';
import { isAbsolute } from 'node:path';
import { responseSecrets } from './secret-output.js';

const escape = (value: string) => value.replaceAll('~', '~0').replaceAll('/', '~1');
const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
export const foundationWrites = writeOperations;

const families = [
  { writes: ['OP-049', 'OP-050', 'OP-052'], list: 'OP-048', show: 'OP-051', rows: 'networks', row: 'network', target: 'network-id' },
  { writes: ['OP-008', 'OP-011', 'OP-013'], list: 'OP-007', show: 'OP-012', rows: 'aclRules', row: 'aclRule', target: 'acl-rule-id' },
  { writes: ['OP-031', 'OP-034', 'OP-036', 'OP-037'], list: 'OP-030', show: 'OP-035', rows: 'firewallPolicies', row: 'firewallPolicy', target: 'firewall-policy-id' },
  { writes: ['OP-039', 'OP-040', 'OP-042'], list: 'OP-038', show: 'OP-041', rows: 'firewallZones', row: 'firewallZone', target: 'firewall-zone-id' },
  { writes: ['OP-043', 'OP-045', 'OP-046'], list: 'OP-044', show: 'OP-047', rows: 'vouchers', row: 'voucher', target: 'voucher-id' },
  { writes: ['OP-070', 'OP-071', 'OP-073'], list: 'OP-069', show: 'OP-072', rows: 'wifiBroadcasts', row: 'wifiBroadcast', target: 'wifi-broadcast-id' },
];
const ordering: Record<string, { read: string; row: string }> = {
  'OP-010': { read: 'OP-009', row: 'aclRuleOrder' }, 'OP-033': { read: 'OP-032', row: 'firewallPolicyOrder' },
};

function orderedIds(body: Record<string, unknown>): string[] {
  if (Array.isArray(body.orderedAclRuleIds)) return body.orderedAclRuleIds as string[];
  return Object.values(body.orderedFirewallPolicyIds as Record<string, string[]>).flat();
}

function normalizeProtocols(value: unknown): void {
  if (!value || typeof value !== 'object') return;
  const record = value as Record<string, unknown>;
  if (record.type === 'NAMED_PROTOCOL' && record.protocol && typeof record.protocol === 'object') {
    const protocol = record.protocol as Record<string, unknown>;
    if (typeof protocol.name === 'string') protocol.name = protocol.name.toLowerCase();
  }
  Object.values(record).forEach(normalizeProtocols);
}

function policy(selected: Selection, grants: string[]): void {
  if (!writeAllowed(selected.profile, grants)) {
    throw new ToolError('WRITE_DENIED', `Execution requires writes.allowWrites and exact grants: ${grants.join(', ')}; read-only overrides take precedence.`);
  }
}

async function context(profiles: Profiles, explicit: string | undefined, redactor: Redactor) {
  const selected = await profiles.select(explicit);
  const secret = await profiles.secret(selected.profile, redactor);
  const peer: PeerIdentity = { leaf: '', address: '' };
  const { api } = await application(selected.profile, secret, peer);
  if (api.status !== 'verified' || !api.contract) throw new ToolError('UNVERIFIED_API_VERSION', 'Writes require an observed, shipped Network application version.');
  const contractHash = createHash('sha256').update(await readFile(new URL(`../evidence/sources/network-${api.contract}-openapi.json`, import.meta.url))).digest('hex');
  const identity = digest({ config: profiles.path, profile: selected.name, source: selected.source, profileSettings: selected.profile,
    credentialHash: digest(secret), peer, version: api.applicationVersion, contractHash });
  return { selected, secret, peer, api, identity };
}

type Context = Awaited<ReturnType<typeof context>>;
interface Candidate {
  operation: Operation;
  path: string;
  site: string;
  target: string | null;
  body: Record<string, unknown> | null;
  grants: string[];
  binding: string;
  selectors: Record<string, string>;
  targets: string[];
}

async function candidate(ctx: Context, operation: Operation, values: Record<string, string>): Promise<Candidate> {
  const version = ctx.api.contract!;
  const site = values.site ?? ctx.selected.profile.siteId ?? selectSite((await sites(ctx.selected.profile, ctx.secret, {}, version, ctx.peer)).sites);
  const inputs: Record<string, string> = { ...values, site };
  if (operation.id === 'OP-043') {
    // Preserve the predicate as one expression when adding the approved ID restriction.
    let depth = 0;
    let quote = '';
    for (const character of values.filter ?? '') {
      if (quote) {
        if (character === quote) quote = '';
      } else if (character === "'") quote = character;
      else if (character === '(') depth++;
      else if (character === ')') {
        if (--depth < 0) throw new ToolError('INVALID_ARGUMENT', 'Unbalanced deletion filter.');
      } else if (!/[A-Za-z0-9_.:,+ \t-]/.test(character)) throw new ToolError('INVALID_ARGUMENT', 'Invalid deletion filter token.');
    }
    if (depth || quote || !values.filter?.trim()) throw new ToolError('INVALID_ARGUMENT', 'Unbalanced or empty deletion filter.');
  }
  const validator = contractValidator(version);
  const pointer = `#/paths/${escape(operation.path)}/${operation.method.toLowerCase()}`;
  let path = operation.path;
  const query = new URLSearchParams();
  for (const [index, parameter] of operation.contracts.find(contract => contract.version === version)!.parameters.entries()) {
    const raw = inputs[parameterFlag(parameter.name)];
    let value = raw === undefined ? parameter.schema.default : parameter.schema.type === 'boolean' ? raw === 'true' : raw;
    if (value === undefined && !parameter.required) continue;
    if (validator.validate(`${pointer}/parameters/${index}/schema`, value).length) throw new ToolError('INVALID_ARGUMENT', `Invalid --${parameterFlag(parameter.name)}.`);
    if (typeof value === 'string' && parameter.schema.format === 'uuid') value = value.toLowerCase();
    inputs[parameterFlag(parameter.name)] = String(value);
    if (parameter.in === 'path') path = path.replace(`{${parameter.name}}`, encodeURIComponent(String(value)));
    else query.set(parameter.name, String(value));
  }
  let body: Record<string, unknown> | null = null;
  const grants = [operation.vendorOperationId];
  if (operation.contracts.find(contract => contract.version === version)!.requestBody) {
    if (!values['body-file']) throw new ToolError('INVALID_ARGUMENT', `${operation.command} requires --body-file <path>.`);
    let parsed: unknown;
    try { parsed = JSON.parse(await new PrivateFiles().read(values['body-file'], true)); }
    catch { throw new ToolError('INVALID_ARGUMENT', 'Unable to read a JSON request body file.'); }
    if (validator.validateRequest(`${pointer}/requestBody/content/application~1json/schema`, parsed).length) {
      throw new ToolError('INVALID_ARGUMENT', 'Request body does not match the selected Network contract.');
    }
    body = parsed as Record<string, unknown>;
    if (operation.command.startsWith('firewall policy ')) normalizeProtocols(body);
    if (['OP-049', 'OP-052'].includes(operation.id)) grants.push(`${operation.vendorOperationId}:${String(body.management)}`);
  }
  query.sort();
  if (query.size) path += `?${query}`;
  const family = families.find(family => family.writes.includes(operation.id));
  const target = family ? inputs[family.target] ?? null : null;
  const selectors = Object.fromEntries(['source-firewall-zone-id', 'destination-firewall-zone-id', ...(operation.id === 'OP-043' ? ['filter'] : [])]
    .filter(key => inputs[key] !== undefined).map(key => [key, inputs[key]!]));
  const targets = target ? [target] : ordering[operation.id] ? orderedIds(body!) : [];
  const binding = digest({ identity: ctx.identity, method: operation.method, path: `/proxy/network/integration${path}`, site: inputs.site!,
    targets, body: operation.id === 'OP-045' ? { ...body, count: body!.count ?? 1 } : body,
    protectedOutput: values['secret-output'] ?? null, grants });
  return { operation, path, site: inputs.site!, target, body, grants, binding, selectors, targets };
}

async function selectedState(ctx: Context, request: Pick<Candidate, 'operation' | 'site' | 'target' | 'body' | 'selectors'>): Promise<unknown> {
  const version = ctx.api.contract!;
  const order = ordering[request.operation.id];
  if (order) return (await readOperation(ctx.selected.profile, ctx.secret, catalogue.find(op => op.id === order.read)!,
    { site: request.site, ...request.selectors }, version, ctx.peer) as Record<string, unknown>)[order.row];
  const family = families.find(family => family.writes.includes(request.operation.id))!;
  const listing = await readOperation(ctx.selected.profile, ctx.secret, catalogue.find(op => op.id === family.list)!,
    { site: request.site, ...request.selectors }, version, ctx.peer, true);
  const rows = (listing as Record<string, unknown>)[family.rows] as Record<string, unknown>[];
  if (request.operation.id === 'OP-043') return rows.toSorted((a, b) => String(a.id).localeCompare(String(b.id)));
  if (request.operation.id === 'OP-049') return rows.filter(row => row.vlanId === request.body!.vlanId).map(row => ({ id: row.id, vlanId: row.vlanId }));
  if (request.operation.method === 'POST' && !request.target) return rows;
  if (!rows.some(row => (row.id as string).toLowerCase() === request.target)) return null;
  return (await readOperation(ctx.selected.profile, ctx.secret, catalogue.find(op => op.id === family.show)!,
    { site: request.site, [family.target]: request.target! }, version, ctx.peer, true) as Record<string, unknown>)[family.row];
}

function receipt(record: Intent, requestId: string) {
  return { write: { requestId, ...record },
    ...(record.outcome === 'unknown' ? { error: { code: 'OUTCOME_UNKNOWN', message: 'The request may have reached the vendor. Never resend it.' } } : {}),
    help: [`unifi-axi write show --request-id ${requestId}`, `unifi-axi write reconcile --request-id ${requestId}`] };
}

async function verify(ctx: Context, record: Intent): Promise<Intent['outcome']> {
  const operation = catalogue.find(op => op.id === record.operation)!;
  if (record.operation === 'OP-043' || record.operation === 'OP-045') {
    if (!record.targets) return record.outcome;
    const listing = await readOperation(ctx.selected.profile, ctx.secret, catalogue.find(op => op.id === 'OP-044')!,
      { site: record.site }, ctx.api.contract!, ctx.peer, true);
    const rows = (listing as Record<string, unknown>).vouchers as Record<string, unknown>[];
    if (record.operation === 'OP-043') return record.targets.every(id => !rows.some(row => row.id === id)) &&
      ['accepted', 'verified', 'no-op'].includes(record.outcome) ? 'verified' : record.outcome;
    return ['accepted', 'verified'].includes(record.outcome) && record.targets.every(id => {
      const row = rows.find(row => row.id === id);
      return row && digest(Object.fromEntries(record.bodyKeys.map(key => [key, row[key]]))) === record.bodyHash;
    }) ? 'verified' : record.outcome;
  }
  if (!record.target && !ordering[record.operation]) return record.outcome;
  const request = { operation: operation.id === 'OP-049' ? catalogue.find(op => op.id === 'OP-050')! : operation,
    site: record.site, target: record.target, body: null, selectors: record.selectors ?? {} };
  const state = await selectedState(ctx, request) as Record<string, unknown> | null;
  if (operation.command.startsWith('firewall policy ')) normalizeProtocols(state);
  if (operation.method === 'DELETE') return state === null && ['accepted', 'verified', 'no-op'].includes(record.outcome) ? 'verified' : record.outcome;
  if (state && ['accepted', 'verified'].includes(record.outcome) && digest(Object.fromEntries(record.bodyKeys.map(key => [key, state[key]]))) === record.bodyHash) return 'verified';
  return record.outcome;
}

async function performWrite(profiles: Profiles, explicit: string | undefined, redactor: Redactor,
  operation: Operation, values: Record<string, string>, execute: boolean) {
  if (execute) {
    const selected = await profiles.select(explicit);
    policy(selected, [operation.vendorOperationId]);
    if (!values.confirm || !values['request-id']) throw new ToolError('INVALID_ARGUMENT', 'Execution requires --confirm and a stable --request-id.');
  }
  const ctx = await context(profiles, explicit, redactor);
  const request = await candidate(ctx, operation, values);
  if (execute) policy(ctx.selected, request.grants);
  const journal = execute ? new WriteJournal(profiles.path, ctx.selected.name, values['request-id']!) : undefined;
  const previous = await journal?.read();
  if (previous) {
    if (previous.binding !== request.binding || previous.confirmation !== values.confirm) throw new ToolError('WRITE_BINDING_MISMATCH', 'Request ID is bound to another request or identity.');
    return inspectWrite(profiles, explicit, redactor, values['request-id']!, true);
  }
  const state = await selectedState(ctx, request);
  if (operation.id === 'OP-043') request.targets = (state as Record<string, unknown>[]).map(row => String(row.id).toLowerCase()).sort();
  if (ordering[operation.id] && (new Set(request.targets).size !== request.targets.length ||
      digest(request.targets.toSorted()) !== digest(orderedIds(state as Record<string, unknown>).toSorted()))) {
    throw new ToolError('WRITE_CONFLICT', 'Ordering must retain exactly the selected IDs without duplicates.');
  }
  const confirmation = digest({ binding: request.binding, state });
  if (!execute) return { preview: { outcome: 'preview', operation: operation.id, grants: request.grants,
    method: operation.method, origin: ctx.selected.profile.origin,
    path: `/proxy/network/integration${operation.id === 'OP-043' ? request.path.split('?')[0] + '?filter=[REDACTED]' : request.path}`,
    site: request.site, targets: request.targets, body: request.body, confirmation,
    identity: ctx.identity, applicationVersion: ctx.api.applicationVersion },
    help: ['Repeat the same request with --execute --confirm <confirmation> --request-id <stable-id>. Concurrent vendor changes can occur after the final read.'] };
  if (values.confirm !== confirmation) throw new ToolError('CONFIRMATION_MISMATCH', 'Request, selected state or identity changed. Preview the request again.');
  let projection = request.body;
  if (operation.id === 'OP-045') projection = Object.fromEntries(Object.entries(request.body!).filter(([key]) => key !== 'count'));
  if (operation.method === 'PUT' && !ordering[operation.id] && operation.id !== 'OP-052') {
    projection = contractValidator(ctx.api.contract!).replacementProjection(
      `#/paths/${escape(operation.path)}/put/requestBody/content/application~1json/schema`, request.body!);
  }
  if (['OP-031', 'OP-037'].includes(operation.id) && ctx.api.contract === '11.0.97' && !Object.hasOwn(request.body!, 'reportFlowEnabled')) {
    projection = { ...projection, reportFlowEnabled: true };
  }
  const record = await journal!.claim({ binding: request.binding, identity: ctx.identity, confirmation, operation: operation.id as Intent['operation'],
    site: request.site, target: request.target, bodyHash: digest(projection), bodyKeys: Object.keys(projection ?? {}).sort(),
    selectors: operation.id === 'OP-043' ? {} : request.selectors,
    ...(operation.id === 'OP-043' ? { targets: request.targets } : {}) });
  try {
    // Transport calls this after peer verification and before writing HTTP bytes.
    const beforeSend = async () => {
      const fresh = await context(profiles, explicit, redactor);
      const updated = await candidate(fresh, operation, values);
      policy(fresh.selected, updated.grants);
      if (digest({ binding: updated.binding, state: await selectedState(fresh, updated) }) !== confirmation) throw new ToolError('WRITE_DRIFT', 'Selected identity, input or state changed before dispatch.');
      record.outcome = 'unknown';
      await journal!.save(record);
    };
    if (operation.method === 'DELETE' && (state === null || (operation.id === 'OP-043' && request.targets.length === 0))) {
      record.outcome = 'no-op';
      await journal!.save(record);
      return receipt(record, values['request-id']!);
    }
    if (operation.id === 'OP-049' && (state as unknown[]).length) throw new ToolError('WRITE_CONFLICT', 'The requested VLAN is already present. A similar network cannot prove a previous creation.');
    let path = request.path;
    if (operation.id === 'OP-043') {
      const url = new URL(path, ctx.selected.profile.origin);
      url.searchParams.set('filter', `and(${values.filter},id.in(${request.targets.join(',')}))`);
      path = url.pathname + url.search;
    }
    const response = await sendMutation(ctx.selected.profile, ctx.secret, path, {
      method: operation.method, body: request.body === null ? undefined : JSON.stringify(request.body),
      status: operation.method === 'POST' ? 201 : 200, peer: ctx.peer, beforeSend,
    });
    if (request.body || ['OP-043', 'OP-046'].includes(operation.id)) {
      const status = operation.method === 'POST' ? 201 : 200;
      const pointer = `#/paths/${escape(operation.path)}/${operation.method.toLowerCase()}/responses/${status}/content/application~1json/schema`;
      if (contractValidator(ctx.api.contract!).validate(pointer, response).length) throw new ToolError('RESPONSE_INVALID', 'Invalid mutation acknowledgement.');
      if (operation.id === 'OP-045') {
        const rows = (response as { vouchers?: Record<string, unknown>[] }).vouchers;
        if (!rows || rows.length !== (request.body!.count ?? 1) || rows.some(row => typeof row.id !== 'string' || !uuid.test(row.id)) ||
            new Set(rows.map(row => String(row.id).toLowerCase())).size !== rows.length) throw new ToolError('RESPONSE_INVALID', 'Invalid generated voucher batch.');
        record.targets = rows.map(row => String(row.id).toLowerCase()).sort();
      } else if (operation.method === 'POST') {
        const target = (response as Record<string, unknown>).id;
        if (typeof target !== 'string' || !uuid.test(target)) throw new ToolError('RESPONSE_INVALID', 'Invalid created resource ID.');
        record.target = target.toLowerCase();
      } else if (operation.method !== 'DELETE' && record.target && String((response as Record<string, unknown>).id).toLowerCase() !== record.target) {
        throw new ToolError('RESPONSE_INVALID', 'Mutation acknowledgement does not match the selected resource.');
      }
    }
    record.outcome = 'accepted';
    await journal!.save(record);
    record.outcome = await verify(ctx, record);
    await journal!.save(record);
  } catch (error) {
    if (record.outcome === 'not-sent') throw error;
    // Keep the synced possible-send record if acknowledgement or verification failed.
    return { ...receipt(record, values['request-id']!), ...(record.outcome === 'accepted' ? { verification: 'pending' } : {}) };
  }
  return receipt(record, values['request-id']!);
}

export async function writeOperation(profiles: Profiles, explicit: string | undefined, redactor: Redactor,
  operation: Operation, values: Record<string, string>, execute: boolean) {
  const destination = values['secret-output'];
  if (destination) {
    if (process.env.UNIFI_AXI_HOSTED === '1') throw new ToolError('HOSTED_DENIED', 'Local secret export is unavailable in hosted execution.');
    const selected = await profiles.select(explicit);
    if (selected.profile.allowSecretExport !== true) throw new ToolError('SECRET_EXPORT_DENIED', 'Set allowSecretExport: true in the selected profile to enable --secret-output.');
    if (!isAbsolute(destination)) throw new ToolError('INVALID_ARGUMENT', '--secret-output requires an absolute path in an existing private directory.');
  }
  if (!destination || !execute) return performWrite(profiles, explicit, redactor, operation, values, execute);
  let result: Awaited<ReturnType<typeof performWrite>> | undefined;
  try {
    await new PrivateFiles().create(destination, async () => {
      result = await performWrite(profiles, explicit, redactor, operation, values, execute);
      if (!('write' in result) || !['accepted', 'verified'].includes(result.write.outcome)) throw new ToolError('SECRET_DELIVERY_FAILED', 'No accepted resource is available for export.');
      const ctx = await context(profiles, explicit, redactor);
      if (ctx.identity !== result.write.identity) throw new ToolError('WRITE_BINDING_MISMATCH', 'Stored request belongs to another identity context.');
      const family = families.find(family => family.writes.includes(operation.id))!;
      const ids = result.write.targets ?? (result.write.target ? [result.write.target] : []);
      const secrets = [];
      for (const id of ids) {
        const detail = await readOperation(ctx.selected.profile, ctx.secret, catalogue.find(op => op.id === family.show)!,
          { site: result.write.site, [family.target]: id }, ctx.api.contract!, ctx.peer, true);
        secrets.push(...responseSecrets(operation.id === 'OP-045' ? 'OP-047' : 'OP-072',
          (detail as Record<string, unknown>)[family.row] as Record<string, unknown>, redactor));
      }
      return JSON.stringify({ operation: operation.id, secrets }) + '\n';
    });
  } catch (error) {
    if (!result) throw error;
    return { ...result, delivery: { path: destination, delivered: false },
      help: [...(result.help ?? []), 'Reconcile the stored request ID, then export its exact IDs using hotspot voucher show or wifi broadcast show --secret-output <new-file>. Never generate again.'] };
  }
  return { ...result!, delivery: { path: destination, delivered: true } };
}

export async function inspectWrite(profiles: Profiles, explicit: string | undefined, redactor: Redactor,
  requestId: string, reconcile: boolean) {
  const ctx = await context(profiles, explicit, redactor);
  const journal = new WriteJournal(profiles.path, ctx.selected.name, requestId);
  const record = await journal.read();
  if (!record) throw new ToolError('WRITE_NOT_FOUND', 'No ownership record exists for this request ID.');
  if (record.identity !== ctx.identity) throw new ToolError('WRITE_BINDING_MISMATCH', 'Stored request belongs to another identity context.');
  if (!reconcile) return receipt(record, requestId);
  // An ambiguous create has no trustworthy vendor ID. Similar objects prove nothing.
  const outcome = await verify(ctx, record);
  if (!record.target && !record.targets && !ordering[record.operation]) {
    const family = families.find(family => family.writes.includes(record.operation))!;
    await readOperation(ctx.selected.profile, ctx.secret, catalogue.find(op => op.id === family.list)!, { site: record.site }, ctx.api.contract!, ctx.peer);
  }
  await journal.observe(outcome);
  return { ...receipt({ ...record, outcome }, requestId), reconciliation: { outcome, readOnly: true } };
}
