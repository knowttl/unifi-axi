import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { application, sites, selectSite } from './application.js';
import { catalogue, parameterFlag, type Operation } from './catalogue.js';
import { Profiles, writeAllowed, type Selection } from './profiles.js';
import { readOperation } from './reads.js';
import { ToolError, type Redactor } from './security.js';
import { contractValidator } from './validation.js';
import { sendMutation, type PeerIdentity } from './transport.js';
import { digest, WriteJournal, type Intent } from './write-journal.js';
import { PrivateFiles } from './private-file.js';

const escape = (value: string) => value.replaceAll('~', '~0').replaceAll('/', '~1');
const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
export const foundationWrites = new Set(['OP-049', 'OP-050', 'OP-052']);

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
}

async function candidate(ctx: Context, operation: Operation, values: Record<string, string>): Promise<Candidate> {
  const version = ctx.api.contract!;
  const site = values.site ?? ctx.selected.profile.siteId ?? selectSite((await sites(ctx.selected.profile, ctx.secret, {}, version, ctx.peer)).sites);
  const inputs: Record<string, string> = { ...values, site };
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
  if (operation.id !== 'OP-050') {
    if (!values['body-file']) throw new ToolError('INVALID_ARGUMENT', 'Network creation and update require --body-file <path>.');
    let parsed: unknown;
    try { parsed = JSON.parse(await new PrivateFiles().read(values['body-file'], true)); }
    catch { throw new ToolError('INVALID_ARGUMENT', 'Unable to read a JSON request body file.'); }
    if (validator.validateRequest(`${pointer}/requestBody/content/application~1json/schema`, parsed).length) {
      throw new ToolError('INVALID_ARGUMENT', 'Request body does not match the selected Network contract.');
    }
    body = parsed as Record<string, unknown>;
    grants.push(`${operation.vendorOperationId}:${String(body.management)}`);
  }
  query.sort();
  if (query.size) path += `?${query}`;
  const target = inputs['network-id'] ?? null;
  const binding = digest({ identity: ctx.identity, method: operation.method, path: `/proxy/network/integration${path}`, site: inputs.site!,
    targets: target ? [target] : [], body, protectedOutput: null, grants });
  return { operation, path, site: inputs.site!, target, body, grants, binding };
}

async function selectedState(ctx: Context, request: Pick<Candidate, 'operation' | 'site' | 'target' | 'body'>): Promise<unknown> {
  const version = ctx.api.contract!;
  const listing = await readOperation(ctx.selected.profile, ctx.secret, catalogue.find(op => op.id === 'OP-048')!, { site: request.site }, version, ctx.peer);
  const networks = (listing as Record<string, unknown>).networks as Record<string, unknown>[];
  if (request.operation.id === 'OP-049') return networks.filter(row => row.vlanId === request.body!.vlanId).map(row => ({ id: row.id, vlanId: row.vlanId }));
  if (!networks.some(row => (row.id as string).toLowerCase() === request.target)) return null;
  return (await readOperation(ctx.selected.profile, ctx.secret, catalogue.find(op => op.id === 'OP-051')!,
    { site: request.site, 'network-id': request.target! }, version, ctx.peer)).network;
}

function receipt(record: Intent, requestId: string) {
  return { write: { requestId, ...record },
    ...(record.outcome === 'unknown' ? { error: { code: 'OUTCOME_UNKNOWN', message: 'The request may have reached the vendor. Never resend it.' } } : {}),
    help: [`unifi-axi write show --request-id ${requestId}`, `unifi-axi write reconcile --request-id ${requestId}`] };
}

async function verify(ctx: Context, record: Intent): Promise<Intent['outcome']> {
  if (!record.target) return record.outcome;
  const request = { operation: catalogue.find(op => op.id === 'OP-050')!, site: record.site, target: record.target, body: null };
  const state = await selectedState(ctx, request) as Record<string, unknown> | null;
  if (record.operation === 'OP-050') return state === null && ['accepted', 'verified', 'no-op'].includes(record.outcome) ? 'verified' : record.outcome;
  if (state && ['accepted', 'verified'].includes(record.outcome) && digest(Object.fromEntries(record.bodyKeys.map(key => [key, state[key]]))) === record.bodyHash) return 'verified';
  return record.outcome;
}

export async function writeOperation(profiles: Profiles, explicit: string | undefined, redactor: Redactor,
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
    return receipt(previous, values['request-id']!);
  }
  const state = await selectedState(ctx, request);
  const confirmation = digest({ binding: request.binding, state });
  if (!execute) return { preview: { outcome: 'preview', operation: operation.id, grants: request.grants,
    method: operation.method, origin: ctx.selected.profile.origin, path: `/proxy/network/integration${request.path}`,
    site: request.site, targets: request.target ? [request.target] : [], body: request.body, confirmation,
    identity: ctx.identity, applicationVersion: ctx.api.applicationVersion },
    help: ['Repeat the same request with --execute --confirm <confirmation> --request-id <stable-id>. Concurrent vendor changes can occur after the final read.'] };
  if (values.confirm !== confirmation) throw new ToolError('CONFIRMATION_MISMATCH', 'Request, selected state or identity changed. Preview the request again.');
  const record = await journal!.claim({ binding: request.binding, identity: ctx.identity, confirmation, operation: operation.id as Intent['operation'],
    site: request.site, target: request.target, bodyHash: digest(request.body), bodyKeys: Object.keys(request.body ?? {}).sort() });
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
    if (operation.id === 'OP-050' && state === null) {
      record.outcome = 'no-op';
      await journal!.save(record);
      return receipt(record, values['request-id']!);
    }
    if (operation.id === 'OP-049' && (state as unknown[]).length) throw new ToolError('WRITE_CONFLICT', 'The requested VLAN is already present. A similar network cannot prove a previous creation.');
    const response = await sendMutation(ctx.selected.profile, ctx.secret, request.path, {
      method: operation.method, body: request.body === null ? undefined : JSON.stringify(request.body),
      status: operation.id === 'OP-049' ? 201 : 200, peer: ctx.peer, beforeSend,
    });
    if (operation.id !== 'OP-050') {
      const pointer = `#/paths/${escape(operation.path)}/${operation.method.toLowerCase()}/responses/${operation.id === 'OP-049' ? 201 : 200}/content/application~1json/schema`;
      if (contractValidator(ctx.api.contract!).validate(pointer, response).length) throw new ToolError('RESPONSE_INVALID', 'Invalid mutation acknowledgement.');
      const target = (response as Record<string, unknown>).id;
      if (typeof target !== 'string' || !uuid.test(target)) throw new ToolError('RESPONSE_INVALID', 'Invalid created network ID.');
      if (request.target && target.toLowerCase() !== request.target) throw new ToolError('RESPONSE_INVALID', 'Mutation acknowledgement does not match the selected network.');
      record.target = target.toLowerCase();
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
  if (!record.target) await readOperation(ctx.selected.profile, ctx.secret, catalogue.find(op => op.id === 'OP-048')!, { site: record.site }, ctx.api.contract!, ctx.peer);
  await journal.observe(outcome);
  return { ...receipt(record, requestId), reconciliation: { outcome, readOnly: true } };
}
