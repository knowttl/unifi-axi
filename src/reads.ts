import { parameterFlag, type Operation } from './catalogue.js';
import type { Profile } from './profiles.js';
import { enumerate, type Page } from './paging.js';
import { readJson } from './transport.js';
import { validateResponse } from './validation.js';
import { ToolError } from './security.js';

type RecordData = Record<string, unknown>;
const names: Record<string, string> = {
  'OP-003': 'countries', 'OP-004': 'applications', 'OP-005': 'categories', 'OP-006': 'pendingDevices',
  'OP-014': 'clients', 'OP-015': 'client', 'OP-017': 'deviceTags', 'OP-018': 'devices',
  'OP-021': 'device', 'OP-024': 'statistics', 'OP-048': 'networks', 'OP-051': 'network',
  'OP-053': 'references', 'OP-054': 'radiusProfiles', 'OP-066': 'vpnServers',
  'OP-067': 'vpnTunnels', 'OP-068': 'wans',
  'OP-007': 'aclRules', 'OP-009': 'aclRuleOrder', 'OP-012': 'aclRule',
  'OP-025': 'dnsPolicies', 'OP-028': 'dnsPolicy', 'OP-030': 'firewallPolicies',
  'OP-032': 'firewallPolicyOrder', 'OP-035': 'firewallPolicy', 'OP-038': 'firewallZones', 'OP-041': 'firewallZone',
  'OP-044': 'vouchers', 'OP-047': 'voucher', 'OP-055': 'lags', 'OP-056': 'lag',
  'OP-057': 'mcLagDomains', 'OP-058': 'mcLagDomain', 'OP-059': 'switchStacks', 'OP-060': 'switchStack',
  'OP-061': 'trafficLists', 'OP-064': 'trafficList', 'OP-069': 'wifiBroadcasts', 'OP-072': 'wifiBroadcast',
};

export async function readOperation(profile: Profile, secret: string, operation: Operation,
  values: Record<string, string>, version: string) {
  let path = operation.path;
  const parameters = operation.contracts.find(contract => contract.version === version)!.parameters;
  for (const parameter of parameters.filter(parameter => parameter.in === 'path')) {
    const flag = parameterFlag(parameter.name);
    const value = values[flag];
    if (!value) throw new ToolError('INVALID_ARGUMENT', `--${flag} is required.`);
    path = path.replace(`{${parameter.name}}`, encodeURIComponent(value));
  }
  const read = async (url: string, budget?: Parameters<typeof readJson>[3]) => {
    const result = await readJson(profile, secret, url, budget);
    validateResponse(version, operation.id, result);
    // Voucher codes are credentials; diagnostic error.code fields stay visible.
    if (operation.id === 'OP-047') (result as RecordData).code = '[REDACTED]';
    if (operation.id === 'OP-044') for (const voucher of (result as { data: RecordData[] }).data) voucher.code = '[REDACTED]';
    return result as RecordData;
  };
  const name = names[operation.id]!;
  if (!parameters.some(parameter => parameter.name === 'offset')) {
    const query = new URLSearchParams();
    for (const parameter of parameters.filter(parameter => parameter.in === 'query')) {
      const value = values[parameterFlag(parameter.name)];
      if (value !== undefined) query.set(parameter.name, value);
    }
    const result = await read(`${path}${query.size ? `?${query}` : ''}`);
    const targetParameter = parameters.find(parameter => parameter.in === 'path' && parameter.name !== 'siteId');
    const target = targetParameter ? values[parameterFlag(targetParameter.name)] : undefined;
    if (target !== undefined && Object.hasOwn(result, 'id') && result.id !== target) {
      throw new ToolError('RESPONSE_INVALID', '/id: response does not match the requested resource.');
    }
    if (operation.id === 'OP-053') {
      const networkPath = path.slice(0, -'/references'.length);
      const network = await readJson(profile, secret, networkPath);
      validateResponse(version, 'OP-051', network);
      const selected = network as RecordData;
      if (selected.id !== target) throw new ToolError('RESPONSE_INVALID', '/id: response does not match the requested network.');
      return { network: { id: selected.id, name: selected.name }, [name]: result };
    }
    return { [name]: result };
  }
  const limit = Number(values.limit ?? parameters.find(parameter => parameter.name === 'limit')!.schema.default ?? 25);
  const result = await enumerate(async (offset, budget) => {
    const query = new URLSearchParams({ offset: String(offset), limit: String(limit) });
    for (const parameter of parameters.filter(parameter => parameter.in === 'query' && !['offset', 'limit'].includes(parameter.name))) {
      const value = values[parameterFlag(parameter.name)];
      if (value !== undefined) query.set(parameter.name, value);
    }
    const page = await read(`${path}?${query}`, budget) as unknown as Page<RecordData>;
    for (const field of ['offset', 'limit', 'count', 'totalCount'] as const) {
      if (!Number.isSafeInteger(page[field]) || page[field] < 0) {
        throw new ToolError('RESPONSE_INVALID', `/${field}: expected a nonnegative safe integer.`);
      }
    }
    if (page.count !== page.data.length) throw new ToolError('RESPONSE_INVALID', '/count: does not match data length.');
    // These operations document overviews only, never connection secrets or configuration.
    if (['OP-066', 'OP-067', 'OP-068'].includes(operation.id)) {
      const fields = operation.id === 'OP-068' ? ['id', 'name'] :
        ['id', 'name', 'type', 'metadata', ...(operation.id === 'OP-066' ? ['enabled'] : [])];
      page.data = page.data.map(row => Object.fromEntries(Object.entries(row)
        .filter(([field]) => fields.includes(field))
        .map(([field, value]) => [field, field === 'metadata' ? Object.fromEntries(Object.entries(value as RecordData)
          .filter(([key]) => key === 'origin' || (key === 'source' && operation.id === 'OP-067' &&
            (value as RecordData).origin === 'DERIVED'))) : value])));
    }
    return page;
  }, row => String(row[operation.id === 'OP-003' ? 'code' : operation.id === 'OP-006' ? 'macAddress' : 'id']),
  Number(values.offset ?? 0), limit);
  const { data, ...metadata } = result;
  return { [name]: data, ...metadata };
}
