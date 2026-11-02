import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Harness } from './writes.ts';
import { firewallBody, firewallRecord, id, neighbourId, site, type Row } from './policy-fixtures.ts';
import { obligations } from './variant-coverage.ts';

interface Source { components: { schemas: Record<string, {
  discriminator?: { mapping: Record<string, string> }; properties?: { name?: { enum?: string[] } };
}> } }

export function protocolVariants(version: string) {
  const source = JSON.parse(readFileSync(new URL(`../evidence/sources/network-${version}-openapi.json`, import.meta.url), 'utf8')) as Source;
  const selected = new Map<string, { ipVersion: string; name: string }>();
  for (const variant of obligations.cases) {
    if (!variant.versions.includes(version) || !variant.schema?.includes('named protocol')) continue;
    const name = variant.tag?.property === 'name' ? variant.tag.value : variant.value;
    if (typeof name !== 'string') continue;
    const schema = variant.schema.replace('/properties/name', '').replace('#/components/schemas/', '');
    const definition = source.components.schemas[schema];
    const tag = name.toUpperCase().replaceAll('-', '_').replaceAll('.', '_');
    if (!definition?.discriminator?.mapping[tag]) continue;
    const values = definition.properties?.name?.enum ?? [];
    const wireName = values.includes(name.toLowerCase()) ? name :
      values.find(value => value.toUpperCase().replaceAll('-', '_').replaceAll('.', '_') === tag);
    if (wireName === undefined) continue;
    const ipVersion = schema.includes('IPv4 and IPv6') ? 'IPV4_AND_IPV6' : schema.includes('IPv4') ? 'IPV4' : 'IPV6';
    selected.set(`${ipVersion}:${wireName}`, { ipVersion, name: wireName });
  }
  return [...selected.values()];
}

export async function verifyProtocolVariants(h: Harness) {
  const file = join(h.home, 'protocol-variant.json');
  const run = (args: string[]) => h.cli(args, 0, { UNIFI_AXI_WRITE_LOG: join(h.home, 'protocol-variant-journal') });
  const base = `/proxy/network/integration/v1/sites/${site}/firewall/policies`;
  h.configure({ lab: { ...h.trusted, siteId: site, writes: { allowWrites: true,
    operations: ['createFirewallPolicy', 'updateFirewallPolicy', 'patchFirewallPolicy'] } } });
  for (const version of ['10.6.109', '11.0.97']) {
    for (const [index, { ipVersion, name }] of protocolVariants(version).entries()) {
      const body = { ...firewallBody(version), ipProtocolScope: { ipVersion,
        protocolFilter: { type: 'NAMED_PROTOCOL', matchOpposite: false, protocol: { name } } } };
      const record = firewallRecord(version, body);
      const neighbour = { ...firewallRecord(version), id: neighbourId, index: 1, name: 'Untouched neighbour' };
      let state: Row[] = [neighbour, record];
      const sent: { method: string; path: string; body: Row }[] = [];
      h.seed((request, response) => {
        assert.equal(request.headers['x-api-key'], h.syntheticKey);
        const url = new URL(request.url!, h.trusted.origin);
        if (url.pathname.endsWith('/info')) return { applicationVersion: version };
        if (request.method === 'GET') {
          if (url.pathname === base) return { offset: 0, limit: 25, count: state.length, totalCount: state.length, data: state };
          assert.equal(url.pathname, `${base}/${id}`);
          return state.find(row => row.id === id);
        }
        let bytes = '';
        request.on('data', chunk => { bytes += chunk; });
        request.on('end', () => {
          const received = JSON.parse(bytes) as Row;
          sent.push({ method: request.method!, path: request.url!, body: received });
          const updated = { ...record, ...received, ipProtocolScope: body.ipProtocolScope };
          state = [neighbour, updated];
          response.statusCode = request.method === 'POST' ? 201 : 200;
          response.end(JSON.stringify(updated));
        });
      });
      assert.deepEqual((await run(['firewall', 'policy', 'list']) as unknown as { firewallPolicies: Row[] }).firewallPolicies, state);
      assert.deepEqual((await run(['firewall', 'policy', 'show', '--firewall-policy-id', id]) as unknown as { firewallPolicy: Row }).firewallPolicy, record);
      if (process.platform === 'win32') continue;
      for (const [action, method] of [['create', 'POST'], ['update', 'PUT'], ['patch', 'PATCH']] as const) {
        state = action === 'create' ? [neighbour] : [neighbour, record];
        sent.length = 0;
        const requested = action === 'patch' ? { loggingEnabled: true } : body;
        writeFileSync(file, JSON.stringify(requested), { mode: 0o600 });
        const args = ['firewall', 'policy', action, '--body-file', file, ...(action === 'create' ? [] : ['--firewall-policy-id', id])];
        const confirmation = (await run(args)).preview.confirmation;
        assert.deepEqual(sent, []);
        assert.equal((await run([...args, '--execute', '--confirm', confirmation,
          '--request-id', `ledger-${version}-${index}-${action}`])).write.outcome, 'verified');
        const expected = action === 'patch' ? requested : { ...body, ipProtocolScope: { ipVersion,
          protocolFilter: { type: 'NAMED_PROTOCOL', matchOpposite: false, protocol: { name: name.toLowerCase() } } } };
        assert.deepEqual(sent, [{ method, path: action === 'create' ? base : `${base}/${id}`, body: expected }]);
        assert.deepEqual(state, [neighbour, { ...record, ...(action === 'patch' ? requested : {}) }]);
      }
    }
  }
}
