import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Harness } from './writes.ts';
import { aclBodies, firewallRecord, id, neighbourId, site, type Row } from './policy-fixtures.ts';
import { dnsBodies, trafficBodies } from './dns-traffic-fixtures.ts';
import { wifi } from './wifi-vouchers.ts';
import { device } from './guest-devices.ts';

// These ten routes have a 200 response without content in both retained contracts.
const routes = [
  { operation: 'OP-011', command: 'acl-rule delete', path: 'acl-rules', flag: 'acl-rule-id', grant: 'deleteAclRule', row: aclBodies[0]! },
  { operation: 'OP-020', command: 'device remove', path: 'devices', flag: 'device-id', grant: 'removeDevice', row: device },
  { operation: 'OP-022', command: 'device action', path: 'devices', flag: 'device-id', grant: 'executeAdoptedDeviceAction', row: device, body: { action: 'RESTART' }, suffix: '/actions' },
  { operation: 'OP-023', command: 'device interfaces ports action', path: 'devices', flag: 'device-id', grant: 'executePortAction', row: device, body: { action: 'POWER_CYCLE' }, suffix: '/interfaces/ports/3/actions' },
  { operation: 'OP-027', command: 'dns policy delete', path: 'dns/policies', flag: 'dns-policy-id', grant: 'deleteDnsPolicy', row: dnsBodies[0]! },
  { operation: 'OP-034', command: 'firewall policy delete', path: 'firewall/policies', flag: 'firewall-policy-id', grant: 'deleteFirewallPolicy' },
  { operation: 'OP-040', command: 'firewall zone delete', path: 'firewall/zones', flag: 'firewall-zone-id', grant: 'deleteFirewallZone', row: { name: 'Synthetic zone', networkIds: [] } },
  { operation: 'OP-050', command: 'network delete', path: 'networks', flag: 'network-id', grant: 'deleteNetwork', row: { name: 'Synthetic network', management: 'UNMANAGED', enabled: true, vlanId: 42, default: false } },
  { operation: 'OP-063', command: 'traffic-list delete', path: 'traffic-matching-lists', flag: 'traffic-matching-list-id', grant: 'deleteTrafficMatchingList', row: trafficBodies[0]! },
  { operation: 'OP-071', command: 'wifi broadcast delete', path: 'wifi/broadcasts', flag: 'wifi-broadcast-id', grant: 'deleteWifiBroadcast', row: wifi },
];

export async function verifyBodyless(h: Harness) {
  const rows: Row[] = [];
  const bodyFile = join(h.home, 'bodyless-action.json');
  const run = (args: string[], code = 0) => h.cli(args, code, { UNIFI_AXI_WRITE_LOG: join(h.home, 'bodyless-journal') });
  for (const version of ['10.6.109', '11.0.97']) {
    for (const route of routes) {
      const profile = { ...h.trusted, siteId: site, writes: { allowWrites: true,
        operations: [route.grant, ...(route.body ? [`${route.grant}:${route.body.action}`] : [])] } };
      const target = { ...(route.row ?? firewallRecord(version)), id, index: 0, metadata: { origin: 'USER_DEFINED' } };
      const neighbour = { ...target, id: neighbourId, name: 'Untouched neighbour' };
      const base = `/proxy/network/integration/v1/sites/${site}/${route.path}`;
      const args = [...route.command.split(' '), `--${route.flag}`, id,
        ...(route.operation === 'OP-023' ? ['--port-idx', '3'] : []),
        ...(route.body ? ['--body-file', bodyFile] : [])];
      if (route.body) writeFileSync(bodyFile, JSON.stringify(route.body), { mode: 0o600 });
      for (const mode of ['success', 'http-failure', 'verification-failure']) {
        h.configure({ lab: profile });
        let state: Row[] = [neighbour, target];
        const sent: unknown[] = [];
        let acknowledged = false;
        let verificationRestored = false;
        h.seed((request, response) => {
          assert.equal(request.headers['x-api-key'], h.syntheticKey);
          const url = new URL(request.url!, h.trusted.origin);
          if (url.pathname.endsWith('/info')) return { applicationVersion: version };
          if (request.method === 'GET') {
            if (acknowledged && mode === 'verification-failure' && !verificationRestored) {
              response.statusCode = 503;
              return {};
            }
            if (url.pathname === base) {
              const data = route.path === 'devices' ? state.map(row => ({ ...row, features: [], interfaces: [] })) : state;
              return { offset: 0, limit: 25, count: data.length, totalCount: data.length, data };
            }
            assert.equal(url.pathname, `${base}/${id}`);
            return target;
          }
          assert.equal(url.pathname, `${base}/${id}${route.suffix ?? ''}`);
          assert.equal(url.search, ['OP-050', 'OP-071'].includes(route.operation) ? '?force=false' : '', `${route.operation} ${version}`);
          let bytes = '';
          request.on('data', chunk => { bytes += chunk; });
          request.on('end', () => {
            sent.push({ method: request.method, body: bytes ? JSON.parse(bytes) as unknown : null });
            if (mode === 'http-failure') { response.statusCode = 403; response.end(); return; }
            if (!route.body) state = [neighbour];
            acknowledged = true;
            response.statusCode = 200;
            response.end();
          });
        });
        if (version === '11.0.97' && route.path === 'devices') {
          assert.equal((await run(args, 1)).error.code, 'CONTRACT_CONFLICT');
          assert.deepEqual(sent, []);
          rows.push({ task: 'B4.11', acceptance: 'NORM-002', operation: route.operation, version,
            status: 'blocked-by-CF-007', mode });
          continue;
        }
        const confirmation = (await run(args)).preview.confirmation;
        assert.deepEqual(sent, [], 'Preview never mutates');
        const requestId = `bodyless-${route.operation}-${version}-${mode}`;
        const execute = [...args, '--execute', '--confirm', confirmation, '--request-id', requestId];
        const outcome = mode === 'http-failure' ? 'unknown' : mode === 'verification-failure' || route.body ? 'accepted' : 'verified';
        const result = await run(execute, mode === 'http-failure' ? 1 : 0);
        assert.equal(result.write.outcome, outcome, `${route.operation} ${version} ${mode}`);
        assert.deepEqual(sent, [{ method: route.body ? 'POST' : 'DELETE', body: route.body ?? null }]);
        assert.deepEqual(state, mode === 'http-failure' || route.body ? [neighbour, target] : [neighbour]);
        verificationRestored = true;
        assert.equal((await run(['write', 'show', '--request-id', requestId], mode === 'http-failure' ? 1 : 0)).write.outcome, outcome);
        const recovered = mode === 'verification-failure' && !route.body ? 'verified' : outcome;
        assert.equal((await run(execute, mode === 'http-failure' ? 1 : 0)).write.outcome, recovered);
        assert.equal(sent.length, 1, 'A failed status or verification never permits replay');
        if (mode === 'http-failure') assert.equal(result.error.code, 'OUTCOME_UNKNOWN');
        rows.push({ task: 'B4.11', acceptance: 'NORM-002', operation: route.operation, version, mode, outcome, status: 'passed' });
      }
    }
  }
  return rows;
}
