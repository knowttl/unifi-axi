import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Harness } from './writes.ts';

type Row = Record<string, unknown>;
const site = '9361553d-e20d-45b8-a516-6948ab010011';
const id = '8c850c83-1111-4111-8111-000000000001';
const neighbourId = '8c850c83-1111-4111-8111-000000000002';
const macAddress = '02:00:00:00:00:01';
export const device = { id, macAddress, name: 'Synthetic switch', configurationId: 'synthetic-configuration',
  ipAddress: '192.0.2.10', model: 'SYNTHETIC', state: 'ONLINE', supported: true, firmwareUpdatable: false,
  features: {}, interfaces: {} };
const client = { id, name: 'Synthetic guest', type: 'WIRED', macAddress, uplinkDeviceId: neighbourId,
  access: { type: 'GUEST', authorized: false } };
const authorization = { authorizationMethod: 'API', authorizedAt: '2026-10-30T12:00:00Z',
  expiresAt: '2026-10-30T13:00:00Z', dataUsageLimitMBytes: 256, rxRateLimitKbps: 1000, txRateLimitKbps: 500 };
const cases: { operation: string; command: string[]; grant: string; body: Row | null; suffix: string; outcome: string }[] = [
  { operation: 'OP-016', command: ['client', 'action', '--client-id', id], grant: 'executeConnectedClientAction',
    body: { action: 'AUTHORIZE_GUEST_ACCESS', timeLimitMinutes: 60, dataUsageLimitMBytes: 256, rxRateLimitKbps: 1000, txRateLimitKbps: 500 }, suffix: `/clients/${id}/actions`, outcome: 'accepted' },
  { operation: 'OP-016', command: ['client', 'action', '--client-id', id], grant: 'executeConnectedClientAction',
    body: { action: 'UNAUTHORIZE_GUEST_ACCESS' }, suffix: `/clients/${id}/actions`, outcome: 'accepted' },
  { operation: 'OP-019', command: ['device', 'adopt'], grant: 'adoptDevice',
    body: { macAddress, ignoreDeviceLimit: false }, suffix: '/devices', outcome: 'verified' },
  { operation: 'OP-019', command: ['device', 'adopt'], grant: 'adoptDevice',
    body: { macAddress, ignoreDeviceLimit: true }, suffix: '/devices', outcome: 'verified' },
  { operation: 'OP-020', command: ['device', 'remove', '--device-id', id], grant: 'removeDevice',
    body: null, suffix: `/devices/${id}`, outcome: 'verified' },
  { operation: 'OP-022', command: ['device', 'action', '--device-id', id], grant: 'executeAdoptedDeviceAction',
    body: { action: 'RESTART' }, suffix: `/devices/${id}/actions`, outcome: 'accepted' },
  { operation: 'OP-023', command: ['device', 'interfaces', 'ports', 'action', '--device-id', id, '--port-idx', '3'], grant: 'executePortAction',
    body: { action: 'POWER_CYCLE' }, suffix: `/devices/${id}/interfaces/ports/3/actions`, outcome: 'accepted' },
];

export async function verifyGuestDevices(h: Harness) {
  const rows: Row[] = [];
  const bodyFile = join(h.home, 'guest-device-body.json');
  const guard = fileURLToPath(new URL('./fixtures/write-guard.ts', import.meta.url));
  const env = { NODE_OPTIONS: `--import=${guard}`, UNIFI_AXI_TEST_PORT: String(h.port),
    UNIFI_AXI_WRITE_LOG: join(h.home, 'guest-device-journal') };
  const run = (args: string[], code = 0) => h.cli(args, code, env);
  for (const version of ['10.6.109', '11.0.97']) {
    for (const [index, entry] of cases.entries()) {
      if (h.task === 'B4.9' && entry.operation !== 'OP-016') continue;
      if (process.platform === 'win32') { rows.push({ task: h.task, status: 'pending-native-windows' }); continue; }
      const guest = entry.operation === 'OP-016';
      const adopt = entry.operation === 'OP-019';
      const neighbour = { ...(guest ? client : device), id: neighbourId, macAddress: '02:00:00:00:00:02', name: 'Untouched neighbour' };
      let state: Row[] = [neighbour, ...(adopt ? [] : [structuredClone(guest ? client : device)])];
      if (entry.body?.action === 'UNAUTHORIZE_GUEST_ACCESS') state[1] = { ...client,
        access: { type: 'GUEST', authorized: true, authorization } };
      const pending = { macAddress, ipAddress: '192.0.2.10', model: 'SYNTHETIC', state: 'PENDING_ADOPTION',
        supported: true, firmwareUpdatable: false, features: ['switching'], adoptionTargetSiteIds: [site] };
      let available = true;
      let failure = false;
      let completed = 0;
      let changingUsage = false;
      let changeAuthorizationAt = Infinity;
      const usageReads: number[] = [];
      const sent: { method: string; path: string; body: unknown }[] = [];
      const base = `/proxy/network/integration/v1/sites/${site}`;
      const profile = { ...h.trusted, siteId: site, writes: { allowWrites: true,
        operations: [entry.grant, ...(entry.body?.action ? [`${entry.grant}:${String(entry.body.action)}`] : [])] } };
      h.configure({ lab: profile });
      h.seed((request, response) => {
        assert.equal(request.headers['x-api-key'], h.syntheticKey);
        const url = new URL(request.url!, h.trusted.origin);
        if (url.pathname.endsWith('/info')) return { applicationVersion: version };
        if (request.method === 'GET') {
          if (url.pathname === '/proxy/network/integration/v1/pending-devices') {
            return { offset: 0, limit: 25, count: available ? 1 : 0, totalCount: available ? 1 : 0, data: available ? [pending] : [] };
          }
          const collection = `${base}/${guest ? 'clients' : 'devices'}`;
          assert.ok(url.pathname === collection || url.pathname === `${collection}/${id}` || url.pathname === `${collection}/${neighbourId}`);
          if (url.pathname !== collection) {
            const row = state.find(row => row.id === url.pathname.split('/').at(-1));
            if (changingUsage && row?.id === id) {
              const access = row.access as Row;
              if (access.authorization) {
                const durationSec = 10 + usageReads.length;
                usageReads.push(durationSec);
                return { ...row, access: { ...access, authorization: { ...access.authorization as Row,
                  ...(usageReads.length >= changeAuthorizationAt ? { expiresAt: '2026-10-30T14:00:00Z' } : {}),
                  usage: { durationSec, bytes: durationSec * 3, rxBytes: durationSec * 2, txBytes: durationSec } } } };
              }
            }
            return row;
          }
          const data = guest ? state : state.map(row => ({ ...row, features: [], interfaces: [] }));
          return { offset: 0, limit: 25, count: data.length, totalCount: data.length, data };
        }
        let bytes = '';
        request.on('data', chunk => { bytes += chunk; });
        request.on('end', () => {
          sent.push({ method: request.method!, path: request.url!, body: bytes ? JSON.parse(bytes) as unknown : null });
          if (failure) { response.statusCode = 403; response.end('{}'); return; }
          completed++;
          let result: unknown;
          if (guest) {
            const authorized = entry.body!.action === 'AUTHORIZE_GUEST_ACCESS';
            state = state.map(row => row.id === id ? { ...row, access: { type: 'GUEST', authorized,
              ...(authorized ? { authorization } : {}) } } : row);
            result = { action: entry.body!.action, ...(authorized ? { grantedAuthorization: authorization } : { revokedAuthorization: authorization }) };
          } else if (adopt) { state.push(device); available = false; result = device; }
          else if (entry.operation === 'OP-020') state = state.filter(row => row.id !== id);
          response.statusCode = 200;
          response.end(result === undefined ? '' : JSON.stringify(result));
        });
      });
      const args = [...entry.command, ...(entry.body ? ['--body-file', bodyFile] : [])];
      const execute = (confirmation: string, label: string) => [...args, '--execute', '--confirm', confirmation,
        '--request-id', `${label}-${index}-${version}`];
      if (entry.body) writeFileSync(bodyFile, JSON.stringify(entry.body), { mode: 0o600 });
      if (version === '11.0.97' && !guest) {
        const initial = structuredClone(state);
        assert.equal((await run(args, 1)).error.code, 'CONTRACT_CONFLICT');
        assert.equal((await run(execute('unavailable', 'conflict'), 1)).error.code, 'CONTRACT_CONFLICT');
        assert.deepEqual(sent, []);
        assert.deepEqual(state, initial);
        rows.push({ task: 'B4.10', operation: entry.operation, version, variant: index,
          status: 'blocked-by-CF-007', direction: 'preview-and-execution-refuse-before-mutation' });
        continue;
      }
      const confirmation = (await run(args)).preview.confirmation;
      assert.equal(sent.length, 0, 'Preview sends zero mutations');
      if (entry.body) {
        writeFileSync(bodyFile, JSON.stringify({ ...entry.body, ...(entry.body.action ? { action: 'UNSUPPORTED' } : { ignoreDeviceLimit: 'false' }) }));
        assert.equal((await run(args, 1)).error.code, 'INVALID_ARGUMENT');
        writeFileSync(bodyFile, JSON.stringify(entry.body));
      }
      h.configure({ lab: { ...profile, writes: { allowWrites: true, operations: [entry.body?.action ? entry.grant : 'unrelatedOperation',
        ...(entry.body?.action ? [`${entry.grant}:${entry.body.action === 'AUTHORIZE_GUEST_ACCESS' ? 'UNAUTHORIZE_GUEST_ACCESS' : 'AUTHORIZE_GUEST_ACCESS'}`] : [])] } } });
      assert.equal((await run(execute(confirmation, 'denied'), 1)).error.code, 'WRITE_DENIED');
      h.configure({ lab: profile });
      const driftArgs = args.map(value => value === id ? neighbourId : value);
      if (!adopt) {
        assert.equal((await run([...driftArgs, '--execute', '--confirm', confirmation, '--request-id', `drift-${index}-${version}`], 1)).error.code, 'CONFIRMATION_MISMATCH');
      } else {
        writeFileSync(bodyFile, JSON.stringify({ ...entry.body, ignoreDeviceLimit: !entry.body!.ignoreDeviceLimit }));
        assert.equal((await run(execute(confirmation, 'drift'), 1)).error.code, 'CONFIRMATION_MISMATCH');
        writeFileSync(bodyFile, JSON.stringify(entry.body));
      }
      assert.equal(sent.length, 0, 'Malformed, denied and stale requests send zero mutations');
      failure = true;
      assert.equal((await run(execute(confirmation, 'http-failure'), 1)).write.outcome, 'unknown');
      assert.equal(completed, 0);
      failure = false;
      const result = await run(execute(confirmation, 'success'));
      assert.equal(result.write.outcome, entry.outcome);
      assert.deepEqual(sent.at(-1), { method: entry.body ? 'POST' : 'DELETE', path: base + entry.suffix, body: entry.body });
      assert.equal(completed, 1);
      assert.deepEqual(state[0], neighbour);
      if (guest) assert.deepEqual(state[1], { ...client, access: { type: 'GUEST', authorized: entry.body!.action === 'AUTHORIZE_GUEST_ACCESS',
        ...(entry.body!.action === 'AUTHORIZE_GUEST_ACCESS' ? { authorization } : {}) } });
      else assert.deepEqual(state, entry.operation === 'OP-020' ? [neighbour] : [neighbour, device]);
      assert.equal((await run(execute(confirmation, 'success'))).write.outcome, entry.outcome);
      assert.equal(sent.length, 2, 'Repeated request ID reads instead of resending');
      assert.equal(completed, 1);
      if (guest) {
        changingUsage = true;
        for (const [stage, changedAt, error] of [
          ['execution', 2, 'CONFIRMATION_MISMATCH'],
          ['dispatch', 3, 'WRITE_DRIFT'],
          ['usage-only', Infinity, null],
        ] as const) {
          state = [neighbour, { ...client, access: { type: 'GUEST', authorized: true, authorization } }];
          usageReads.length = 0;
          changeAuthorizationAt = changedAt;
          const previousSent: number = sent.length;
          const preview = await run(args);
          const result = await run(execute(preview.preview.confirmation, stage), error ? 1 : 0);
          if (error) {
            assert.equal(result.error.code, error);
            assert.equal(sent.length, previousSent, 'Authorization changes refuse before mutation');
          } else {
            assert.equal(result.write.outcome, 'accepted');
            assert.deepEqual(usageReads.slice(0, 3), [10, 11, 12], 'Usage changes through preview, execution and dispatch');
            assert.deepEqual(sent.slice(previousSent), [{ method: 'POST', path: base + entry.suffix, body: entry.body }]);
            assert.deepEqual(state[1], { ...client, access: { type: 'GUEST', authorized: entry.body!.action === 'AUTHORIZE_GUEST_ACCESS',
              ...(entry.body!.action === 'AUTHORIZE_GUEST_ACCESS' ? { authorization } : {}) } });
          }
          assert.deepEqual(state[0], neighbour);
        }
      }
      rows.push({ task: guest ? 'B4.9' : 'B4.10', operation: entry.operation, version, action: entry.body?.action,
        variant: index, status: 'passed', direction: 'exact-request-target-grants-drift-http-failure-and-replay' });
    }
  }
  return rows;
}
