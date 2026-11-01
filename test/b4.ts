import assert from 'node:assert/strict';
import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Harness } from './writes.ts';

const site = '9361553d-e20d-45b8-a516-6948ab010011';
const id = '8c850c83-1111-4111-8111-000000000001';
const other = '8c850c83-1111-4111-8111-000000000002';
const metadata = { origin: 'USER_DEFINED' };
const base = { name: 'Synthetic network', management: 'UNMANAGED', enabled: true, vlanId: 42 };
const neighbour = { ...base, name: 'Untouched network', id: other, vlanId: 7, default: false, metadata };
const ipv4 = { autoScaleEnabled: false, hostIpAddress: '192.0.2.1', prefixLength: 24, additionalHostIpSubnets: ['198.51.100.1/24'] };
const bodies = [
  { ...base, dhcpGuarding: null },
  { ...base, management: 'SWITCH', deviceId: other, cellularBackupEnabled: false, isolationEnabled: true,
    ipv4Configuration: ipv4, dhcpGuarding: { trustedDhcpServerIpAddresses: ['192.0.2.53'] } },
  { ...base, management: 'GATEWAY', cellularBackupEnabled: true, isolationEnabled: false, internetAccessEnabled: true,
    mdnsForwardingEnabled: false, zoneId: other, ipv4Configuration: ipv4 },
  ...['SWITCH', 'GATEWAY'].flatMap(management => ['RELAY', 'SERVER'].map(mode => ({
    ...base, management, cellularBackupEnabled: false, isolationEnabled: true,
    ...(management === 'SWITCH' ? { deviceId: other } : { internetAccessEnabled: false, mdnsForwardingEnabled: true,
      ipv6Configuration: mode === 'RELAY' ? { interfaceType: 'PREFIX_DELEGATION', prefixDelegationWanInterfaceId: other,
        clientAddressAssignment: { slaacEnabled: true }, routerAdvertisement: { priority: 'LOW' } } :
        { interfaceType: 'STATIC', hostIpAddress: '2001:db8::1', prefixLength: 64,
          clientAddressAssignment: { slaacEnabled: true }, routerAdvertisement: { priority: 'MEDIUM' } } }),
    ipv4Configuration: { ...ipv4, dhcpConfiguration: mode === 'RELAY' ? { mode, dhcpServerIpAddresses: ['192.0.2.53'] } :
      { mode, ipAddressRange: { start: '192.0.2.10', stop: '192.0.2.100' }, leaseTimeSeconds: 3600,
        dnsServerIpAddressesOverride: ['192.0.2.53'], domainName: 'synthetic.example',
        ...(management === 'GATEWAY' ? { pingConflictDetectionEnabled: true } : {}) },
      ...(management === 'GATEWAY' ? { natOutboundIpAddressConfiguration: [
        { type: 'AUTO', wanInterfaceId: other, ipAddressSelectionMode: 'ALL' },
        { type: 'AUTO', wanInterfaceId: id, ipAddressSelectionMode: 'MAIN' },
        { type: 'STATIC', wanInterfaceId: other, ipAddressSelectors: [
          { type: 'IP_ADDRESS', value: '203.0.113.10' }, { type: 'IP_ADDRESS_RANGE', start: '203.0.113.20', stop: '203.0.113.30' }] },
      ] } : {}) },
  }))),
  { ...base, management: 'GATEWAY', cellularBackupEnabled: false, isolationEnabled: true, internetAccessEnabled: true,
    mdnsForwardingEnabled: false, ipv4Configuration: ipv4, ipv6Configuration: { interfaceType: 'STATIC',
      hostIpAddress: '2001:db8:1::1', prefixLength: 64, clientAddressAssignment: { slaacEnabled: true },
      routerAdvertisement: { priority: 'HIGH' } } },
];
const variantCases = [
  ['VAR-034', 'VAR-214'], ['VAR-033', 'VAR-213'], ['VAR-032', 'VAR-212'],
  ['VAR-033', 'VAR-213', 'VAR-226'], ['VAR-033', 'VAR-213', 'VAR-227'],
  ['VAR-032', 'VAR-212', 'VAR-185', 'VAR-210', 'VAR-995', 'VAR-255', 'VAR-256', 'VAR-190', 'VAR-191', 'VAR-966', 'VAR-967'],
  ['VAR-032', 'VAR-212', 'VAR-186', 'VAR-211', 'VAR-997', 'VAR-255', 'VAR-256', 'VAR-190', 'VAR-191', 'VAR-966', 'VAR-967'],
  ['VAR-032', 'VAR-212', 'VAR-211', 'VAR-996'],
];
const voucher = { id, name: 'Synthetic voucher', code: 'VOUCHER-CANARY-48291', authorizedGuestCount: 0,
  createdAt: '2026-10-30T12:00:00Z', expired: false, timeLimitMinutes: 60 };
const wifi = { id, name: 'Synthetic Wi-Fi', type: 'STANDARD', metadata, enabled: true, broadcastingFrequenciesGHz: [2.4, 5],
  channel2gLockedTo6: false, clientIsolationEnabled: true, dtimPeriod2gLockedTo3: false, hideName: false,
  multicastToUnicastConversionEnabled: true, uapsdEnabled: true, advertiseDeviceName: false, arpProxyEnabled: true,
  bssTransitionEnabled: true, basicDataRateKbpsByFrequencyGHz: { '2.4': 2000, '5': 6000 },
  securityConfiguration: { type: 'WPA2_PERSONAL', passphrase: 'WIFI-CANARY-48291',
    presharedKeys: [{ passphrase: 'PPSK-CANARY-48291', network: { type: 'SPECIFIC', networkId: other } }] } };

export async function verifyB4(h: Harness) {
  const rows: Record<string, unknown>[] = [];
  const env = { UNIFI_AXI_WRITE_LOG: join(h.home, 'b4-journal') };
  const run = (args: string[], code = 0, overrides: Record<string, string> = {}) => h.cli(args, code, { ...env, ...overrides });
  const profile = { ...h.trusted, siteId: site, writes: { allowWrites: true,
    operations: ['deleteNetwork', ...['createNetwork', 'updateNetwork'].flatMap(op => [op, ...['UNMANAGED', 'SWITCH', 'GATEWAY'].map(tag => `${op}:${tag}`)])] } };
  const exportProfile = { ...profile, allowSecretExport: true };
  h.configure({ lab: exportProfile });
  for (const version of ['10.6.109', '11.0.97']) {
    for (const [operation, words, resource] of [
      ['OP-044', ['hotspot', 'voucher', 'list'], 'voucher'],
      ['OP-047', ['hotspot', 'voucher', 'show', '--voucher-id', id], 'voucher'],
      ['OP-069', ['wifi', 'broadcast', 'list'], 'wifi'],
      ['OP-072', ['wifi', 'broadcast', 'show', '--wifi-broadcast-id', id], 'wifi'],
    ] as const) {
      const expected = resource === 'voucher' ? [{ id, path: '/code', value: voucher.code }] : [
        { id, path: '/securityConfiguration/passphrase', value: wifi.securityConfiguration.passphrase },
        { id, path: '/securityConfiguration/presharedKeys/0/passphrase', value: wifi.securityConfiguration.presharedKeys[0]!.passphrase },
      ];
      h.seed(request => {
        assert.equal(request.method, 'GET');
        assert.equal(request.headers['x-api-key'], h.syntheticKey);
        const url = new URL(request.url!, h.trusted.origin);
        if (url.pathname.endsWith('/info')) return { applicationVersion: version };
        const row = resource === 'voucher' ? voucher : wifi;
        const injected = { ...row, apiKey: h.syntheticKey, echo: h.syntheticKey, unexpected: { passphrase: 'NEVER-EXPORT' } };
        return url.pathname.endsWith(`/${id}`) ? injected : { offset: 0, limit: 25, count: 1, totalCount: 1, data: [injected] };
      });
      const destination = join(h.home, `${operation}-${version}.json`);
      const args = [...words, '--secret-output', destination];
      h.configure({ lab: profile });
      const refusedFile = join(h.home, `disabled-${operation}-${version}.json`);
      const beforeRefusal = h.requests().length;
      assert.deepEqual((await run([...words, '--secret-output', refusedFile], 1)).error, {
        code: 'SECRET_EXPORT_DENIED', message: 'Set allowSecretExport: true in the selected profile to enable --secret-output.',
      });
      assert.equal(h.requests().length, beforeRefusal, 'A profile without standing export opt-in sends no vendor request');
      assert.equal(existsSync(refusedFile), false);
      h.configure({ lab: exportProfile });
      const result = await run(args, 0, { UNIFI_AXI_READ_ONLY: 'true' });
      assert.deepEqual(result, { ids: [id], receipt: { operation, path: destination, delivered: true } });
      assert.deepEqual(JSON.parse(readFileSync(destination, 'utf8')), { operation, secrets: expected });
      if (process.platform !== 'win32') {
        assert.equal(statSync(destination).mode & 0o777, 0o600);
        assert.equal(statSync(destination).uid, process.getuid!());
      }
      const before = readFileSync(destination, 'utf8');
      assert.equal((await run(args, 1)).error.code, 'OUTPUT_EXISTS');
      assert.equal(readFileSync(destination, 'utf8'), before, 'Existing exports are never replaced');
      const denied = join(h.home, `hosted-${operation}-${version}.json`);
      const requests = h.requests().length;
      assert.equal((await run([...words, '--secret-output', denied], 1, { UNIFI_AXI_HOSTED: '1' })).error.code, 'HOSTED_DENIED');
      assert.equal(h.requests().length, requests, 'Hosted export fails before vendor access');
      assert.equal(existsSync(denied), false);
      rows.push({ task: 'B4.0', acceptance: 'STEP-B4.0', operation, version, status: 'passed',
        direction: 'private-response-export-and-host-denial' });
    }
    // Authentication material at an allowlisted response location is still removed.
    for (const [index, code] of [h.syntheticKey, JSON.stringify(h.syntheticKey).slice(1, -1), encodeURIComponent(h.syntheticKey)].entries()) {
      h.seed(request => request.url!.endsWith('/info') ? { applicationVersion: version } : { ...voucher, code });
      const keyFile = join(h.home, `auth-in-code-${version}-${index}.json`);
      await run(['hotspot', 'voucher', 'show', '--voucher-id', id, '--secret-output', keyFile]);
      assert.deepEqual(JSON.parse(readFileSync(keyFile, 'utf8')).secrets, [{ id, path: '/code', value: '[REDACTED]' }]);
    }
    h.seed(request => request.url!.endsWith('/info') ? { applicationVersion: version } : { ...voucher, expired: 'false' });
    const failedFile = join(h.home, `failed-export-${version}.json`);
    assert.equal((await run(['hotspot', 'voucher', 'show', '--voucher-id', id, '--secret-output', failedFile], 1)).error.code, 'RESPONSE_INVALID');
    assert.equal(existsSync(failedFile), false, 'Failed reads discard the empty reservation');
    if (h.task === 'B4.0') continue;
    if (process.platform === 'win32') {
      rows.push({ task: 'B4.1', status: 'pending-native-windows', reason: 'Durable native Windows mutations remain unavailable.' });
      continue;
    }
    h.configure({ lab: profile });
    const bodyFile = join(h.home, 'b4-network.json');
    for (const [index, body] of bodies.entries()) {
      const variant = `${body.management}-${index}`;
      const responseMetadata = { origin: ['USER_DEFINED', 'SYSTEM_DEFINED', 'ORCHESTRATED'][index % 3]! };
      let state: Record<string, unknown>[] = [neighbour];
      const sent: { method: string; path: string; body: unknown }[] = [];
      let lostAck = false;
      let failAfterAck = false;
      let failVerification = false;
      h.seed((request, response) => {
        assert.equal(request.headers['x-api-key'], h.syntheticKey);
        const url = new URL(request.url!, h.trusted.origin);
        if (url.pathname.endsWith('/info')) return { applicationVersion: version };
        const path = `/proxy/network/integration/v1/sites/${site}/networks`;
        if (request.method === 'GET') {
          if (failVerification) {
            failVerification = false;
            response.statusCode = 400;
            return {};
          }
          if (url.pathname === path) return { offset: 0, limit: 25, count: state.length, totalCount: state.length, data: state };
          assert.equal(url.pathname, `${path}/${id}`);
          return state.find(row => row.id === id);
        }
        assert.equal(url.pathname, request.method === 'POST' ? path : `${path}/${id}`);
        let bytes = '';
        request.on('data', chunk => { bytes += chunk; });
        request.on('end', () => {
          const parsed = bytes ? JSON.parse(bytes) as unknown : null;
          sent.push({ method: request.method!, path: request.url!, body: parsed });
          if (request.method === 'DELETE') state = state.filter(row => row.id !== id);
          else {
            const row = { ...(parsed as Record<string, unknown>), id, default: false, metadata: responseMetadata };
            state = request.method === 'POST' ? [...state, row] : state.map(old => old.id === id ? row : old);
          }
          if (lostAck) { request.socket.destroy(); return; }
          failVerification = failAfterAck;
          response.statusCode = request.method === 'POST' ? 201 : 200;
          response.end(request.method === 'DELETE' ? '' : JSON.stringify(state.find(row => row.id === id)));
        });
      });
      for (const [verb, operation, method] of [['create', 'OP-049', 'POST'], ['update', 'OP-052', 'PUT']] as const) {
        const requested = verb === 'create' ? body : { ...body, name: 'Replacement name', enabled: false };
        writeFileSync(bodyFile, JSON.stringify(requested), { mode: 0o600 });
        const args = ['network', verb, '--body-file', bodyFile, ...(verb === 'update' ? ['--network-id', id] : [])];
        const preview = (await run(args)).preview.confirmation;
        const requestId = `${verb}-${variant}-${version}`;
        const execute = [...args, '--execute', '--confirm', preview, '--request-id', requestId];
        const before = sent.length;
        h.configure({ lab: { ...profile, writes: { allowWrites: true, operations: [`${verb}Network`] } } });
        assert.equal((await run(execute, 1)).error.code, 'WRITE_DENIED');
        assert.equal(sent.length, before);
        h.configure({ lab: profile });
        assert.equal((await run(execute)).write.outcome, 'verified');
        assert.deepEqual(sent.slice(before), [{ method, path: `/proxy/network/integration/v1/sites/${site}/networks${verb === 'update' ? `/${id}` : ''}`, body: requested }]);
        assert.deepEqual(state, [neighbour, { ...requested, id, default: false, metadata: responseMetadata }]);
        assert.equal((await run(execute)).write.outcome, 'verified');
        assert.equal(sent.length, before + 1, 'Repeated ownership never sends a second write');
        writeFileSync(bodyFile, JSON.stringify({ ...requested, enabled: true, name: 'Drifted name' }));
        assert.equal((await run([...args, '--execute', '--confirm', preview, '--request-id', `drift-${requestId}`], 1)).error.code, 'CONFIRMATION_MISMATCH');
        assert.equal(sent.length, before + 1);
        writeFileSync(bodyFile, JSON.stringify({ ...requested, unexpected: true }));
        assert.equal((await run(args, 1)).error.code, 'INVALID_ARGUMENT');
        rows.push({ task: 'B4.1', acceptance: `AC-${operation.slice(3)}`, operation, version,
          variant, cases: [...variantCases[index]!, ['VAR-247', 'VAR-246', 'VAR-245'][index % 3]!, 'VAR-1029', 'VAR-1062'],
          status: 'passed', direction: 'preview-exact-request-state-and-no-replay' });
      }
      if (index === 0) {
        const requested = { ...body, name: 'Pending verification' };
        writeFileSync(bodyFile, JSON.stringify(requested));
        const update = ['network', 'update', '--network-id', id, '--body-file', bodyFile];
        const confirmation = (await run(update)).preview.confirmation;
        const execute = [...update, '--execute', '--confirm', confirmation, '--request-id', `pending-update-${version}`];
        const before = sent.length;
        failAfterAck = true;
        const accepted = await run(execute);
        assert.equal(accepted.write.outcome, 'accepted');
        failAfterAck = false;
        const repeated = await run(execute);
        assert.equal(repeated.write.auditId, accepted.write.auditId);
        assert.equal(repeated.write.outcome, 'verified');
        assert.deepEqual(repeated.reconciliation, { outcome: 'verified', readOnly: true });
        assert.equal(sent.length, before + 1, 'An accepted update reconciles without another mutation');
        assert.deepEqual(state, [neighbour, { ...requested, id, default: false, metadata: responseMetadata }]);
        rows.push({ task: 'B4.1', operation: 'OP-052', version, status: 'passed', direction: 'accepted-update-replay-reconciliation' });
      }
      const remove = ['network', 'delete', '--network-id', id];
      const defaultConfirmation = (await run(remove)).preview.confirmation;
      assert.equal((await run([...remove, '--force', 'false'])).preview.confirmation, defaultConfirmation);
      const force = (await run([...remove, '--force', 'true'])).preview.confirmation;
      assert.notEqual(force, defaultConfirmation);
      assert.equal((await run([...remove, '--force', 'true', '--execute', '--confirm', defaultConfirmation,
        '--request-id', `wrong-force-${variant}-${version}`], 1)).error.code, 'CONFIRMATION_MISMATCH');
      assert.equal((await run([...remove, '--force', 'true', '--execute', '--confirm', force,
        '--request-id', `delete-${variant}-${version}`])).write.outcome, 'verified');
      assert.deepEqual(state, [neighbour]);
      assert.deepEqual(sent.at(-1), { method: 'DELETE', path: `/proxy/network/integration/v1/sites/${site}/networks/${id}?force=true`, body: null });
      // Most likely transport failure: a lost update acknowledgement must never resend.
      state = [neighbour, { ...body, id, default: false, metadata }];
      writeFileSync(bodyFile, JSON.stringify({ ...body, name: 'Lost acknowledgement' }));
      const update = ['network', 'update', '--network-id', id, '--body-file', bodyFile];
      const confirmation = (await run(update)).preview.confirmation;
      const execute = [...update, '--execute', '--confirm', confirmation, '--request-id', `lost-update-${variant}-${version}`];
      lostAck = true;
      assert.equal((await run(execute, 1)).write.outcome, 'unknown');
      const count = sent.length;
      assert.equal((await run(execute, 1)).write.outcome, 'unknown');
      assert.equal(sent.length, count);
      assert.deepEqual(state, [neighbour, { ...body, name: 'Lost acknowledgement', id, default: false, metadata: responseMetadata }]);
    }
    for (const invalid of [
      { ...base, management: 'UNKNOWN' },
      { ...base, management: 'GATEWAY' },
      { ...base, management: 'SWITCH', deviceId: other, cellularBackupEnabled: false, isolationEnabled: false, ipv4Configuration: null },
      { ...base, dhcpGuarding: false },
    ]) {
      writeFileSync(bodyFile, JSON.stringify(invalid));
      assert.equal((await run(['network', 'create', '--body-file', bodyFile], 1)).error.code, 'INVALID_ARGUMENT');
    }
    rows.push({ task: 'B4.1', acceptance: 'STEP-B4.1', operation: 'OP-050', version, status: 'passed', direction: 'force-bound-deletion' });
  }
  return rows;
}
