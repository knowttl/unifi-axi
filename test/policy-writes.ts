import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Harness } from './writes.ts';
import { aclBodies, firewallBody, firewallRecord, firewallVariants, id, neighbourId, otherSite, site, type Row } from './policy-fixtures.ts';
import { dnsBodies, trafficBodies, dnsTrafficCases } from './dns-traffic-fixtures.ts';

export async function verifyPolicyWrites(h: Harness) {
  if (process.platform === 'win32') return [{ status: 'pending-native-windows', task: h.task }];
  const bodyFile = join(h.home, 'policy-body.json');
  const guard = fileURLToPath(new URL('./fixtures/write-guard.ts', import.meta.url));
  const env = { NODE_OPTIONS: `--import=${guard}`, UNIFI_AXI_TEST_PORT: String(h.port), UNIFI_AXI_WRITE_LOG: join(h.home, 'policy-journal') };
  const run = (args: string[], code = 0) => h.cli(args, code, env);
  let serial = 0;
  const execute = (command: string[], confirmation: string, requestId = `policy-${++serial}`) =>
    [...command, '--execute', '--confirm', confirmation, '--request-id', requestId];
  const rows: Row[] = [];
  for (const version of ['10.6.109', '11.0.97']) {
    for (const family of [
      { task: 'B4.2', command: 'firewall policy', path: 'firewall/policies', flag: 'firewall-policy-id',
        bodies: firewallVariants(version), grants: ['createFirewallPolicy', 'updateFirewallPolicy', 'patchFirewallPolicy', 'deleteFirewallPolicy', 'updateFirewallPolicyOrdering'] },
      { task: 'B4.3', command: 'firewall zone', path: 'firewall/zones', flag: 'firewall-zone-id',
        bodies: [{ name: 'Synthetic zone', networkIds: [] }, { name: 'Selected networks', networkIds: [neighbourId] }],
        grants: ['createFirewallZone', 'updateFirewallZone', 'deleteFirewallZone'] },
      { task: 'B4.4', command: 'acl-rule', path: 'acl-rules', flag: 'acl-rule-id', bodies: aclBodies,
        grants: ['createAclRule', 'updateAclRule', 'deleteAclRule', 'updateAclRuleOrdering'] },
      { task: 'B4.5', command: 'dns policy', path: 'dns/policies', flag: 'dns-policy-id', bodies: dnsBodies,
        grants: ['createDnsPolicy', 'updateDnsPolicy', 'deleteDnsPolicy'] },
      { task: 'B4.6', command: 'traffic-list', path: 'traffic-matching-lists', flag: 'traffic-matching-list-id', bodies: trafficBodies,
        grants: ['createTrafficMatchingList', 'updateTrafficMatchingList', 'deleteTrafficMatchingList'] },
    ]) {
      if (h.task !== 'all' && h.task !== family.task) continue;
      const base = `/proxy/network/integration/v1/sites/${site}/${family.path}`;
      const neighbour = { ...(family.task === 'B4.2' ? firewallRecord(version) : family.bodies[0]),
        id: neighbourId, index: 1, metadata: { origin: 'USER_DEFINED' }, name: 'Untouched neighbour' };
      const initial = { ...neighbour, id, name: 'Original target', index: 0 };
      const profile = { ...h.trusted, siteId: site, writes: { allowWrites: true, operations: family.grants } };
      let state: Row[] = [];
      let mutations = 0;
      let sent: unknown;
      let sentMethod: string | undefined;
      let mode = 'normal';
      let retained: Row = {};
      let order: Row = {};
      const reset = () => {
        h.configure({ lab: profile }); state = [initial, neighbour]; mutations = 0; sent = undefined; mode = 'normal'; retained = {};
        order = family.task === 'B4.2' ? { orderedFirewallPolicyIds: { beforeSystemDefined: [id], afterSystemDefined: [neighbourId] } } : { orderedAclRuleIds: [id, neighbourId] };
        h.seed((request, response) => {
          assert.equal(request.headers['x-api-key'], h.syntheticKey);
          const url = new URL(request.url!, h.trusted.origin);
          if (url.pathname.endsWith('/info')) return { applicationVersion: version };
          if (url.pathname.includes(`/sites/${otherSite}/`)) { response.writeHead(403); response.end(); return; }
          assert.equal(url.pathname.startsWith(base), true, request.url);
          if (request.method === 'GET') {
            if (url.pathname.endsWith('/ordering')) return order;
            if (url.pathname === base) return { offset: 0, limit: 25, count: state.length, totalCount: state.length, data: state };
            return state.find(row => url.pathname.endsWith(`/${String(row.id)}`));
          }
          mutations++;
          sentMethod = request.method;
          if (family.task === 'B4.5' || family.task === 'B4.6') {
            assert.equal(url.pathname, request.method === 'POST' ? base : `${base}/${id}`);
            assert.equal(url.search, '');
          }
          let bytes = '';
          request.on('data', chunk => { bytes += chunk; });
          request.on('end', () => {
            sent = bytes ? JSON.parse(bytes) as Row : null;
            if (mode === 'referenced') { response.writeHead(409); response.end(); return; }
            let result: Row | undefined;
            if (url.pathname.endsWith('/ordering')) { order = sent as Row; result = order; }
            else if (request.method === 'DELETE') state = state.filter(row => row.id !== id);
            else {
              result = { ...(request.method === 'PATCH' ? state.find(row => row.id === id) : {}),
                ...(family.task === 'B4.2' && version === '11.0.97' && request.method !== 'PATCH' ? { reportFlowEnabled: true } : {}),
                ...(sent as Row), id, index: 0, metadata: { origin: 'USER_DEFINED' } };
              state = [...state.filter(row => row.id !== id), { ...result, ...retained }];
            }
            if (mode === 'lost-ack') { request.socket.destroy(); return; }
            response.statusCode = request.method === 'POST' ? 201 : 200;
            response.end(result ? JSON.stringify(result) : '');
          });
          return undefined;
        });
      };
      const command = (action: string, body?: Row) => {
        if (body) writeFileSync(bodyFile, JSON.stringify(body), { mode: 0o600 });
        return [...family.command.split(' '), action, ...(action === 'create' ? [] : [`--${family.flag}`, id]),
          ...(body ? ['--body-file', bodyFile] : [])];
      };
      for (const action of ['create', 'update', ...(family.task === 'B4.2' ? ['patch'] : [])]) {
        const bodies = action === 'patch' ? [{ loggingEnabled: true, ...(version === '11.0.97' ? { reportFlowEnabled: true } : {}) }] : family.bodies;
        for (const [index, body] of bodies.entries()) {
          reset();
          const metadata = { origin: family.task === 'B4.5' ? ['USER_DEFINED', 'SYSTEM_DEFINED', 'ORCHESTRATED'][index % 3]! : 'USER_DEFINED' };
          if (family.task === 'B4.5') retained = { metadata };
          if (action === 'create') state = [neighbour];
          const args = command(action, body);
          const before = structuredClone(state);
          const confirmation = (await run(args)).preview.confirmation;
          assert.equal(mutations, 0); assert.deepEqual(state, before);
          if (family.task === 'B4.5' || family.task === 'B4.6') {
            h.configure({ lab: { ...profile, writes: { allowWrites: true, operations: [] } } });
            assert.equal((await run(execute(args, confirmation), 1)).error.code, 'WRITE_DENIED');
            assert.equal(mutations, 0);
            h.configure({ lab: profile });
          }
          const requestId = `success-${++serial}`;
          assert.equal((await run(execute(args, confirmation, requestId))).write.outcome, 'verified', `${family.command} ${action} ${JSON.stringify(body)}`);
          assert.deepEqual(sent, body);
          assert.equal(sentMethod, action === 'create' ? 'POST' : action === 'patch' ? 'PATCH' : 'PUT');
          assert.deepEqual(state.find(row => row.id === neighbourId), neighbour);
          assert.deepEqual(state.find(row => row.id === id), { ...(action === 'patch' ? initial : {}), ...body, id, index: 0, metadata });
          assert.equal((await run(execute(args, confirmation, requestId))).write.outcome, 'verified');
          assert.equal(mutations, 1);
          assert.equal((await run(['write', 'reconcile', '--request-id', requestId])).reconciliation.outcome, 'verified');
          const operation = family.task === 'B4.5' ? (action === 'create' ? 'OP-026' : 'OP-029') :
            family.task === 'B4.6' ? (action === 'create' ? 'OP-062' : 'OP-065') : undefined;
          rows.push({ task: family.task, version, operation, action, status: 'passed', body,
            ...(operation ? { acceptance: [`AC-${operation.slice(3)}`, `AC-${operation.slice(3)}-PREVIEW`, `AC-${operation.slice(3)}-VARIANTS`],
              cases: [...dnsTrafficCases[String(body.type)]!, ...(family.task === 'B4.5'
                ? ['VAR-1028', 'VAR-1033', ['VAR-247', 'VAR-246', 'VAR-245'][index % 3]!]
                : ['VAR-1032', 'VAR-1069'])],
              direction: 'preview-exact-request-independent-state-grant-denial-and-no-replay' } : {}) });
        }
        reset();
        const args = command(action, action === 'patch' ? { loggingEnabled: true } : family.bodies[0]);
        const confirmation = (await run(args)).preview.confirmation;
        state = state.map(row => row.id === id ? { ...row, name: 'Changed since preview' } : row);
        assert.equal((await run(execute(args, confirmation), 1)).error.code, 'CONFIRMATION_MISMATCH');
        assert.equal(mutations, 0);
      }
      if (family.task === 'B4.2' && version === '11.0.97') {
        reset();
        state = [neighbour];
        retained = { reportFlowEnabled: false };
        const body = firewallBody(version);
        delete body.reportFlowEnabled;
        const args = command('create', body);
        const preview = await run(args);
        assert.deepEqual(preview.preview.body, body);
        assert.equal(mutations, 0);
        const requestId = `create-wrong-default-${++serial}`;
        assert.equal((await run(execute(args, preview.preview.confirmation, requestId))).write.outcome, 'accepted');
        assert.deepEqual(sent, body);
        assert.equal(state.find(row => row.id === id)!.reportFlowEnabled, false);
        assert.deepEqual(state.find(row => row.id === neighbourId), neighbour);
        assert.equal((await run(['write', 'reconcile', '--request-id', requestId])).reconciliation.outcome, 'accepted');
        assert.equal((await run(execute(args, preview.preview.confirmation, requestId))).write.outcome, 'accepted');
        assert.equal(mutations, 1);
        state = state.map(row => row.id === id ? { ...row, reportFlowEnabled: true } : row);
        assert.equal((await run(['write', 'reconcile', '--request-id', requestId])).reconciliation.outcome, 'verified');
        assert.equal(mutations, 1);
        rows.push({ task: family.task, version, action: 'create-independent-default', status: 'passed' });
      }
      const replacements: { body: Row; retained: Row }[] = [];
      if (family.task === 'B4.4') {
        for (const acl of [aclBodies[0]!, aclBodies[3]!]) {
          const original: Row = { ...acl, description: 'Old description', enforcingDeviceFilter: { type: 'DEVICES', deviceIds: [neighbourId] } };
          for (const field of ['description', 'enforcingDeviceFilter', 'sourceFilter', 'destinationFilter', ...(acl.type === 'IPV4' ? ['protocolFilter'] : [])]) {
            const body = { ...original };
            delete body[field];
            replacements.push({ body, retained: { [field]: original[field] } });
          }
        }
      }
      if (family.task === 'B4.2') {
        const original = firewallVariants(version).at(-1)!;
        for (const field of ['connectionStateFilter', 'ipsecFilter', 'schedule', 'description', ...(version === '11.0.97' ? ['reportFlowEnabled'] : [])]) {
          const body = { ...original };
          delete body[field];
          replacements.push({ body, retained: { [field]: original[field] } });
        }
        for (const field of ['source', 'destination', 'ipProtocolScope']) {
          const original = firewallVariants(version).find(body => field === 'ipProtocolScope'
            ? (body[field] as Row).protocolFilter !== undefined : (body[field] as Row).trafficFilter !== undefined)!;
          replacements.push({ body: firewallBody(version), retained: { [field]: original[field] } });
        }
      }
      for (const replacement of replacements) {
        reset();
        retained = replacement.retained;
        state = [{ ...initial, ...replacement.body, ...retained }, neighbour];
        const args = command('update', replacement.body);
        const confirmation = (await run(args)).preview.confirmation;
        const requestId = `stale-replacement-${++serial}`;
        assert.equal((await run(execute(args, confirmation, requestId))).write.outcome, 'accepted', JSON.stringify(replacement));
        assert.deepEqual(sent, replacement.body);
        assert.deepEqual(state.find(row => row.id === neighbourId), neighbour);
        assert.equal((await run(['write', 'reconcile', '--request-id', requestId])).reconciliation.outcome, 'accepted');
        assert.equal((await run(execute(args, confirmation, requestId))).write.outcome, 'accepted');
        assert.equal(mutations, 1);
        state = [{ ...replacement.body,
          ...(family.task === 'B4.2' && version === '11.0.97' && !Object.hasOwn(replacement.body, 'reportFlowEnabled') ? { reportFlowEnabled: true } : {}),
          id, index: 0, metadata: { origin: 'USER_DEFINED' } }, neighbour];
        assert.equal((await run(['write', 'reconcile', '--request-id', requestId])).reconciliation.outcome, 'verified');
        assert.equal(mutations, 1);
        rows.push({ task: family.task, version, action: 'replacement-independent-state', status: 'passed', retained });
      }
      reset();
      const remove = command('delete');
      const confirmation = (await run(remove)).preview.confirmation;
      assert.equal((await run(execute(remove, confirmation))).write.outcome, 'verified');
      assert.deepEqual(state, [neighbour]);
      assert.equal(sentMethod, 'DELETE');
      if (family.task === 'B4.5' || family.task === 'B4.6') {
        const operation = family.task === 'B4.5' ? 'OP-027' : 'OP-063';
        rows.push({ task: family.task, version, operation, action: 'delete', status: 'passed',
          acceptance: [`AC-${operation.slice(3)}`, `AC-${operation.slice(3)}-PREVIEW`, `AC-${operation.slice(3)}-VARIANTS`, `STEP-${family.task}`] });
      }
      const absent = (await run(remove)).preview.confirmation;
      assert.equal((await run(execute(remove, absent))).write.outcome, 'no-op');
      assert.equal(mutations, 1);
      reset();
      mode = 'referenced';
      const referenced = (await run(remove)).preview.confirmation;
      assert.equal((await run(execute(remove, referenced), 1)).error.code, 'OUTCOME_UNKNOWN');
      assert.deepEqual(state, [initial, neighbour]);
      reset();
      h.configure({ lab: { ...profile, writes: { allowWrites: true, operations: [] } } });
      assert.equal((await run(execute(remove, confirmation), 1)).error.code, 'WRITE_DENIED');
      assert.equal(mutations, 0);
      reset();
      assert.equal((await run([...remove, '--site', otherSite], 1)).error.code, 'UPSTREAM_ERROR');
      assert.equal(mutations, 0);
      reset();
      const create = command('create', family.bodies[0]);
      const lost = (await run(create)).preview.confirmation;
      mode = 'lost-ack';
      const lostId = `lost-policy-${++serial}`;
      assert.equal((await run(execute(create, lost, lostId), 1)).error.code, 'OUTCOME_UNKNOWN');
      assert.equal((await run(['write', 'reconcile', '--request-id', lostId], 1)).reconciliation.outcome, 'unknown');
      assert.equal((await run(execute(create, lost, lostId), 1)).error.code, 'OUTCOME_UNKNOWN');
      assert.equal(mutations, 1);
      if (family.task === 'B4.2' || family.task === 'B4.4') {
        reset();
        const reordered = family.task === 'B4.2' ? { orderedFirewallPolicyIds: { beforeSystemDefined: [neighbourId, id], afterSystemDefined: [] } } : { orderedAclRuleIds: [neighbourId, id] };
        writeFileSync(bodyFile, JSON.stringify(reordered));
        const selectors = family.task === 'B4.2' ? ['--source-firewall-zone-id', id, '--destination-firewall-zone-id', neighbourId] : [];
        const args = [...family.command.split(' '), 'order', 'set', '--body-file', bodyFile, ...selectors];
        const duplicate = family.task === 'B4.2' ? { orderedFirewallPolicyIds: { beforeSystemDefined: [id, id], afterSystemDefined: [] } } : { orderedAclRuleIds: [id, id] };
        writeFileSync(bodyFile, JSON.stringify(duplicate));
        assert.equal((await run(args, 1)).error.code, 'WRITE_CONFLICT');
        assert.equal(mutations, 0);
        writeFileSync(bodyFile, JSON.stringify(reordered));
        const preview = (await run(args)).preview.confirmation;
        if (family.task === 'B4.2') {
          const changed = [...family.command.split(' '), 'order', 'set', '--body-file', bodyFile,
            '--source-firewall-zone-id', neighbourId, '--destination-firewall-zone-id', id];
          assert.equal((await run(execute(changed, preview), 1)).error.code, 'CONFIRMATION_MISMATCH');
          assert.equal(mutations, 0);
        }
        const requestId = `order-${++serial}`;
        assert.equal((await run(execute(args, preview, requestId))).write.outcome, 'verified');
        assert.deepEqual(order, reordered); assert.deepEqual(state, [initial, neighbour]);
        assert.equal((await run(['write', 'reconcile', '--request-id', requestId])).reconciliation.outcome, 'verified');
        const stale = (await run(args)).preview.confirmation;
        order = family.task === 'B4.2' ? { orderedFirewallPolicyIds: { beforeSystemDefined: [], afterSystemDefined: [id, neighbourId] } } : { orderedAclRuleIds: [id, neighbourId] };
        assert.equal((await run(execute(args, stale), 1)).error.code, 'CONFIRMATION_MISMATCH');
        assert.equal(mutations, 1);
      }
      reset();
      const invalid = command('create', { name: 'Missing required fields' });
      assert.equal((await run(invalid, 1)).error.code, 'INVALID_ARGUMENT');
      assert.equal(mutations, 0);
      if (family.task === 'B4.5' || family.task === 'B4.6') {
        for (const body of family.bodies) {
          reset();
          const invalidBody = family.task === 'B4.5' ? { ...body, ttlSeconds: -1 } :
            { ...body, items: [{ type: 'UNKNOWN', value: 443 }] };
          const invalid = command('create', invalidBody);
          assert.equal((await run(invalid, 1)).error.code, 'INVALID_ARGUMENT');
          assert.equal(mutations, 0);
          const wrongTag = command('update', { ...body, type: 'UNKNOWN' });
          assert.equal((await run(wrongTag, 1)).error.code, 'INVALID_ARGUMENT');
          assert.equal(mutations, 0);
        }
      }
      if (family.task === 'B4.6') {
        const invalidEntries: [string, Row][] = [
          ['IPV4_ADDRESSES', { type: 'IP_ADDRESS', value: 'not-an-ip' }],
          ['IPV4_ADDRESSES', { type: 'IP_ADDRESS', value: '256.0.0.1' }],
          ['IPV4_ADDRESSES', { type: 'IP_ADDRESS', value: '2001:db8::1' }],
          ['IPV6_ADDRESSES', { type: 'IP_ADDRESS', value: 'not-an-ip' }],
          ['IPV6_ADDRESSES', { type: 'IP_ADDRESS', value: '2001:db8::gg' }],
          ['IPV6_ADDRESSES', { type: 'IP_ADDRESS', value: '192.0.2.1' }],
          ['IPV6_ADDRESSES', { type: 'IP_ADDRESS', value: 'fe80::1%eth0' }],
          ['IPV4_ADDRESSES', { type: 'SUBNET', value: 'not-an-ip/24' }],
          ['IPV4_ADDRESSES', { type: 'SUBNET', value: '2001:db8::/24' }],
          ['IPV4_ADDRESSES', { type: 'SUBNET', value: '192.0.2.0/33' }],
          ['IPV4_ADDRESSES', { type: 'SUBNET', value: '192.0.2.0/-1' }],
          ['IPV4_ADDRESSES', { type: 'SUBNET', value: '192.0.2.0/1.5' }],
          ['IPV4_ADDRESSES', { type: 'SUBNET', value: '192.0.2.0/' }],
          ['IPV4_ADDRESSES', { type: 'SUBNET', value: '192.0.2.0/24/1' }],
          ['IPV6_ADDRESSES', { type: 'SUBNET', value: 'not-an-ip/64' }],
          ['IPV6_ADDRESSES', { type: 'SUBNET', value: '192.0.2.0/24' }],
          ['IPV6_ADDRESSES', { type: 'SUBNET', value: '2001:db8::/129' }],
          ['IPV6_ADDRESSES', { type: 'SUBNET', value: '2001:db8::/-1' }],
          ['IPV6_ADDRESSES', { type: 'SUBNET', value: '2001:db8::/1.5' }],
          ['IPV6_ADDRESSES', { type: 'SUBNET', value: '2001:db8::' }],
          ['IPV6_ADDRESSES', { type: 'SUBNET', value: 'fe80::%eth0/64' }],
          ['IPV4_ADDRESSES', { type: 'IP_ADDRESS_RANGE', start: 'not-an-ip', stop: '192.0.2.10' }],
          ['IPV4_ADDRESSES', { type: 'IP_ADDRESS_RANGE', start: '192.0.2.1', stop: 'not-an-ip' }],
          ['IPV4_ADDRESSES', { type: 'IP_ADDRESS_RANGE', start: '2001:db8::1', stop: '192.0.2.10' }],
          ['IPV4_ADDRESSES', { type: 'IP_ADDRESS_RANGE', start: '192.0.2.1', stop: '2001:db8::10' }],
          ['IPV4_ADDRESSES', { type: 'IP_ADDRESS_RANGE', start: '192.0.2.10', stop: '192.0.2.2' }],
          ['PORTS', { type: 'PORT_NUMBER', value: 0 }],
          ['PORTS', { type: 'PORT_NUMBER', value: 65536 }],
          ['PORTS', { type: 'PORT_NUMBER_RANGE', start: 8080, stop: 8000 }],
          ['PORTS', { type: 'PORT_NUMBER_RANGE', start: 0, stop: 80 }],
          ['PORTS', { type: 'PORT_NUMBER_RANGE', start: 65536, stop: 65536 }],
          ['PORTS', { type: 'PORT_NUMBER_RANGE', start: 1, stop: 0 }],
          ['PORTS', { type: 'PORT_NUMBER_RANGE', start: 80, stop: 65536 }],
        ];
        for (const [type, entry] of invalidEntries) {
          for (const action of ['create', 'update']) {
            reset();
            const before: Row[] = structuredClone(state);
            const args = command(action, { name: 'Invalid entry', type, items: [entry] });
            assert.equal((await run(args, 1)).error.code, 'INVALID_ARGUMENT', JSON.stringify({ version, action, type, entry }));
            assert.equal((await run(execute(args, 'invalid-entry'), 1)).error.code, 'INVALID_ARGUMENT');
            assert.equal(mutations, 0);
            assert.deepEqual(state, before);
          }
        }
      }
      if (family.task === 'B4.2') {
        for (const name of ['TCP', 'tcp']) {
          reset(); state = [neighbour];
          const normalized = { ...firewallBody(version), ipProtocolScope: { ipVersion: 'IPV4', protocolFilter: { type: 'NAMED_PROTOCOL', matchOpposite: false, protocol: { name } } } };
          const args = command('create', normalized);
          const preview = (await run(args)).preview.confirmation;
          assert.equal((await run(execute(args, preview))).write.outcome, 'verified');
          assert.deepEqual((sent as Row).ipProtocolScope, { ipVersion: 'IPV4', protocolFilter: { type: 'NAMED_PROTOCOL', matchOpposite: false, protocol: { name: 'tcp' } } });
        }
      }
    }
  }
  return rows;
}
