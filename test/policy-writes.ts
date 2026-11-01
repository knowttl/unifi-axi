import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Harness } from './writes.ts';
import { aclBodies, firewallBody, firewallRecord, firewallVariants, id, neighbourId, otherSite, site, type Row } from './policy-fixtures.ts';

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
      let mode = 'normal';
      let order: Row = {};
      const reset = () => {
        h.configure({ lab: profile }); state = [initial, neighbour]; mutations = 0; sent = undefined; mode = 'normal';
        order = family.task === 'B4.2' ? { orderedFirewallPolicyIds: { beforeSystemDefined: [id], afterSystemDefined: [neighbourId] } } : { orderedAclRuleIds: [id, neighbourId] };
        h.seed((request, response) => {
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
                ...(sent as Row), id, index: 0, metadata: { origin: 'USER_DEFINED' } };
              state = [...state.filter(row => row.id !== id), result];
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
        for (const body of bodies) {
          reset();
          if (action === 'create') state = [neighbour];
          const args = command(action, body);
          const before = structuredClone(state);
          const confirmation = (await run(args)).preview.confirmation;
          assert.equal(mutations, 0); assert.deepEqual(state, before);
          const requestId = `success-${++serial}`;
          assert.equal((await run(execute(args, confirmation, requestId))).write.outcome, 'verified', `${family.command} ${action} ${JSON.stringify(body)}`);
          assert.deepEqual(sent, body);
          assert.deepEqual(state.find(row => row.id === neighbourId), neighbour);
          assert.deepEqual(state.find(row => row.id === id), { ...(action === 'patch' ? initial : {}), ...body, id, index: 0, metadata: { origin: 'USER_DEFINED' } });
          assert.equal((await run(execute(args, confirmation, requestId))).write.outcome, 'verified');
          assert.equal(mutations, 1);
          assert.equal((await run(['write', 'reconcile', '--request-id', requestId])).reconciliation.outcome, 'verified');
          rows.push({ task: family.task, version, action, status: 'passed', body });
        }
        reset();
        const args = command(action, action === 'patch' ? { loggingEnabled: true } : family.bodies[0]);
        const confirmation = (await run(args)).preview.confirmation;
        state = state.map(row => row.id === id ? { ...row, name: 'Changed since preview' } : row);
        assert.equal((await run(execute(args, confirmation), 1)).error.code, 'CONFIRMATION_MISMATCH');
        assert.equal(mutations, 0);
      }
      reset();
      const remove = command('delete');
      const confirmation = (await run(remove)).preview.confirmation;
      assert.equal((await run(execute(remove, confirmation))).write.outcome, 'verified');
      assert.deepEqual(state, [neighbour]);
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
      if (family.task !== 'B4.3') {
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
