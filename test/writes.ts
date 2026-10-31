import assert from 'node:assert/strict';
import { writeFileSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Profile } from '../src/profiles.js';

interface Result {
  preview: { confirmation: string; identity: string };
  write: { outcome: string; auditId: string };
  error: { code: string };
  reconciliation: { outcome: string; readOnly: boolean };
}
interface Harness {
  cli: (args: string[], code?: number, env?: Record<string, string>) => Promise<Result>;
  configure: (profiles: Record<string, Profile>) => void;
  trusted: Profile;
  home: string;
  port: number;
  syntheticKey: string;
  task: string;
  seed: (handler: (request: IncomingMessage, response: ServerResponse) => unknown) => void;
  requests: () => { method: string; path: string; key: string }[];
}

const site = '9361553d-e20d-45b8-a516-6948ab010011';
const id = '8c850c83-1111-4111-8111-000000000001';
const neighbourId = '8c850c83-1111-4111-8111-000000000002';
const metadata = { origin: 'USER_DEFINED' };
const body = { name: 'Created synthetic network', management: 'UNMANAGED', enabled: true, vlanId: 42 };
const target = { ...body, id, default: false, metadata };
const neighbour = { ...target, name: 'Untouched neighbour', id: neighbourId, vlanId: 7 };

export async function verifyWrites(h: Harness) {
  const log = join(h.home, 'write-journal');
  const bodyFile = join(h.home, 'network-body.json');
  const guard = fileURLToPath(new URL('./fixtures/write-guard.ts', import.meta.url));
  const env = { NODE_OPTIONS: `--import=${guard}`, UNIFI_AXI_TEST_PORT: String(h.port), UNIFI_AXI_WRITE_LOG: log };
  const run = (args: string[], code = 0, overrides: Record<string, string> = {}) => h.cli(args, code, { ...env, ...overrides });
  const profile: Profile = { ...h.trusted, siteId: site, writes: { allowWrites: true, operations: ['createNetwork', 'createNetwork:UNMANAGED', 'deleteNetwork'] } };
  const create = ['network', 'create', '--body-file', bodyFile];
  const remove = ['network', 'delete', '--network-id', id];
  const execute = (command: string[], confirmation: string, requestId: string) => [...command, '--execute', '--confirm', confirmation, '--request-id', requestId];
  const rows: Record<string, unknown>[] = [];
  let version = '10.6.109';
  let state: Record<string, unknown>[] = [];
  let mutations = 0;
  let mode = 'normal';
  let reads = 0;
  let driftOnRead = 0;
  let changeTargetOnRead = 0;
  const sent: { method: string; path: string; body: unknown }[] = [];
  const reset = () => {
    state = [neighbour]; mutations = 0; mode = 'normal'; reads = 0; driftOnRead = 0; changeTargetOnRead = 0; sent.length = 0;
    h.configure({ lab: profile });
    writeFileSync(bodyFile, JSON.stringify(body), { mode: 0o600 });
    h.seed((request, response) => {
      assert.equal(request.headers['x-api-key'], h.syntheticKey);
      const url = new URL(request.url!, h.trusted.origin);
      if (url.pathname.endsWith('/info')) return { applicationVersion: version };
      if (url.pathname === '/proxy/network/integration/v1/sites') return {
        offset: 0, limit: 25, count: 1, totalCount: 1, data: [{ id: site, internalReference: 'default', name: 'Synthetic site' }],
      };
      const base = `/proxy/network/integration/v1/sites/${site}/networks`;
      if (request.method === 'GET') {
        reads++;
        if (reads === driftOnRead) h.configure({ lab: { ...profile, apiKey: { env: 'REPLACED_KEY' } } });
        if (url.pathname === base) return { offset: 0, limit: 25, count: state.length, totalCount: state.length, data: state };
        const found = state.find(row => url.pathname === `${base}/${String(row.id).toLowerCase()}`);
        assert.ok(found, `Unexpected read: ${request.url}`);
        if (reads === changeTargetOnRead) state = state.map(row => row.id === id ? { ...row, name: 'Changed after selected-state read' } : row);
        return found;
      }
      mutations++;
      assert.equal(url.pathname, request.method === 'POST' ? base : `${base}/${id}`);
      let bytes = '';
      request.on('data', chunk => { bytes += chunk; });
      request.on('end', () => {
        sent.push({ method: request.method!, path: request.url!, body: bytes ? JSON.parse(bytes) as unknown : null });
        if (request.method === 'POST') { assert.deepEqual(JSON.parse(bytes), body); state.push(target); }
        else { assert.equal(url.searchParams.get('force'), 'false'); state = state.filter(row => String(row.id).toLowerCase() !== id); }
        if (mode === 'lost-ack') { request.socket.destroy(); return; }
        if (mode === 'stall') { response.writeHead(201); response.write('{'); return; }
        response.statusCode = request.method === 'POST' ? 201 : 200;
        response.end(request.method === 'POST' ? JSON.stringify({ ...target, id: id.toUpperCase(), echo: h.syntheticKey }) : '');
      });
      return undefined;
    });
  };
  for (const contractVersion of ['10.6.109', '11.0.97']) {
    version = contractVersion;
    reset();
    const preview = (await run(create)).preview;
    assert.equal(mutations, 0);
    writeFileSync(bodyFile, JSON.stringify({ ...body, name: h.syntheticKey }));
    assert.notEqual((await run(create)).preview.confirmation, preview.confirmation);
    writeFileSync(bodyFile, JSON.stringify(body));
    const deletion = (await run(remove)).preview.confirmation;
    assert.equal((await run([...remove, '--force', 'false'])).preview.confirmation, deletion);
    assert.notEqual((await run([...remove, '--force', 'true'])).preview.confirmation, deletion);
    assert.equal((await run(execute([...remove, '--force', 'true'], deletion, `force-${version}`), 1)).error.code, 'CONFIRMATION_MISMATCH');
    h.configure({ lab: { ...profile, apiKey: { env: 'REPLACED_KEY' } } });
    assert.equal((await run(execute(create, preview.confirmation, `ref-${version}`), 1, { REPLACED_KEY: h.syntheticKey })).error.code, 'CONFIRMATION_MISMATCH');
    h.configure({ lab: profile });
    writeFileSync(bodyFile, JSON.stringify({ ...body, enabled: false }));
    assert.equal((await run(execute(create, preview.confirmation, `body-${version}`), 1)).error.code, 'CONFIRMATION_MISMATCH');
    writeFileSync(bodyFile, JSON.stringify(body));
    for (const operations of [[], ['createNetwork'], ['OP-049']]) {
      h.configure({ lab: { ...profile, writes: { allowWrites: true, operations } } });
      assert.equal((await run(execute(create, preview.confirmation, `grant-${version}`), 1)).error.code, 'WRITE_DENIED');
    }
    h.configure({ lab: profile });
    assert.equal((await run(execute(create, preview.confirmation, `readonly-${version}`), 1, { UNIFI_AXI_READ_ONLY: 'true' })).error.code, 'WRITE_DENIED');
    assert.equal(mutations, 0);
    version = '99.0.0';
    h.configure({ lab: { ...profile, apiContract: '11.0.97' } });
    assert.equal((await run(create, 1)).error.code, 'UNVERIFIED_API_VERSION');
    version = contractVersion;
    reset();
    rows.push({ task: 'B3.1', version, operation: ['OP-049', 'OP-050'], status: 'passed', direction: 'normalized-preview-and-exact-grants' });
    if (h.task === 'B3.1') continue;
    if (process.platform === 'win32') {
      const confirmation = (await run(create)).preview.confirmation;
      assert.equal((await run(execute(create, confirmation, `windows-${version}`), 1)).error.code, 'WRITE_UNSUPPORTED');
      rows.push({ task: 'B3.2', status: 'pending-native-windows' });
      continue;
    }
    const confirmation = (await run(create)).preview.confirmation;
    const requestId = `concurrent-${version}`;
    const outcomes = await Promise.all([run(execute(create, confirmation, requestId), -1), run(execute(create, confirmation, requestId), -1)]);
    assert.equal(mutations, 1);
    assert.ok(outcomes.some(result => result.write?.outcome === 'verified'));
    assert.deepEqual(sent, [{ method: 'POST', path: `/proxy/network/integration/v1/sites/${site}/networks`, body }]);
    assert.deepEqual(state, [neighbour, target]);
    assert.equal((await run(execute(create, confirmation, requestId))).write.outcome, 'verified');
    writeFileSync(bodyFile, JSON.stringify({ ...body, vlanId: 43 }));
    assert.equal((await run(execute(create, confirmation, requestId), 1)).error.code, 'WRITE_BINDING_MISMATCH');
    writeFileSync(bodyFile, JSON.stringify(body));
    const before = mutations;
    assert.equal((await run(['write', 'show', '--request-id', requestId])).write.outcome, 'verified');
    assert.deepEqual((await run(['write', 'reconcile', '--request-id', requestId])).reconciliation, { outcome: 'verified', readOnly: true });
    assert.equal(mutations, before);
    const deleteConfirmation = (await run(remove)).preview.confirmation;
    const uppercaseRemove = ['network', 'delete', '--site', site.toUpperCase(), '--network-id', id.toUpperCase()];
    assert.equal((await run(uppercaseRemove)).preview.confirmation, deleteConfirmation);
    assert.equal((await run(execute(uppercaseRemove, deleteConfirmation, `delete-${version}`))).write.outcome, 'verified');
    assert.deepEqual(state, [neighbour]);
    const absent = (await run(remove)).preview.confirmation;
    assert.equal((await run(execute(remove, absent, `absent-${version}`))).write.outcome, 'no-op');
    assert.equal(mutations, before + 1);
    reset();
    state = [neighbour, { ...target, id: id.toUpperCase() }];
    const uppercaseState = (await run(remove)).preview.confirmation;
    assert.equal((await run(execute(remove, uppercaseState, `uppercase-state-${version}`))).write.outcome, 'verified');
    assert.deepEqual(state, [neighbour]);
    for (const connection of [2, 3, 5, 6, 7]) {
      reset();
      state = [neighbour, target];
      const confirmation = (await run(remove)).preview.confirmation;
      assert.equal((await run(execute(remove, confirmation, `peer-${connection}-${version}`), 1,
        { UNIFI_AXI_TEST_PEER_DRIFT: String(connection) })).error.code, 'WRITE_DRIFT');
      assert.equal(mutations, 0);
    }
    reset();
    const discoverProfile = { ...profile };
    delete discoverProfile.siteId;
    h.configure({ lab: discoverProfile });
    assert.equal((await run(create, 1, { UNIFI_AXI_TEST_PEER_DRIFT: '2' })).error.code, 'WRITE_DRIFT');
    assert.equal(mutations, 0);
    reset();
    const durable = (await run(create)).preview.confirmation;
    assert.equal((await run(execute(create, durable, `ancestor-${version}`), 1,
      { UNIFI_AXI_TEST_FAULT: 'ancestor-sync' })).error.code, 'WRITE_FAILED');
    assert.equal(mutations, 0);
    reset();
    state = [neighbour, target];
    const recovery = (await run(remove)).preview.confirmation;
    assert.equal((await run(execute(remove, recovery, `recovery-peer-${version}`), 0,
      { UNIFI_AXI_TEST_PEER_DRIFT: '8' })).write.outcome, 'accepted');
    assert.equal(mutations, 1);
    assert.equal((await run(['write', 'reconcile', '--request-id', `recovery-peer-${version}`], 1,
      { UNIFI_AXI_TEST_PEER_DRIFT: '2' })).error.code, 'WRITE_DRIFT');
    assert.equal(mutations, 1);
    reset();
    state = [neighbour, target];
    const beforeDrift = (await run(remove)).preview.confirmation;
    changeTargetOnRead = reads + 2;
    assert.equal((await run(execute(remove, beforeDrift, `state-drift-${version}`), 1)).error.code, 'WRITE_DRIFT');
    assert.equal(mutations, 0);
    reset();
    const drift = (await run(create)).preview.confirmation;
    driftOnRead = reads + 1;
    assert.equal((await run(execute(create, drift, `drift-${version}`), 1, { REPLACED_KEY: h.syntheticKey })).error.code, 'WRITE_DRIFT');
    assert.equal(mutations, 0);
    reset();
    mode = 'lost-ack';
    const lost = (await run(create)).preview.confirmation;
    const unknownId = `lost-${version}`;
    const unknown = await run(execute(create, lost, unknownId), 1);
    assert.equal(unknown.error.code, 'OUTCOME_UNKNOWN');
    assert.equal(mutations, 1);
    assert.equal((await run(execute(create, lost, unknownId), 1)).write.auditId, unknown.write.auditId);
    const reconciled = await run(['write', 'reconcile', '--request-id', unknownId], 1);
    assert.deepEqual(reconciled.reconciliation, { outcome: 'unknown', readOnly: true });
    assert.equal(mutations, 1, 'An indistinguishable existing network cannot resolve an ambiguous create');
    if (version === '11.0.97' && h.task === 'B3.3') {
      reset();
      mode = 'stall';
      const stalled = (await run(create)).preview.confirmation;
      assert.equal((await run(execute(create, stalled, 'timed-out'), 1)).error.code, 'OUTCOME_UNKNOWN');
      assert.equal(mutations, 1, 'A mutation timeout never triggers a transport retry');
      assert.equal((await run(['write', 'reconcile', '--request-id', 'timed-out'], 1)).write.outcome, 'unknown');
      assert.equal(mutations, 1);
    }
    for (const [fault, outcome] of [['before-claim', null], ['after-claim', 'corrupt'], ['after-intent-sync', 'not-sent'],
      ['before-send', 'unknown'], ['after-possible-send', 'unknown'], ['after-ack', 'accepted']] as const) {
      reset();
      const preview = (await run(create)).preview.confirmation;
      const requestId = `${fault}-${version}`;
      await run(execute(create, preview, requestId), fault === 'before-claim' ? 1 : 99, { UNIFI_AXI_TEST_FAULT: fault });
      const count: number = mutations;
      if (fault !== 'after-possible-send' && fault !== 'after-ack') assert.equal(count, 0);
      if (fault === 'after-ack') assert.equal(count, 1);
      const show = await run(['write', 'show', '--request-id', requestId], outcome === null || outcome === 'corrupt' || outcome === 'unknown' ? 1 : 0);
      if (outcome === null) assert.equal(show.error.code, 'WRITE_NOT_FOUND');
      else if (outcome === 'corrupt') assert.equal(show.error.code, 'WRITE_JOURNAL_INVALID');
      else {
        assert.equal(show.write.outcome, outcome);
        await run(execute(create, preview, requestId), outcome === 'unknown' ? 1 : 0);
        assert.equal(mutations, count, 'Restart never reclaims a durable request ID');
      }
    }
    const files = readdirSync(log, { recursive: true }).map(String).filter(path => path.endsWith('.json'));
    for (const file of files) {
      const path = join(log, file);
      const text = readFileSync(path, 'utf8');
      for (const form of [h.syntheticKey, JSON.stringify(h.syntheticKey).slice(1, -1), encodeURIComponent(h.syntheticKey)]) assert.equal(text.includes(form), false);
      assert.equal(statSync(path).mode & 0o777, 0o600);
    }
    const journalFile = files.find(file => file.endsWith('intent.json') &&
      (JSON.parse(readFileSync(join(log, file), 'utf8')) as { auditId: string }).auditId === unknown.write.auditId)!;
    const intact = readFileSync(join(log, journalFile), 'utf8');
    writeFileSync(join(log, journalFile), '{truncated');
    assert.equal((await run(['write', 'show', '--request-id', unknownId], 1)).error.code, 'WRITE_JOURNAL_INVALID');
    assert.equal((await run(execute(create, lost, unknownId), 1)).error.code, 'WRITE_JOURNAL_INVALID');
    writeFileSync(join(log, journalFile), intact);
    rows.push({ task: 'B3.2', version, status: 'passed', direction: 'durable-ownership-crash-recovery-and-redaction' });
    if (h.task === 'B3.3') rows.push({ task: 'B3.3', version, status: 'passed', direction: 'native-exact-target-and-denials',
      hosted: 'opt-in frozen Artium proof required; hosted writes deliberately denied without custody' });
  }
  return rows;
}
