import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { spawn, execFileSync } from 'node:child_process';
import { EventEmitter, once } from 'node:events';
import { appendFileSync, existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync, rmSync, symlinkSync, watch } from 'node:fs';
import { createServer } from 'node:https';
import { arch, release } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { decode } from '@toon-format/toon';
import { guardEgress } from '../test/fixtures/fake-egress.mjs';
import { verifyInventory } from '../test/inventory.mjs';
import { verifyPolicies } from '../test/policies.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2).filter(arg => arg !== '--');
assert.equal(args.length, 4, 'Usage: pnpm verify:artium --host <reviewed-fixture> --output <external-evidence-directory>');
assert.equal(args[0], '--host');
assert.equal(args[2], '--output');
const host = resolve(args[1]);
const output = resolve(args[3]);
assert.equal(process.platform, 'linux', 'This proof uses the native Linux runner. Native Windows remains a separate blocking compatibility gate.');
assert.ok(isAbsolute(args[1]) && isAbsolute(args[3]));
assert.ok(!output.startsWith(root + '/'), 'Keep proof and scratch outside the product repository');
const scratch = join(output, 'scratch');
mkdirSync(scratch, { recursive: false, mode: 0o700 });
process.chdir(host);
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const git = (...args) => execFileSync('git', ['-C', host, ...args], { encoding: 'utf8' }).trim();
const base = '3cfc65afc2d7c1a0f50d2f6e02dc2ee13d6fd7e8';
assert.equal(git('merge-base', base, 'HEAD'), base, 'Use the reviewed fixture or its reviewed delta');
const load = path => import(pathToFileURL(join(host, 'dist', path)));
const [{ createApp }, { Runner }, { createCredentialStore, openStore }, { EnvironmentKeyProvider },
  { EmbeddedSecretSource }, { SharedIdentityResolver }, { Audit }, { createUnifiAdapter },
  { unifiFixtureRuntime }, { runnerLimits, toolPaths, toolCredentialSchemaPaths, healthDefaults }, { hashPassword }] = await Promise.all([
  'src/server/app.js', 'src/server/runner/runner.js', 'src/server/store/db.js', 'src/server/store/key-provider.js',
  'src/server/store/secret-source.js', 'src/server/policy/identity-resolver.js', 'src/server/audit/audit.js',
  'src/server/adapters/unifi.js', 'src/server/adapters/unifi-fixture.js', 'src/server/config.js', 'src/server/auth/local.js',
].map(load));
const { createTestCertificates } = await import(pathToFileURL(join(host, 'test/fake-service/certificates.mjs')));
const report = { task: 'B3.3', platform: process.platform, osRelease: release(), architecture: arch(), node: process.version,
  nativeWindows: 'PENDING', stockArtium: 'unsupported', fixtureBase: base, fixtureRevision: git('rev-parse', 'HEAD'),
  fixtureDiffSha256: sha(execFileSync('git', ['-C', host, 'diff', base, '--'])), defaultLimits: { ...runnerLimits },
  liveMutationProbes: '32 unrun', rows: [], processObservations: [], isolation: [], runnerEvidence: [],
  fixtureHealthTickMs: 600_000, defaultHealthTickMs: healthDefaults.tickMs };
let db, app, vendor, watcher;
const sockets = new Set();
const requests = [];
const staged = new Set();
let mode = 'normal', version = '10.6.109', sites = [];
let stalled;
let identity = 'normal';
let rejectAfterStaging = false;
let stagingRejections = 0;
let activeCli;
let inventoryHandler;
const terminalEvents = new EventEmitter();
const first = { id: '9361553d-e20d-45b8-a516-6948ab010011', internalReference: 'north', name: 'North synthetic lab' };
const second = { id: '5925a212-9b6e-402b-a675-c658ab010022', internalReference: 'south', name: 'South synthetic lab' };
const client = join(host, 'dist/cli/artium-axi.mjs');
const calls = join(scratch, 'calls');
const guard = join(scratch, 'guard.mjs');
const deniedLog = join(scratch, 'denied-egress');
const processLog = join(scratch, 'processes.jsonl');
const canary = 'CANARY-unifi-b1-3-only';
const cliEnvironment = { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot,
  HOME: join(scratch, 'developer-home'), XDG_CONFIG_HOME: join(scratch, 'client'), ARTIUM_AXI_TEST_HTTP: '1',
  UNIFI_AXI_ORIGIN: 'https://developer.invalid', UNIFI_AXI_API_KEY: 'CANARY-developer-must-not-be-used' };

function launch(words, input = '') {
  const child = spawn(process.execPath, ['--import', guard, client, ...words], {
    cwd: host, env: cliEnvironment, stdio: ['pipe', 'pipe', 'pipe'], timeout: 30_000,
  });
  activeCli = child;
  let stdout = '', stderr = '';
  child.stdout.on('data', bytes => { stdout += bytes; });
  child.stderr.on('data', bytes => { stderr += bytes; });
  child.stdin.on('error', () => {});
  child.stdin.end(input);
  const result = once(child, 'close').then(([status, signal]) => {
    assert.ok(!stdout.includes(canary) && !stderr.includes(canary), 'Never expose injected secrets');
    return { status, signal, stdout, stderr };
  });
  child.once('close', () => { if (activeCli === child) activeCli = undefined; });
  return { child, result };
}

async function cli(words, status = 0, input = '') {
  const result = await launch(words, input).result;
  assert.equal(result.signal, null, result.stderr);
  assert.equal(result.status, status, `${words.join(' ')}\n${result.stdout}\n${result.stderr}`);
  return result;
}

function record(acceptance, detail) { report.rows.push({ acceptance, status: 'passed', ...detail }); }
function cleanupObserved() {
  assert.deepEqual(readdirSync(calls), [], 'All isolated profiles, uploads, stdin and trust files are removed');
  for (const path of staged) assert.equal(existsSync(path), false, `Staged file survived: ${path}`);
}

async function denied(words, code) {
  const count = requests.length;
  const result = await launch(['unifi-axi', ...words]).result;
  assert.notEqual(result.status, 0, result.stdout);
  assert.equal(decode(result.stdout).error.code, code);
  assert.equal(requests.length, count, 'Denied calls must never reach the fake vendor');
  cleanupObserved();
}

try {
  createTestCertificates(scratch, ['localhost']);
  sites = [first, second];
  vendor = createServer({ key: readFileSync(join(scratch, 'server.key')), cert: readFileSync(join(scratch, 'server.crt')) }, (request, response) => {
    const url = new URL(request.url, 'https://localhost');
    requests.push({ path: url.pathname, query: url.search, method: request.method });
    assert.equal(request.method, 'GET');
    assert.equal(request.headers['x-api-key'], canary, 'Only the host-owned synthetic key reaches the vendor');
    response.setHeader('content-type', 'application/json');
    if (inventoryHandler) {
      const body = inventoryHandler(request, response);
      if (body !== undefined) response.end(JSON.stringify(body));
      return;
    }
    if (url.pathname.endsWith('/info')) {
      const body = mode === 'bad-info' ? { applicationVersion: 11 } : { applicationVersion: version, siteManagerVersion: '5.2.23',
        ...(mode === 'long-info' ? { description: 'a'.repeat(1500), passphrase: 'CANARY-wifi-secret' } : {}) };
      response.end(JSON.stringify(body));
    } else {
      assert.equal(url.pathname, '/proxy/network/integration/v1/sites');
      if (mode === 'stall') { stalled?.(); return; }
      if (mode === 'oversize') { response.end(JSON.stringify({ padding: 'x'.repeat(1024 * 1024) })); return; }
      const offset = Number(url.searchParams.get('offset'));
      const limit = Number(url.searchParams.get('limit'));
      const data = sites.slice(offset, offset + Math.min(limit, mode === 'paged' ? 1 : limit));
      response.end(JSON.stringify(mode === 'bad-sites' ? { data: [{}] } : { offset, limit, count: data.length, totalCount: sites.length, data }));
    }
  });
  vendor.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  vendor.listen(0, '127.0.0.1');
  await once(vendor, 'listening');
  const vendorPort = vendor.address().port;
  const provider = new EnvironmentKeyProvider({ ARTIUM_AXI_MASTER_KEY: randomBytes(32).toString('base64') });
  db = openStore(join(scratch, 'data', 'artium.db'), provider);
  const password = 'CANARY-local-b1-3-password';
  db.prepare(`INSERT INTO users (id, username, display_name, password_hash, must_change, administrator)
    VALUES ('synthetic-user', 'synthetic-user', 'Synthetic User', ?, 0, 0)`).run(await hashPassword(password));
  db.exec(`INSERT INTO roles (id, name) VALUES ('synthetic-role', 'Synthetic Role');
    INSERT INTO user_roles (user_id, role_id) VALUES ('synthetic-user', 'synthetic-role');
    INSERT INTO role_tools (role_id, tool) VALUES ('synthetic-role', 'unifi-axi');
    UPDATE tools SET enabled = 1 WHERE name = 'unifi-axi'`);
  const store = createCredentialStore(db, provider);
  const origin = `https://localhost:${vendorPort}`;
  store.replaceCredential('unifi-axi', { origin, apiKey: canary }, 0, 'synthetic-user', Date.now());
  const resolver = new SharedIdentityResolver(store);
  const runner = await Runner.create(calls, { pem: readFileSync(join(scratch, 'ca.crt'), 'utf8'), certificates: [] });
  const adapter = createUnifiAdapter(new EmbeddedSecretSource(store), join(scratch, 'writes.log'));
  healthDefaults.tickMs = report.fixtureHealthTickMs;
  app = createApp({ db, audit: new Audit(db, Date.now, line => {
    const event = JSON.parse(line);
    if (event.event === 'run-terminal' && event.user_id === 'synthetic-user') terminalEvents.emit('terminal', event);
  }), runner, credentialStore: store,
    resolver: { async resolve(user, tool) {
      const ref = await resolver.resolve(user, tool);
      return identity === 'wrong-tool' ? { ...ref, tool: 'gitea-axi' } : identity === 'wrong-profile' ? { ...ref, id: 'nonexistent' } :
        identity === 'wrong-revision' ? { ...ref, revision: ref.revision - 1 } : ref;
    } }, environment: {}, adapters: [adapter] });
  const url = await app.listen({ host: '127.0.0.1', port: 0 });
  mkdirSync(join(cliEnvironment.XDG_CONFIG_HOME, 'unifi-axi'), { recursive: true, mode: 0o700 });
  const developerProfile = join(cliEnvironment.XDG_CONFIG_HOME, 'unifi-axi/config.json');
  writeFileSync(developerProfile, JSON.stringify({ version: 1, defaultProfile: 'developer', profiles: {
    developer: { origin: 'https://developer.invalid', apiKey: { env: 'UNIFI_AXI_API_KEY' } },
  } }), { mode: 0o600 });
  cliEnvironment.UNIFI_AXI_CONFIG = developerProfile;
  cliEnvironment.UNIFI_AXI_PROFILE = 'developer';
  cliEnvironment.ARTIUM_AXI_URL = url;
  const ports = [vendorPort, Number(new URL(url).port)];
  const guardSource = pathToFileURL(join(root, 'test/fixtures/fake-egress.mjs')).href;
  writeFileSync(guard, `import { guardEgress } from ${JSON.stringify(guardSource)};
import {appendFileSync,readFileSync} from 'node:fs';
guardEgress(${JSON.stringify(ports)},()=>appendFileSync(${JSON.stringify(deniedLog)},'denied\\n'));
if (process.argv[1]?.endsWith('/dist/bin.js') || process.argv[1]?.endsWith('unifi-input-consumer.mjs')) {
  const config=JSON.parse(readFileSync(process.env.XDG_CONFIG_HOME+'/unifi-axi/config.json','utf8'));
  if (config.profiles.artium.apiKey.env !== 'ARTIUM_SECRET_0' || process.env.ARTIUM_SECRET_0 !== ${JSON.stringify(canary)}) throw Error('Wrong SecretRef');
  appendFileSync(${JSON.stringify(processLog)},JSON.stringify({pid:process.pid,ppid:process.ppid,config:process.env.XDG_CONFIG_HOME+'/unifi-axi/config.json',secretRef:config.profiles.artium.apiKey})+'\\n');
}
`, { mode: 0o600 });
  unifiFixtureRuntime.guard = guard;
  guardEgress(ports, () => appendFileSync(deniedLog, 'denied\n'));
  // Negative control: a swallowed denial is still recorded without opening a socket.
  const { connect } = await import('node:net');
  assert.throws(() => connect(443, 'non-fake.invalid'), /forbids/);
  assert.equal(readFileSync(deniedLog, 'utf8'), 'denied\n');
  rmSync(deniedLog);
  watcher = watch(calls, { recursive: true }, () => {
    const observe = path => {
      let entries;
      try { entries = readdirSync(path, { withFileTypes: true }); }
      catch (error) {
        if (error.code === 'ENOENT') return;
        throw error;
      }
      for (const entry of entries) {
        const target = join(path, entry.name);
        if (entry.isDirectory()) observe(target);
        else {
          try {
            staged.add(target);
            assert.equal(statSync(target).mode & 0o077, 0, 'Staged files are private');
            if (entry.name === 'config.json') {
              const config = JSON.parse(readFileSync(target, 'utf8'));
              if (config.profiles?.artium) {
                assert.deepEqual(config.profiles.artium.apiKey, { env: 'ARTIUM_SECRET_0' });
                report.isolation.push({ file: target.slice(scratch.length), mode: statSync(target).mode & 0o777, secretRef: config.profiles.artium.apiKey });
                if (rejectAfterStaging) {
                  rejectAfterStaging = false;
                  stagingRejections++;
                  db.prepare("UPDATE users SET disabled = 1 WHERE id = 'synthetic-user'").run();
                }
              }
            }
          } catch (error) {
            if (error.code !== 'ENOENT') throw error;
          }
        }
      }
    };
    observe(calls);
  });
  await cli(['login', '--username', 'synthetic-user', '--password-stdin'], 0, password);
  report.installedExecutable = toolPaths['unifi-axi'];
  const installed = dirname(dirname(toolPaths['unifi-axi']));
  const installedPackage = JSON.parse(readFileSync(join(installed, 'package.json'), 'utf8'));
  const sourcePackage = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  for (const field of ['name', 'version', 'type', 'bin', 'exports', 'dependencies', 'engines']) {
    assert.deepEqual(installedPackage[field], sourcePackage[field], `Reject stale package identity: ${field}`);
  }
  for (const file of readdirSync(join(root, 'dist')).filter(file => /\.(js|json)$/.test(file))) {
    assert.equal(sha(readFileSync(join(installed, 'dist', file))), sha(readFileSync(join(root, 'dist', file))),
      `Installed runtime asset must match the current build: ${file}`);
  }
  report.installedPackageHashes = Object.fromEntries(['package.json', 'dist/bin.js', 'dist/axi-credential.schema.json'].map(path =>
    [path, sha(readFileSync(join(installed, path)))]));
  report.inventorySha256 = sha(readFileSync(join(host, 'tools/inventories/unifi-axi.json')));
  const packagePath = JSON.parse(readFileSync(join(host, 'tools/package.json'), 'utf8')).dependencies['@knowttl/unifi-axi'].replace(/^file:/, '');
  report.packageIntegritySha256 = sha(readFileSync(resolve(host, 'tools', packagePath)));
  report.hostLockfileSha256 = sha(readFileSync(join(host, 'tools/pnpm-lock.yaml')));

  for (version of ['10.6.109', '11.0.97']) {
    for (const [variant, records, paging] of [['observed', [first, second], 'normal'], ['empty', [], 'normal'], ['two-pages', [first, second], 'paged']]) {
      sites = records; mode = paging;
      const information = decode((await cli(['unifi-axi', 'info'])).stdout);
      assert.deepEqual(information.information, { applicationVersion: version, siteManagerVersion: '5.2.23' });
      assert.deepEqual(information.api, { applicationVersion: version, contract: version, status: 'verified', writesAvailable: false });
      const listing = decode((await cli(['unifi-axi', 'site', 'list'])).stdout);
      assert.deepEqual(listing.sites, records);
      assert.equal(listing.count, records.length);
      assert.equal(listing.totalCount, records.length);
      assert.equal(listing.complete, true);
      record('AC-001/AC-001-VARIANTS/AC-002/AC-002-VARIANTS', { version, variant });
      cleanupObserved();
    }
  }
  await verifyInventory({
    cli: async (words, status = 0) => {
      const result = decode((await cli(['unifi-axi', ...words], status)).stdout);
      cleanupObserved();
      return result;
    },
    seed: handler => { inventoryHandler = handler; },
  });
  report.rows.push(...await verifyPolicies({
    cli: async (words, status = 0) => {
      const result = decode((await cli(['unifi-axi', ...words], status)).stdout);
      cleanupObserved();
      return result;
    },
    seed: handler => { inventoryHandler = handler; },
  }));
  inventoryHandler = undefined;
  record('STEP-B2.2/STEP-B2.3/STEP-B2.4/STEP-B2.5', { versions: ['10.6.109', '11.0.97'],
    knownLimitation: '11.0.97 device reads remain blocked by CF-007' });
  for (const [bad, words] of [['bad-info', ['info']], ['bad-sites', ['site', 'list']]]) {
    mode = bad;
    assert.equal(decode((await cli(['unifi-axi', ...words], 1)).stdout).error.code, 'RESPONSE_INVALID');
  }
  mode = 'normal'; sites = [first, second];
  mode = 'long-info';
  const shortText = decode((await cli(['unifi-axi', 'info'])).stdout);
  assert.deepEqual(shortText.textTruncation.fields, [{ path: '/information/description', originalSize: 1500 }]);
  const fullText = decode((await cli(['unifi-axi', 'info', '--full'])).stdout);
  assert.equal(fullText.information.description, 'a'.repeat(1500));
  assert.equal(fullText.information.passphrase, '[REDACTED]');
  record('AXI-003/STEP-B2.10', { fullText: 'redacted', originalSize: 1500 });
  mode = 'normal';
  for (const [words, code] of [
    [['info', '--config', '/other'], 'FLAG_BLOCKED'], [['info', '--profile', 'developer'], 'FLAG_BLOCKED'],
    [['info', '--origin', 'https://other.invalid'], 'FLAG_BLOCKED'], [['info', '--api-key', 'CANARY-other'], 'FLAG_BLOCKED'],
    ...['route', 'trust', 'journal', 'tls', 'secret-output'].map(flag => [['info', `--${flag}`, 'other'], 'INVALID_INPUT']),
    [['setup'], 'INVALID_INPUT'], [['auth', 'export'], 'INVALID_INPUT'], [['device', 'adopt'], 'INVALID_INPUT'],
    [['network', 'create'], 'INVALID_INPUT'],
    [['network', 'create', '--execute', '--confirm', '0'.repeat(64), '--request-id', 'host-custody-denied', '--body-file', '/other'], 'INVALID_INPUT'],
    [['network', 'delete', '--network-id', first.id, '--execute', '--confirm', '0'.repeat(64), '--request-id', 'host-delete-denied'], 'INVALID_INPUT'],
    [['network', 'update', '--network-id', first.id, '--body-file', '/other', '--execute', '--confirm', '0'.repeat(64), '--request-id', 'host-update-denied'], 'INVALID_INPUT'],
    [['hotspot', 'voucher', 'list', '--site', first.id, '--secret-output', '/other'], 'INVALID_INPUT'],
    [['wifi', 'broadcast', 'show', '--site', first.id, '--wifi-broadcast-id', first.id, '--secret-output', '/other'], 'INVALID_INPUT'],
    [['write', 'show', '--request-id', 'host-custody-denied'], 'INVALID_INPUT'],
    [['write', 'reconcile', '--request-id', 'host-custody-denied'], 'INVALID_INPUT'],
  ]) await denied(words, code);
  record('HOST-005/WRITE-006/STEP-B3.3', { admission: 'hosted-writes-denied',
    durableCustody: 'absent; read-only fixture cannot admit mutations', mutationRequests: 0 });
  db.prepare("DELETE FROM role_tools WHERE tool = 'unifi-axi'").run();
  await denied(['info'], 'TOOL_NOT_GRANTED');
  db.prepare("INSERT INTO role_tools VALUES ('synthetic-role', 'unifi-axi')").run();
  for (const [wrongIdentity, code] of [['wrong-tool', 'CREDENTIAL_INVALID'], ['wrong-profile', 'REVISION_CONFLICT'], ['wrong-revision', 'REVISION_CONFLICT']]) {
    identity = wrongIdentity;
    await denied(['info'], code);
  }
  identity = 'normal';
  record('WRITE-001', { task: 'B4.11', hostCredentialRevision: 'stale revision refused before vendor access',
    hostedWrites: 'denied; no durable hosted write custody' });
  const executable = toolPaths['unifi-axi'];
  toolPaths['unifi-axi'] = executable + '.unknown';
  await denied(['info'], 'CREDENTIAL_INVALID');
  toolPaths['unifi-axi'] = executable;
  const schema = toolCredentialSchemaPaths['unifi-axi'];
  toolCredentialSchemaPaths['unifi-axi'] = schema + '.unknown';
  await denied(['info'], 'CREDENTIAL_INVALID');
  toolCredentialSchemaPaths['unifi-axi'] = schema;
  const { default: inventory } = await import(pathToFileURL(join(host, 'dist/tools/inventories/unifi-axi.json')), { with: { type: 'json' } });
  const recordedHash = inventory.sources[0].sha256;
  try { inventory.sources[0].sha256 = '0'.repeat(64); await denied(['info'], 'CREDENTIAL_INVALID'); }
  finally { inventory.sources[0].sha256 = recordedHash; }
  try { inventory.tool = 'unknown-axi'; await denied(['info'], 'CREDENTIAL_INVALID'); }
  finally { inventory.tool = 'unifi-axi'; }
  assert.equal(db.prepare("SELECT action FROM audit WHERE event = 'run-terminal' AND user_id = 'synthetic-user' AND outcome = 'completed' ORDER BY id DESC LIMIT 1").get().action, 'read');
  record('CRED-009/HOST-004', { developerProfile: 'excluded', readJournal: 'read' });

  mode = 'stall'; runnerLimits.timeoutMs = 1000;
  for (const cancel of [true, false]) {
    const arrived = new Promise(resolve => { stalled = resolve; });
    const terminal = once(terminalEvents, 'terminal');
    const started = performance.now();
    const invocation = launch(['unifi-axi', 'site', 'list']);
    await Promise.race([arrived, invocation.result.then(() => { throw new Error('CLI exited before the stalled vendor request'); })]);
    const observations = readFileSync(processLog, 'utf8').trim().split('\n').map(JSON.parse);
    const leader = observations.at(-1).pid;
    const tree = execFileSync('ps', ['-eo', 'pid,ppid,pgid,args'], { encoding: 'utf8' }).split('\n')
      .filter(line => new RegExp(`^\\s*\\d+\\s+\\d+\\s+${leader}\\s`).test(line));
    assert.ok(tree.some(line => line.includes(String(leader))));
    if (cancel) invocation.child.kill('SIGINT');
    const result = await invocation.result;
    assert.notEqual(result.status, 0);
    assert.equal((await terminal)[0].outcome, cancel ? 'CANCELLED' : 'TIMEOUT');
    assert.ok(performance.now() - started < 4500, 'Host deadline plus 2 s grace and bounded scheduling tolerance');
    assert.throws(() => process.kill(leader, 0), { code: 'ESRCH' });
    assert.equal(sockets.size, 0);
    cleanupObserved();
    report.processObservations.push({ cancel, leader, tree, elapsedMs: performance.now() - started });
  }
  for (const hostTimeoutMs of [60_000, 20_000]) {
    runnerLimits.timeoutMs = hostTimeoutMs;
    const before = performance.now();
    const toolTimeout = await cli(['unifi-axi', 'site', 'list'], 1);
    assert.equal(decode(toolTimeout.stdout).error.code, 'READ_INCOMPLETE', 'Longer host deadline must preserve a tool timeout');
    assert.equal(db.prepare("SELECT outcome FROM audit WHERE event='run-terminal' AND user_id='synthetic-user' ORDER BY id DESC LIMIT 1").get().outcome, 'completed');
    assert.throws(() => assert.equal(db.prepare("SELECT outcome FROM audit WHERE event='run-terminal' AND user_id='synthetic-user' ORDER BY id DESC LIMIT 1").get().outcome, 'TIMEOUT'),
      { code: 'ERR_ASSERTION' }, 'The host-timeout assertion must fail when only the tool deadline expires');
    assert.ok(performance.now() - before >= 9000, 'The tool request deadline remains 10 s');
    cleanupObserved();
    report.processObservations.push({ hostTimeoutMs, toolTimeout: true, elapsedMs: performance.now() - before });
  }
  record('HOST-001', { hostTimeoutMs: 1000, toolDeadlineMs: 10000, terminationGraceMs: 2000, negativeControl: 'tool timeout is not host TIMEOUT' });

  mode = 'oversize';
  assert.equal(decode((await cli(['unifi-axi', 'site', 'list'], 1)).stdout).error.code, 'READ_INCOMPLETE');
  mode = 'normal';
  sites = Array.from({ length: 100 }, (_, index) => ({ ...first,
    id: `9361553d-e20d-45b8-a516-${String(index).padStart(12, '0')}`, name: `Synthetic ${index} ${'x'.repeat(120)}` }));
  runnerLimits.outputBytesPerStream = 512;
  const retained = await cli(['unifi-axi', 'site', 'list']);
  assert.equal(Buffer.byteLength(retained.stdout), 512);
  assert.match(retained.stderr, /output truncated/);
  runnerLimits.floodBytes = 8192;
  const flood = await launch(['unifi-axi', 'site', 'list']).result;
  assert.notEqual(flood.status, 0);
  assert.equal(decode(flood.stdout).error.code, 'OUTPUT_LIMIT');
  cleanupObserved();
  // Disabling only the flood cap must invalidate the host-limit assertion.
  runnerLimits.floodBytes = report.defaultLimits.floodBytes;
  const control = await cli(['unifi-axi', 'site', 'list']);
  assert.equal(control.status, 0, 'Disabling only the flood cap invalidates the host OUTPUT_LIMIT assertion');
  assert.throws(() => assert.equal(db.prepare("SELECT outcome FROM audit WHERE event='run-terminal' AND user_id='synthetic-user' ORDER BY id DESC LIMIT 1").get().outcome, 'OUTPUT_LIMIT'),
    { code: 'ERR_ASSERTION' });
  runnerLimits.outputBytesPerStream = report.defaultLimits.outputBytesPerStream;
  const unretained = await cli(['unifi-axi', 'site', 'list']);
  assert.ok(Buffer.byteLength(unretained.stdout) > 8192);
  assert.equal(unretained.stderr, '');
  assert.throws(() => assert.equal(Buffer.byteLength(unretained.stdout), 512), { code: 'ERR_ASSERTION' });
  runnerLimits.outputBytesPerStream = 512;
  const stderrCanary = await runner.run('synthetic-user', process.execPath, ['-e', "process.stderr.write('x'.repeat(2048))"], {}, [], {});
  assert.equal(Buffer.byteLength(stderrCanary.stderr), 512);
  assert.equal(stderrCanary.outputBytes.stderr, 2048);
  assert.equal(stderrCanary.truncated.stderr, true);
  runnerLimits.floodBytes = 8192;
  await assert.rejects(runner.run('synthetic-user', process.execPath, ['-e', "process.stderr.write('x'.repeat(16384))"], {}, []), { code: 'OUTPUT_LIMIT' });
  report.runnerEvidence.push({ stream: 'stderr', retained: 512, observed: 2048, flood: 8192, canary: 'host-only, not a UniFi operation' });
  Object.assign(runnerLimits, report.defaultLimits);
  record('HOST-002', { fixtureRetentionBytes: 512, fixtureFloodBytes: 8192, productionLimitsUnchanged: true });

  mode = 'normal';
  const upload = join(scratch, 'synthetic.txt');
  writeFileSync(upload, 'synthetic upload', { mode: 0o600 });
  for (const [mode, status] of [['success', 0], ['fail', 7]]) {
    await cli(['unifi-axi', 'fixture', 'input', '--filea', upload, '--stdin', 'pipe', '--mode', mode], status, 'synthetic stdin');
    cleanupObserved();
  }
  const eightUploads = ['unifi-axi', 'fixture', 'input', '--stdin', 'pipe', '--mode', 'success'];
  for (const letter of 'abcdefgh') {
    const file = join(scratch, `valid-${letter}.txt`);
    writeFileSync(file, 'synthetic upload');
    eightUploads.push(`--file${letter}`, file);
  }
  await cli(eightUploads, 0, 'synthetic stdin');
  cleanupObserved();
  const countBeforeRejection = requests.length;
  const processesBeforeRejection = readFileSync(processLog, 'utf8');
  rejectAfterStaging = true;
  try {
    const rejected = await launch(['unifi-axi', 'fixture', 'input', '--filea', upload, '--stdin', 'pipe', '--mode', 'success'], 'synthetic stdin').result;
    assert.notEqual(rejected.status, 0);
    assert.equal(decode(rejected.stdout).error.code, 'USER_DISABLED');
    assert.equal(stagingRejections, 1);
    assert.equal(readFileSync(processLog, 'utf8'), processesBeforeRejection, 'Reauthentication rejects staged state before spawning');
    assert.equal(requests.length, countBeforeRejection);
    cleanupObserved();
  } finally {
    rejectAfterStaging = false;
    db.prepare("UPDATE users SET disabled = 0 WHERE id = 'synthetic-user'").run();
  }
  await cli(['login', '--username', 'synthetic-user', '--password-stdin'], 0, password);
  runnerLimits.timeoutMs = 1000;
  for (const cancel of [true, false]) {
    const processWatcher = watch(processLog);
    const spawned = once(processWatcher, 'change');
    const terminal = once(terminalEvents, 'terminal');
    const count = requests.length;
    const invocation = launch(['unifi-axi', 'fixture', 'input', '--filea', upload, '--stdin', 'pipe', '--mode', 'stall'], 'synthetic stdin');
    await Promise.race([spawned, invocation.result.then(() => { throw new Error('CLI exited before the staged consumer started'); })]);
    processWatcher.close();
    if (cancel) invocation.child.kill('SIGINT');
    const result = await invocation.result;
    assert.notEqual(result.status, 0);
    assert.equal((await terminal)[0].outcome, cancel ? 'CANCELLED' : 'TIMEOUT');
    assert.equal(requests.length, count);
    cleanupObserved();
  }
  Object.assign(runnerLimits, report.defaultLimits);
  const invalidInputs = [
    { name: 'per-file', files: [1024 * 1024 + 1] },
    { name: 'total', files: [1024 * 1024, 1024 * 1024, 1024 * 1024, 1024 * 1024, 1] },
    { name: 'nine-files', files: Array(9).fill(1) },
    { name: 'stdin', files: [], stdin: 'x'.repeat(512 * 1024 + 1) },
  ];
  for (const input of invalidInputs) {
    const words = ['unifi-axi', 'fixture', 'input', '--stdin', 'pipe'];
    input.files.forEach((size, index) => {
      const file = join(scratch, `input-${index}.txt`);
      writeFileSync(file, 'x'.repeat(size));
      words.push(`--file${'abcdefghi'[index]}`, file);
    });
    const count = requests.length;
    const result = await launch(words, input.stdin ?? 'synthetic stdin').result;
    assert.notEqual(result.status, 0);
    assert.equal(decode(result.stdout).error.code, 'INVALID_INPUT');
    assert.equal(requests.length, count);
    cleanupObserved();
  }
  symlinkSync(upload, join(scratch, 'link.txt'));
  const unsafe = join(scratch, 'unsafe:name.txt');
  writeFileSync(unsafe, 'synthetic upload');
  for (const words of [
    ['--filea', join(scratch, 'link.txt')], ['--filea', `${scratch}/../scratch/synthetic.txt`],
    ['--filea', upload, '--fileb', upload],
    ['--filea', unsafe],
  ]) {
    const count = requests.length;
    const result = await launch(['unifi-axi', 'fixture', 'input', ...words, '--stdin', 'pipe'], 'synthetic stdin').result;
    assert.notEqual(result.status, 0);
    assert.equal(decode(result.stdout).error.code, 'INVALID_INPUT');
    assert.equal(requests.length, count);
    cleanupObserved();
  }
  record('HOST-003', { inputFiles: 8, fileBytes: 1048576, totalFileBytes: 4194304, stdinBytes: 524288, consumer: 'fixture-only' });
  report.processes = readFileSync(processLog, 'utf8').trim().split('\n').map(JSON.parse).map(({ config, ...row }) => ({ ...row, config: config.slice(scratch.length) }));
  assert.ok(report.processes.every(row => row.config.startsWith('/calls/artium-call-')));
  assert.deepEqual(JSON.parse(readFileSync(developerProfile, 'utf8')).profiles.developer.apiKey, { env: 'UNIFI_AXI_API_KEY' });
  assert.ok(report.isolation.length > 0, 'An independent filesystem observer saw the shared profile');
  assert.equal(existsSync(deniedLog), false, 'No non-fake egress was attempted');
  report.requests = requests;
  report.hostRuns = db.prepare("SELECT outcome, action, exit_code, duration_ms, stdout_bytes, stderr_bytes, error_code FROM audit WHERE event = 'run-terminal' ORDER BY id").all();
  report.result = 'passed-on-linux; native Windows PENDING';
} finally {
  activeCli?.kill('SIGTERM');
  watcher?.close();
  await app?.close();
  for (const socket of sockets) socket.destroy();
  if (vendor) await new Promise(resolve => vendor.close(resolve));
  db?.close();
  Object.assign(runnerLimits, report.defaultLimits);
  healthDefaults.tickMs = report.defaultHealthTickMs;
  writeFileSync(join(output, 'artium-proof.json'), JSON.stringify(report, null, 2) + '\n');
  rmSync(scratch, { recursive: true, force: true });
}
console.log(JSON.stringify({ result: report.result, cases: report.rows.length, evidence: join(output, 'artium-proof.json') }));
