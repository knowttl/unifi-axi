import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, mkdirSync, existsSync, rmSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decode } from '@toon-format/toon';
import { verifyCredentials } from '../test/credentials.mjs';
import { verifyIntegrations } from '../test/integrations.ts';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2).filter(arg => arg !== '--');
assert.ok(args.length === 0 || (args.length === 2 && args[0] === '--task' && ['B1.1', 'B1.2', 'B1.2a', 'B2.0', 'B2.2', 'B2.3', 'B2.4', 'B2.5', 'B2.6', 'B2.7', 'B2.8', 'B2.9', 'B2.10', 'B3.1', 'B3.2', 'B3.3'].includes(args[1])),
  'Select an implemented task. Unknown, future, duplicate or incomplete selectors fail.');
const temporary = mkdtempSync(join(tmpdir(), 'unifi-axi-packaged-'));
const prefix = join(temporary, 'install');
const user = join(temporary, 'user');
mkdirSync(prefix);
mkdirSync(user);
const networkLog = join(temporary, 'network-attempts');
const guard = fileURLToPath(new URL('../test/fixtures/no-network.mjs', import.meta.url));
const sourcePackage = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const expected = JSON.parse(readFileSync(join(root, 'test/fixtures/catalogue.json'), 'utf8'));
const implemented = ['info', 'site list', 'country list', 'dpi application list', 'dpi category list', 'device pending list',
  'device-tag list', 'radius profile list', 'vpn server list', 'vpn site-to-site-tunnel list', 'wan list',
  'device list', 'device show', 'device statistics latest', 'client list', 'client show', 'network list', 'network show', 'network references',
  'acl-rule list', 'acl-rule order show', 'acl-rule show', 'dns policy list', 'dns policy show',
  'firewall policy list', 'firewall policy order show', 'firewall policy show', 'firewall zone list', 'firewall zone show',
  'hotspot voucher list', 'hotspot voucher show', 'switching lag list', 'switching lag show',
  'switching mc-lag-domain list', 'switching mc-lag-domain show', 'switching switch-stack list', 'switching switch-stack show',
  'traffic-list list', 'traffic-list show', 'wifi broadcast list', 'wifi broadcast show', 'network create', 'network delete'];
const expectedStatus = command => implemented.includes(command) ? 'implemented' : 'not-implemented';
const detail = ['network delete', 'device show', 'device statistics latest', 'client show', 'network show', 'network references',
  'acl-rule show', 'dns policy show', 'firewall policy order show', 'firewall policy show', 'firewall zone show',
  'hotspot voucher show', 'switching lag show', 'switching mc-lag-domain show', 'switching switch-stack show',
  'traffic-list show', 'wifi broadcast show'];
const pnpmScript = process.env.npm_execpath;
assert.ok(pnpmScript, 'Run this entry through pnpm verify:packaged');

function command(bin, args, options = {}) {
  const result = spawnSync(bin, args, { cwd: root, encoding: 'utf8', timeout: 120_000, ...options });
  assert.ifError(result.error);
  assert.equal(result.signal, null, `Command terminated: ${result.stderr}`);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  return result;
}

function sha(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

try {
  const sourceHashes = {};
  const evidence = readFileSync(join(root, 'evidence/README.md'), 'utf8');
  for (const line of evidence.split('\n').filter(line => /^\| (sources|fixtures)\//.test(line))) {
    const [, file, packPath, hash] = line.split('|').map(cell => cell.trim());
    assert.equal(file, packPath, 'Retain relative pack paths');
    assert.equal(sha(readFileSync(join(root, 'evidence', file))), hash, `Retained hash: ${file}`);
    sourceHashes[file] = hash;
  }
  assert.equal(Object.keys(sourceHashes).length, 6, 'All six retained files must be checked');
  command(process.execPath, [pnpmScript, 'pack', '--pack-destination', temporary]);
  const archives = readdirSync(temporary).filter(file => file.endsWith('.tgz'));
  assert.equal(archives.length, 1);
  const archive = join(temporary, archives[0]);
  const integrity = sha(readFileSync(archive));
  command(process.execPath, [pnpmScript, '--dir', prefix, 'add', '--prefer-offline', '--ignore-scripts', '--save-exact', archive]);
  const installed = join(prefix, 'node_modules/@knowttl/unifi-axi');
  const installedPackage = JSON.parse(readFileSync(join(installed, 'package.json'), 'utf8'));
  assert.equal(installedPackage.name, '@knowttl/unifi-axi');
  assert.equal(installedPackage.version, sourcePackage.version, 'Reject stale artifact identity');
  const executable = join(installed, installedPackage.bin['unifi-axi']);
  const env = {
    PATH: process.env.PATH, SystemRoot: process.env.SystemRoot,
    HOME: user, USERPROFILE: user, APPDATA: user, LOCALAPPDATA: user,
    XDG_CONFIG_HOME: user, XDG_STATE_HOME: user, TMPDIR: temporary, TEMP: temporary, TMP: temporary,
    UNIFI_AXI_TEST_NETWORK_LOG: networkLog,
  };
  assert.equal(command(process.execPath, [pnpmScript, '--dir', prefix, 'exec', 'unifi-axi', '--version'],
    { cwd: user, env }).stdout, `${sourcePackage.version}\n`, 'The installed package-manager launcher must work');

  // Prove the guard detects a swallowed external-boundary failure before trusting zero attempts.
  command(process.execPath, ['--import', guard, '-e', "import('node:net').then(({connect}) => {try {connect(9, '127.0.0.1')} catch {}})"], { env });
  assert.equal(readFileSync(networkLog, 'utf8'), 'network-attempt\n');
  rmSync(networkLog);

  function cli(args, status = 0, extraEnv = {}, guarded = true) {
    const result = spawnSync(process.execPath, [...(guarded ? ['--import', guard] : []), executable, ...args], {
      cwd: user, env: { ...env, ...extraEnv }, encoding: 'utf8', timeout: 10_000,
    });
    assert.ifError(result.error);
    assert.equal(result.signal, null);
    assert.equal(result.status, status, `${args.join(' ')}\n${result.stdout}\n${result.stderr}`);
    assert.equal(result.stderr, '', 'Structured output must stay on stdout');
    assert.equal(existsSync(networkLog), false, 'No network attempt, even if the command catches the error');
    return result.stdout;
  }

  const discovery = decode(cli(['commands']));
  assert.equal(discovery.count, 73);
  assert.deepEqual(discovery.commands, expected.map(({ id, command, effect }) => ({ id, command, effect, status: expectedStatus(command) })));
  const top = decode(cli(['--help']));
  assert.deepEqual(top.examples, ['unifi-axi commands', 'unifi-axi info --help', 'unifi-axi auth status']);
  assert.deepEqual(top.commands.filter(entry => entry.command === 'info'), [{ command: 'info', status: 'implemented' }]);
  const rows = [];
  for (const operation of expected) {
    const words = operation.command.split(' ');
    const help = decode(cli([...words, '--help']));
    assert.equal(help.command, operation.command);
    assert.equal(help.effect, operation.effect);
    assert.equal(help.method, operation.method);
    assert.equal(help.path, operation.path);
    assert.equal(help.status, expectedStatus(operation.command));
    assert.deepEqual(help.examples[0], `unifi-axi ${operation.command} --help`);
    const unfinished = decode(cli(words, detail.includes(operation.command) ? 2 : 1, { UNIFI_AXI_ORIGIN: 'https://127.0.0.1:9' }));
    assert.equal(unfinished.error.code, detail.includes(operation.command) ? 'INVALID_ARGUMENT' : expectedStatus(operation.command) === 'implemented' ? 'CONFIG_INVALID' : 'NOT_IMPLEMENTED');
    const unknown = decode(cli([...words, '--misspelled'], 2, { UNIFI_AXI_ORIGIN: 'https://127.0.0.1:9' }));
    assert.equal(unknown.error.code, 'UNKNOWN_FLAG');
    assert.equal(unknown.help[0].includes('--help'), true);
    rows.push({ task: 'B1.1', acceptance: 'STEP-B1.1', operation: operation.id,
      version: ['10.6.109', '11.0.97'], variant: null, direction: 'static-discovery', status: 'passed' });
  }
  for (const entry of top.commands.filter(entry => !expected.some(operation => operation.command === entry.command))) {
    const words = entry.command.split(' ');
    const help = decode(cli([...words, '--help']));
    assert.equal(help.command, entry.command);
    if (['write show', 'write reconcile'].includes(entry.command)) {
      assert.equal(decode(cli(words, 2)).error.code, 'INVALID_ARGUMENT');
    }
  }
  for (const [args, code] of [
    [['site', 'list', '--limit', '201'], 'INVALID_ARGUMENT'],
    [['site', 'list', '--offset', '-1'], 'INVALID_ARGUMENT'],
    [['site', 'list', '--limit', '1.5'], 'INVALID_ARGUMENT'],
    [['site', 'list', '--limit', 'no'], 'INVALID_ARGUMENT'],
    [['site', 'list', '--limit'], 'INVALID_ARGUMENT'],
    [['site', 'list', '--limit', '1', '--limit', '2'], 'DUPLICATE_FLAG'],
    [['info', '--profile', 'one', '--profile', 'two'], 'DUPLICATE_FLAG'],
    [['info', '--help', '--misspelled'], 'UNKNOWN_FLAG'],
    [['info', '--help=true'], 'INVALID_ARGUMENT'],
    [['info', 'unexpected'], 'UNKNOWN_COMMAND'],
    [['OP-999'], 'UNKNOWN_COMMAND'],
    [['--misspelled'], 'UNKNOWN_FLAG'],
  ]) assert.equal(decode(cli(args, 2)).error.code, code);
  assert.equal(decode(cli(['site', 'list', '--limit=0', '--offset', '0'], 1)).error.code, 'PROFILE_REQUIRED');
  assert.equal(decode(cli([], 1)).error.code, 'PROFILE_REQUIRED');
  assert.equal(decode(cli(['auth', 'status'], 1)).error.code, 'PROFILE_REQUIRED');
  assert.equal(decode(cli(['auth', 'status'], 1, { UNIFI_AXI_ORIGIN: 'https://127.0.0.1:9' })).error.code, 'CONFIG_INVALID');

  const metadata = JSON.parse(command(process.execPath, ['--input-type=module', '-e',
    "import {catalogue} from '@knowttl/unifi-axi/catalogue';import capabilities from '@knowttl/unifi-axi/capabilities' with {type:'json'};import {readFileSync} from 'node:fs';const skill=readFileSync(new URL(import.meta.resolve('@knowttl/unifi-axi/skill')),'utf8');console.log(JSON.stringify({catalogue,capabilities,skill}));"], { cwd: prefix, env }).stdout);
  verifyIntegrations({ cli, temporary, user, guard });
  assert.deepEqual(metadata.catalogue.map(({ id, command, vendorOperationId, method, path, effect }) =>
    ({ id, command, vendorOperationId, method, path, effect })), expected);
  assert.deepEqual(metadata.capabilities.operations, metadata.catalogue, 'Generated metadata must match the public catalogue');
  const skillRows = metadata.skill.split('\n').filter(line => line.startsWith('| ') && !line.startsWith('| Command'))
    .map(line => line.split('|').slice(1, -1).map(cell => cell.trim()));
  assert.deepEqual(skillRows, expected.map(({ command, effect }) => [command, effect, expectedStatus(command)]),
    'The generated public skill must describe the agreed command surface');
  for (const version of ['10.6.109', '11.0.97']) {
    const contract = JSON.parse(readFileSync(join(installed, `evidence/sources/network-${version}-openapi.json`), 'utf8'));
    const pairs = Object.entries(contract.paths).flatMap(([path, methods]) => Object.entries(methods)
      .map(([method, value]) => ({ method: method.toUpperCase(), path, vendorOperationId: value.operationId })));
    const byOperation = (a, b) => a.vendorOperationId.localeCompare(b.vendorOperationId);
    assert.deepEqual(pairs.toSorted(byOperation), expected.map(({ method, path, vendorOperationId }) =>
      ({ method, path, vendorOperationId })).toSorted(byOperation));
    for (const operation of metadata.catalogue) {
      const source = contract.paths[operation.path][operation.method.toLowerCase()];
      const retained = operation.contracts.find(entry => entry.version === version);
      assert.deepEqual(retained.parameters, source.parameters ?? []);
      assert.deepEqual(retained.requestBody, source.requestBody);
      assert.deepEqual(retained.responses, source.responses);
    }
  }

  const median = values => values.toSorted((a, b) => a - b)[Math.floor(values.length / 2)];
  const timings = {};
  for (const flag of ['-v', '-V', '--version']) {
    const floor = [], version = [];
    for (let sample = 0; sample < 11; sample++) {
      let start = performance.now();
      command(process.execPath, ['-e', 'console.log(1)'], { cwd: user, env });
      floor.push(performance.now() - start);
      start = performance.now();
      assert.equal(cli([flag], 0, {}, false), `${sourcePackage.version}\n`);
      version.push(performance.now() - start);
    }
    timings[flag] = { floorMedianMs: median(floor), versionMedianMs: median(version), ratio: median(version) / median(floor) };
    assert.ok(timings[flag].ratio <= 2, `${flag} must remain within twice this host's bare Node median: ${JSON.stringify(timings[flag])}`);
  }
  assert.equal(new Set(rows.map(row => row.operation)).size, 73, 'No duplicate or missing results');
  if (args[1] !== 'B1.1') rows.push(...await verifyCredentials({ executable, installed, temporary, env, guard,
    journey: args[1] !== 'B1.2', writeTask: args[1] === undefined ? 'B3.3' : args[1].startsWith('B3.') ? args[1] : undefined }));
  if (args[1] === undefined || args[1] === 'B2.10') rows.push({ task: 'B2.10', acceptance: 'STEP-B2.10',
    operation: ['OP-001', 'OP-002'], direction: 'standalone-synthetic', status: 'passed-on-current-platform',
    integrations: ['claude', 'codex', 'opencode'], nativeWindows: 'PENDING', liveCommissioning: 'PENDING' });
  if (args[1] === undefined || ['B1.2a', 'B2.0'].includes(args[1])) rows.push({ task: 'B2.0', acceptance: 'STEP-B2.0',
    operation: ['OP-001', 'OP-002'], version: ['10.6.109', '11.0.97'], direction: 'standalone-synthetic', status: 'passed-on-current-platform' });
  console.log(JSON.stringify({ task: args[1] ?? 'B2.0', result: 'passed-on-current-platform', platform: process.platform,
    nativeWindows: process.platform === 'win32' ? 'passed' : 'PENDING', node: process.version,
    packageIntegritySha256: integrity, executable, sourceHashes,
    inputHashes: { catalogue: sha(readFileSync(join(root, 'test/fixtures/catalogue.json'))),
      lockfile: sha(readFileSync(join(root, 'pnpm-lock.yaml'))),
      credentials: sha(readFileSync(join(root, 'test/credentials.mjs'))),
      application: sha(readFileSync(join(root, 'test/application.mjs'))),
      reads: sha(readFileSync(join(root, 'test/reads.mjs'))),
      writes: sha(readFileSync(join(root, 'test/writes.ts'))),
      writeGuard: sha(readFileSync(join(root, 'test/fixtures/write-guard.ts'))) },
    timings, rows, futureTasks: 'unimplemented', liveMutationProbes: '32 unrun' }, null, 2));
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
