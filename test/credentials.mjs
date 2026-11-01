import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { appendFileSync, writeFileSync, readFileSync, chmodSync, mkdirSync, statSync, symlinkSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { X509Certificate } from 'node:crypto';
import { createServer } from 'node:https';
import { once } from 'node:events';
import { decode } from '@toon-format/toon';
import { verifyApplication } from './application.mjs';
import { verifyReads } from './reads.mjs';
import { verifyInventory } from './inventory.mjs';
import { verifyPolicies } from './policies.mjs';
import { guardEgress } from './fixtures/fake-egress.mjs';

export async function verifyCredentials({ executable, installed, temporary, env, guard, journey = false, writeTask }) {
  const inventoryRows = [];
  let fakePort;
  const home = join(temporary, 'credentials');
  mkdirSync(home, { mode: 0o700 });
  const config = join(home, 'config with spaces.json');
  const secretFile = join(home, 'key.txt');
  const syntheticKey = 'synthetic-"key+/=%';
  const redactedForms = [syntheticKey, JSON.stringify(syntheticKey).slice(1, -1), encodeURIComponent(syntheticKey)];
  const source = { origin: 'https://localhost:9', apiKey: { env: 'SYNTHETIC_KEY' } };
  function protectWindows(path) {
    if (process.platform !== 'win32') return;
    const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', `
$ErrorActionPreference='Stop'
$p=$env:UNIFI_AXI_FIXTURE_PATH
$me=[Security.Principal.WindowsIdentity]::GetCurrent().User
$acl=Get-Acl -LiteralPath $p
$acl.SetAccessRuleProtection($true,$false)
foreach($r in @($acl.Access)) { $acl.RemoveAccessRuleSpecific($r) }
$acl.SetOwner($me)
foreach($sid in @($me.Value,'S-1-5-18','S-1-5-32-544')) {
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','Allow'))
}
Set-Acl -LiteralPath $p -AclObject $acl
`], { env: { ...process.env, UNIFI_AXI_FIXTURE_PATH: path }, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
  }
  function makeWritableByOthers(path) {
    if (process.platform !== 'win32') { chmodSync(path, 0o666); return; }
    const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', `
$ErrorActionPreference='Stop'
$p=$env:UNIFI_AXI_FIXTURE_PATH
$acl=Get-Acl -LiteralPath $p
$sid=[Security.Principal.SecurityIdentifier]::new('S-1-1-0')
$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'Write','Allow'))
Set-Acl -LiteralPath $p -AclObject $acl
`], { env: { ...process.env, UNIFI_AXI_FIXTURE_PATH: path }, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
  }
  const write = (path, value) => { writeFileSync(path, value, { mode: 0o600 }); protectWindows(path); };
  const configure = (profiles = {}, defaultProfile) => write(config, JSON.stringify({ version: 1, profiles, ...(defaultProfile ? { defaultProfile } : {}) }));
  configure();

  async function cli(args, code = 0, overrides = {}, guarded = true) {
    const child = spawn(process.execPath, [...(guarded ? ['--import', guard] : []), executable, ...args], {
      cwd: home, env: { ...env, UNIFI_AXI_CONFIG: config,
        ...(!guarded ? { NODE_OPTIONS: `--import=${new URL('./fixtures/write-guard.ts', import.meta.url).pathname}`, UNIFI_AXI_TEST_PORT: String(fakePort) } : {}),
        ...overrides }, stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 15000,
    });
    let stdout = '', stderr = '';
    child.stdout.on('data', value => { stdout += value; });
    child.stderr.on('data', value => { stderr += value; });
    const [status, signal] = await once(child, 'close');
    assert.equal(signal, null, stdout + stderr);
    if (code === -1) assert.ok([0, 1].includes(status), `${args.join(' ')}\n${stdout}${stderr}`);
    else assert.equal(status, code, `${args.join(' ')}\n${stdout}${stderr}`);
    assert.equal(stderr, '');
    for (const key of redactedForms) assert.equal((stdout + stderr).includes(key), false, 'No raw, escaped or encoded key in retained output');
    assert.equal(existsSync(env.UNIFI_AXI_TEST_NETWORK_LOG), false, 'Offline command attempted network');
    return code === 99 ? { interrupted: true } : decode(stdout);
  }
  const status = (args = [], overrides = {}, code = 0) => cli(['auth', 'status', ...args], code, overrides);
  const error = async (expected, profiles, args = [], overrides = {}) => {
    configure(profiles);
    assert.equal((await status(args, overrides, 1)).error.code, expected);
  };

  assert.equal((await cli(['config', 'path'])).config.path, config);
  assert.deepEqual((await cli(['profile', 'list'])).profiles, []);
  await error('PROFILE_REQUIRED', {});
  await error('PROFILE_NOT_FOUND', {}, ['--profile', 'absent']);
  await error('PROFILE_AMBIGUOUS', { first: source, second: source });
  await error('AUTH_REQUIRED', { first: source });
  await error('CONFIG_INVALID', {}, [], { UNIFI_AXI_ORIGIN: source.origin });
  await error('CONFIG_INVALID', {}, [], { UNIFI_AXI_API_KEY: syntheticKey });
  const keys = { SYNTHETIC_KEY: syntheticKey };
  configure({ first: source, second: { ...source, origin: 'https://second.invalid' } }, 'second');
  assert.equal((await status([], keys)).auth.profile, 'second');
  assert.equal((await status([], { ...keys, UNIFI_AXI_PROFILE: 'first' })).auth.profile, 'first');
  assert.equal((await status(['--profile', 'second'], { ...keys, UNIFI_AXI_PROFILE: 'first' })).auth.profile, 'second');
  const competing = { ...keys, UNIFI_AXI_ORIGIN: 'https://environment.invalid', UNIFI_AXI_API_KEY: syntheticKey,
    UNIFI_AXI_TLS: '{invalid', UNIFI_AXI_WRITES: '{invalid' };
  const isolated = (await status(['--profile', 'first'], competing)).auth;
  assert.equal(isolated.origin, source.origin);
  assert.equal(isolated.secretSource, 'env:SYNTHETIC_KEY');
  const envProfile = await status([], { ...keys, UNIFI_AXI_ORIGIN: 'https://environment.invalid', UNIFI_AXI_API_KEY: syntheticKey });
  assert.equal(envProfile.auth.profile, 'env');
  assert.equal(envProfile.auth.origin, 'https://environment.invalid');
  configure({ only: { origin: source.origin } });
  assert.equal((await status(['--profile', 'only'], { UNIFI_AXI_API_KEY: syntheticKey })).auth.secretSource, 'env:UNIFI_AXI_API_KEY');
  assert.equal((await status(['--profile', 'only'], { UNIFI_AXI_API_KEY: syntheticKey })).auth.origin, source.origin);

  for (const profile of [
    { ...source, apiKey: syntheticKey }, { ...source, apiKey: null },
    { ...source, apiKey: { stored: true } }, { ...source, apiKey: { env: 'BAD-NAME' } },
    { ...source, apiKey: { env: 'SYNTHETIC_KEY', file: secretFile } },
    { ...source, apiKey: { file: './relative' } }, { ...source, unexpected: true },
    { ...source, apiContract: ['10.6.109'] },
    { ...source, allowSecretExport: 'true' },
    { ...source, origin: 'http://localhost' }, { ...source, origin: 'https://localhost/path' },
    { ...source, origin: 'https://user:password@localhost' },
    { ...source, tls: { insecure: true } }, { ...source, writes: { allowWrites: true, operations: [], extra: true } },
  ]) await error('CONFIG_INVALID', { invalid: profile });
  configure({ only: source });
  for (const value of ['yes', '', '2']) assert.equal((await status([], { ...keys, UNIFI_AXI_READ_ONLY: value }, 1)).error.code, 'CONFIG_INVALID');
  for (const value of ['TRUE', 'false', '1', '0']) assert.equal((await status([], { ...keys, UNIFI_AXI_READ_ONLY: value })).auth.profile, 'only');
  for (const field of ['TLS', 'WRITES']) assert.equal((await status([], {
    UNIFI_AXI_ORIGIN: source.origin, UNIFI_AXI_API_KEY: syntheticKey, [`UNIFI_AXI_${field}`]: '{"extra":true}',
  }, 1)).error.code, 'CONFIG_INVALID');
  assert.equal((await cli(['auth', 'status', '--api-key', syntheticKey], 2)).error.code, 'UNKNOWN_FLAG');

  write(secretFile, `\uFEFF${syntheticKey}\r\n \t`);
  configure({ file: { origin: source.origin, apiKey: { file: secretFile } } });
  assert.equal((await status()).auth.secretSource, `file:${secretFile}`);
  if (process.platform !== 'win32') {
    chmodSync(secretFile, 0o644);
    assert.equal((await status([], {}, 1)).error.code, 'CONFIG_INSECURE');
    chmodSync(secretFile, 0o400);
    assert.equal((await status()).auth.profile, 'file');
    chmodSync(config, 0o666);
    assert.equal((await status([], {}, 1)).error.code, 'CONFIG_INSECURE');
    chmodSync(config, 0o600);
    const link = join(home, 'symlink');
    symlinkSync(secretFile, link);
    await error('CONFIG_INSECURE', { file: { origin: source.origin, apiKey: { file: link } } });
    if (process.getuid() !== 0) await error('CONFIG_INSECURE', { file: { origin: source.origin, apiKey: { file: '/etc/passwd' } } });
  } else {
    for (const path of ['\\\\server\\share\\key.txt', '\\\\?\\C:\\Secrets\\key.txt']) {
      await error('CONFIG_INVALID', { file: { origin: source.origin, apiKey: { file: path } } });
    }
  }
  const input = join(home, 'profile.json');
  write(input, JSON.stringify(source));
  configure();
  await cli(['profile', 'configure', '--profile', 'created', '--file', input]);
  assert.deepEqual((await cli(['profile', 'list'])).profiles, ['created']);
  assert.equal((await status([], keys)).auth.profile, 'created');
  if (process.platform !== 'win32') {
    assert.equal(statSync(config).mode & 0o777, 0o600);
    assert.equal(statSync(home).mode & 0o777, 0o700);
    assert.equal(statSync(config).uid, process.getuid());
  }
  const prior = readFileSync(config, 'utf8');
  writeFileSync(input, JSON.stringify({ ...source, apiKey: syntheticKey }));
  assert.equal((await cli(['profile', 'configure', '--profile', 'created', '--file', input], 1)).error.code, 'CONFIG_INVALID');
  assert.equal(readFileSync(config, 'utf8'), prior, 'Rejected replacement preserves prior valid config');
  assert.deepEqual(readdirSync(home).filter(file => file.endsWith('.tmp')), []);

  // Certificates and keys are generated per test run and removed with the temporary installation.
  const openssl = args => {
    const result = spawnSync('openssl', args, { cwd: home, encoding: 'utf8' });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
  };
  const cert = name => readFileSync(join(home, `${name}.crt`), 'utf8');
  const fingerprint = name => new X509Certificate(cert(name)).fingerprint256.replaceAll(':', '').toLowerCase();
  for (const [name, dns] of [['valid', 'localhost'], ['wrong', 'wrong.invalid'], ['ca', 'test-ca']]) {
    openssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', `${name}.key`, '-out', `${name}.crt`, '-days', '1', '-subj', `/CN=${dns}`, '-addext', `subjectAltName=DNS:${dns}`]);
  }
  openssl(['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'signed.key', '-out', 'signed.csr', '-subj', '/CN=localhost']);
  write(join(home, 'extensions'), 'subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\n');
  for (const [name, days] of [['signed', '1'], ['expired', '-1']]) {
    openssl(['x509', '-req', '-in', 'signed.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-out', `${name}.crt`, '-days', days, '-extfile', 'extensions']);
  }
  let requests = [];
  let respond = () => ({ applicationVersion: '11.0.97', echo: syntheticKey, encoded: encodeURIComponent(syntheticKey), escaped: JSON.stringify(syntheticKey).slice(1, -1), passphrase: 'synthetic-wifi' });
  const server = createServer({ key: readFileSync(join(home, 'valid.key')), cert: cert('valid') }, (request, response) => {
    requests.push({ method: request.method, path: request.url, host: request.headers.host, key: request.headers['x-api-key'] });
    response.setHeader('Content-Type', 'application/json');
    const body = respond(request, response);
    if (body !== undefined) response.end(JSON.stringify(body));
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;
  fakePort = port;
  guardEgress([port], () => appendFileSync(env.UNIFI_AXI_TEST_NETWORK_LOG, 'network-attempt\n'));
  const origin = `https://localhost:${port}`;
  const tls = name => ({ trustedCertificatePem: cert(name), peerFingerprintSha256: fingerprint(name), connectAddress: '127.0.0.1' });
  try {
    const trusted = { origin, apiKey: { env: 'SYNTHETIC_KEY' }, tls: tls('valid') };
    configure({ tls: trusted });
    const information = await cli(['info'], 0, keys, false);
    assert.equal(information.information.applicationVersion, '11.0.97');
    assert.equal(information.information.passphrase, '[REDACTED]');
    assert.deepEqual(requests, [{ method: 'GET', path: '/proxy/network/integration/v1/info', host: `localhost:${port}`, key: syntheticKey }]);
    requests = [];
    configure({ file: { ...trusted, apiKey: { file: secretFile } } });
    await cli(['info'], 0, {}, false);
    assert.equal(requests[0].key, syntheticKey, 'BOM and trailing whitespace stripped from protected key');
    requests = [];
    for (const path of [config, secretFile]) {
      makeWritableByOthers(path);
      assert.equal((await cli(['info'], 1, {}, false)).error.code, 'CONFIG_INSECURE');
      assert.equal(requests.length, 0, 'Files writable by another user send zero authenticated HTTP requests');
      if (process.platform !== 'win32') chmodSync(path, 0o600);
      protectWindows(path);
    }
    configure({ untrusted: { origin: `https://127.0.0.1:${port}`, apiKey: source.apiKey } });
    assert.equal((await cli(['info'], 1, keys, false)).error.code, 'TLS_REJECTED');
    assert.equal(requests.length, 0, 'Untrusted chain sends zero authenticated HTTP requests');
    for (const [serverName, trustName, keyName] of [['wrong', 'wrong', 'wrong'], ['signed', 'ca', 'signed'], ['expired', 'ca', 'signed'], ['signed', 'valid', 'signed']]) {
      server.setSecureContext({ key: readFileSync(join(home, `${keyName}.key`)), cert: cert(serverName) });
      configure({ rejected: { ...trusted, tls: tls(trustName) } });
      assert.equal((await cli(['info'], 1, keys, false)).error.code, 'TLS_REJECTED');
      assert.equal(requests.length, 0, `${serverName}/${trustName} rejected before authenticated HTTP`);
    }
    for (const overrides of [
      { ...tls('valid'), peerFingerprintSha256: '0'.repeat(64) },
      { ...tls('valid'), connectAddress: 'host.invalid' },
      { ...tls('valid'), trustedCertificatePem: readFileSync(join(home, 'valid.key'), 'utf8') },
      { ...tls('valid'), insecure: true },
    ]) {
      configure({ invalid: { ...trusted, tls: overrides } });
      assert.equal((await status([], keys, 1)).error.code, 'CONFIG_INVALID');
    }
    if (journey) {
      server.setSecureContext({ key: readFileSync(join(home, 'valid.key')), cert: cert('valid') });
      await verifyApplication({
        cli: (args, code = 0, overrides = {}) => cli(args, code, { ...keys, ...overrides }, false),
        configure, trusted, config,
        seed: handler => { requests = []; respond = handler; },
        requests: () => requests,
      });
      await verifyReads({
        cli: (args, code = 0) => cli(args, code, keys, false),
        configure, trusted, installed,
        seed: handler => { requests = []; respond = handler; }, requests: () => requests,
      });
      configure({ lab: trusted });
      inventoryRows.push(...await verifyInventory({
        cli: (args, code = 0) => cli(args, code, keys, false),
        seed: handler => { requests = []; respond = handler; },
      }));
      inventoryRows.push(...await verifyPolicies({
        cli: (args, code = 0) => cli(args, code, keys, false),
        seed: handler => { requests = []; respond = handler; },
      }));
      if (writeTask) {
        const { verifyWrites } = await import('./writes.ts');
        inventoryRows.push(...await verifyWrites({
          cli: (args, code = 0, overrides = {}) => cli(args, code, { ...keys, ...overrides }, false),
          configure, trusted, home, config, port, syntheticKey, task: writeTask.startsWith('B4.') ? 'B3.3' : writeTask,
          seed: handler => { requests = []; respond = handler; }, requests: () => requests,
        }));
        if (writeTask.startsWith('B4.')) {
          const { verifyB4 } = await import('./b4.ts');
          inventoryRows.push(...await verifyB4({
            cli: (args, code = 0, overrides = {}) => cli(args, code, { ...keys, ...overrides }, false),
            configure, trusted, home, port, syntheticKey, task: writeTask,
            seed: handler => { requests = []; respond = handler; }, requests: () => requests,
          }));
        }
      }
    }
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
  const schema = JSON.parse(readFileSync(join(installed, 'dist/axi-credential.schema.json'), 'utf8'));
  assert.equal(schema.properties.apiKey['x-secret'], true, 'Packaged host-facing credential schema marks the secret field');
  const rows = ['CRED-001', 'CRED-002', 'CRED-003', 'CRED-004', 'CRED-005', 'CRED-006', 'CRED-007', 'CRED-010', 'CRED-013', 'STEP-B1.2'].map(acceptance => ({
    task: 'B1.2', acceptance, operation: null, version: null, variant: null, direction: 'standalone-synthetic',
    status: ['CRED-013', 'STEP-B1.2'].includes(acceptance) && process.platform !== 'win32' ? 'pending-native-windows' : 'passed-on-current-platform',
    nativeWindows: process.platform === 'win32' ? 'passed' : 'PENDING',
  }));
  if (journey) rows.push({ task: 'B1.2a', acceptance: 'STEP-B1.2a', operation: ['OP-001', 'OP-002'],
    version: ['10.6.109', '11.0.97'], variant: null, direction: 'standalone-synthetic',
    status: 'passed-on-current-platform', nativeWindows: process.platform === 'win32' ? 'passed' : 'PENDING' });
  return [...rows, ...inventoryRows];
}
