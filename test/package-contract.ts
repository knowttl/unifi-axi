import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { decode } from '@toon-format/toon';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const temporary = mkdtempSync(join(tmpdir(), 'unifi-axi-contract-'));
const prefix = join(temporary, 'install');
const networkLog = join(temporary, 'network-attempts');
const guard = fileURLToPath(new URL('./fixtures/no-network.mjs', import.meta.url));
const packageEnv = {
  ...process.env,
  NODE_OPTIONS: `--import="${pathToFileURL(guard).href}"`,
  UNIFI_AXI_TEST_NETWORK_LOG: networkLog,
};
const env = { ...packageEnv, HOME: temporary, XDG_CONFIG_HOME: temporary };
const pnpm = process.env.npm_execpath;
assert.ok(pnpm, 'Run through pnpm verify:package-contract');
const source = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { version: string };

function command(bin: string, args: string[], cwd = root, commandEnv: NodeJS.ProcessEnv = env): string {
  const result = spawnSync(bin, args, { cwd, env: commandEnv, encoding: 'utf8', timeout: 20_000 });
  assert.ifError(result.error);
  assert.equal(result.signal, null, result.stderr);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.equal(existsSync(networkLog), false, 'Package contract must not attempt network access');
  return result.stdout;
}

try {
  mkdirSync(prefix);
  command(process.execPath, [pnpm, 'pack', '--pack-destination', temporary], root, packageEnv);
  const archives = readdirSync(temporary).filter(file => file.endsWith('.tgz'));
  assert.equal(archives.length, 1);
  const archive = join(temporary, archives[0]!);
  const files = command('tar', ['-tzf', archive]).trim().split('\n');
  assert.equal(new Set(files).size, files.length, 'No duplicate archive entries');
  const notices = readdirSync(root).filter(file => /^(?:LICENSE(?:[.-].*)?|.*-LICENSE\.txt|THIRD_PARTY_NOTICES\.md)$/i.test(file));
  // Runtime files pinned by the admission inventory, without its private evidence or hashes.
  const required = [
    'package.json', 'README.md', ...notices,
    ...['bin.js', 'version.js', 'cli.js', 'writes.js', 'write-journal.js', 'secret-output.js',
      'transport.js', 'profiles.js', 'private-file.js', 'security.js', 'application.js',
      'catalogue.js', 'reads.js', 'validation.js', 'paging.js', 'commands.json',
      'contract-conflicts.json', 'normalization-ledger.json', 'axi-credential.schema.json',
      'capabilities.json', 'SKILL.md'].map(file => `dist/${file}`),
    ...['10.6.109', '11.0.97'].map(version => `evidence/sources/network-${version}-openapi.json`),
  ];
  for (const file of required) assert.ok(files.includes(`package/${file}`), `Missing published file: ${file}`);
  for (const file of files) {
    assert.ok(required.includes(file.slice('package/'.length)) ||
      /^package\/dist\/[\w-]+\.(?:js|d\.ts)$/.test(file), `Unexpected published file: ${file}`);
  }

  command(process.execPath, [pnpm, '--dir', prefix, 'add', '--offline', '--ignore-scripts', '--save-exact', archive], root, packageEnv);
  const installed = join(prefix, 'node_modules/@knowttl/unifi-axi');
  const manifest = JSON.parse(readFileSync(join(installed, 'package.json'), 'utf8')) as {
    name: string; version: string; bin: Record<string, string>; exports: Record<string, string>;
  };
  assert.equal(manifest.name, '@knowttl/unifi-axi');
  assert.equal(manifest.version, source.version);
  assert.deepEqual(manifest.bin, { 'unifi-axi': 'dist/bin.js' });
  assert.deepEqual(manifest.exports, {
    './catalogue': './dist/catalogue.js', './capabilities': './dist/capabilities.json',
    './skill': './dist/SKILL.md', './credential-schema': './dist/axi-credential.schema.json',
  });
  for (const file of files) {
    const content = readFileSync(join(installed, file.slice('package/'.length)), 'utf8');
    assert.doesNotMatch(content, /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----|(?:\/home\/|\/Users\/)[^\s"']+|[A-Z]:\\Users\\/,
      `Secret material or local path in ${file}`);
    assert.ok(!content.includes(root) && !content.includes(temporary), `Build path leaked in ${file}`);
  }
  assert.equal(command(process.execPath, [pnpm, '--dir', prefix, 'exec', 'unifi-axi', '--version'], temporary), `${source.version}\n`);
  const help = decode(command(process.execPath, [pnpm, '--dir', prefix, 'exec', 'unifi-axi', '--help'], temporary)) as { command: string };
  assert.equal(help.command, 'unifi-axi');
  // Resolve from the consumer directory so the checkout cannot satisfy imports.
  command(process.execPath, ['--input-type=module', '-e', `
    import assert from 'node:assert/strict';
    import { readFileSync } from 'node:fs';
    import { catalogue } from '@knowttl/unifi-axi/catalogue';
    import capabilities from '@knowttl/unifi-axi/capabilities' with { type: 'json' };
    import schema from '@knowttl/unifi-axi/credential-schema' with { type: 'json' };
    assert.ok(catalogue.some(entry => entry.command === 'site list'));
    assert.deepEqual(capabilities.operations, catalogue);
    assert.equal(schema.type, 'object');
    assert.match(readFileSync(new URL(import.meta.resolve('@knowttl/unifi-axi/skill')), 'utf8'), /name: unifi-axi/);
  `], prefix);
  console.log('Package contract passed (offline tarball, launcher and exports)');
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
