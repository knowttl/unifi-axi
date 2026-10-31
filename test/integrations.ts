import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, writeFileSync, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { decode } from '@toon-format/toon';
import { parse } from '@decimalturn/toml-patch';

interface SetupResult { setup: { status: string; digest: string; changed: boolean; targets: string[] } }
interface ErrorResult { error: { code: string } }
interface Context {
  cli: (args: string[], status?: number, env?: Record<string, string>) => string;
  temporary: string;
  user: string;
  guard: string;
}

export function verifyIntegrations({ cli, temporary, user, guard }: Context): void {
  const config = join(temporary, 'integration-profiles.json');
  writeFileSync(config, JSON.stringify({ version: 1, profiles: {
    lab: { origin: 'https://synthetic.invalid', apiKey: { env: 'SYNTHETIC_KEY' } },
  } }), { mode: 0o600 });
  for (const app of ['claude', 'codex', 'opencode']) {
    const directory = join(temporary, `scope ${app}`);
    mkdirSync(directory);
    const args = ['setup', '--app', app, '--directory', directory, '--profile', 'lab', '--config', config];
    const preview = decode(cli(args)) as unknown as SetupResult;
    for (const path of preview.setup.targets) assert.equal(existsSync(path), false, 'Preview creates nothing');
    assert.equal((decode(cli([...args, '--execute', '--confirm', 'wrong'], 1)) as unknown as ErrorResult).error.code, 'CONFIRMATION_REQUIRED');
    const installed = decode(cli([...args, '--execute', '--confirm', preview.setup.digest])) as unknown as SetupResult;
    assert.equal(installed.setup.status, 'installed');
    const times = installed.setup.targets.map(path => statSync(path).mtimeMs);
    const again = decode(cli([...args, '--execute', '--confirm', preview.setup.digest])) as unknown as SetupResult;
    assert.equal(again.setup.status, 'no-op');
    assert.deepEqual(again.setup.targets.map(path => statSync(path).mtimeMs), times);
    if (app !== 'opencode') {
      const target = installed.setup.targets[0]!;
      const document = JSON.parse(readFileSync(target, 'utf8'));
      const command = document.hooks.SessionStart[0].hooks[0].command as string;
      const outside = spawnSync(command, { shell: true, cwd: user, encoding: 'utf8' });
      assert.equal(outside.status, 0, outside.stderr);
      assert.equal(outside.stdout, '', 'Hooks emit no context outside the selected directory');
      const inside = spawnSync(command, { shell: true, cwd: directory, encoding: 'utf8',
        env: { PATH: process.env.PATH, NODE_OPTIONS: `--import=${guard}`, SYNTHETIC_KEY: '' } });
      assert.equal(inside.status, 1, inside.stderr);
      assert.equal((decode(inside.stdout) as unknown as ErrorResult).error.code, 'AUTH_REQUIRED', 'The installed hook resolves its bound profile');
      document.unrelated = { keep: true };
      writeFileSync(target, JSON.stringify(document));
      const repair = decode(cli(args)) as unknown as SetupResult;
      writeFileSync(target, JSON.stringify({ ...document, changedAfterPreview: true }));
      assert.equal((decode(cli([...args, '--execute', '--confirm', repair.setup.digest], 1)) as unknown as ErrorResult).error.code, 'CONFIRMATION_REQUIRED');
      const next = decode(cli(args)) as unknown as SetupResult;
      cli([...args, '--execute', '--confirm', next.setup.digest]);
      assert.deepEqual(JSON.parse(readFileSync(target, 'utf8')).unrelated, { keep: true });
      if (app === 'codex') assert.match(readFileSync(installed.setup.targets[1]!, 'utf8'), /\[features\]\nhooks = true/);
    } else assert.match(readFileSync(installed.setup.targets[0]!, 'utf8'), /experimental.chat.system.transform/);
    assert.equal((decode(cli(args, 1, { UNIFI_AXI_HOSTED: '1' })) as unknown as ErrorResult).error.code, 'HOSTED_DENIED');
  }
  for (const [name, definition] of Object.entries({
    bare: '[features]\nhooks = false\nother = false',
    quotedKey: '[features]\n"hooks" = false\nother = false',
    literalKeys: "['features']\n'hooks' = false\nother = false",
    quotedTable: '[ "features" ] # retained table\n"hooks" = false\nother = false',
    escapedKeys: '["fea\\u0074ures"]\n"hoo\\u006bs" = false\nother = false',
    dotted: 'features.hooks = false\nfeatures.other = false',
    inline: 'features = { hooks = false, other = false }',
    missingKey: '[features]\nother = false',
    missingTable: '',
  })) {
    const directory = join(temporary, `codex-toml-${name}`);
    mkdirSync(join(directory, '.codex'), { recursive: true });
    const target = join(directory, '.codex/config.toml');
    const before = `# retained configuration\nmodel = "retained"\nquota = 9223372036854775807\n${definition}\n[unrelated]\nvalue = "retained"\n`;
    writeFileSync(target, before);
    const expected = parse(before) as { features?: Record<string, unknown> };
    const args = ['setup', '--app', 'codex', '--directory', directory, '--profile', 'lab', '--config', config];
    const preview = decode(cli(args)) as unknown as SetupResult;
    assert.equal(readFileSync(target, 'utf8'), before, `${name}: preview preserves configuration`);
    cli([...args, '--execute', '--confirm', preview.setup.digest]);
    const actual = parse(readFileSync(target, 'utf8')) as { features: Record<string, unknown> };
    assert.deepEqual({ ...actual, features: { ...actual.features } }, { ...expected, features: { ...expected.features, hooks: true } },
      `${name}: R1 enables the semantic hooks key and preserves other definitions`);
    const installed = readFileSync(target, 'utf8');
    const again = decode(cli([...args, '--execute'])) as unknown as SetupResult;
    assert.equal(again.setup.status, 'no-op', name);
    assert.equal(readFileSync(target, 'utf8'), installed, name);
  }
  for (const folder of ['.claude', '.codex', '.opencode']) assert.equal(existsSync(join(user, folder)), false, 'Normal commands install no integrations');
}
