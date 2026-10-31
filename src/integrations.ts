import { access, lstat, mkdir, readFile, realpath, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { delimiter, dirname, isAbsolute, join, resolve } from 'node:path';
import { parse, patch } from '@decimalturn/toml-patch';
import { effectPolicy } from './effects.js';
import { ToolError } from './security.js';

export async function setup(values: Record<string, string>, execute: boolean) {
  const { app, directory, profile, config } = values;
  if (!app || !['claude', 'codex', 'opencode'].includes(app) || !directory || !isAbsolute(directory) || !profile) {
    throw new ToolError('INVALID_ARGUMENT', 'setup requires --app claude|codex|opencode, --directory <absolute-path> and --profile <name>.');
  }
  const scope = await realpath(directory);
  const executable = await realpath(resolve(process.argv[1]!));
  let binary = executable;
  for (const path of (process.env.PATH ?? '').split(delimiter)) {
    const candidate = join(path, process.platform === 'win32' ? 'unifi-axi.cmd' : 'unifi-axi');
    try {
      await access(candidate, constants.X_OK);
      if (await realpath(candidate) === executable) { binary = 'unifi-axi'; break; }
    } catch (error) {
      if (!['ENOENT', 'EACCES'].includes((error as NodeJS.ErrnoException).code ?? '')) throw error;
    }
  }
  const runBinary = binary === 'unifi-axi' ? binary : process.execPath;
  const runArgs = [...(binary === 'unifi-axi' ? [] : [binary]), '--profile', profile, ...(config ? ['--config', config] : [])];
  // Base64 keeps shell expansion away from profile names and paths.
  const script = `if(process.cwd()===${JSON.stringify(scope)}){const{spawnSync}=require('node:child_process');const r=spawnSync(${JSON.stringify(runBinary)},${JSON.stringify(runArgs)},{encoding:'utf8',stdio:['ignore','pipe','pipe'],timeout:30000});process.stdout.write(r.stdout||'');process.stderr.write(r.stderr||'');process.exitCode=r.status??1}`;
  const marker = ' unifi-axi-session-context';
  const command = `node -e "eval(Buffer.from('${Buffer.from(script).toString('base64')}','base64').toString())"${marker}`;
  const relative = app === 'claude' ? '.claude/settings.json' : app === 'codex' ? '.codex/hooks.json' : '.opencode/plugins/unifi-axi.ts';
  const target = join(scope, relative);
  // Refuse symlinked configuration paths so the effect stays inside the selected scope.
  let current = scope;
  for (const part of relative.split('/')) {
    current = join(current, part);
    try {
      if ((await lstat(current)).isSymbolicLink()) throw new ToolError('SETUP_UNSAFE', 'Integration paths must not be symbolic links.');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
  }
  let before: string | null = null;
  try { before = await readFile(target, 'utf8'); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
  let content: string;
  if (app === 'opencode') {
    content = `// Managed by unifi-axi setup.\nimport { spawnSync } from 'node:child_process';\nexport const UnifiContext = async () => ({\n  'experimental.chat.system.transform': async (_input: unknown, output: { system: string[] }) => {\n    if (process.cwd() !== ${JSON.stringify(scope)}) return;\n    const result = spawnSync(${JSON.stringify(runBinary)}, ${JSON.stringify(runArgs)}, { encoding: 'utf8', timeout: 30000 });\n    if (result.stdout) output.system.push(result.stdout);\n  },\n});\n`;
    if (before !== null && !before.startsWith('// Managed by unifi-axi setup.\n')) {
      throw new ToolError('SETUP_CONFLICT', 'The selected plugin file is not managed by unifi-axi.');
    }
  } else {
    const document = before === null ? {} : JSON.parse(before) as Record<string, unknown>;
    const hooks = (document.hooks ?? {}) as Record<string, unknown>;
    const starts = (hooks.SessionStart ?? []) as { matcher?: string; hooks: { type: string; command?: string }[] }[];
    const entry = { matcher: '*', hooks: [{ type: 'command', command }] };
    const remaining = starts.map(entry => ({ ...entry,
      hooks: entry.hooks.filter(hook => !(hook.type === 'command' && hook.command?.endsWith(marker))) }))
      .filter(entry => entry.hooks.length > 0);
    content = `${JSON.stringify({ ...document, hooks: { ...hooks, SessionStart: [...remaining, entry] } }, null, 2)}\n`;
  }
  const files = [{ target, before, content }];
  if (app === 'codex') {
    const target = join(scope, '.codex/config.toml');
    let before: string | null = null;
    try {
      if ((await lstat(target)).isSymbolicLink()) throw new ToolError('SETUP_UNSAFE', 'Integration paths must not be symbolic links.');
      before = await readFile(target, 'utf8');
    } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error; }
    const document = parse(before ?? '') as Record<string, unknown>;
    const features = document.features ?? {};
    if (typeof features !== 'object' || Array.isArray(features) || features instanceof Date) {
      throw new ToolError('SETUP_CONFLICT', 'The Codex features setting must be a TOML table.');
    }
    const content = patch(before ?? '', { ...document, features: { ...features, hooks: true } });
    files.push({ target, before, content });
  }
  const binding = { operation: 'setup', app, directory: scope, profile, config: config ?? null, executable, files };
  const changed = files.some(file => file.content !== file.before);
  const digest = effectPolicy(binding, execute && changed, values.confirm);
  if (execute && changed) {
    for (const file of files.filter(file => file.content !== file.before)) {
      await mkdir(dirname(file.target), { recursive: true });
      await writeFile(file.target, file.content, { mode: 0o600 });
    }
  }
  return { setup: { app, directory: scope, profile, targets: files.map(file => file.target), status: execute ? changed ? 'installed' : 'no-op' : 'preview', changed, digest } };
}
