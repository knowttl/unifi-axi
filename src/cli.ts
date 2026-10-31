import { homedir } from 'node:os';
import { resolve } from 'node:path';
import { encode } from '@toon-format/toon';
import { catalogue, parameterFlag, type Operation, type Parameter } from './catalogue.js';
import { Profiles, configPath } from './profiles.js';
import { Redactor, ToolError } from './security.js';
import { readInformation } from './transport.js';

const description = 'Discover UniFi Network Integration API commands.';
const auxiliary = [
  { command: 'commands', summary: 'List all documented vendor commands', status: 'implemented' },
  ...['auth status', 'profile list', 'profile configure', 'config path']
    .map(command => ({ command, summary: 'Manage protected credential references offline', status: 'implemented' })),
  ...['doctor', 'setup', 'write show', 'write reconcile']
    .map(command => ({ command, summary: 'Planned capability', status: 'not-implemented' })),
];

interface Flag {
  name: string;
  type: string;
  required: boolean;
  default?: unknown;
  schema?: Parameter['schema'];
}

function flagsFor(operation?: Operation): Flag[] {
  const flags: Flag[] = [{ name: 'help', type: 'switch', required: false }];
  if (!operation) return flags;
  flags.push({ name: 'profile', type: 'string', required: false }, { name: 'config', type: 'string', required: false });
  for (const parameter of operation.contracts[0]!.parameters) {
    flags.push({ name: parameterFlag(parameter.name), type: parameter.schema.type ?? 'string',
      required: parameter.required ?? false, default: parameter.schema.default, schema: parameter.schema });
  }
  if (operation.contracts.some(contract => contract.requestBody)) {
    flags.push({ name: 'body-file', type: 'string', required: false });
  }
  if (operation.effect === 'write') {
    flags.push({ name: 'execute', type: 'switch', required: false },
      { name: 'confirm', type: 'string', required: false }, { name: 'request-id', type: 'string', required: false });
  }
  return flags;
}

function output(value: Parameters<typeof encode>[0], code = 0): number {
  console.log(encode(value));
  return code;
}

function usage(code: string, message: string, flags: Flag[]): number {
  return output({ error: { code, message }, help: [`Valid flags: ${flags.map(flag => `--${flag.name}`).join(', ')}`] }, 2);
}

export async function main(args: string[]): Promise<number> {
  const firstFlag = args.findIndex(arg => arg.startsWith('-'));
  const words = firstFlag < 0 ? args : args.slice(0, firstFlag);
  const command = words.join(' ');
  const operation = catalogue.find(entry => entry.command === command);
  const extra = auxiliary.find(entry => entry.command === command);
  const children = [...catalogue, ...auxiliary].filter(entry => entry.command.startsWith(`${command} `));
  const flags = flagsFor(operation);
  if (['auth status', 'profile list', 'profile configure', 'config path'].includes(command)) {
    flags.push({ name: 'config', type: 'string', required: false }, { name: 'profile', type: 'string', required: false });
  }
  if (command === 'profile configure') flags.push({ name: 'file', type: 'string', required: true });
  const seen = new Set<string>();
  const values: Record<string, string> = {};
  const tokens = firstFlag < 0 ? [] : args.slice(firstFlag);
  for (let index = 0; index < tokens.length; index++) {
    const token = tokens[index]!;
    if (!token.startsWith('--')) return usage('INVALID_ARGUMENT', 'Unexpected argument. Use the named command and documented flags.', flags);
    const equals = token.indexOf('=');
    const name = token.slice(2, equals < 0 ? undefined : equals);
    const flag = flags.find(flag => flag.name === name);
    if (!flag) return usage('UNKNOWN_FLAG', 'Unknown flag. Use only the documented flags.', flags);
    if (seen.has(name)) return usage('DUPLICATE_FLAG', `Flag --${name} may appear only once.`, flags);
    seen.add(name);
    if (flag.type === 'switch') {
      if (equals >= 0) return usage('INVALID_ARGUMENT', `Flag --${name} takes no value.`, flags);
      continue;
    }
    const value = equals >= 0 ? token.slice(equals + 1) : tokens[++index];
    if (!value || value.startsWith('--')) return usage('INVALID_ARGUMENT', `Flag --${name} requires a value.`, flags);
    values[name] = value;
    if (flag.type === 'integer' || flag.type === 'number') {
      const number = Number(value);
      if (!Number.isFinite(number) || (flag.type === 'integer' && !Number.isInteger(number)) ||
        (flag.schema?.minimum !== undefined && number < flag.schema.minimum) ||
        (flag.schema?.maximum !== undefined && number > flag.schema.maximum)) {
        return usage('INVALID_ARGUMENT', `Flag --${name} requires a valid ${flag.type} within its documented bounds.`, flags);
      }
    }
    if (flag.type === 'boolean' && !['true', 'false'].includes(value)) {
      return usage('INVALID_ARGUMENT', `Flag --${name} requires true or false.`, flags);
    }
  }

  if (command && !operation && !extra && children.length === 0) {
    return output({ error: { code: 'UNKNOWN_COMMAND', message: 'Unknown command.' }, help: ['unifi-axi commands', 'unifi-axi --help'] }, 2);
  }
  if (seen.has('help')) {
    if (operation) {
      const required = flags.filter(flag => flag.required).map(flag => ` --${flag.name} <${flag.name}>`).join('');
      const example = `unifi-axi ${command}${required}`;
      return output({ command, summary: operation.summary, status: operation.status,
        effect: operation.effect, method: operation.method, path: operation.path,
        permission: 'Local Integration API key; effective upstream permissions unverified.',
        output: command === 'info' ? 'Bounded JSON information response with redaction; application schema validation pending B1.2a.' : 'No vendor output until implemented. This operation fails before network access.',
        flags: flags.map(({ name, type, required, default: fallback }) => ({
          name: `--${name}`, type, required, default: fallback ?? null,
        })), examples: [`unifi-axi ${command} --help`, example] });
    }
    return output({ command: command || 'unifi-axi', description,
      flags: flags.map(flag => `--${flag.name}${flag.type === 'switch' ? '' : ' <value>'}`),
      commands: command ? children.map(({ command, status }) => ({ command, status })) :
        [...auxiliary, ...catalogue].map(({ command, status }) => ({ command, status })),
      examples: ['unifi-axi commands', 'unifi-axi info --help', 'unifi-axi auth status'] });
  }
  if (command === 'commands') {
    return output({ count: catalogue.length, commands: catalogue.map(({ id, command, effect, status }) => ({ id, command, effect, status })),
      help: ['unifi-axi info --help', 'unifi-axi site list --help'] });
  }
  if (['auth status', 'profile list', 'profile configure', 'config path', 'info'].includes(command)) {
    const redactor = new Redactor();
    try {
      const path = configPath(values.config);
      const profiles = new Profiles(path);
      if (command === 'config path') return output({ config: { path } });
      if (command === 'profile list') return output({ profiles: await profiles.list() });
      if (command === 'profile configure') {
        if (!values.profile || !values.file) return usage('INVALID_ARGUMENT', 'profile configure requires --profile and --file.', flags);
        await profiles.configure(values.profile, values.file);
        return output({ profile: { name: values.profile, configured: true }, config: { path } });
      }
      const selected = await profiles.select(values.profile, command === 'auth status');
      const secret = await profiles.secret(selected.profile, redactor, command === 'auth status');
      if (command === 'auth status') {
        const ref = selected.profile.apiKey;
        console.log(redactor.text(encode({ auth: { status: 'configured', profile: selected.name, origin: selected.profile.origin,
          source: selected.source, secretSource: 'env' in ref ? `env:${ref.env}` : `file:${ref.file}` } })));
        return 0;
      }
      console.log(redactor.text(encode({ information: redactor.payload(await readInformation(selected.profile, secret)),
        validation: 'Transport verified; application schema and version selection pending B1.2a.' } as Parameters<typeof encode>[0])));
      return 0;
    } catch (error) {
      const known = error instanceof ToolError;
      console.log(redactor.text(encode({ error: { code: known ? error.code : 'CONFIG_INVALID',
        message: known ? error.message : 'Unable to read or write protected configuration.' } })));
      return 1;
    }
  }
  if (command === '') {
    const executable = resolve(process.argv[1]!);
    const home = homedir();
    return output({ bin: executable.startsWith(`${home}/`) || executable.startsWith(`${home}\\`) ? `~${executable.slice(home.length)}` : executable,
      description, error: { code: 'PROFILE_REQUIRED', message: 'No usable profile. Credential configuration and live home data are not implemented in B1.1.' },
      help: ['unifi-axi commands', 'unifi-axi auth status', 'unifi-axi --help'] }, 1);
  }
  if (operation || extra) {
    return output({ error: { code: 'NOT_IMPLEMENTED', message: 'This command is not implemented. No network request was sent.' },
      command, status: 'not-implemented', help: [`unifi-axi ${command} --help`] }, 1);
  }
  return output({ command, commands: children.map(({ command, status }) => ({ command, status })),
    help: [`unifi-axi ${command} --help`] });
}
