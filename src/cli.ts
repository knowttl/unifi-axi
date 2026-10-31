import { homedir } from 'node:os';
import { resolve } from 'node:path';
import { encode } from '@toon-format/toon';
import { catalogue, parameterFlag, type Operation, type Parameter } from './catalogue.js';

const description = 'Discover UniFi Network Integration API commands.';
const auxiliary = [
  { command: 'commands', summary: 'List all documented vendor commands', status: 'implemented' },
  { command: 'auth status', summary: 'Report unconfigured status without resolving credentials', status: 'implemented-unconfigured-only' },
  ...['profile list', 'profile configure', 'config path', 'doctor', 'setup', 'write show', 'write reconcile']
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

export function main(args: string[]): number {
  const firstFlag = args.findIndex(arg => arg.startsWith('-'));
  const words = firstFlag < 0 ? args : args.slice(0, firstFlag);
  const command = words.join(' ');
  const operation = catalogue.find(entry => entry.command === command);
  const extra = auxiliary.find(entry => entry.command === command);
  const children = [...catalogue, ...auxiliary].filter(entry => entry.command.startsWith(`${command} `));
  const flags = flagsFor(operation);
  const seen = new Set<string>();
  const tokens = firstFlag < 0 ? [] : args.slice(firstFlag);
  for (let index = 0; index < tokens.length; index++) {
    const token = tokens[index]!;
    if (!token.startsWith('--')) return usage('INVALID_ARGUMENT', 'Unexpected argument. Use the named command and documented flags.', flags);
    const equals = token.indexOf('=');
    const name = token.slice(2, equals < 0 ? undefined : equals);
    const flag = flags.find(flag => flag.name === name);
    if (!flag) return usage('UNKNOWN_FLAG', `Unknown flag --${name}.`, flags);
    if (seen.has(name)) return usage('DUPLICATE_FLAG', `Flag --${name} may appear only once.`, flags);
    seen.add(name);
    if (flag.type === 'switch') {
      if (equals >= 0) return usage('INVALID_ARGUMENT', `Flag --${name} takes no value.`, flags);
      continue;
    }
    const value = equals >= 0 ? token.slice(equals + 1) : tokens[++index];
    if (!value || value.startsWith('--')) return usage('INVALID_ARGUMENT', `Flag --${name} requires a value.`, flags);
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
        output: 'No vendor output until implemented. This operation fails before network access.',
        flags: flags.map(({ name, type, required, default: fallback }) => ({
          name: `--${name}`, type, required, default: fallback ?? null,
        })), examples: [`unifi-axi ${command} --help`, example] });
    }
    return output({ command: command || 'unifi-axi', description,
      flags: ['--help (offline; no default arguments)'],
      commands: command ? children.map(({ command, status }) => ({ command, status })) :
        [...auxiliary, ...catalogue].map(({ command, status }) => ({ command, status })),
      examples: ['unifi-axi commands', 'unifi-axi info --help', 'unifi-axi auth status'] });
  }
  if (command === 'commands') {
    return output({ count: catalogue.length, commands: catalogue.map(({ id, command, effect, status }) => ({ id, command, effect, status })),
      help: ['unifi-axi info --help', 'unifi-axi site list --help'] });
  }
  if (command === 'auth status') {
    const supplied = ['CONFIG', 'PROFILE', 'ORIGIN', 'API_KEY', 'SITE_ID', 'API_CONTRACT', 'TLS', 'WRITES']
      .some(name => process.env[`UNIFI_AXI_${name}`] !== undefined);
    if (supplied) return output({ error: { code: 'NOT_IMPLEMENTED', message: 'Configured credential status is not implemented in B1.1. No credentials were resolved.' } }, 1);
    return output({ auth: { status: 'unconfigured', profile: null, source: 'none supplied' },
      scope: 'B1.1 checks environment presence only; stored profile discovery is not implemented.',
      help: ['unifi-axi auth status --help', 'unifi-axi commands'] });
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
