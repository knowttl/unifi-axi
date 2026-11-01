import { readFileSync } from 'node:fs';
import commands from './commands.json' with { type: 'json' };

interface Schema {
  type?: string;
  format?: string;
  default?: unknown;
  minimum?: number;
  maximum?: number;
  enum?: unknown[];
}

export interface Parameter {
  name: string;
  in: string;
  required?: boolean;
  schema: Schema;
}

interface VendorOperation {
  operationId: string;
  summary: string;
  parameters?: Parameter[];
  requestBody?: unknown;
  responses: unknown;
}

interface Contract {
  paths: Record<string, Record<string, VendorOperation>>;
}

export const versions = ['10.6.109', '11.0.97'] as const;

export const writeOperations = new Set(['OP-049', 'OP-050', 'OP-052', 'OP-008', 'OP-010', 'OP-011', 'OP-013',
  'OP-016', 'OP-019', 'OP-020', 'OP-022', 'OP-023',
  'OP-031', 'OP-033', 'OP-034', 'OP-036', 'OP-037', 'OP-039', 'OP-040', 'OP-042',
  'OP-043', 'OP-045', 'OP-046', 'OP-070', 'OP-071', 'OP-073',
  'OP-026', 'OP-027', 'OP-029', 'OP-062', 'OP-063', 'OP-065']);

export const readOperations = new Set(['OP-003', 'OP-004', 'OP-005', 'OP-006', 'OP-014', 'OP-015',
  'OP-017', 'OP-018', 'OP-021', 'OP-024', 'OP-048', 'OP-051', 'OP-053', 'OP-054', 'OP-066', 'OP-067', 'OP-068',
  'OP-007', 'OP-009', 'OP-012', 'OP-025', 'OP-028', 'OP-030', 'OP-032', 'OP-035', 'OP-038', 'OP-041',
  'OP-044', 'OP-047', 'OP-055', 'OP-056', 'OP-057', 'OP-058', 'OP-059', 'OP-060', 'OP-061', 'OP-064', 'OP-069', 'OP-072']);

export const contracts = Object.fromEntries(versions.map(version => [version,
  JSON.parse(readFileSync(new URL(`../evidence/sources/network-${version}-openapi.json`, import.meta.url), 'utf8')) as Contract,
]));

export const catalogue = commands.map(command => {
  const variants = versions.map(version => {
    const contract = contracts[version]!;
    const matches = Object.entries(contract.paths).flatMap(([path, methods]) =>
      Object.entries(methods).filter(([, operation]) => operation.operationId === command.vendorOperationId)
        .map(([method, operation]) => ({ version, method: method.toUpperCase(), path, ...operation })),
    );
    if (matches.length !== 1) throw new Error(`Contract operation is not unique: ${command.id}/${version}`);
    return matches[0]!;
  });
  const primary = variants[0]!;
  return {
    ...command,
    summary: primary.summary,
    method: primary.method,
    path: primary.path,
    effect: primary.method === 'GET' ? 'read' : 'write',
    status: ['info', 'site list'].includes(command.command) || readOperations.has(command.id) || writeOperations.has(command.id) ? 'implemented' : 'not-implemented',
    contracts: variants.map(({ version, parameters = [], requestBody, responses }) => ({
      version, source: `evidence/sources/network-${version}-openapi.json`,
      parameters, ...(requestBody ? { requestBody } : {}), responses,
    })),
  };
});

export type Operation = typeof catalogue[number];

export function parameterFlag(name: string): string {
  return name === 'siteId' ? 'site' : name.replace(/[A-Z]/g, letter => `-${letter.toLowerCase()}`);
}

export const description = 'Read UniFi Network information and manage network configuration with confirmed writes.';

export function examplesFor(operation: Operation): string[] {
  const required = operation.contracts[0]!.parameters.filter(parameter => parameter.required)
    .map(parameter => ` --${parameterFlag(parameter.name)} <${parameterFlag(parameter.name)}>`).join('');
  return [`unifi-axi ${operation.command} --help`, `unifi-axi ${operation.command}${required}`];
}

export const guidance = [
  'Use unifi-axi with no arguments for bounded live application and site context.',
  'Use unifi-axi commands for offline discovery and unifi-axi <command> --help for inputs, defaults and effects.',
  'Select context with --profile <name>, --config <absolute-path> and --site <site-id>.',
  'Install directory-scoped ambient context with setup --app <claude|codex|opencode> --directory <absolute-path> --profile <name>. Preview first, then repeat with --execute --confirm <digest>.',
  'Secrets must be env/file references. TLS verification cannot be disabled. Implemented writes require preview, exact grants, confirmation and a stable request ID.',
];
