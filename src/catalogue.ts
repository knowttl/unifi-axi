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
    status: 'not-implemented',
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
