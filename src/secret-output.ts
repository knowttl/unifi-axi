import { isAbsolute } from 'node:path';
import { catalogue, type Operation } from './catalogue.js';
import type { Profile } from './profiles.js';
import { PrivateFiles } from './private-file.js';
import { readOperation } from './reads.js';
import { Redactor, ToolError } from './security.js';

export const secretReads = new Set(['OP-044', 'OP-047', 'OP-069', 'OP-072']);

export async function exportResponse(profile: Profile, secret: string, operation: Operation,
  values: Record<string, string>, version: string, redactor: Redactor) {
  const destination = values['secret-output']!;
  if (!isAbsolute(destination)) throw new ToolError('INVALID_ARGUMENT', '--secret-output requires an absolute path in an existing private directory.');
  const ids: string[] = [];
  await new PrivateFiles().create(destination, async () => {
    const result = await readOperation(profile, secret, operation, values, version, undefined, true);
    const rows = Object.values(result).find(Array.isArray) as Record<string, unknown>[] | undefined;
    const records = rows ?? [Object.values(result)[0] as Record<string, unknown>];
    const secrets: { id: string; path: string; value: unknown }[] = [];
    for (let row of records) {
      const id = row.id as string;
      ids.push(id);
      if (operation.id === 'OP-069') {
        const detail = await readOperation(profile, secret, catalogue.find(op => op.id === 'OP-072')!,
          { ...values, 'wifi-broadcast-id': id }, version, undefined, true);
        row = (detail as Record<string, unknown>).wifiBroadcast as Record<string, unknown>;
      }
      const keep = (path: string, value: unknown) => {
        if (typeof value === 'string') secrets.push({ id, path, value: redactor.payload(value) });
      };
      if (operation.id === 'OP-044' || operation.id === 'OP-047') keep('/code', row.code);
      else {
        const security = row.securityConfiguration as Record<string, unknown>;
        if (['WPA2_PERSONAL', 'WPA2_WPA3_PERSONAL', 'WPA3_PERSONAL'].includes(String(security.type))) {
          keep('/securityConfiguration/passphrase', security.passphrase);
          if (security.type === 'WPA2_PERSONAL' && Array.isArray(security.presharedKeys)) {
            security.presharedKeys.forEach((key: Record<string, unknown>, index: number) =>
              keep(`/securityConfiguration/presharedKeys/${index}/passphrase`, key.passphrase));
          }
        }
      }
    }
    return JSON.stringify({ operation: operation.id, secrets }) + '\n';
  });
  return { ids, receipt: { operation: operation.id, path: destination, delivered: true } };
}
