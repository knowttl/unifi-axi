import { writeFile, copyFile } from 'node:fs/promises';
import { catalogue } from '../dist/catalogue.js';

await copyFile(new URL('../src/axi-credential.schema.json', import.meta.url), new URL('../dist/axi-credential.schema.json', import.meta.url));

await writeFile(new URL('../dist/capabilities.json', import.meta.url), `${JSON.stringify({
  stage: 'B1.2', operations: catalogue,
  unsupported: ['WAN changes', 'VPN changes', 'RADIUS changes', 'UniFi OS backup/restore', 'Firmware upgrades', 'Administrator accounts', 'SSH', 'Undocumented endpoints'],
}, null, 2)}\n`);
await writeFile(new URL('../dist/SKILL.md', import.meta.url), [
  '---', 'name: unifi-axi', 'description: Discover documented UniFi Network Integration API commands and their implementation status.', '---',
  '', '# UniFi AXI', '', 'Use `unifi-axi commands` for static offline discovery.',
  'Use `unifi-axi <command> --help` for inputs and effects.',
  'B1.2 implements protected profiles and verified information transport. Application schema validation is pending B1.2a.',
  'Use auth status, profile list and config path offline. Configure with profile configure --profile <name> --file <absolute-profile-json>.',
  'Secrets must be env/file references, never argv or inline profile values. TLS verification cannot be disabled.',
  'No router access or live write is authorized by this catalogue.', '',
  '| Command | Effect | Status |', '|---|---|---|',
  ...catalogue.map(entry => `| ${entry.command} | ${entry.effect} | ${entry.status} |`), '',
].join('\n'));
