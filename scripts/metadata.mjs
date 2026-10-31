import { writeFile } from 'node:fs/promises';
import { catalogue } from '../dist/catalogue.js';

await writeFile(new URL('../dist/capabilities.json', import.meta.url), `${JSON.stringify({
  stage: 'B1.1', operations: catalogue,
  unsupported: ['WAN changes', 'VPN changes', 'RADIUS changes', 'UniFi OS backup/restore', 'Firmware upgrades', 'Administrator accounts', 'SSH', 'Undocumented endpoints'],
}, null, 2)}\n`);
await writeFile(new URL('../dist/SKILL.md', import.meta.url), [
  '---', 'name: unifi-axi', 'description: Discover documented UniFi Network Integration API commands and their implementation status.', '---',
  '', '# UniFi AXI', '', 'Use `unifi-axi commands` for static offline discovery.',
  'Use `unifi-axi <command> --help` for inputs and effects.',
  'B1.1 implements offline discovery only; every vendor operation is not-implemented and sends nothing.',
  'No router access or live write is authorized by this catalogue.', '',
  '| Command | Effect | Status |', '|---|---|---|',
  ...catalogue.map(entry => `| ${entry.command} | ${entry.effect} | ${entry.status} |`), '',
].join('\n'));
