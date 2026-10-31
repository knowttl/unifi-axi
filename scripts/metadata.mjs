import { writeFile, copyFile } from 'node:fs/promises';
import { catalogue, description, guidance, examplesFor } from '../dist/catalogue.js';

await copyFile(new URL('../src/axi-credential.schema.json', import.meta.url), new URL('../dist/axi-credential.schema.json', import.meta.url));

await writeFile(new URL('../dist/capabilities.json', import.meta.url), `${JSON.stringify({
  stage: 'B2.10', operations: catalogue,
  unsupported: ['WAN changes', 'VPN changes', 'RADIUS changes', 'UniFi OS backup/restore', 'Firmware upgrades', 'Administrator accounts', 'SSH', 'Undocumented endpoints'],
}, null, 2)}\n`);
await writeFile(new URL('../dist/SKILL.md', import.meta.url), [
  '---', 'name: unifi-axi', 'description: Discover documented UniFi Network Integration API commands and their implementation status.', '---',
  '', '# UniFi AXI', '', description, ...guidance.map(line => line.replaceAll('unifi-axi', 'npx -y @knowttl/unifi-axi')),
  ...catalogue.flatMap(operation => examplesFor(operation).map(example => `\`${example.replace('unifi-axi', 'npx -y @knowttl/unifi-axi')}\``)),
  'Use `unifi-axi commands` for static offline discovery.',
  'Use `unifi-axi <command> --help` for inputs and effects.',
  'Implemented reads include supporting catalogues, WAN/VPN overviews, devices, clients, networks, firewall policies and zones, ACL rules, DNS policies, traffic lists, vouchers, Wi-Fi broadcasts and switching structures, plus info/site discovery and doctor.',
  'Device reads on Network 11.0.97 remain gated by the unresolved CF-007 PoE contract conflict. Network 10.6.109 preserves numeric PoE types.',
  'Firewall policy list/show and Wi-Fi broadcast show remain gated by reachable unresolved source conflicts. Ordering, zones and Wi-Fi overview lists remain available.',
  'Voucher codes and Wi-Fi passphrases are redacted. Diagnostic error codes remain visible.',
  'Use site list to discover site UUIDs; select one with --site <site-id> when home reports ambiguity.',
  'Unknown application versions require an explicit profile apiContract for visibly unverified read-only investigation. Writes remain unavailable.',
  'Use auth status, profile list and config path offline. Configure with profile configure --profile <name> --file <absolute-profile-json>.',
  'Secrets must be env/file references, never argv or inline profile values. TLS verification cannot be disabled.',
  'No router access or live write is authorized by this catalogue.', '',
  '| Command | Effect | Status |', '|---|---|---|',
  ...catalogue.map(entry => `| ${entry.command} | ${entry.effect} | ${entry.status} |`), '',
].join('\n'));
