import { writeFile, copyFile } from 'node:fs/promises';
import { catalogue, description, guidance, examplesFor } from '../dist/catalogue.js';

await copyFile(new URL('../src/axi-credential.schema.json', import.meta.url), new URL('../dist/axi-credential.schema.json', import.meta.url));

await writeFile(new URL('../dist/capabilities.json', import.meta.url), `${JSON.stringify({
  stage: 'B4.11', operations: catalogue,
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
  'Firewall policy list/show remain gated by reachable unresolved source conflicts. Wi-Fi detail radio rates use reviewed exact-field numeric enum resolutions.',
  'Voucher codes and Wi-Fi passphrases are redacted. Standalone voucher and Wi-Fi exports default off: the selected file profile must set allowSecretExport: true and the caller must supply --secret-output <absolute-path>. Refusal precedes vendor access and file reservation. Export uses a new file in an existing private directory; ordinary output contains only IDs and a receipt. Native read-only semantics remain unchanged. Hosted exports are denied. Diagnostic error codes remain visible.',
  'Use site list to discover site UUIDs; select one with --site <site-id> when home reports ambiguity.',
  'Unknown application versions require an explicit profile apiContract for visibly unverified read-only investigation and cannot execute writes.',
  'Network create, update and delete preview by default. Creation and update support GATEWAY, SWITCH and UNMANAGED, with a protected --body-file. Execution requires writes.allowWrites, exact vendor operation and management variant grants, --execute, --confirm and a stable --request-id. Update uses PUT replacement semantics. Delete force defaults and overrides are confirmation-bound.',
  'Use write show and write reconcile with --request-id for durable ownership recovery. Unknown outcomes never authorize another send. Hosted writes and native Windows writes remain unavailable.',
  'Wi-Fi broadcast create/update/delete and hotspot voucher create/delete/delete-many use the same write controls. Voucher bulk deletion intersects the original predicate with exactly the previewed IDs. Generation retains all batch IDs. Optional --secret-output on generation or Wi-Fi writes additionally requires profile allowSecretExport: true and reserves a protected destination before mutation. Delivery failure preserves vendor acceptance; repeat the exact owned request to recover all codes through reads without another generation.',
  'Use auth status, profile list and config path offline. Configure with profile configure --profile <name> --file <absolute-profile-json>.',
  'Secrets must be env/file references, never argv or inline profile values. TLS verification cannot be disabled.',
  'No router access or live write is authorized by this catalogue.', '',
  '| Command | Effect | Status |', '|---|---|---|',
  ...catalogue.map(entry => `| ${entry.command} | ${entry.effect} | ${entry.status} |`), '',
].join('\n'));
