# unifi-axi

Agent-facing CLI for the official UniFi Network Integration API, read-only by default, with confirmed writes behind exact grants.

[![npm](https://img.shields.io/npm/v/@knowttl/unifi-axi)](https://www.npmjs.com/package/@knowttl/unifi-axi)
![Node](https://img.shields.io/badge/node-%3E%3D24.11.0-brightgreen)

[Why](#why-this-exists) | [Quickstart](#quickstart) | [Use with your agent](#use-with-your-agent) | [Commands](#commands) | [Safety](#safety) | [Configuration](#configuration) | [Output and exit codes](#output-and-exit-codes) | [Limitations](#limitations) | [Development](#development) | [Security](#security) | [License](#license)

## Why this exists

Agents that manage a UniFi controller need bounded, structured answers and safe write paths, not raw vendor JSON.
`unifi-axi` covers all 73 vendor operations of the Network Integration API and returns bounded TOON on stdout with structured error codes and next-step hints.
Credentials are references only, TLS verification cannot be disabled, and every implemented write requires a preview, exact grants, a confirmation and a stable request ID.

## Quickstart

Requires Node 24.11.0 or newer.

```sh
npm install --global @knowttl/unifi-axi
unifi-axi --version
unifi-axi
```

Without a profile the home view exits 1 with setup guidance:

```text
error:
  code: PROFILE_REQUIRED
  message: Select a profile with --profile or configure a complete environment profile.
help[3]: unifi-axi auth status,unifi-axi profile configure --profile <name> --file <absolute-profile-json>,unifi-axi site list
```

Configure a profile from a protected JSON file of references (see [Configuration](#configuration)), then make the first authenticated reads:

```sh
unifi-axi profile configure --profile lab --file /absolute/path/profile.json
unifi-axi auth status --profile lab
unifi-axi doctor --profile lab
unifi-axi site list --profile lab
unifi-axi --profile lab --site <site-id>
```

`auth status` resolves references offline.
`doctor` resolves credentials, verifies TLS and reads application information only.
The home view returns application and Site Manager versions plus at most 25 sites.

## Use with your agent

Two optional discovery paths ship; either one is sufficient, and normal read commands install nothing.

- Session hook: preview, then install a directory-scoped integration for `claude`, `codex` or `opencode`.

  ```sh
  unifi-axi setup --app claude --directory /absolute/project --profile lab
  unifi-axi setup --app claude --directory /absolute/project --profile lab --execute --confirm <digest>
  ```

  Setup binds the named file-backed profile and configuration path to that directory, preserves unrelated settings, repairs its managed integration and is a no-op when repeated.
  Claude uses `.claude/settings.json`, Codex uses `.codex/hooks.json` (and enables project hooks in `.codex/config.toml`), and OpenCode uses `.opencode/plugins/unifi-axi.ts`.
  The hook emits context only when the working directory matches the selected directory.
- Static skill: the generated skill is exported at `@knowttl/unifi-axi/skill` for on-demand discovery without hooks.

## Commands

Run `unifi-axi commands` for the offline catalogue with each operation's id, effect and status.
Run `unifi-axi <command> --help` for flags, defaults and effects.
Global flags: `--help`, `--config <absolute-path>`, `--profile <name>`, `--site <site-id>`, `--full`.

| Group | Commands |
|---|---|
| Local | `commands`, `doctor`, `auth status`, `profile list`, `profile configure`, `config path`, `setup`, `--version` |
| Application and sites | `info`, `site list` |
| Inventory | `device list/show/pending list/adopt/remove/action`, `device statistics latest`, `device interfaces ports action`, `device-tag list`, `client list/show/action`, `network list/show/references`, `country list`, `dpi application list`, `dpi category list`, `radius profile list`, `vpn server list`, `vpn site-to-site-tunnel list`, `wan list` |
| Policies | `firewall policy list/show/create/update/patch/delete/order show/order set`, `firewall zone list/show/create/update/delete`, `acl-rule list/show/create/update/delete/order show/order set`, `dns policy list/show/create/update/delete`, `traffic-list list/show/create/update/delete` |
| Wi-Fi and guests | `wifi broadcast list/show/create/update/delete`, `hotspot voucher list/show/create/delete/delete-many` |
| Switching | `switching lag`, `switching mc-lag-domain`, `switching switch-stack` (each `list` and `show`) |
| Networks | `network create`, `network update`, `network delete` |
| Write recovery | `write show --request-id <id>`, `write reconcile --request-id <id>` |

Unimplemented operations exit 1 with `NOT_IMPLEMENTED` before network access.
At the current head every catalogue entry reports `implemented`.

Reading notes:

- Lists use bounded paging and report `count`, `totalCount`, `offset` and `complete`, and accept `--offset`, `--limit` and `--filter` where the operation documents them.
  The default limit is 25 per request, `--limit 0` reads metadata only, and voucher lists default to 100.
- Enumeration is bounded to 100 pages, 10,000 rows, eight MiB across responses and thirty seconds, then fails with `READ_INCOMPLETE` and guidance.
- Details verify the returned ID against the requested resource and never substitute a similar resource.
- Select a site with `--site <site-id>`, then the profile `siteId`, then the sole discovered site.
  Otherwise the home view reports `SITE_AMBIGUOUS` or `SITE_REQUIRED`.
- Every live command bootstraps from the actual Network `applicationVersion`.
  Versions 10.6.109 and 11.0.97 select their matching contract.
  An unknown version returns `UNVERIFIED_API_VERSION`.
  A profile `apiContract` of one of those versions permits read-only investigation that stays visibly `unverified`, and never enables writes.
- Long text is bounded to 1,000 characters plus an ellipsis; `--full` on `info` and `client list` shows more, still redacted.

Write commands follow the same preview, confirm and recover pattern, take `--body-file <path>` where a body is needed, and are described in [Safety](#safety).
Pass `--secret-output <absolute-path>` to `hotspot voucher` and `wifi broadcast` reads and creates for protected secret export.

## Safety

- Reads are the default.
  `UNIFI_AXI_READ_ONLY=true` or `1` overrides every write grant.
  It accepts only `1`, `0`, `true` or `false`, case-insensitively.
- Execution needs `writes.allowWrites: true` and the exact vendor grant in `writes.operations`.
  Some operations also need a qualified grant, for example `createNetwork:<management>` or `executeConnectedClientAction:<action>`.
  Legacy `OP-049` and `OP-050` entries are readable profile syntax but do not authorize execution.
- Each write is previewed first.
  Repeat the command with `--execute --confirm <confirmation> --request-id <stable-id>`.
  The confirmation binds the normalized request, resolved path, body, target set, selected resource state, origin, profile, credential reference, application version, contract hash, TLS leaf and connection route.
  Changed bindings fail closed, and `update` commands replace the resource rather than merge.
- Write grants by family:

  | Family | Grants |
  |---|---|
  | Network | `createNetwork`, `updateNetwork`, `deleteNetwork` |
  | Firewall policy | `createFirewallPolicy`, `updateFirewallPolicy`, `patchFirewallPolicy`, `deleteFirewallPolicy`, `updateFirewallPolicyOrdering` |
  | Firewall zone | `createFirewallZone`, `updateFirewallZone`, `deleteFirewallZone` |
  | ACL rule | `createAclRule`, `updateAclRule`, `deleteAclRule`, `updateAclRuleOrdering` |
  | DNS policy | `createDnsPolicy`, `updateDnsPolicy`, `deleteDnsPolicy` |
  | Traffic list | `createTrafficMatchingList`, `updateTrafficMatchingList`, `deleteTrafficMatchingList` |
  | Wi-Fi broadcast | `createWifiBroadcast`, `updateWifiBroadcast`, `deleteWifiBroadcast` |
  | Hotspot voucher | `createVouchers`, `deleteVoucher`, `deleteVouchers` |
  | Clients and devices | `executeConnectedClientAction`, `adoptDevice`, `removeDevice`, `executeAdoptedDeviceAction`, `executePortAction` |

- Unknown outcomes are never retried.
  An exclusive claim and a synced intent precede dispatch, and a synced `unknown` record precedes any possible send.
  Reusing an owned request ID runs read-only reconciliation instead of resending.
  `write reconcile` records a separate observation; receipts distinguish `not-sent`, `unknown`, `accepted`, `verified` and `no-op`, with an audit ID.
  A lost acknowledgement stays `unknown`, and a similar resource never proves creation.
- The write journal lives under `$XDG_STATE_HOME/unifi-axi/writes.log/` (or `.local/state/unifi-axi/writes.log/` under the home directory) with owner-only access, or under the absolute directory in `UNIFI_AXI_WRITE_LOG`.
  It stores hashes, audit IDs, resource IDs and outcomes, never request bodies or keys.
  Keep the same profile, configuration and journal location across invocations.
- Secrets are redacted: voucher `code` and Wi-Fi `passphrase` appear as `[REDACTED]`, and keys are redacted in raw, JSON-escaped and URL-encoded forms.
  Export of voucher codes and personal Wi-Fi passphrases requires both `--secret-output <absolute-path>` and `"allowSecretExport": true` in the selected file profile.
  The destination must be a new file in an existing private directory, and exported files use mode 0600.
  Without the profile opt-in, `SECRET_EXPORT_DENIED` refuses before any credential or vendor access.
  Never issue a new generation request to recover an existing code; use `write reconcile` and re-export with `show --secret-output`.
- `hotspot voucher delete-many` requires `--filter`, previews the matching IDs and deletes exactly the approved ID set.
- Request bodies are validated against the selected contract and reject undeclared fields before any mutation.
- Disruptive actions (restart, PoE power cycle, guest authorization) are accepted, not proven complete: receipts stay `accepted`.

## Configuration

Configuration file: `--config`, then `UNIFI_AXI_CONFIG`, then `$XDG_CONFIG_HOME/unifi-axi/config.json` (or `.config/unifi-axi/config.json` under the home directory).
Use `unifi-axi config path` to find it and `unifi-axi profile list` to list profiles.
Profile selection: `--profile`, `UNIFI_AXI_PROFILE`, a complete environment profile, the default profile, then the sole profile.

```json
{
  "version": 1,
  "defaultProfile": "lab",
  "profiles": {
    "lab": {
      "origin": "https://controller.example",
      "apiKey": { "env": "UNIFI_AXI_API_KEY" }
    }
  }
}
```

- `apiKey` takes exactly one environment or absolute local file reference, and defaults to `UNIFI_AXI_API_KEY`.
  Inline secrets and secret flags are refused.
- An environment profile needs `UNIFI_AXI_ORIGIN` and `UNIFI_AXI_API_KEY`.
  Optional: `UNIFI_AXI_SITE_ID`, `UNIFI_AXI_API_CONTRACT`, `UNIFI_AXI_TLS` and `UNIFI_AXI_WRITES` (the last two are strict JSON objects).
  A partial environment profile fails with `CONFIG_INVALID`.
- Other variables: `UNIFI_AXI_CONFIG`, `UNIFI_AXI_PROFILE`, `UNIFI_AXI_READ_ONLY`, `UNIFI_AXI_WRITE_LOG`.
- Secret and config files must be owner-only and configs cannot be group- or world-writable; unsafe files fail with `CONFIG_INSECURE` before any authenticated request.
  No credential store or token cache is created.
- TLS uses system trust and hostname verification.
  An appliance profile may set `tls.trustedCertificatePem` and `tls.peerFingerprintSha256` together, plus an optional IP `tls.connectAddress` that changes only the TCP destination.
  Certificate failures return `TLS_REJECTED` without retrying or sending credentials.
- The credential schema ships as `dist/axi-credential.schema.json` with `apiKey` marked `x-secret`.
- Metadata exports: `./catalogue`, `./capabilities`, `./skill` and `./credential-schema`.

## Output and exit codes

- Output is TOON on stdout, except `-v`, `-V` and `--version`, which print the bare package version.
- Errors use structured codes, for example `PROFILE_REQUIRED`, `PROFILE_NOT_FOUND`, `PROFILE_AMBIGUOUS`, `AUTH_REQUIRED`, `RESPONSE_INVALID`, `READ_INCOMPLETE`, `TIMEOUT`, `UPSTREAM_ERROR`, `CONTRACT_CONFLICT`, `INVALID_ARGUMENT` and `NOT_IMPLEMENTED`.
- Exit code 0 is success, 1 is a command error, and 2 is a usage error such as an unknown command, unknown flag, duplicate flag or invalid scalar value.
- Each API request has a ten-second deadline, at most two reads run concurrently, and each response is bounded to one MiB.
- Reads retry transport failures and HTTP 502, 503 and 504 at most twice within the deadline.
  HTTP 401 is never retried, 429 retries only with an exact `Retry-After` of 0, 1 or 2 seconds, and redirects are refused.
  Mutations are never retried by transport.

## Limitations

- The catalogue covers the captured 10.6.109 and 11.0.97 contracts.
  Other versions are read-only and unverified.
- Known vendor contract conflicts are blocked rather than normalized, for example all 11.0.97 device reads fail with `CONTRACT_CONFLICT` (CF-007), and unknown named firewall protocols are refused.
  The conflict registry is `src/contract-conflicts.json` and the reviewed resolutions are in `src/normalization-ledger.json`.
- WAN, VPN and RADIUS changes, UniFi OS backup and restore, firmware upgrades and administrator management are absent from the vendor contracts.
  SSH and undocumented endpoints are excluded.
- The vendor offers no atomic conditional write, so concurrent changes can still occur after the final pre-dispatch read.
- All 32 live mutation probes remain unrun.
  Verification uses local synthetic controllers only and performs no router reads or writes.
- Native Windows ACL, install and write behavior is pending, and native Windows writes remain gated until directory durability is proven.
  Linux results cannot establish Windows behavior.
- Hosted execution denies setup, local secret export and mutations.
- Stock Artium remains unsupported; the opt-in first-read proof uses a reviewed, temporary local fixture.

## Development

Use Node 24.14.0 and pnpm 10.34.6, as pinned in this checkout.
There are no install hooks or telemetry.

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm check
```

`pnpm check` runs strict types, lint, the package-contract check, the packaged verification suite, versioned contract checks and private-file, paging, transport and variant-coverage tests.
`pnpm verify:package-contract` packs and installs offline, checks the published file list, rejects private keys and local build paths, and smoke-tests the installed launcher and exports without an external fixture.
Both `pnpm test` and `pnpm check` enforce that package contract with outbound network denied.
`pnpm verify:packaged -- --task <id>` runs a single packaged selector against the built, packed and installed executable, with outbound network denied except a synthetic controller.
See the [B4.11 regression gate](evidence/B4.11.md) for combined coverage, acceptance-report semantics and deferred obligations.
`pnpm verify:artium --host <absolute-reviewed-fixture-path> --output <absolute-external-evidence-directory>` runs the opt-in proof against an external fixture.
Tests never connect to a real controller or use a real API key.
`src/commands.json` owns command names and operation IDs, and the build derives the catalogue, capability metadata and skill from the [retained OpenAPI sources](evidence/README.md).
Releases are published by release-please through npm trusted publishing.
See [CONTRIBUTING.md](CONTRIBUTING.md) for test-quality rules.

## Security

No `SECURITY.md` ships yet; the security policy is pending.

## License

No `LICENSE` file ships yet; the license is pending.
