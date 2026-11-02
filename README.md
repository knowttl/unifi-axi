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
  An explicit `--limit N` caps the returned rows; `complete: false` and `nextOffset` identify where to resume with `--offset`.
  Without `--limit`, enumeration uses pages of 25 (100 for vouchers) until complete within the read budget.
  `--limit 0` reads metadata only.
  Voucher and Wi-Fi lists retain this pagination metadata on stdout when using `--secret-output`, alongside exported IDs and the delivery receipt.
- Enumeration is bounded to 100 pages, 10,000 rows, eight MiB across responses and thirty seconds, then fails with `READ_INCOMPLETE` and guidance.
- Details verify the returned ID against the requested resource and never substitute a similar resource.
- Select a site with `--site <site-id>`, then the profile `siteId`, then the sole discovered site.
  Otherwise the home view reports `SITE_AMBIGUOUS` or `SITE_REQUIRED`.
- Every live command bootstraps from the actual Network `applicationVersion`.
  Versions 10.6.109 and 11.0.97 select their matching contract.
  An unknown version returns `UNVERIFIED_API_VERSION`.
  A profile `apiContract` of one of those versions permits read-only investigation that stays visibly `unverified`, and never enables writes.
- `api.writesAvailable` reports whether a network write is authorized on a shipped application version outside Windows.
  It requires `writes.allowWrites: true`, no read-only override, and either `deleteNetwork` or a matching create/update operation and management variant grant (`UNMANAGED`, `SWITCH` or `GATEWAY`).
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
  `write reconcile` records a separate observation; receipts distinguish `not-sent`, `unknown`, `rejected`, `accepted`, `verified` and `no-op`, with an audit ID.
  A lost acknowledgement stays `unknown`, and a similar resource never proves creation.
  Network update verification checks replacement expectations, including omitted settings, rather than only submitted fields.
  Network create/update verification treats omitted and null `dhcpGuarding` as disabled; retained enabled guarding keeps the receipt `accepted`.
  Omitted gateway `mdnsForwardingEnabled` delegates to the site default, so either read-back boolean can verify; an explicitly supplied boolean must match.
  Device adoption matches pending/adopted devices and acknowledgement MAC addresses case-insensitively, while confirmation and request-ID binding retain the submitted body's casing.
  Voucher creation and bulk-deletion reconciliation compare UUIDs case-insensitively.
- HTTP 4xx mutation responses produce terminal `rejected` receipts with sanitized vendor diagnostics.
  Their request IDs remain final; preview a corrected request and use a new request ID.
  Transport loss, timeouts, and server failures after possible dispatch remain `unknown` and must not be resent.
- The write journal lives under `$XDG_STATE_HOME/unifi-axi/writes.log/` (or `.local/state/unifi-axi/writes.log/` under the home directory) with owner-only access, or under the absolute directory in `UNIFI_AXI_WRITE_LOG`.
  It stores hashes, audit IDs, resource IDs, outcomes and sanitized refusal diagnostics; request bodies and credentials are not stored as journal fields.
  Keep the same profile, configuration and journal location across invocations.
- Secrets are redacted: voucher `code` and Wi-Fi `passphrase` appear as `[REDACTED]`, and keys are redacted in raw, JSON-escaped and URL-encoded forms.
  Export of voucher codes and personal Wi-Fi passphrases requires both `--secret-output <absolute-path>` and `"allowSecretExport": true` in the selected file profile.
  The destination must be a new file in an existing private directory, and exported files use mode 0600.
  Without the profile opt-in, `SECRET_EXPORT_DENIED` refuses before any credential or vendor access.
  Never issue a new generation request to recover an existing code; use `write reconcile` and re-export with `show --secret-output`.
- `hotspot voucher delete-many` requires `--filter`, previews the matching IDs and restricts deletion to those IDs together with the original filter.
  An approved voucher that stops matching the filter can survive; the receipt remains `accepted` while any approved ID is still present.
- Request bodies are validated against the selected contract and reject undeclared fields before any mutation.
  For STANDARD WPA2_PERSONAL broadcasts, explicitly set `securityConfiguration.fastRoamingEnabled`; preview warns when it is missing.
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
- Request body files must be owner-only: use `chmod 600 '<body-file>'` on POSIX or a protected owner ACL on Windows.
  Write command help includes the body fields, subtype requirements, and the packaged contract location for nested schemas.
- The credential schema ships as `dist/axi-credential.schema.json` with `apiKey` marked `x-secret`.
- Metadata exports: `./catalogue`, `./capabilities`, `./skill` and `./credential-schema`.

### Self-signed controllers reached by IP

When the certificate contains a DNS subject alternative name but no matching IP subject alternative name, a pinned IP origin still fails hostname verification.
Set `origin` to `https://<certificate-dns-name>` (including the controller port when needed), and set `tls.connectAddress` to the controller IP.
The TCP connection uses that IP while TLS SNI, certificate hostname verification, and the HTTP Host header use the origin DNS name.
DNS resolution of that name is not needed with `connectAddress`.

Obtain the certificate from the controller administrator through a trusted channel, or inspect the certificate presented on its TLS port:

```sh
openssl s_client -connect '<controller-ip>:<port>' -servername '<certificate-dns-name>' -showcerts </dev/null
openssl x509 -in '<certificate.pem>' -noout -ext subjectAltName -fingerprint -sha256
```

Save the leaf certificate PEM block as `<certificate.pem>` and independently confirm its SHA-256 fingerprint with the administrator before trusting it.
Set `tls.trustedCertificatePem` to the PEM text and `tls.peerFingerprintSha256` to the fingerprint's 64 hexadecimal digits with colons removed.
Keep all certificate verification enabled, then check the profile with `unifi-axi doctor --profile <name>`.

## Output and exit codes

- Output is TOON on stdout, except `-v`, `-V` and `--version`, which print the bare package version.
- Errors use structured codes, for example `PROFILE_REQUIRED`, `PROFILE_NOT_FOUND`, `PROFILE_AMBIGUOUS`, `AUTH_REQUIRED`, `RESPONSE_INVALID`, `READ_INCOMPLETE`, `TIMEOUT`, `UPSTREAM_ERROR`, `CONTRACT_CONFLICT`, `INVALID_ARGUMENT` and `NOT_IMPLEMENTED`.
- API failures include `upstream.status` and, when available, sanitized vendor `code`, `message` and `requestId` fields.
  HTTP 404 reads return `NOT_FOUND`; other HTTP read failures return `UPSTREAM_ERROR`, with guidance for the failure.
  Mutation refusals follow the receipt rules in [Safety](#safety).
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
