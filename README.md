# unifi-axi

An agent-facing CLI for the official UniFi Network Integration API.
Package: `@knowttl/unifi-axi`.

B1.2a adds application version validation, site discovery, doctor and a configured live home to the protected profiles and verified HTTPS transport from B1.2.
B1.3 adds an opt-in first-read proof through a reviewed, temporary local Artium fixture.
Stock Artium remains unsupported.
All 73 vendor operations are discoverable.
`info` and `site list` use versioned response validation as described in [Application and sites](#application-and-sites).
Read coverage includes [inventory and networks](#inventory-clients-networks-and-references) and [policies, vouchers, Wi-Fi and switching](#policies-vouchers-wi-fi-and-switching), subject to the documented contract gates.
Network creation, update and deletion support [previews and explicitly granted execution](#network-write-foundation).
Use `unifi-axi commands` for each operation's implementation status; unimplemented operations exit 1 with `NOT_IMPLEMENTED` before network access.
Development verification uses local synthetic controllers only and performs no router reads or writes.
All 32 live mutation probes remain unrun.

```text
unifi-axi commands
unifi-axi info --help
unifi-axi site list --help
unifi-axi auth status
unifi-axi --version
```

Output is TOON on stdout except for the bare version; errors use structured codes.
`info` and `client list` retain the published `--full` switch; see [Application and sites](#application-and-sites) for text bounds.
Unknown commands, unknown flags, duplicate flags and invalid scalar values exit 2.
Bare `-v`, `-V` and `--version` print the package version before loading the catalogue.
Without a profile the home view exits 1 with `PROFILE_REQUIRED` and setup guidance.
`auth status` resolves protected references offline and reports only profile, origin and source.
No profiles, an absent named profile, ambiguous selection and an unavailable key produce distinct `PROFILE_REQUIRED`, `PROFILE_NOT_FOUND`, `PROFILE_AMBIGUOUS` and `AUTH_REQUIRED` errors.
See [Application and sites](#application-and-sites) for the configured home view.
`doctor` resolves protected credentials, verifies TLS and reads application information only.
Session setup is [explicit and directory-scoped](#optional-integrations).

## Install

Use Node 24.11.0 or newer.

```sh
npm install -g @knowttl/unifi-axi
unifi-axi --version
```

The npm package is scoped; the executable is `unifi-axi`.

## Application and sites

Every implemented live command bootstraps from the actual Network `applicationVersion`, separately from any Site Manager label.
Output identifies the actual application version, selected contract, verification status and native write-policy availability.
Known versions 10.6.109 and 11.0.97 select their matching contract, regardless of a profile override.
An unknown version returns `UNVERIFIED_API_VERSION` after the info read.
A profile `apiContract` of 10.6.109 or 11.0.97 permits read-only investigation while output remains visibly `unverified` and retains the actual version.
Application information is schema-validated only for known application versions; unknown versions require an object with a string `applicationVersion` but skip full info validation.
Site responses are validated against the selected contract, including during unverified investigation.
Unknown application versions cannot enable writes, even with an explicit read-only contract override.

Running `unifi-axi` with a configured profile returns application and Site Manager versions and at most 25 sites, each with its ID, internal reference and name.
The result includes the vendor total, truncation metadata and commands that retain profile and site context.
Use `site list` for the full site listing within the enumeration budgets below.
Live read output bounds long text to 1,000 characters plus an ellipsis, with original sizes and a `--full` command; full text still redacts secrets and does not expand the home view's site limit.

`site list` enumerates pages and reports exact site UUIDs, internal references, names, returned `count`, `totalCount`, starting `offset` and `complete`.
It accepts the official `--offset`, `--limit` and `--filter` query flags.
The default limit is 25 per request; `--limit 0` reads metadata only and reports incomplete when rows remain.
Enumeration is bounded to 100 pages, 10,000 rows, eight MiB across responses and thirty seconds.
Repeated records, stalled offsets, changing totals, counts exceeding requested or reported bounds, or exhausted budgets fail with `READ_INCOMPLETE`, including progress and filter guidance.
Malformed JSON, missing fields and wrong types fail with `RESPONSE_INVALID`.
An empty result at or beyond `totalCount` reports `count: 0` and `complete: true`, preserving the requested `offset` and upstream `totalCount`.

Select a site with `--site <site-id>`, then the profile's `siteId`, then the sole discovered site.
Site discovery works without selection; without an explicit or profile selection, home reports `SITE_AMBIGUOUS` for multiple sites and `SITE_REQUIRED` when no sites exist.
An explicit selection survives contextual hints along with the selected file profile and explicit configuration path.
Inventory reads use the selected site for every resource request.

```text
unifi-axi doctor --profile lab
unifi-axi site list --profile lab
unifi-axi --profile lab --site <site-id>
```

## Optional integrations

For optional ambient session context, preview an explicit directory-scoped integration:

```sh
unifi-axi setup --app claude --directory /absolute/project --profile lab
unifi-axi setup --app claude --directory /absolute/project --profile lab --execute --confirm <digest>
```

Choose `claude`, `codex` or `opencode`.
Setup binds the named file-backed profile and configuration path to that directory, preserves unrelated settings and repairs its managed integration.
Repeat setup for a successful no-op.
Claude uses `.claude/settings.json`, Codex uses `.codex/hooks.json`, and OpenCode uses `.opencode/plugins/unifi-axi.ts` within the selected directory.
Codex setup also enables project hooks in `.codex/config.toml`.
The hook or plugin emits context only when the working directory matches the selected directory.
Hosted execution denies setup before any filesystem changes.
Normal read commands install no integrations.
Alternatively, install the generated static skill exported at `@knowttl/unifi-axi/skill` for on-demand discovery without session hooks.
The hook and skill are two optional discovery paths; either one is sufficient.

## Inventory, clients, networks and references

`country list`, `dpi application list`, `dpi category list`, `device pending list`, `device-tag list`, `radius profile list`, `vpn server list`, `vpn site-to-site-tunnel list` and `wan list` enumerate the documented supporting records.
`device list`, `client list` and `network list` enumerate inventory for the selected site.
These lists use the same bounded paging and completeness metadata as `site list`.
Filters are forwarded unchanged where the documented operation accepts them; WAN does not accept a filter.
Country codes and numeric DPI IDs keep their original types.
WAN and VPN output contains documented overview fields only.
VPN `metadata.source` is returned only for `DERIVED` site-to-site tunnels.
Missing totals or invalid page shapes fail with `RESPONSE_INVALID` instead of claiming completeness.

`device show --device-id <id>`, `device statistics latest --device-id <id>`, `client show --client-id <id>` and `network show --network-id <id>` address the exact selected resource.
Required resource IDs are checked before credentials or network access.
An upstream missing or cross-site resource returns `UPSTREAM_ERROR`; no similar resource is substituted.
`network references --network-id <id>` includes the selected network's ID and name and the complete documented reference response.

```text
unifi-axi device list --site <site-id>
unifi-axi client show --site <site-id> --client-id <client-id>
unifi-axi network references --site <site-id> --network-id <network-id>
```

Responses preserve gateway, switch and unmanaged network fields and validate their selected subtype.
Response-side NORM-001 accepts omitted or explicit null `dhcpGuarding` as disabled, preserving null in output.
Other null fields must satisfy the original schema; request-side normalization remains unavailable.
Validation failures include the offending field path without echoing its value.
The approved 10.6.109 PoE resolution preserves integer values without coercion and rejects strings.
All 11.0.97 device reads remain blocked with `CONTRACT_CONFLICT` for unresolved CF-007; its integer type and string enum disagree, and no 11.0.97 override is approved.

## Policies, vouchers, Wi-Fi and switching

`acl-rule`, `dns policy`, `traffic-list`, `firewall zone`, `hotspot voucher`, `switching lag`, `switching mc-lag-domain` and `switching switch-stack` provide `list` and `show` reads.
Use each command's `--help` for its required resource ID flag.
Lists preserve the vendor order, filters and bounded paging metadata.
Details preserve nested subtype fields and verify the returned ID against the requested resource.
Empty switching lists remain empty; missing details return an explicit upstream error.

`acl-rule order show` returns the ordered rule IDs.
`firewall policy order show` requires both `--source-firewall-zone-id` and `--destination-firewall-zone-id` and returns ordering for that zone pair.
Zone details include their network IDs.
Firewall policy `list` and `show` remain gated by unresolved named-protocol conflicts CF-002 through CF-004 on 10.6.109 and CF-008 through CF-010 on 11.0.97.
Wi-Fi broadcast `show` validates radio rates using the reviewed exact-field numeric enum resolutions CF-005/CF-006 and CF-011/CF-012 respectively.
The unresolved firewall conflicts block the reachable response schema even when the affected optional field is absent or a list is empty.
Firewall policy `list` and `show` return `CONTRACT_CONFLICT` diagnostics naming the selected version, conflict IDs and source pointers.
`wifi broadcast list`, policy ordering and zone reads remain available.
No source conflict is silently normalized.

`hotspot voucher list/show` and `wifi broadcast list/show` accept `--secret-output <absolute-path>` for standalone protected response export.
The destination must be new and inside an existing private directory.
The file contains JSON entries with a resource ID, an allowlisted response path and its secret value.
Voucher codes and personal Wi-Fi passphrases, including WPA2 personal preshared keys, are the only exported values.
Wi-Fi list exports fetch the documented detail for each listed ID.
Authentication keys remain redacted even at an allowlisted location.
Ordinary output contains IDs and a delivery receipt only.
An existing destination is never replaced, and a failed read removes the reserved file so the read can be repeated with a new destination.
Hosted execution refuses local exports before resolving a profile or contacting the vendor.
Mutation-time secret delivery remains pending B4.8.

Voucher `code` fields and Wi-Fi `passphrase` fields are replaced with `[REDACTED]` in default output.
Diagnostic `error.code` fields remain visible.
Voucher lists use the documented default limit of 100; other lists use their documented defaults.

## Network write foundation

`network create --body-file <path>` previews network creation.
`network update --network-id <id> --body-file <path>` previews a complete replacement using PUT.
Both support the selected contract's `GATEWAY`, `SWITCH` and `UNMANAGED` variants, including nested DHCP, IPv6 and NAT settings.
Requests reject undeclared fields, unmapped tags and missing required subtype fields.
Optional `dhcpGuarding` accepts omission, a schema-valid configuration or explicit null to disable it under NORM-001.
`network delete --network-id <id>` previews deletion of that exact network.
Omitted `--force` and `--force false` normalize to the same request; `--force true` needs a new preview.
Request site and network UUIDs normalize to lowercase before binding and dispatch; resource identity comparisons ignore UUID letter case.
All three commands select a site through `--site`, the profile or unambiguous discovery.

Execution requires `writes.allowWrites: true` and exact vendor grants in `writes.operations`: `createNetwork` plus `createNetwork:<management>` for creation, `updateNetwork` plus `updateNetwork:<management>` for update, or `deleteNetwork` for deletion.
Legacy `OP-049`/`OP-050` entries are readable profile syntax but do not authorize execution.
`UNIFI_AXI_READ_ONLY=true` or `1` overrides all grants.
Repeat the previewed command with `--execute --confirm <confirmation> --request-id <stable-id>`.
Confirmation binds the complete normalized method, resolved path, query defaults, body, target set, selected resource state, origin, profile/config identity, credential reference and value hash, application version, contract hash, TLS leaf and connection route.
Secret values are hashed internally and redacted from output.
Identity, body input, grants and selected state are reread before dispatch, and changed bindings fail closed.
Every write-related read, including site discovery, selected-state checks and recovery, enforces the TLS leaf and connection address captured by its initial application read before sending credentials.
The vendor provides no atomic conditional write, so concurrent changes can still occur after that final read.

Linux stores owner-only request claims under `$XDG_STATE_HOME/unifi-axi/writes.log/`, or the runtime home under `.local/state/unifi-axi/writes.log/`.
`UNIFI_AXI_WRITE_LOG` selects an absolute private journal directory.
Each configuration/profile namespace owns its request IDs durably.
The journal contains hashes, audit IDs, resource IDs and outcomes, never request bodies or keys.
An exclusive claim and synced intent precede dispatch; a synced `unknown` record precedes any possible send.
Mutations are never retried by transport.
Reusing an owned ID runs the read-only reconciliation described below and reports the reconciled outcome without resending the mutation; changing its request or identity fails.
Empty, truncated or corrupt claims fail closed and never expire into retry permission.

`write show --request-id <id>` reports the stored intent for the selected identity.
`write reconcile --request-id <id>` uses documented reads and records a separate observation without replacing ownership.
A verified acknowledgement plus its exact returned ID can establish the created resource through a subsequent read.
A lost acknowledgement stays `unknown`; finding a similar network cannot prove that creation succeeded.
An independently read absent deletion target returns `no-op` without sending a mutation.
Receipts distinguish `not-sent`, `unknown`, `accepted`, `verified` and `no-op`, with an audit ID for recovery.
Keep the same profile/configuration and journal location across invocations.
Native Windows writes remain gated until directory durability is proven.
The Artium read fixture has no cross-invocation write custody, so hosted mutations remain denied before vendor access.

## Credentials and transport

Use `config path` to find configuration and `profile list` to list its profiles.
Choose configuration with `--config`, then `UNIFI_AXI_CONFIG`, then the platform default.
Linux uses an absolute `XDG_CONFIG_HOME` or the runtime home directory under `.config/unifi-axi/config.json`.
Windows uses `APPDATA\unifi-axi\config.json` and protected ACLs.
Profiles are selected by `--profile`, `UNIFI_AXI_PROFILE`, complete environment profile, default profile, then sole profile.
An explicit file profile ignores competing environment profile fields.
A partial environment profile fails with `CONFIG_INVALID`.

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

`apiKey` accepts exactly one environment or absolute local file reference.
Omitting `apiKey` defaults to the `UNIFI_AXI_API_KEY` environment reference.
An environment profile requires `UNIFI_AXI_ORIGIN` and `UNIFI_AXI_API_KEY`; optional fields are `UNIFI_AXI_SITE_ID`, `UNIFI_AXI_API_CONTRACT`, `UNIFI_AXI_TLS` and `UNIFI_AXI_WRITES`.
The last two contain strict JSON objects.
`UNIFI_AXI_READ_ONLY` accepts only `1`, `0`, `true` or `false`, case-insensitively.
See [Network write foundation](#network-write-foundation) for execution grants and journal custody.
Inline secret values and secret flags are refused.
File keys lose a leading BOM and trailing whitespace.
Linux checks ownership and permissions before reading; secret files require owner-only permissions and configs cannot be group- or world-writable.
Windows refuses UNC/device secret references and reparse points.
On Windows, every config, configure-input and secret-file read verifies current-user ownership and a protected ACL with explicit FullControl grants only to the current user, SYSTEM and Administrators, requiring all three.
Unsafe files fail with `CONFIG_INSECURE` before any authenticated HTTP request.
No credential store or token cache is created.

To configure a profile, put one profile object containing references in a protected JSON file, then run:

```text
unifi-axi profile configure --profile lab --file /absolute/path/profile.json
unifi-axi auth status --profile lab
```

The config writer uses exclusive private temporary files, fsync and same-directory rename.
Windows writes restrict ACLs to the current user, SYSTEM and Administrators and retry transient rename failures for about one second.
Unknown top-level and nested fields are refused.

Default TLS uses system trust and hostname verification.
An appliance profile may specify `tls.trustedCertificatePem` and `tls.peerFingerprintSha256` together, plus an optional IP `tls.connectAddress`.
The fingerprint is 64 hexadecimal characters for the exact public certificate.
Private key PEM, mismatched fingerprints and unknown TLS options are refused.
The route changes only the TCP destination; the origin remains the TLS name and HTTP Host.
Chain, validity, hostname and peer pin checks finish before any authenticated HTTP request.
There is no TLS bypass flag.
Each API request has a ten-second deadline across queueing, TLS establishment, retries and HTTP response consumption.
At most two reads run concurrently per process.
Reads retry transport failures and HTTP 502/503/504 at most twice with a 100 ms delay, within that same deadline.
Before TLS completes, transient connection failures (`ECONNRESET`, `ECONNREFUSED`, `ETIMEDOUT`, `EPIPE` and socket hang-up) are eligible for those retries.
Certificate chain, validity, hostname and peer pin rejections fail with `TLS_REJECTED` without retrying or sending an authenticated request.
HTTP 401 is never retried.
Reads receiving HTTP 429 retry only with an exact Retry-After delta of 0, 1 or 2 seconds that fits the remaining deadline.
Redirects are refused without sending credentials to the destination.
Each API response is bounded to one MiB and sensitive fields and raw, JSON-escaped and URL-encoded key forms are redacted.
Response byte-budget failures return `READ_INCOMPLETE`; request deadline failures return `TIMEOUT`, which paginated list enumeration converts to `READ_INCOMPLETE` with progress guidance.

The catalogue covers the captured 10.6.109 and 11.0.97 contracts.
WAN, VPN and RADIUS changes, UniFi OS backup/restore, firmware upgrades and administrator management are absent from those contracts.
SSH and undocumented endpoints are excluded.

For metadata consumers, the package exports `./catalogue`, `./capabilities`, `./skill` and `./credential-schema`.
The command mapping in `src/commands.json` owns command names and their official operation IDs.
The catalogue derives effects and both versions' parameter, request and response contracts from the [retained OpenAPI sources](evidence/README.md).
The build generates capability metadata and static skill guidance from it.
The credential schema ships as `dist/axi-credential.schema.json` with `apiKey` marked `x-secret`.

## Versioned validation

The validation compiler checks the retained source hashes and compiles each version independently without changing its source.
It supports the validation keywords present in those contracts and rejects unsupported keywords.
Discriminator dispatch follows the recorded interpretation in [the normalization ledger](src/normalization-ledger.json).
Required fields and additional-property rules retain their recorded meaning.
Nullability follows the source schema except at the exact request and response fields approved in the normalization ledger.
UUID, date, date-time, int32 and int64 formats are checked; other OpenAPI formats remain annotations.

[The conflict registry](src/contract-conflicts.json) owns the structural and description-versus-null conflicts, including their versions, pointers, source hashes, assigned operations and contract cases.
The contract runner reports these diagnostics without claiming that blocked public operation cases passed.
Unresolved structural conflicts block operations whose response schemas reach the conflicting field, with the retained device-family exception described in [Inventory, clients, networks and references](#inventory-clients-networks-and-references).
Application and site validation remain available.
The normalization ledger owns the reviewed PoE and Wi-Fi radio-rate enum resolutions and request/response NORM-001 rules, their version scopes and expectations, and the required fields for future resolutions.

## Development and verification

Use Node 24.14.0 and pnpm 10.34.6, pinned in this checkout.
The package engine floor is Node 24.11.0, matching the approved integration baseline.
TypeScript 5.9.3 and TOON 2.3.1 follow the inspected foundation precedent.
ESLint 9.39.1, typescript-eslint 8.46.3 and Node types 24.10.0 are exact build pins; pnpm-lock.yaml fixes the transitive graph.
There are no install hooks, telemetry or vendor connections.
The release workflow uses pnpm to install dependencies and run `pnpm check` before publishing a tagged release through npm OIDC trusted publishing.
Configure the npm trusted publisher for `knowttl/unifi-axi` and `.github/workflows/release-please.yml` before releasing.

```text
pnpm install --frozen-lockfile
pnpm check
pnpm verify:packaged -- --task B1.1
pnpm verify:packaged -- --task B1.2
pnpm verify:packaged -- --task B1.2a
pnpm verify:packaged -- --task B2.0
pnpm verify:contracts -- --task B2.1
```

`pnpm check` runs strict types, lint, all implemented packaged obligations, versioned contract checks and direct private-file, paging and transport tests.
The opt-in Artium proof runs separately with `pnpm verify:artium`, extending B1.3 read coverage with B3.3 write-admission denials and reporting task `B3.3`.
The configured no-mistakes test command also runs it when `UNIFI_AXI_ARTIUM_HOST` and `UNIFI_AXI_ARTIUM_OUTPUT` select a frozen exported fixture and an external evidence directory.
That command prints an explicit skip reason when no Artium host fixture is selected.
The packaged selector builds and packs the distribution, installs it into a clean temporary prefix and invokes the installed public executable in a temporary user environment.
Packaged verification installs dependencies offline and requires a pre-seeded pnpm store.
It compares command outcomes with an independent manifest-derived expectation fixture and validates exported metadata against both retained official contracts.
Offline discovery and credential commands run with a fail-closed network attempt recorder; transport checks use a local fake HTTPS controller.
Domain code, command parsing and execution stay real.
The guard is proven with a deliberately attempted loopback connection before checking for zero attempts.
Version measurements compare eleven paired samples per alias against the same host's bare Node median, with a relative two-times budget and no fixed millisecond threshold.
The verifier emits package integrity, source/input hashes, runtime, platform, timings and task/operation result rows.
Temporary installation and user state are removed even on failure.

`--task B1.1`, `--task B1.2`, `--task B1.2a`, `--task B2.0`, B2.2 through B2.10, B3.1 through B3.3 and B4.0/B4.1 selectors, plus the default implemented suite, are supported now.
The B4 selectors add protected response exports; B4.1 also exercises all network management variants with nested DHCP, IPv6 and NAT fields, exact replacements, force binding and lost-acknowledgement recovery.
The B3 selectors add normalized write previews, exact grants, fake target mutations, concurrent ownership, persistence/dispatch crash points and read-only recovery through the installed executable.
B3 processes run under an outbound network deny allowing only their synthetic vendor listener.
Hosted journeys remain opt-in and emit an explicit skip reason when no frozen fixture is configured.
The B2.2-B2.9 selectors run the combined read journey against the installed package, including filtered paging, exact targets, field-path failures, network variants, policy ordering, ACL/DNS/traffic variants, voucher and Wi-Fi redaction, switching structures and the documented contract gates.
The B2.10 selector also covers bounded home output, redacted full text and directory-scoped integration preview, confirmation, installation and repeat setup.
The B2.0 journey adds installed-executable paging, retry, redirect, body-budget and deadline checks plus direct transport concurrency checks against the same synthetic TLS service.
`verify:contracts` separately exercises schema roots, enum versions, required fields, nullable conflicts and added fields against independently selected synthetic contract fixtures.
The B1.2a journey reuses the credential suite's synthetic TLS setup and drives installed info, doctor, site list and home against independently seeded HTTPS responses.
Unknown, future, empty and duplicate selectors fail rather than skip.
Future stage tasks remain unimplemented; a B1.1 pass does not complete B1.
Run the same selector on native Windows for separate Windows evidence.
Linux results cannot establish Windows behavior.
Native Windows ACL and install evidence remain PENDING on Linux/WSL; injected Windows branch tests are supplementary only.
TLS tests generate temporary synthetic CAs, certificates and keys with OpenSSL, exercise accepted and rejected peers, and count HTTP requests at the fake controller.
No private keys are committed or retained.
See [retained evidence](evidence/README.md) for original paths and manifest hashes.

The Artium Linux proof requires a separate, built fixture descended from revision `3cfc65afc2d7c1a0f50d2f6e02dc2ee13d6fd7e8`, with the reviewed B1.3 delta and current package installed.
The installed package's runtime assets must match this checkout's current `dist` build.
Both paths must be absolute; the output directory must already exist outside this repository and must not contain a `scratch` entry.
It never edits the shared fixture checkout or connects to a controller.

```text
pnpm verify:artium --host /absolute/task-owned/artium --output /absolute/external/evidence
```

The real host CLI talks to the real loopback server, parser, shared v2 profile writer and runner.
Only task-owned loopback vendor and host ports are reachable through the Node socket guard in the host, client and packaged child.
The proof checks typed info/sites and the combined read journey described above for both retained versions, competing developer profiles, admission failures before vendor access, read journal classification, cancellation, deadlines, output bounds and private input cleanup.
The fixture-only input consumer is host evidence and adds no command to the UniFi package.
The host's shorter deadline remains distinct from the package request deadline described in [Credentials and transport](#credentials-and-transport).
The verifier writes provenance, package integrity, effective limits and native platform results to `artium-proof.json` outside this repository, and removes synthetic TLS keys and scratch state.
This harness currently uses the native Linux process observer and POSIX host runner.
Native Windows execution remains PENDING and is a blocking host compatibility gate; WSL or these Linux results cannot pass it.
