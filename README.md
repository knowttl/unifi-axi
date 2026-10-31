# unifi-axi

An agent-facing CLI for the official UniFi Network Integration API.
Package: `@knowttl/unifi-axi`.

B1.2a adds application version validation, site discovery, doctor and a configured live home to the protected profiles and verified HTTPS transport from B1.2.
All 73 vendor operations are discoverable.
`info` and `site list` are implemented with the minimal application and site schemas shared by the two retained contracts.
The other 71 vendor operations exit 1 with `NOT_IMPLEMENTED` before network access.
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
Unknown commands, unknown flags, duplicate flags and invalid scalar values exit 2.
Bare `-v`, `-V` and `--version` print the package version before loading the catalogue.
Without a profile the home view exits 1 with `PROFILE_REQUIRED` and setup guidance.
`auth status` resolves protected references offline and reports only profile, origin and source.
No profiles, an absent named profile, ambiguous selection and an unavailable key produce distinct `PROFILE_REQUIRED`, `PROFILE_NOT_FOUND`, `PROFILE_AMBIGUOUS` and `AUTH_REQUIRED` errors.
With a configured profile, the home view reads application information and a bounded site list.
`doctor` resolves protected credentials, verifies TLS and reads application information only.
Session setup belongs to a later task.

## Application and sites

Every implemented live command bootstraps from the actual Network `applicationVersion`, separately from any Site Manager label.
Output identifies the actual application version, selected contract, verification status and unavailable writes.
Known versions 10.6.109 and 11.0.97 select their matching contract, regardless of a profile override.
An unknown version returns `UNVERIFIED_API_VERSION` after the info read.
A profile `apiContract` of 10.6.109 or 11.0.97 permits read-only investigation while output remains visibly `unverified` and retains the actual version.
All writes remain unavailable, including profiles with write permissions enabled.

`site list` enumerates pages and reports exact site UUIDs, internal references, names, returned `count`, `totalCount`, starting `offset` and `complete`.
It accepts the official `--offset`, `--limit` and `--filter` query flags.
The default limit is 25 per request; `--limit 0` reads metadata only and reports incomplete when rows remain.
Enumeration still unfinished after 100 pages fails with `READ_INCOMPLETE`; malformed or inconsistent pages fail with `RESPONSE_INVALID`.
An empty result at or beyond `totalCount` reports `count: 0` and `complete: true`, preserving the requested `offset` and upstream `totalCount`.

Select a site with `--site <site-id>`, then the profile's `siteId`, then the sole discovered site.
Site discovery works without selection; without an explicit or profile selection, home reports `SITE_AMBIGUOUS` for multiple sites and `SITE_REQUIRED` when no sites exist.
An explicit selection survives contextual hints along with the selected file profile and explicit configuration path.
This stage sends no site-specific request.

```text
unifi-axi doctor --profile lab
unifi-axi site list --profile lab
unifi-axi --profile lab --site <site-id>
```

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
Write execution and `UNIFI_AXI_WRITE_LOG` custody arrive in later tasks; this version cannot mutate vendor state.
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
Each API response is bounded to one MiB and sensitive fields and raw, JSON-escaped and URL-encoded key forms are redacted.

The catalogue covers the captured 10.6.109 and 11.0.97 contracts.
WAN, VPN and RADIUS changes, UniFi OS backup/restore, firmware upgrades and administrator management are absent from those contracts.
SSH and undocumented endpoints are excluded.

For metadata consumers, the package exports `./catalogue`, `./capabilities`, `./skill` and `./credential-schema`.
The command mapping in `src/commands.json` owns command names and their official operation IDs.
The catalogue derives effects and both versions' parameter, request and response contracts from the [retained OpenAPI sources](evidence/README.md).
The build generates capability metadata and static skill guidance from it.
The credential schema ships as `dist/axi-credential.schema.json` with `apiKey` marked `x-secret`.

## Development and verification

Use Node 24.14.0 and pnpm 10.34.6, pinned in this checkout.
The package engine floor is Node 24.11.0, matching the approved integration baseline.
TypeScript 5.9.3 and TOON 2.3.1 follow the inspected foundation precedent.
ESLint 9.39.1, typescript-eslint 8.46.3 and Node types 24.10.0 are exact build pins; pnpm-lock.yaml fixes the transitive graph.
There are no install hooks, hosted CI, telemetry or vendor connections.

```text
pnpm install --frozen-lockfile
pnpm check
pnpm verify:packaged -- --task B1.1
pnpm verify:packaged -- --task B1.2
pnpm verify:packaged -- --task B1.2a
```

`pnpm check` runs strict types, lint and all implemented packaged obligations.
The packaged selector builds and packs the distribution, installs it offline into a clean temporary prefix and invokes the installed public executable in a temporary user environment.
It compares command outcomes with an independent manifest-derived expectation fixture and validates exported metadata against both retained official contracts.
Offline discovery and credential commands run with a fail-closed network attempt recorder; transport checks use a local fake HTTPS controller.
Domain code, command parsing and execution stay real.
The guard is proven with a deliberately attempted loopback connection before checking for zero attempts.
Version measurements compare eleven paired samples per alias against the same host's bare Node median, with a relative two-times budget and no fixed millisecond threshold.
The verifier emits package integrity, source/input hashes, runtime, platform, timings and task/operation result rows.
Temporary installation and user state are removed even on failure.

`--task B1.1`, `--task B1.2`, `--task B1.2a` and the default implemented suite are supported now.
The B1.2a journey reuses the credential suite's synthetic TLS setup and drives installed info, doctor, site list and home against independently seeded HTTPS responses.
Unknown, future, empty and duplicate selectors fail rather than skip.
Future stage tasks remain unimplemented; a B1.1 pass does not complete B1.
Run the same selector on native Windows for separate Windows evidence.
Linux results cannot establish Windows behavior.
Native Windows ACL and install evidence remain PENDING on Linux/WSL; injected Windows branch tests are supplementary only.
TLS tests generate temporary synthetic CAs, certificates and keys with OpenSSL, exercise accepted and rejected peers, and count HTTP requests at the fake controller.
No private keys are committed or retained.
See [retained evidence](evidence/README.md) for original paths and manifest hashes.
