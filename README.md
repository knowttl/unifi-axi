# unifi-axi

An agent-facing CLI catalogue for the official UniFi Network Integration API.
Package: `@knowttl/unifi-axi`.

B1.1 implements offline discovery, help, fast version and unconfigured status.
All 73 vendor operations are discoverable and explicitly `not-implemented`.
Invoking one exits 1 with `NOT_IMPLEMENTED` before network access.
This build performs no router reads or writes.
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
Unconfigured `auth status` examines environment presence only and does not read stored profiles or resolve secrets.
Configured credential handling, transport, profile editing, live home data and session setup belong to later tasks.

The catalogue covers the captured 10.6.109 and 11.0.97 contracts.
WAN, VPN and RADIUS changes, UniFi OS backup/restore, firmware upgrades and administrator management are absent from those contracts.
SSH and undocumented endpoints are excluded.

For future metadata consumers, the package exports `./catalogue`, `./capabilities` and `./skill`.
The command mapping in `src/commands.json` owns command names and their official operation IDs.
The catalogue derives effects and both versions' parameter, request and response contracts from the [retained OpenAPI sources](evidence/README.md).
The build generates capability metadata and static skill guidance from it.
The credential schema will ship with the protected credential implementation in B1.2.

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
```

`pnpm check` runs strict types, lint and all implemented packaged obligations.
The packaged selector builds and packs the distribution, installs it offline into a clean temporary prefix and invokes the installed public executable in a temporary user environment.
It compares command outcomes with an independent manifest-derived expectation fixture and validates exported metadata against both retained official contracts.
Only the external network boundary is replaced with a fail-closed attempt recorder; domain code, command parsing and execution stay real.
The guard is proven with a deliberately attempted loopback connection before checking for zero attempts.
Version measurements compare eleven paired samples per alias against the same host's bare Node median, with a relative two-times budget and no fixed millisecond threshold.
The verifier emits package integrity, source/input hashes, runtime, platform, timings and task/operation result rows.
Temporary installation and user state are removed even on failure.

Only `--task B1.1` and the default implemented suite are supported now.
Unknown, future, empty and duplicate selectors fail rather than skip.
Future stage tasks remain unimplemented; a B1.1 pass does not complete B1.
Run the same selector on native Windows for separate Windows evidence.
Linux results cannot establish Windows behavior.
See [retained evidence](evidence/README.md) for original paths and manifest hashes.
