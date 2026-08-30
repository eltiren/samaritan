# AGENTS.md — Samaritan

## Rule 0: NEVER touch `project.pbxproj`

**`project.yml` is the single source of truth for the Xcode project.**

- `Samaritan.xcodeproj` is **generated output**. It is disposable, `.gitignore`d, and MUST NOT be committed.
- **Do NOT create, edit, patch, or hand-merge `project.pbxproj`.** Ever.
- **Do NOT use `xcodeproj`/`ruby` scripts, `pbxproj` CLI tools, or `sed` on the project file.**
- To add a file, target, build setting, entitlement, capability, or dependency:
  1. Edit `project.yml` (and/or the relevant `*.entitlements` / `Info.plist` / `Config/*.xcconfig`).
  2. Run `xcodegen generate`.
- If a change "only works" by editing the pbxproj, it is wrong. Fix `project.yml` instead.
- Files added under an existing source directory are picked up automatically by the directory-based
  `sources:` entries in `project.yml` — regenerate, don't edit.

Regenerate at any time; nothing of value lives in the `.xcodeproj`:

```sh
rm -rf Samaritan.xcodeproj && xcodegen generate
```

## Rule 1: signing lives in `Config/Signing.xcconfig`

Team ID and bundle-ID prefix are set in `Config/Signing.xcconfig`, not in Xcode's UI (the UI writes
to the disposable pbxproj). If Xcode shows a signing error, fix the xcconfig and regenerate.

## Rule 2: three targets, one App Group

| Target          | Bundle ID                              | Role                                   |
|-----------------|----------------------------------------|----------------------------------------|
| `Samaritan`     | `$(PRODUCT_BUNDLE_PREFIX)`             | SwiftUI container app + `NEFilterManager` |
| `FilterData`    | `$(PRODUCT_BUNDLE_PREFIX).FilterData`  | `NEFilterDataProvider` (hot path)      |
| `FilterControl` | `$(PRODUCT_BUNDLE_PREFIX).FilterControl` | `NEFilterControlProvider` (`.needRules()`) |

All three share `group.$(PRODUCT_BUNDLE_PREFIX)`. The App Group ID is injected into each target's
`Info.plist` as `SamaritanAppGroupIdentifier` — read it via `SharedContainer.appGroupIdentifier`,
never hard-code it in Swift.

## Rule 3: respect the extension sandbox

`FilterData` runs in a tight, memory-limited, long-lived sandbox.

- Allowed and used here: `OSLog`, App Group container file I/O (`pread`/`pwrite`), `NWPathMonitor`.
- **Not** available on iOS: `applySettings(_:)` / `NEFilterSettings` / `NENetworkRule`, `pauseVerdict`,
  `resumeFlow`, `updateFlow`, `sourceAppAuditToken` — all macOS-only (verified against the iOS 26.5 SDK
  headers). Do not write code that assumes them.
- Do **not** invent IPC. The only supported app↔extension channels are the App Group container and
  `NEFilterControlProvider` via `.needRules()`.
- `UNUserNotificationCenter` works from `FilterControl`, not from `FilterData`.

## Rule 3b: the scheme lists ONLY the app target

`schemes.Samaritan.build.targets` must contain `Samaritan` alone. XcodeGen sorts a scheme's build
targets alphabetically and treats the first as the scheme's runnable, so adding `FilterData` /
`FilterControl` there makes `FilterControl` win — producing `wasCreatedForAppExtension = "YES"` and
a scheme whose Run action launches an `.appex` instead of the app.

The extensions are `dependencies:` of the app with `embed: true`, so `buildImplicitDependencies`
builds and embeds both. After changing schemes, verify:

```sh
grep -c wasCreatedForAppExtension Samaritan.xcodeproj/xcshareddata/xcschemes/Samaritan.xcscheme  # 0
```

Xcode may still auto-create *user* schemes for the two extension targets (they land in
`xcuserdata/`, not in git). Ignore them and select the shared `Samaritan` scheme.

## Rule 3c: the first statement of `handleNewFlow` is the bypass check

`FilterDataProvider.handleNewFlow` begins with an L0 bypass test and an early `return .allow()`.
Nothing may be inserted above it, and nothing that runs below it may be moved above it.

"Bypass" means the app is invisible to Samaritan — not "allowed after processing". A bypassed flow
must produce no `FlowRecord`, no ring append, no Observed entry, no counter, no log line, no
configuration reload and no sandbox probe. A timing measurement or a "just one counter" added above
the return is a behaviour change, not an instrumentation change.

The test reads `BypassGate` without taking `lock`, by design: it is one atomic pointer load and one
`Set` membership test. Do not add a lock, a `stat`, an allocation or an `await` to that path.

Entries are raw `sourceAppIdentifier` strings (`<teamID>.<bundleID>`), never bundle IDs. Normalising
them would make every stored bypass stop matching, silently. See `docs/firewall-rules.md` §1.3 and
§2.0.

## Rule 4: this is a spike

Milestone 1 proves NetworkExtension behaves on a real device. Do not build the CIDR/policy engine,
feed downloader, or per-app policy UI until `README.md`'s "On-device results" table is filled in.
