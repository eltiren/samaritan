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

The rest of `handleNewFlow` takes `lock` exactly **once**, to read the rules and configuration
together. Keep it that way. A one-shot diagnostic guarded by a lock-protected `Bool` costs that
lock on every flow forever, long after the thing it was measuring has been answered — the sandbox
probe did this for two milestones. Put one-shot work in `startFilter`, per-flow diagnostics behind
a configuration flag read from the snapshot that lock already returns, and a bare word that only
needs the latest value in an `Atomic`.

Entries are raw `sourceAppIdentifier` strings (`<teamID>.<bundleID>`), never bundle IDs. Normalising
them would make every stored bypass stop matching, silently. See `docs/firewall-rules.md` §1.3 and
§2.0.

## Rule 3d: a new field on a persisted type needs a hand-written decoder

Swift's synthesised `Codable` **ignores property default values** and throws `keyNotFound`. Adding a
non-optional field to a type that is already written to disk therefore makes every existing file
undecodable — and every one of these stores swallows a decode failure and carries on with empty
state, so the symptom is not an error but silently erased user data.

Any field added to `AppPolicy`, `ObservedApp`, `SpikeConfiguration`, `BypassList` or anything else
that reaches the App Group container needs an explicit `init(from:)` using `decodeIfPresent`, plus a
test that decodes a document written before the field existed. Every type here that has grown a field
— `SpikeConfiguration`, `AppPolicy`, `ObservedApp` — needed one, and none of them failed loudly.

The mirror image applies to a file whose *shape* changes: `observed.json` gained an envelope, and its
`version` key is deliberately **required** on decode, because a wrapper of all-optional keys happily
decodes a legacy payload as an empty wrapper.

## Rule 4: platform claims are measured, not assumed

What iOS gives a content filter is thinly documented and differs from macOS in ways that are not
obvious from the headers. Every constraint this codebase is built around — that the data provider
cannot write, that a hostname is often the only usable matcher, that escalation is bimodal in
latency — came from running it on a device, and the comments say so where it matters.

So: do not add behaviour that depends on an unverified platform assumption. Measure it on hardware
first, then write the code the measurement justifies, and record the finding next to the code that
relies on it. `docs/firewall-rules.md` marks its claims **[STATED]** / **[DERIVED]** /
**[PROPOSED]** / **[DEVICE]** for the same reason — keep that up when you edit it.
