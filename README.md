# Samaritan

A user-controlled network firewall for iOS.

Samaritan is built on the NetworkExtension **content filter** APIs — `NEFilterManager`,
`NEFilterDataProvider`, `NEFilterControlProvider` — rather than `NEPacketTunnelProvider`. That
choice is the point of the project: a content filter sees every flow with the originating app's
identity attached, and it coexists with a real VPN, which a packet tunnel cannot.

Every connection an app opens is decided against your rules before it leaves the device. The
default is deny; everything you allow is an exception you added.

> **This runs on your own phone, from your own development build.** Apple supports content filters
> only on supervised or managed devices, or under a child Screen Time account. A development-signed
> build configures the filter on an ordinary unsupervised iPhone — that works today and is what this
> project targets, but Apple has never documented it as a guarantee. There is no App Store path.

---

## What it does

- **Per-app rules.** Allow and deny lists per app, holding domains (exact, or `*.` suffix) and
  addresses (literal or CIDR). Most specific match wins; deny wins a tie.
- **Global lists.** Hand-edited allow/deny lists that apply across every app.
- **Subscriptions.** Remote blocklists fetched by URL, in one-entry-per-line or hosts-file format,
  refreshed on an interval. A failed refresh keeps the last good copy rather than failing open.
- **Blanket per-app default.** *Deny all* (the default) or *Allow all*, consulted last, so any list
  above still overrides it. Apple system apps ship with *Allow all* pre-enabled — a writable
  toggle, not a hardcoded exemption.
- **Bypass.** Exempts an app from Samaritan entirely: the first statement in the hot path, before
  anything is parsed, recorded or counted. Not "allow after processing" — the app becomes invisible
  to the filter and the filter to it.
- **Observed list.** Per app, the destinations it tried to reach that no rule decided and that were
  therefore dropped, coalesced by hostname with first/last seen, attempt count and ports. This is
  how you turn a freshly denied app into a working one.
- **Traffic and flows.** Per-app received/sent byte counters, a recent-flows view, and a
  diagnostics screen fed by the extensions.

## How a flow is decided

```
INPUT  flow { app, hostname?, address?, port, proto }

  ├─ L0  BYPASS ................... terminal, before anything else
  │      allow immediately; nothing is parsed, recorded, counted or logged
  │
  ├─     NORMALISE ................ app → (teamID, bundleID); host → lowercase, punycode;
  │                                 discard :: and 0.0.0.0 as "no address"
  │
  ├─ L1  PER-APP RULES ............ this app's allow/deny lists
  ├─ L2  GLOBAL USER LISTS ........ hand-edited, on device
  ├─ L3  GLOBAL WEB LISTS ......... subscribed, read-only
  │      (each terminal if matched; most specific wins, deny wins a tie)
  │
  └─ L4  APP BLANKET DEFAULT ...... Allow all → allow
                                    otherwise → deny, and record in the Observed list
```

The full model — rule syntax, tie-breaking, worked examples, and the reasoning behind the order —
is in [`docs/firewall-rules.md`](docs/firewall-rules.md).

## Architecture

Three processes, sharing an App Group container. There is no invented IPC: the only channels are
files in the shared container and the `.needRules()` round trip Apple provides.

```
┌──────────────────────────────┐
│ Samaritan (container app)    │  NEFilterManager: create/enable the configuration
│  · rules, lists, UI          │  compiles policy.bin + bypass.json; fetches subscriptions
└───────────┬──────────────────┘
            │  App Group container   (policy.bin, bypass.json, flows-*.ring)
            │
┌───────────┴──────────────────┐        .needRules()         ┌──────────────────────────────┐
│ FilterData.appex             │ ─────────────────────────►  │ FilterControl.appex          │
│  NEFilterDataProvider        │                             │  NEFilterControlProvider     │
│  · handleNewFlow → verdict   │ ◄─────────────────────────  │  · records escalated flows   │
│  · HOT PATH, read-only       │   handleRulesChanged()      │  · can write; data cannot    │
└──────────────────────────────┘                             └──────────────────────────────┘
```

The data provider can write nothing, anywhere, so the compiled policy is `mmap`ed read-only and
must arrive complete and self-describing. Diagnostics travel the other way through fixed-width
ring-buffer files — one writer each, bounded size, readable before first unlock.

`Shared/Core` is pure Swift with no `NetworkExtension` import; the test target compiles it
standalone, which keeps that boundary honest. `Shared/Policy` holds the compiler, the flat index
and the resolver. `Shared/Filtering` is where NE-specific code lives.

## Requirements

- iOS 18.0 or later, on a **physical device** — a content filter does nothing in the simulator
- Xcode with Swift 6 (strict concurrency is on)
- A **paid** Apple Developer Program membership, for the Network Extensions capability
- [XcodeGen](https://github.com/yonaskolb/XcodeGen)

## Build

```sh
brew install xcodegen
$EDITOR Config/Signing.xcconfig     # set DEVELOPMENT_TEAM and PRODUCT_BUNDLE_PREFIX
xcodegen generate
open Samaritan.xcodeproj
```

Build the `Samaritan` scheme onto the device. Automatic signing registers the three App IDs and the
App Group on its own.

`Samaritan.xcodeproj` is generated output and is `.gitignore`d. `project.yml` is the source of
truth — **never** edit `project.pbxproj`, and do not fix signing through Xcode's UI, since both are
written into the disposable project. See [`AGENTS.md`](AGENTS.md).

Unit tests cover the pure Swift logic and run on the simulator:

```sh
xcodebuild -project Samaritan.xcodeproj -scheme Samaritan \
  -destination 'platform=iOS Simulator,name=iPhone 17' test
```

## First run

1. Trust the development certificate: **Settings → General → VPN & Device Management**.
2. Launch Samaritan and toggle **Enabled**. iOS asks *"Samaritan Would Like to Filter Network
   Content"*. Allow it.
3. The filter appears under **Settings → General → VPN & Device Management → Filter**.

If `saveToPreferences()` fails with `NEFilterManagerError.configurationPermissionDenied` (code 5),
the device is refusing to let a non-managed app configure a filter; the app surfaces that error with
an explanation inline.

The extensions run as separate processes, so **Xcode's console will not show them**. Use Console.app
with the device selected and filter on `SUBSYSTEM app.samaritan`, or `idevicesyslog -u <UDID>`.

## Limitations worth knowing

These are properties of the platform, not of the implementation:

- **Every flow is decided synchronously, in Swift.** iOS has no `NEFilterSettings` equivalent to
  offload matching to the system, and the verdict is final. One hostname can produce eight flows in
  45 ms, so the resolver is built around that budget.
- **App identity is `<teamID>.<bundleID>` and nothing more.** There is no audit token, so no
  code-signature validation. One app can appear under several identifiers — extensions and helpers
  have their own, and a flow a system framework makes on an app's behalf carries an empty team.
- **Domains are a first-class matcher, not a fallback.** Many flows arrive with no usable address
  and only a hostname. Conversely, LAN and link-local flows arrive with no hostname at all.
- **The data provider has no network access and cannot persist anything.** Subscriptions are
  fetched by the container app; anything the providers learn travels back through the ring files or
  `OSLog`.
- **Escalating a flow to the control provider costs ~1.4 ms warm and up to ~28 ms cold.** That is
  fine for a flow being denied anyway, and too slow to decide one that might be allowed.

## Documentation

- [`docs/firewall-rules.md`](docs/firewall-rules.md) — the rule model, resolver and UI spec
- [`AGENTS.md`](AGENTS.md) — invariants anyone editing this code has to preserve

## References

- Apple, [TN3134: Network Extension provider deployment][tn3134]
- Apple, [WWDC25 session 234 — Filter and tunnel network traffic with NetworkExtension](https://developer.apple.com/videos/play/wwdc2025/234/)
- [agrinman/sift-ios](https://github.com/agrinman/sift-ios) — the 2018 reference implementation

[tn3134]: https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment
