# Samaritan — milestone 1: NetworkExtension architecture spike

A user-controlled network policy firewall for iOS, built on the **content filter** APIs
(`NEFilterManager` / `NEFilterDataProvider` / `NEFilterControlProvider`) rather than
`NEPacketTunnelProvider`, so it can coexist with a real VPN.

**This repository is not the firewall.** It is the smallest thing that proves — or disproves — that
the architecture works on a current physical device, including while NordVPN is connected. The
policy engine, feed management and per-app rules are milestone 2 and are deliberately absent.

---

## Quick start

```sh
brew install xcodegen
$EDITOR Config/Signing.xcconfig     # set DEVELOPMENT_TEAM and PRODUCT_BUNDLE_PREFIX
xcodegen generate
open Samaritan.xcodeproj
```

Build the `Samaritan` scheme onto a physical device. `Samaritan.xcodeproj` is generated output and is
`.gitignore`d — **never** edit `project.pbxproj` (see [`AGENTS.md`](AGENTS.md)).

Unit tests (pure Swift logic only) run on the simulator:

```sh
xcodebuild -project Samaritan.xcodeproj -scheme Samaritan \
  -destination 'platform=iOS Simulator,name=iPhone 17' test
```

### Watching it work

The extension's log is the primary instrument. The in-app UI is a convenience.

**The Xcode console will not show you the extensions.** Xcode only attaches to the app process;
`FilterData.appex` and `FilterControl.appex` are separate processes launched by the system. Their
logs only appear via `log stream` in Terminal, or Console.app with the device selected.

**`log stream` cannot read a connected iOS device.** `--device` was removed, and `devicectl` has no
`console` subcommand. Two options that do work:

**Console.app** — select the device in the sidebar. Filter with `SUBSYSTEM app.samaritan`, or just
type a string such as `PROBE SUMMARY` in the search field to find a line regardless of scroll
position.

**`idevicesyslog`** (`brew install libimobiledevice`) — streams the device's `os_log`, Debug level
included:

```sh
UDID=$(idevice_id -l | head -1)

# All three Samaritan processes
idevicesyslog -u "$UDID" -p "FilterData|FilterControl|Samaritan" --no-colors

# Just the sandbox probe result
idevicesyslog -u "$UDID" -m "PROBE SUMMARY" --no-colors

# Just flow decisions
idevicesyslog -u "$UDID" -m "app=" --no-colors
```

It prints `process(library)[pid] <Level>: message` rather than subsystem/category, which is why
every Samaritan line carries its own `[APP]`/`[DATA]`/`[CTRL]` tag.

All three processes link the same `Shared` code, so startup output is nearly identical between
them. Two ways to tell them apart:

- Startup and path lines carry a `[APP]` / `[DATA]` / `[CTRL]` tag.
- The provider entry points log `★ DATA PROVIDER startFilter` and `★ CONTROL PROVIDER startFilter`.
  **Seeing `★ DATA PROVIDER startFilter` is the only proof the data provider actually launched** —
  ring-buffer and path lines alone are produced by the containing app on its own.

---

## Manual configuration you must do yourself

None of this can live in the repo.

### Apple Developer portal

Xcode's automatic signing handles all of this — verified on this machine: a signed device build
registered the two extension App IDs and the App Group without any portal visit. Listed here so you
know what to look for if it ever fails:

| Kind        | Identifier                                  |
|-------------|---------------------------------------------|
| App ID      | `<prefix>`                                  |
| App ID      | `<prefix>.FilterData`                       |
| App ID      | `<prefix>.FilterControl`                    |
| App Group   | `group.<prefix>`                            |

All three App IDs need **Network Extensions** and **App Groups** (associated with `group.<prefix>`).

The **Content Filter** provider type is covered by the standard Network Extensions capability on a
paid Apple Developer Program membership — there is no separate request form for it (unlike the new
iOS 26 URL Filter, which needs Oblivious HTTP relay approval for distribution builds).

Confirm what actually got signed before blaming the device:

```sh
codesign -d --entitlements - --xml \
  "$(ls -d ~/Library/Developer/Xcode/DerivedData/Samaritan-*/Build/Products/Debug-iphoneos/Samaritan.app)" \
  | plutil -convert xml1 -o - -
```

You want `content-filter-provider`, `group.<prefix>`, and — critically for the deployment question
below — **`get-task-allow` = `true`**.

### Xcode

Set `DEVELOPMENT_TEAM` and `PRODUCT_BUNDLE_PREFIX` in `Config/Signing.xcconfig`, then regenerate.
Do **not** fix signing through Xcode's UI — it writes into the disposable `.xcodeproj`.

### Device

1. Trust the development certificate: **Settings → General → VPN & Device Management**.
2. Launch Samaritan, toggle **Enabled**. iOS shows *"Samaritan Would Like to Filter Network
   Content"*. Allow it.
3. The filter then appears under **Settings → General → VPN & Device Management → Filter**, and
   also as a *Filter* entry alongside VPN configurations.
4. For clean results, turn off **iCloud Private Relay** (Settings → Apple Account → iCloud) while
   testing. It reroutes Safari traffic through a relay and will confound endpoint observations.

---

## Architecture

Three processes, two supported channels between them.

```
┌──────────────────────────────┐
│ Samaritan (container app)    │  NEFilterManager: create/enable the configuration
│  · FilterController          │  DiagnosticsModel: poll + display
└───────────┬──────────────────┘
            │  App Group container   (spike-config.json, flows-*.ring)
            │
┌───────────┴──────────────────┐        .needRules()         ┌──────────────────────────────┐
│ FilterData.appex             │ ─────────────────────────►  │ FilterControl.appex          │
│  NEFilterDataProvider        │                             │  NEFilterControlProvider     │
│  · handleNewFlow → verdict   │ ◄─────────────────────────  │  · handleNewFlow(completion) │
│  · HOT PATH                  │   handleRulesChanged()      │  · not on the hot path       │
└──────────────────────────────┘   (via updateRules: true)   └──────────────────────────────┘
```

`Shared/Core` is pure Swift with **no** `NetworkExtension` import — it is compiled standalone by the
test target, which keeps that boundary honest. `Shared/Filtering` is where NE- and Network-specific
code lives.

### Why a ring buffer and not Core Data / `UserDefaults`

Sift (2018) wrote Core Data and `AwesomeCache` files into the App Group from inside the providers.
That works, but it is a poor fit for a long-lived, memory-limited extension on the hot path.

`DiagnosticsStore` is a fixed-size, single-writer ring file per writing process:

- **Bounded** — the file never grows, so a filter running for days cannot fill the container.
- **No invented IPC** — plain `pread(2)`/`pwrite(2)` on a shared-container file, which is one of the
  two channels Apple actually supports.
- **No cross-process lock** — each process owns its own file (`flows-data.ring`,
  `flows-control.ring`), so there is exactly one writer; the reader validates leading/trailing
  sequence words to reject a torn slot.
- **Readable while locked** — created with `.completeUntilFirstUserAuthentication` protection,
  because a content filter runs long before the user first unlocks after a reboot.

Records are fixed-width 512-byte slots with a hand-rolled binary codec, so `handleNewFlow` performs
no serialisation allocations. (The remaining allocation on the hot path is `String` creation while
extracting flow metadata. That is fine for a spike and is a milestone-2 item, not a milestone-1 one.)

---

## Findings

Each claim is tagged:

- **[SDK]** — read directly out of the iOS 26.5 SDK headers in this Xcode. Not inferred.
- **[DOC]** — current Apple documentation, technote, or WWDC session.
- **[SIFT]** — behaviour inferred from the 2018 Sift project; may be stale.
- **[DEVICE]** — cannot be answered without running on hardware. See *Results* below.

### What the API gives you on iOS

| Property on `NEFilterFlow` / `NEFilterSocketFlow` | Availability | Notes |
|---|---|---|
| `sourceAppIdentifier` | iOS 11+ **[SDK]** | Bundle ID. iOS-only — `API_UNAVAILABLE(macos)`. |
| `sourceAppUniqueIdentifier` | iOS 11+ **[SDK]** | Opaque `Data`. |
| `sourceAppVersion` | iOS 11+ **[SDK]** | |
| `identifier` | iOS 13.1+ **[SDK]** | Stable `UUID`; joins a later `NEFilterReport` back to its flow. |
| `direction` | iOS 13+ **[SDK]** | |
| `remoteHostname` | iOS 14+ **[SDK]** | Frequently `nil`. **[DEVICE]** how often. |
| `remoteFlowEndpoint` / `localFlowEndpoint` | iOS 18+ **[SDK]** | Replace `remoteEndpoint`/`localEndpoint`, **deprecated in iOS 18**. Bridge into Swift as `Network.NWEndpoint`. |
| `socketFamily` / `socketType` / `socketProtocol` | iOS 9+ **[SDK]** | |
| `URL` | iOS 9+ **[SDK]** | Browser flows only in practice. |
| `sourceAppAuditToken` | **macOS only** **[SDK]** | Not available to us. |

**There is no byte count on the flow object.** Byte counts exist only on `NEFilterReport`
(`bytesInboundCount` / `bytesOutboundCount`, iOS 13+) **[SDK]**, which requires setting
`verdict.shouldReport = true`. `NEFilterReport.Event.statistics` and
`statisticsReportFrequency` are macOS-only **[SDK]** — on iOS the useful event is `.flowClosed`.

### What iOS does *not* have that macOS does — this shapes milestone 2

| API | Status |
|---|---|
| `applySettings(_:)`, `NEFilterSettings`, `NEFilterRule`, `NENetworkRule` | **macOS only** **[SDK]** |
| `NEFilterNewFlowVerdict.pauseVerdict`, `resumeFlow(_:with:)` | **macOS only** **[SDK]** |
| `updateFlow(_:using:for:)` | **macOS only** **[SDK]** |
| `NEFilterPacketProvider`, `filterPackets` | **macOS only** **[SDK]** |
| `NEFilterManager.grade` (firewall vs inspector) | **macOS only** **[SDK]** |
| `NEFilterProviderConfiguration.filterDataProviderBundleIdentifier` | **macOS only** **[SDK]** |

Three consequences:

1. **There is no kernel-side prefilter on iOS.** macOS lets you hand the system a rule set and only
   see the flows it cannot decide. iOS does not: *every* flow reaches `handleNewFlow(_:)` and must
   be decided in Swift, synchronously. The prefix-trie work in milestone 2 is therefore not an
   optimisation — it is the whole design constraint.
2. **A verdict is final.** No pause, no later revision. The lookup must complete inline.
3. **Nothing to point at.** iOS finds the providers by looking at the app extensions embedded in the
   container app's bundle. Embedding the two `.appex`es *is* the wiring.

### Deployment: can this run on my own unsupervised iPhone?

This is the single biggest risk in the project, so it is stated carefully.

**Documented policy** — [TN3134: Network Extension provider deployment][tn3134] **[DOC]** lists the
supported iOS content-filter deployments, and Apple DTS has stated that anything not listed there is
unsupported:

| Scenario | Requirement |
|---|---|
| Global content filter | **Supervised device**, configured by MDM profile |
| Per-app content filter (iOS 16+) | **Managed device**; targeted apps must be installed by MDM |
| Screen Time / Family Controls (iOS 15+) | Unmanaged, but **child account only** — the signed-in user must be an under-18 member of an iCloud family |

Apple DTS on unsupervised, unmanaged devices **[DOC]**:

> "TN3134 lists the supported deployment scenarios. Things that aren't listed there aren't
> supported." … "To be clear, the limitations on content filter are not an accidental omission but
> an expression of a privacy policy."

**The development-build carve-out** — the path this project targets — was **[DEVICE]**, and is now
confirmed on hardware (see *Results*): a development-signed build configures the filter fine on an
ordinary unsupervised iPhone. It remains undocumented by Apple, so treat it as an observation about
current iOS rather than a guarantee. Original framing: Apple's own framing is that the restriction bites *distribution* builds; a
development-signed build carrying `get-task-allow` is widely reported to be able to configure
`NEFilterManager` programmatically on an ordinary device, and DTS has described having done exactly
this while testing. Apple has not published this as a guarantee. **Treat it as unverified until you
have run step 1 of the experiment below.**

The failure signal is precise: `NEFilterManager.saveToPreferences()` fails with
`NEFilterManagerError.configurationPermissionDenied` (code 5) in the `NEFilterErrorDomain`. The app
surfaces that error with this explanation inline, so you do not have to decode it.

If it does turn out to be blocked, the remaining options in order of practicality are: enrol the
device in supervision via Apple Configurator (wipes the device); the Family Controls / Screen Time
route (child account only, so unsuitable for a personal daily driver); or fall back to
`NEPacketTunnelProvider` — which is explicitly ruled out for this project because it cannot coexist
with NordVPN and, per WWDC25 **[DOC]**, does not receive flow or app-level metadata anyway.

[tn3134]: https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment

### `.needRules()` and the control provider

**[SDK]** `NEFilterNewFlowVerdict.needRulesVerdict` and `NEFilterControlProvider` are **iOS-only**.
The intended flow **[SIFT]**:

1. `FilterDataProvider.handleNewFlow` returns `.needRules()`.
2. iOS launches (or wakes) `FilterControl.appex` — *a separate process* — and calls
   `handleNewFlow(_:completionHandler:)`.
3. The control provider returns `.allow(withUpdateRules:)` / `.drop(withUpdateRules:)`. **That
   verdict is applied to the flow directly; the data provider does not see the flow again.**
4. If `updateRules` was `true`, iOS calls `handleRulesChanged()` on the data provider. It carries no
   payload — the data provider must re-read state from the shared container.

Sift used this as its interactive-prompt channel: the control provider posted a
`UNUserNotificationCenter` notification asking the user to allow/deny, which the data provider
cannot do. That remains the honest use for it. It is **not** a fast path — it is a cross-process hop
per flow.

This spike sends **one `.needRules()` probe per distinct `sourceAppIdentifier`**, hard-capped at 32,
so the round trip and its metadata can be measured without risking wedged traffic on a personal
device. The control provider flips `updateRules: true` exactly once, so `handleRulesChanged()` can
be observed without a rules-change storm.

### Statistics — what is actually possible

Sift's history came from the *control* provider writing to the App Group, because in 2018 the report
API was thin. Today **[SDK]**:

| Wanted | Available? |
|---|---|
| Flows by originating app | Yes — `sourceAppIdentifier` on every flow |
| Blocked flows | Yes — we author the verdict |
| Destination IP | Yes — `remoteFlowEndpoint` |
| Destination hostname | Sometimes — `remoteHostname`, often `nil` **[DEVICE]** |
| Matched policy / list | Yes — ours |
| Timestamps | Yes |
| **Byte counts** | Yes, but only via `NEFilterReport` at `.flowClosed`, and only with `shouldReport = true` **[DEVICE]** whether iOS delivers these reliably, and to which process |
| Country / list classification | Milestone 2 — derived from the IP, not from the API |

Both providers implement `handle(_ report:)` and tag their records with which process received it,
because *which* process iOS calls on current iOS is **[DEVICE]**.

---

## The experiment

### Step 1 — does the filter work at all?

1. Enable the filter in the app. Confirm **State: Enabled** and **Shared container: available**.
2. Generate traffic (open a few apps). Watch `Flows observed` climb and the flow list populate.
3. Tap **Run drop test**. Expected with the filter enabled:
   - `BLOCKED neverssl.com` → failure (`NSURLErrorNetworkConnectionLost` / `-1005`, or similar)
   - `control captive.apple.com` → `HTTP 200`
4. Disable the filter, tap **Run drop test** again — both should now succeed.

`neverssl.com` is the default block target because it is plain HTTP with no HSTS and no long-lived
connection reuse, which are the two things that most often make an iOS drop test look like a false
negative. If `remoteHostname` turns out to be `nil` for your traffic, put a literal IP in **Blocked
addresses** instead and repeat — the ring buffer records the address for every flow, so pick one you
have already observed.

Config changes are picked up by the data provider within ~2 seconds via a throttled `stat(2)`; there
is no need to toggle the filter.

### Step 2 — coexistence with NordVPN

Connect NordVPN (`NEPacketTunnelProvider`) and repeat. The **Network path** section shows the
`utun*` interfaces and their addresses; every flow record is stamped with the path state at the
moment of the verdict, so the answers survive in the log.

| # | Question | Where to read the answer |
|---|---|---|
| 1 | Does the content filter remain active while NordVPN is connected? | `Flows observed` keeps climbing; `Filter stops` does not increment |
| 2 | Does `handleNewFlow` keep receiving flows? | New rows keep appearing in the flow list |
| 3 | Does `sourceAppIdentifier` remain available? | `app=` on each row — `<no sourceAppIdentifier>` means it was `nil` |
| 4 | What does the remote endpoint contain? | `remote=` / `addr=` — an `<opaque>` value here is itself a finding |
| 5 | Original destination, or the tunnel endpoint? | Compare `addr=` against NordVPN's server IP, and `local=` against the `utun` address shown in **Network path**. `path=[…in-tunnel]` means the flow's local address belongs to the tunnel — i.e. the filter is seeing the flow **after** it entered the tunnel. Its absence, with a real destination in `addr=`, means the filter sits **above** the tunnel. |
| 6 | Can `.drop()` still block a flow? | **Run drop test** with the VPN connected |

Then use **⋯ → Copy diagnostics** to get a single pasteable block with counters, interfaces, probe
results and the last 150 flows.

**Known risk for question 6 [DOC]:** there is an open report ([FB18681313], macOS + Tailscale) of
`handleNewFlow` drop verdicts being ignored while a VPN is active, with
`No current verdict available, cannot report flow closed` in the log. It is unresolved and untested
on iOS. If step 2 shows drops working without a VPN and silently failing with one, that report is
the first thing to compare against — and it would be the finding that decides this project's
architecture.

[FB18681313]: https://developer.apple.com/forums/thread/791769

### Results — fill this in

Do not start milestone 2 until this table is complete.

| Question | Result | Notes |
|---|---|---|
| Dev build configures `NEFilterManager` on an unsupervised device | **✅ YES** | 2026-08-27, iOS 26, personal unsupervised iPhone, development-signed (`get-task-allow` = true). `saveToPreferences ok, enabled=true`; no `configurationPermissionDenied`. The TN3134 supervision requirement does not bite development builds. |
| Both provider processes launch | **✅ YES** | `FilterData` pid 29421, `FilterControl` pid 29422, started within 1 ms of each other on enable. |
| `handleNewFlow` receives flows | **✅ YES** | TCP flows from system apps arrived immediately. |
| `sourceAppIdentifier` populated | **✅ YES** — with a caveat | Format is **`<teamID>.<bundleID>`**. Third-party: `BQR82RBBHL.com.tinyspeck.chatlyio` (Slack). Apple's own apps have an empty team, so the value is `.com.apple.mobilecal` — leading dot included. Any policy matcher must split on the first `.`, not compare against a bundle ID. |
| `sourceAppVersion` populated | ⚠️ depends on the app | Real for third-party apps (`26.08.30` for Slack). For Apple's system apps it is the **OS** version (`26.6` for Safari) or `1.0`, sometimes empty. |
| `remoteHostname` populated | **✅ YES** | `outlook.office365.com` on every observed flow. Much better than expected — but all samples so far are system apps. |
| `remoteFlowEndpoint` / `localFlowEndpoint` | **✅ YES** | Real addresses: `40.101.112.72:443` remote, `192.168.0.65:57946` local (LAN address, pre-NAT). |
| `.needRules()` reaches the control provider | **✅ YES** | ~2.9 ms round trip (`14:45:01.169672` → `14:45:01.172559`). |
| `handleRulesChanged()` after `updateRules: true` | **✅ YES** | Fired 2 ms after the control verdict. Fires only for `true`, as documented. |
| `handle(_ report:)` fires | **✅ YES — in BOTH processes** | Data *and* control providers each receive every report, including for flows the control provider never handled. |
| Byte counts in reports | **✅ YES** | `event=flowClosed action=allow in=6263 out=5111`. Two reports per flow: an early one with `in=0 out=0`, then `flowClosed` with real totals. |
| `handleNewFlow` decision time | **170–450 µs** | Metadata extraction + rule match, with ring writes failing (so storage cost excluded). |
| UDP / QUIC flows delivered | **✅ YES** | Safari's HTTP/3 shows as `IPv4/UDP dir=2` to `www.google.com:443`. A TCP-only policy engine would miss most modern browser traffic. |
| Report delivery differs by process | **⚠️ asymmetric** | Control provider receives `event=1` (newFlow) *and* `event=3` (flowClosed); data provider was only seen receiving `flowClosed`. Same flow id (`B94F10F5`) across both. |
| App can read/write the App Group container | **✅ YES** | All probes OK: create, write, read, read-only opens of both rings, private container, `getifaddrs` 45 addrs / 24 on tunnels. |
| **Data provider can write the App Group container** | **❌ NO** | `open(flows-data.ring) failed: Operation not permitted` (EPERM) — while `FilterControl` opened its ring successfully in the same second with identical entitlements. See below. |
| **Data provider can enumerate tunnel interfaces** | **❌ NO** | `getifaddrs` returned `tunnels=none` in `FilterData` while `FilterControl` simultaneously saw seven `ipsec*`/`utun*` addresses. |
| `.drop()` blocks, VPN off | ☐ | not yet run |
| Filter stays active with NordVPN connected | ☐ | |
| `sourceAppIdentifier` still populated under VPN | ☐ | |
| Endpoint = real destination or tunnel endpoint | ☐ | |
| `.drop()` blocks with NordVPN connected | ☐ | **the decisive one** |

### ⚠️ The data provider is sandboxed far harder than the control provider

Undocumented, and the most consequential finding so far. In a single run, same App Group, same
entitlements, ~20 ms apart:

```
14:44:55.875  FilterData     open(flows-data.ring) failed: Operation not permitted
14:44:55.889  FilterData     [DATA] path ... interfaces=en0,en0,pdp_ip0 tunnels=none
14:44:55.945  FilterControl  [CTRL] ring open: flows-control.ring slots=2048 seq=36
14:44:55.964  FilterControl  [CTRL] path ... tunnels=ipsec1=…,ipsec4=…,utun10=…
```

`SharedContainer.containerURL` is non-`nil` in both — the container resolves, then access is denied.
This is consistent with the privacy model the API is built around: the data provider sees *every*
flow, so it is prevented from persisting or exfiltrating what it sees; the control provider only
sees flows you deliberately escalate with `.needRules()`, so it is trusted with storage.

It also explains Sift's shape retroactively: Sift did all of its caching and history writing in the
**control** provider, not the data provider. That looked like a style choice in 2018. It was not.

**This has to be pinned down before milestone 2**, because the planned architecture — app compiles a
policy blob, data provider memory-maps and reads it — depends on whether the denial is
*write-only* or *total*. `SandboxProbe` (`Shared/Core/SandboxProbe.swift`) now runs at start-up in
all three processes and reports, per capability, with `errno`:

- `stat` / list the container
- create, write, read a new file
- **open an existing file read-only** ← the one that decides milestone 2
- `Data(contentsOf:)` the config file
- write to the process's own private container (is the denial App-Group-specific or blanket?)
- `getifaddrs` visibility

Consequences if reads are also denied:

- Policy cannot be delivered by shared file. The remaining channels are
  `NEFilterProviderConfiguration.vendorConfiguration` (set by the app, readable via
  `filterConfiguration` in the provider) and `.needRules()` round trips.
- Flow statistics from the data provider are impossible except via `OSLog`. Durable history could
  only cover flows escalated to the control provider — which is exactly what Sift did.

### ⚠️ Flows answered with `.needRules()` lose connection races

Every probed flow shows the same pattern: `needRules` → `ctl-allow` → `flowClosed in=0 out=0`, then
the app retrying on a new source port ~2 s later and succeeding with a plain `allow`:

```
14:45:01.169  needRules   local=…:57946  id=CA20B032
14:45:01.172  ctl-allow   local=…:57946  id=CA20B032
14:45:01.177  REPORT[data] flowClosed action=allow in=0 out=0
14:45:03.241  allow       local=…:57949  id=07F6C9E2      ← retry, different port
14:45:03.672  REPORT[data] flowClosed action=allow in=6263 out=5111
```

Confirmed a second time with explicit flow-id correlation (Slack, QUIC to `slack.com:443`):

```
14:57:48.522511  FilterData     needRules  local=…:52985            (id 3100D8A8)
14:57:48.530064  FilterData     allow      local=…:60451  same addr ← a racing sibling flow
14:57:48.536065  FilterControl  ctl-allow  local=…:52985  id=3100D8A8  152us
14:57:48.547765  FilterData     REPORT[data] id=3100D8A8 flowClosed action=allow in=0 out=0
```

The control verdict was **allow**, and the control provider's own work took 152 µs — but the full
round trip was **13.5 ms**, and in that window the app had already opened a sibling connection to
the same host and used it instead. Modern clients race connections (Happy Eyeballs, QUIC racing), so
a flow held for 13 ms simply loses.

So `.needRules()` is not necessarily *destructive*; it is *too slow to compete*. Either way the
conclusion for milestone 2 is the same: **the hot path must be self-contained.** `.needRules()` is
viable only for out-of-band signalling (user prompts, telemetry), which is exactly what Sift used it
for.

---

## Notes for milestone 2 (do not build yet)

Constraints the spike has already established, which the policy engine must be designed around:

- Every flow hits Swift. There is no iOS equivalent of `NEFilterSettings` to offload matching.
- The verdict is synchronous and final; no pause-and-decide-later.
- App identity is `sourceAppIdentifier` only — no audit token, so no code-signature validation.
- Hostnames are unreliable. An IP/CIDR engine is the primary matcher; domains are a secondary,
  best-effort layer.
- The data provider is memory-limited and long-lived. The compiled policy should be an immutable,
  memory-mapped, zero-copy structure built by the app, not a graph the extension allocates. A
  memory-mapped patricia trie over a fixed-stride node array fits both that and the App Group
  channel already proven here.
- `handleRulesChanged()` is the only push into the data provider, it carries no payload, and it only
  fires as a side effect of a `.needRules()` round trip. Policy reloads should therefore be driven
  by a cheap file-generation check on the hot path (as `SpikeConfiguration` reloading already does)
  rather than by relying on that callback.

## References

- Apple, [TN3134: Network Extension provider deployment][tn3134]
- Apple, [WWDC25 session 234 — Filter and tunnel network traffic with NetworkExtension](https://developer.apple.com/videos/play/wwdc2025/234/)
- Apple Developer Forums, [Content Filter Providers in unsupervised and unmanaged iOS devices](https://developer.apple.com/forums/thread/775112)
- Apple Developer Forums, [Can Content Filter run on a NON SUPERVISED device?](https://developer.apple.com/forums/thread/732385)
- Apple Developer Forums, [Unable to drop some flows in NEFilterDataProvider handleNewFlow][FB18681313]
- iOS 26.5 SDK headers: `NEFilterFlow.h`, `NEFilterProvider.h`, `NEFilterDataProvider.h`, `NEFilterControlProvider.h`, `NEFilterManager.h`, `NEFilterProviderConfiguration.h`
- [agrinman/sift-ios](https://github.com/agrinman/sift-ios) — the 2018 reference implementation
