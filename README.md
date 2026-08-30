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

**Caveat — `idevicesyslog` drops messages that Console.app shows.** From the two extensions it
reliably delivers the `Flows` category but not `Storage` / `DataProvider` / `ControlProvider`, even
though all of them use the same `Logger.log()` API at the same level. Cause unknown. Because of it,
start-up lines and the sandbox probe summary are deliberately emitted on the `Flows` logger, and the
probe verdict is also appended to the first three flow lines as `sandbox[…]`. **Use Console.app when
you need the full picture.**

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
   - `BLOCKED suffix neverssl.com` → failure
   - `control captive.apple.com` → `HTTP 200`
   - `control www.google.com` → `HTTP 204`
4. Disable the filter, tap **Run drop test** again — both should now succeed.

There are three rule types, matched in that order — literal address, hostname suffix, hostname
substring:

| Field | Semantics | Example |
|---|---|---|
| `blockedAddresses` | exact literal address | `93.184.216.34` |
| `blockedHostSuffixes` | `host == s` or `host.hasSuffix("." + s)` | `google.com` matches `www.google.com`, **not** `googleapis.com` |
| `blockedHostSubstrings` | `host.contains(s)` anywhere | `google` matches `googleapis.com`, `googlevideo.com`, `google.co.uk` |

The only compiled-in default is `neverssl.com` (suffix). `blockedHostSubstrings` ships empty.

`["google"]` was the milestone-1 drop test — deliberately broad and unmistakable, taking out Search,
YouTube, Maps, ads and every Firebase-backed app. It proved `.drop()` works, including under VPN,
and is not a sane resting state. Put it back from the UI, or in `SpikeConfiguration.default`, to
re-run that test.

The `.needRules()` probe also ships **off**. It cost ~13 ms on the first flow of every app and lost
connection races; the measurement is done. Toggle it on from the UI to re-run it.

Defaults are compiled in as well as being writable from the UI, because the data provider may not be
permitted to read `spike-config.json` at all (see the sandbox finding). A rebuild always applies;
the UI only applies if container reads are allowed — which makes the UI path a test in itself.

`neverssl.com` remains a target because it is plain HTTP with no HSTS and no long-lived connection
reuse, which are the two things that most often make an iOS drop test look like a false negative. If `remoteHostname` turns out to be `nil` for your traffic, put a literal IP in **Blocked
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
| **Data provider can WRITE any file, anywhere** | **❌ NO** | `EPERM` on the App Group container *and* on its own private container. A blanket write denial, not an App-Group permission problem. |
| **Data provider can READ the App Group container** | **✅ YES** | `stat`, `listContainer` (4 entries), `openRO` + `pread` on files written by other processes all succeed. **This is what makes milestone 2 possible.** |
| **Data provider can enumerate network interfaces** | **❌ NO** | `getifaddrs` returns **0 addresses**. Not a tunnel-specific restriction — total blindness. `FilterControl` saw 47 addresses across 29 interfaces at the same moment. |
| `.drop()` blocks, VPN off | **✅ YES** | Substring rule `google` applied; Search, YouTube, Maps and Google push all dead while enabled, restored on toggle off. |
| `remoteHostname` available under VPN | **✅ YES** | Blocking is hostname-driven and it kept working with the tunnel up, so the filter still receives hostnames. |
| Filter stays active with NordVPN connected | **✅ YES** | |
| **`.drop()` blocks with NordVPN connected** | **✅ YES** | **The decisive result.** The content filter is evaluated *before* traffic reaches the packet tunnel, and drop verdicts are honoured with the tunnel up. No sign of the [FB18681313] verdict-ignored failure mode on iOS 26. |
| **Endpoint = real destination or tunnel endpoint** | **✅ REAL DESTINATION** | With NordVPN connected: `addr=63.176.3.100` (AWS Frankfurt), `addr=23.197.161.53` (Akamai), `addr=172.217.115.4` (Google) — all genuine destinations, while `local=100.78.119.133` is NordVPN's CGNAT tunnel address. **The filter runs above encapsulation. IP/CIDR and geo-IP policy work normally under VPN.** |
| Data provider can classify tunnel membership | **❌ NO** | `FilterData` logs `path=[wifi,other]`; `FilterControl`, same flow id, logs `path=[wifi,other,utun,in-tunnel]`. `getifaddrs` is restricted in the data provider, so `tunnelPresent`/`localIsTunnel` never fire there. **`NWPath.usesInterfaceType(.other)` does work** — that is the hot-path VPN signal. |
| Remote address always available at `handleNewFlow` | **❌ NO** | Many flows arrive with `remoteFlowEndpoint == ::` (unspecified) while `remoteHostname` is already populated. See below — this is a hard constraint on the CIDR engine. |
| `sourceAppIdentifier` still populated under VPN | **✅ YES** | `app=.com.apple.ctcategories.service` captured with the tunnel up. |
| Flow's local address under VPN | **tunnel-assigned** | `local=100.78.119.133` — CGNAT range, NordVPN's address, not the LAN `192.168.0.65`. `path=[wifi,other,utun,in-tunnel]`, so `NWPath` reports `.other` **and** the `localIsTunnel` classifier fires. |
| Remote **hostname** under VPN | **✅ real destination** | `host=itunes.apple.com` — the filter sees the app's intended host, not a VPN endpoint. |

### 🔑 The data provider is read-only, and blind to network interfaces

The single most consequential finding of the spike, and undocumented anywhere. `SandboxProbe`
measured all three processes in one run, same App Group, identical entitlements, ~50 ms apart:

| Capability | app | **FilterData** | FilterControl |
|---|---|---|---|
| `containerURL` resolves | OK | **OK** | OK |
| `stat(container)` | OK | **OK** | OK |
| list container | OK | **OK — 4 entries** | OK |
| `open(O_CREAT\|O_RDWR)` | OK | **FAIL — `EPERM`** | OK |
| `write` | OK | — | OK |
| `openRO` another process's file | OK | **OK** | OK |
| `pread` that file | OK | **OK** | OK |
| write to **own private** container | OK | **FAIL — `EPERM`** | OK |
| `getifaddrs` | 45 addrs | **FAIL — 0 addrs** | 47 addrs / 29 ifaces |

Two clean rules for `NEFilterDataProvider` on iOS 26:

1. **It cannot write anywhere.** Not the App Group, not even its own `Library/Caches`. This is a
   blanket filesystem write denial, not a missing entitlement — exactly what you would build if the
   goal were to stop a process that sees every flow from ever persisting what it sees.
2. **It can read the App Group container freely** — directory listing, `open(O_RDONLY)`, `pread` on
   files written by the app or the control provider.

It also explains Sift retroactively: Sift did all its caching and history writing in the **control**
provider. That looked like a style choice in 2018. It was not.

**Milestone 2's architecture survives**, with one change:

- ✅ App compiles the policy blob → writes it to the App Group → data provider `mmap`s it read-only.
  This is precisely the read path that was measured working.
- ❌ The data provider cannot persist statistics, counters, or flow history. `OSLog` is its only
  output. Durable history can only cover flows escalated to the control provider — Sift's design,
  and now clearly a forced one rather than a preference.
- ❌ `NetworkInterfaces` is useless in the data provider. Hot-path VPN detection must come from
  `NWPath.usesInterfaceType(.other)`, which does work there.

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

## Verdict on the spike

**The architecture works.** A development-signed build on an ordinary unsupervised iPhone can
configure a content filter, observe every TCP and UDP flow with app identity and hostname, and drop
flows — including while NordVPN's `NEPacketTunnelProvider` is connected. That was the project's
central risk and it is retired.

`NEPacketTunnelProvider` was never the right tool here anyway (per WWDC25 it receives no flow or
app-level metadata), and now it does not have to be.

All six VPN coexistence questions are answered, and the sandbox boundary that decides how policy
reaches the data provider is measured rather than assumed: **the data provider can read the App
Group container but cannot write anywhere.** The planned design — app compiles a policy blob, data
provider memory-maps it read-only — is viable as drawn.

Milestone 1 is complete.

## Notes for milestone 2 (do not build yet)

### ⚠️ The remote address is not always available — the hostname often is

Safari's Safe Browsing traffic, dropped by the substring rule, arrived like this:

```
DROP app=.com.apple.mobilesafari remote=apple-safebrowsing.googleapis.com:443
     addr=::  host=apple-safebrowsing.googleapis.com  local=?  IPv6/UDP  rule=substr:google  18us
```

`::` is the *unspecified* IPv6 address: the flow reached `handleNewFlow` before the destination was
resolved. `remoteHostname` was populated anyway. The same shape appears on QUIC flows and on unbound
sockets (`local=0.0.0.0`).

Two consequences:

1. **An IP-only policy engine will miss traffic.** A meaningful share of flows carry no address at
   decision time. Domain rules are not a "secondary, best-effort layer" as originally assumed — for
   these flows they are the *only* layer. The earlier expectation that `remoteHostname` would be
   unreliable was wrong; on iOS 26 it is frequently the more reliable of the two.
2. `::` and `0.0.0.0` must never be treated as addresses. `FlowInspector.isUnspecified(_:)` now
   normalises them to "no address" so they cannot be matched against real CIDR rules, and the logs
   print `addr=<unresolved>`.

### Local-network traffic is visible, and has no hostname

`rapportd` (Handoff/Continuity) flows to link-local peers appear like any other flow:

```
allow app=.com.apple.rapportd remote=fe80::3817:9cff:fe64:a43f:53458 addr=fe80::3817:9cff:fe64:a43f
      host=<nil> local=? IPv6/TCP path=[wifi,other] 52us
```

LAN and link-local traffic is in scope for the filter, `remoteHostname` is `nil` for it, and the
local endpoint is unavailable. A policy engine needs an explicit story for RFC1918 / `fe80::/10` /
multicast rather than treating every flow as internet-bound.

### ⚠️ `NEFilterFlow.identifier` may not be one-per-`handleNewFlow`

Four `rapportd` flows to four different endpoints — three link-local IPv6 and one IPv4 — arrived
within 9 ms all reporting the same identifier prefix:

```
15:17:35.067  needRules  remote=fe80::1cd3:1874:ba69:d5bf:52045  id=D89B5B5D
15:17:35.069  allow      remote=fe80::3817:9cff:fe64:a43f:53458  id=D89B5B5D
15:17:35.072  allow      remote=192.168.0.13:52045               id=D89B5B5D
15:17:35.076  allow      remote=fe80::18f4:1ff2:b899:a8ee:53458  id=D89B5B5D
```

Resolved by logging the full UUID: the identifiers are **distinct**, but they share a long common
prefix, so truncation collides.

```
remote=fe80::1cd3:1874:ba69:d5bf:52045   id=D89B5B5D-793C-4940-22C1-3882FC81E600
remote=fe80::3817:9cff:fe64:a43f:53458   id=D89B5B5D-793C-4940-0CF2-6584FD81E600
remote=192.168.0.13:52045                id=D89B5B5D-793C-4940-B94C-48833282E600
```

`NEFilterFlow.identifier` is **not** a random v4 UUID — the first three groups are stable across
flows (and across processes). **Never truncate it.** Use the whole value as the key for
report-to-flow correlation.

### Connection racing amplifies everything

One `firebaseremoteconfigrealtime.googleapis.com` lookup produced **eight** flows in 45 ms, each to a
different Google IP (`172.217.112.4` … `172.217.119.4`), all dropped. Budget the hot path for bursts
an order of magnitude above the "one flow per connection" intuition.

### Answered: what does `addr=` contain under the tunnel?

Hostname-based dropping works with the VPN up, but that does not establish whether the *address* the
filter sees is the app's real destination or NordVPN's tunnel endpoint. The entire milestone-2 plan
is an IPv4/IPv6 prefix engine, so this decides whether IP-based policy is meaningful under VPN at
all:

- **Real destination** → CIDR, geo-IP and feed-based policy all work normally under VPN.
- **Tunnel endpoint** → every flow collapses to one address, IP policy is useless while connected,
  and domain rules become the only workable layer.

Capture it with the tunnel up:

```sh
# -p filters by process, which excludes the very noisy cloudd/CFNetwork lines that also
# contain "app=". -m "app=" alone is not selective enough.
idevicesyslog -u "$(idevice_id -l | head -1)" -p "FilterData|FilterControl" --no-colors
```

**Answer: the real destination.** With NordVPN connected, every flow showed the app's genuine remote
address and the tunnel's local address:

```
allow app=8A5G68776P.com.enote.staging  remote=tokens.prod.enote.com:443  addr=63.176.3.100
      local=100.78.119.133:53831  IPv4/TCP  path=[wifi,other]  43us
```

`63.176.3.100` is AWS Frankfurt — the real destination. `100.78.119.133` is CGNAT, NordVPN's
tunnel address. So milestone 2's prefix engine is viable under VPN.

Supporting evidence from the control provider on the same flow id:

```
CONTROL ctl-allow app=.com.apple.ctcategories.service remote=itunes.apple.com:443
        host=itunes.apple.com local=100.78.119.133:53764
        path=[wifi,other,utun,in-tunnel] id=9BE80D75 171us
```

```
FilterData     … local=100.78.119.133:53831 path=[wifi,other]                   id=42D009A9
FilterControl  … local=100.78.119.133:53831 path=[wifi,other,utun,in-tunnel]    id=42D009A9
```

Same flow, two processes, different visibility: only the control provider can enumerate the tunnel
interface. Both see `.other` from `NWPath`, which is therefore the only tunnel signal usable on the
hot path.

### Constraints the spike established, which the policy engine must be designed around

**Delivery of policy**

- The app compiles the blob; the data provider `mmap`s it **read-only**. Measured working.
- The data provider can write **nothing**, so the blob must be complete and self-describing — no
  scratch files, no lazily built indexes, no on-device compaction.
- `handleRulesChanged()` is the only push into the data provider, carries no payload, and only fires
  as a side effect of a `.needRules()` round trip. Reload should be driven by a cheap throttled
  `stat(2)` generation check on the hot path, as `SpikeConfiguration` reloading already does.

**Matching**

- Every flow hits Swift; there is no iOS equivalent of `NEFilterSettings` to offload matching, and
  the verdict is synchronous and final.
- Budget for bursts: one hostname produced **eight** flows in 45 ms across eight IPs.
- **Domains are a first-class matcher, not a fallback.** A meaningful share of flows arrive with
  `remoteFlowEndpoint == ::` and only a hostname. An IP-only engine silently misses them.
- Conversely, LAN and link-local flows arrive with a hostname of `nil`. The engine needs explicit
  handling for RFC1918 / `fe80::/10` / multicast rather than assuming internet-bound traffic.
- App identity is `<teamID>.<bundleID>` and nothing else — no audit token, so no code-signature
  validation. Split on the first `.`; Apple's own apps have an empty team.
- `NEFilterFlow.identifier` shares a long common prefix across flows. Use the full UUID as a key.

**Observability**

- The data provider cannot persist anything. Counters, history and statistics must either go through
  `OSLog` or be limited to flows escalated to the control provider.
- `.needRules()` latency is **bimodal**: ~1.4 ms median warm, up to ~28 ms cold. The ~13 ms figure
  measured in milestone 1 was a cold start including process launch — see *Milestone 1.5* below. It
  is a usable path for flows that are being denied anyway; it is still the wrong tool for deciding
  a flow that might be allowed, because a cold escalation loses connection races.
- Hot-path VPN detection is `NWPath.usesInterfaceType(.other)`. `getifaddrs` returns nothing.

## Milestone 1.5 — escalation verified

The rule model in [`docs/firewall-rules.md`](docs/firewall-rules.md) routes default-denied flows
through `.needRules()` so the control provider — the only one of the three processes that can write
— records them. Two things had to be true for that to work, and neither had been tested.

Measured on device: 40 concurrent requests at a denied host, `denyMode = escalate`.

| Question | Result |
|---|---|
| Does a control-provider `.drop()` actually drop the flow? | **✅ YES** — app-side `PASS`; all 40 requests failed on the wire, none inconclusively |
| Does escalation survive being the common case? | **✅ YES** — 41 escalated, 41 arrived, 0 lost, 41 answered `ctl-DROP` |

```
data -> control round trip (ms)   min 0.92   p50 1.36   p95 5.20   max 28.16
control provider own work (ms)    min 0.06   p50 0.09   p95 0.27   max  1.11
```

**This corrects a milestone-1 conclusion.** The ~13 ms round trip recorded earlier was a cold start
including process launch. Warm, the median is 1.36 ms with 90 µs of that being the control
provider's own work; the 28 ms maximum is the first escalation of the run. Escalation latency is
bimodal — cheap while the control provider is active, expensive when it must be woken.

Also found: **escalated flows produce no `NEFilterReport`.** `NEFilterControlVerdict` inherits
`shouldReport` but nothing sets it, so no `flowClosed` event and no byte counts arrive. Harmless for
denial, but it means the report channel cannot be used to confirm that a drop took effect.

Reproduce with `tools/escalation-report.py`; the procedure is in
[`docs/firewall-rules.md` §5.2](docs/firewall-rules.md).

## Milestone 2 — Bypass all filters

A per-app rule class that exempts an app from Samaritan entirely. Not "allow after processing": the
check is the first statement in `handleNewFlow`, before the clock is read, and a bypassed flow is
allowed and forgotten — no `FlowInspector.record`, no ring append, no Observed entry, no counter,
no log line, no configuration reload, no sandbox probe.

Design and precedence are in [`docs/firewall-rules.md` §2.0](docs/firewall-rules.md).

**Why the set is not part of `policy.bin`.** The compiled policy is reached through a throttled
`stat(2)` behind the provider's lock. L0 has to answer before either, so bypass gets its own file
(`bypass.json`) and its own publication path: an immutable `Set<String>` behind a single
`Atomic<UnsafeRawPointer?>`. The hot path is one acquiring load and one hash lookup. Reloads happen
off the hot path — a vnode watch on the container **directory** (not the file: `Data.write(.atomic)`
renames over it, which a file-descriptor watch never sees), a 5-second timer as a fallback, and
`handleRulesChanged()`.

Published snapshots are never freed. Readers hold a bare pointer with no reference count, so
reclaiming one safely needs a quiescence protocol that would cost the hot path exactly what the
design exists to avoid. Growth is bounded from the other end instead: an unchanged set is not
republished, so the timer costs nothing, and each snapshot is a handful of short strings.

### Confirmed on device

Netflix playback — which default-deny was breaking — works with bypass on. [DEVICE]

That is the whole path exercised by real traffic, and it settles three things that could only be
guessed at off-device:

- The L0 early return reaches production flows and genuinely exempts them. Playback is high-volume
  and latency-sensitive, so a bypass that only *mostly* fired would have shown up as stalling rather
  than as success.
- **`bypass.json` is readable from inside the `NEFilterDataProvider` sandbox, and the published set
  arrives.** Not a given: that process cannot write anywhere at all, and `getifaddrs` returns zero
  addresses there, so its read access to the App Group is the only channel this design has.
- Playback traffic is attributed to identifiers the Apps list actually offers — it is not routed
  exclusively through a system media daemon shared with every other app, which was the failure mode
  §1.3 flagged as the reason a bypass might look correct and do nothing.

Still worth pinning from a capture: whether one identifier sufficed or the siblings had to be
bypassed too. `grep "IDENT NEW" ~/device.log` answers it.

### ⚠️ A bypass keyed on a bundle ID silently never fires

`sourceAppIdentifier` is `<teamID>.<bundleID>` — a signing identifier, not a bundle ID (§1.3). The
bypass set is compared against it verbatim, so `com.netflix.Netflix` would save, display as on, and
never match anything. Every identifier the UI stores comes from a row the providers recorded, which
is the only reason this is safe; `BypassTests` pins the mismatch so nobody "fixes" it by normalising.

The same trap applies to allow/deny rules, and there it is already handled: the app list, the policy
document and `PolicyEngine` all key on the same raw string, and `PolicyEngine` maps an empty
identifier onto `<unattributed>` before matching so the pseudo-app's rules work. **No mismatch found
in the existing rule path.**

### Capturing what `sourceAppIdentifier` really contains

`FilterDataProvider.noteIdentity` logs each distinct identifier once, verbatim, distinguishing `nil`
from empty. `logEveryFlow` (Settings, on by default) additionally prints `app=` per flow.

```sh
idevicesyslog -u <UDID> | tee ~/device.log
# then, on the phone: open the app under test and drive the feature you care about
grep "IDENT NEW" ~/device.log
grep -ohE "app=[^ ]*" ~/device.log | sort | uniq -c | sort -rn
```

`IDENT NEW` reports the raw string, the team and bundle halves, whether it parses as an Apple
platform binary, whether it is currently bypassed, the protocol, and the hostname of the flow that
introduced it. What to look for:

- **more than one identifier per app** — extensions and helper processes have their own bundle IDs;
  each needs its own bypass. The app screen lists siblings for this reason.
- **an identifier that is not the app at all** — if media playback is attributed to a system daemon,
  bypassing the app will not exempt the traffic that matters, and bypassing the daemon exempts it
  for every app on the device. Open question; see §1.3.
- **`raw=<nil>` or `raw=<empty>`** — never seen in captures so far. Such a flow cannot be bypassed
  (there is nothing to match) and falls to `<unattributed>` under default-deny.

## References

- Apple, [TN3134: Network Extension provider deployment][tn3134]
- Apple, [WWDC25 session 234 — Filter and tunnel network traffic with NetworkExtension](https://developer.apple.com/videos/play/wwdc2025/234/)
- Apple Developer Forums, [Content Filter Providers in unsupervised and unmanaged iOS devices](https://developer.apple.com/forums/thread/775112)
- Apple Developer Forums, [Can Content Filter run on a NON SUPERVISED device?](https://developer.apple.com/forums/thread/732385)
- Apple Developer Forums, [Unable to drop some flows in NEFilterDataProvider handleNewFlow][FB18681313]
- iOS 26.5 SDK headers: `NEFilterFlow.h`, `NEFilterProvider.h`, `NEFilterDataProvider.h`, `NEFilterControlProvider.h`, `NEFilterManager.h`, `NEFilterProviderConfiguration.h`
- [agrinman/sift-ios](https://github.com/agrinman/sift-ios) — the 2018 reference implementation
