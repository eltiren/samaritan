# Samaritan — firewall rule model

**Status: draft specification. No code written against this yet.**

This document turns the stated intent into a resolver that can actually be implemented, marks the
places where the intent was ambiguous or self-contradictory, and proposes a default for each so the
spec is usable even before every question is answered.

Notation used throughout:

- **[STATED]** — taken directly from the requirements.
- **[DERIVED]** — a consequence of a stated requirement plus a milestone-1 on-device finding.
- **[PROPOSED]** — a decision I made to fill a gap; overridable.
- **[Qn]** — an open question. Answers change behaviour. Collected in *Open questions*.
- **[VERIFY]** — depends on device behaviour not yet measured.

Milestone-1 findings referenced here are in [`../README.md`](../README.md).

---

## 1. Model

### 1.1 Core rule

**Default action is DENY.** [STATED]

Everything else is an exception. A flow is allowed only if some rule says so; no rule means dropped.

### 1.2 What a flow gives us

From `NEFilterDataProvider.handleNewFlow(_:)`, measured on iOS 26:

| Field | Availability |
|---|---|
| `sourceAppIdentifier` | Always, as **`<teamID>.<bundleID>`**. Apple's apps have an empty team: `.com.apple.mobilesafari`. |
| `remoteHostname` | Often, but **not always** |
| remote address | Often, but **not always** — many flows arrive with `::` (unspecified) |
| port, protocol, direction | Always |

Two facts drive the whole design:

1. **A flow can have a hostname and no address, an address and no hostname, or neither.** [DERIVED]
   A rule engine keyed only on IP prefixes silently misses a large share of traffic. Domain rules
   and IP rules are **peers**, not primary and fallback.
2. **The verdict is synchronous and final.** There is no pause-and-decide-later on iOS. Resolution
   must complete inline, in the low hundreds of microseconds.

### 1.3 App identity

Rules are keyed on the **full `sourceAppIdentifier` string**, and the bundle ID is what gets
displayed. [PROPOSED] Keying on bundle ID alone would let a different signer inherit another app's
policy.

Measured on device: [DEVICE]

| Kind | Example | Team component |
|---|---|---|
| Third-party app | `BQR82RBBHL.com.tinyspeck.chatlyio` | the signing team ID |
| Third-party app | `C67CF9S4VU.ph.telegra.Telegraph` | the signing team ID |
| Apple platform binary | `.com.apple.mobilemail` | **empty**, so the string starts with `.` |
| Apple daemon | `.com.apple.rapportd` | empty |

So it is a **signing identifier, not a bundle ID**: `<teamID>.<bundleID>`. Nothing that compares this
against a bundle ID can ever match. Across a full-day capture, every flow carried one — no `nil`, no
empty — but the code treats both as possible, because a single counter-example silently converts
default-deny into default-allow-and-forget.

"Apps whose bundle identifier starts with `com.apple`" [STATED] is implemented as: [DERIVED]

```
teamID.isEmpty && bundleID.hasPrefix("com.apple.")
```

Both halves matter. The empty team component is what actually distinguishes a platform binary; a
prefix test alone would also match a third-party `com.appleseed.*`, and the trailing dot prevents
that too.

Flows with no `sourceAppIdentifier` are attributed to a reserved pseudo-app, **`<unattributed>`**,
which appears in the app list and has its own rule set. [PROPOSED] It is a display key only — no
flow carries that string — so it cannot be bypassed (§2.0), and `PolicyEngine` maps an empty
identifier onto it before matching so a rule written against the row still applies.

**One app is not necessarily one identifier.** [DEVICE, partial] App extensions and helper processes
are signed into the same team but carry their own bundle IDs, and the same bundle can appear under
two teams (a sideloaded and a store build). Each is a separate row and a separate policy. This is
correct — they really are different binaries — but it is also the most likely reason a rule looks
like it is not working, so the app screen lists an app's sibling identifiers explicitly rather than
merging them (§7.2).

**Open, and only answerable on device:** whether media playback in a large streaming app is
attributed to the app itself or to a system media daemon. If playback runs through, say,
`.com.apple.mediaplaybackd`, then bypassing the app's own identifier will not exempt the traffic
that matters, and the daemon's identifier has to be bypassed too — with the obvious consequence that
it is shared with every other app that plays media. The `IDENT NEW` log line in
`FilterDataProvider` exists to answer exactly this; see the capture procedure in `README.md`.

---

## 2. The resolver

### 2.1 Precedence ladder

```
INPUT  flow { app, hostname?, address?, port, proto }

  │
  ├─ L0  BYPASS ....................................... terminal, before anything else
  │      the flow's raw sourceAppIdentifier is in the bypass set
  │      →  ALLOW immediately. Nothing is parsed, recorded, counted or logged.
  │
  ├─     NORMALISE
  │      app  → (teamID, bundleID)
  │      host → lowercase, strip trailing dot, IDN → punycode
  │      ip   → literal address; discard :: and 0.0.0.0 as "no address"
  │
  ├─ L1  PER-APP EXPLICIT RULES ....................... terminal if matched
  │      this app's allow list and deny list
  │      most specific match wins; DENY wins a tie
  │
  ├─ L2  GLOBAL USER LISTS ............................ terminal if matched
  │      hand-edited allow / deny, on device
  │      most specific match wins; DENY wins a tie
  │
  ├─ L3  GLOBAL WEB LISTS ............................. terminal if matched
  │      subscribed, read-only
  │      most specific match wins; DENY wins a tie
  │
  └─ L4  APP BLANKET DEFAULT ......................... always terminal
         "Allow all" ON            →  ALLOW
         Apple system app          →  ALLOW      (ships with Allow-all pre-enabled)
         otherwise                 →  DENY, and record in this app's Observed list
```

### 2.0 Bypass is not a rule — it is an exit

Every other tier is a decision *about* a flow: the flow is inspected, matched, recorded, and a
verdict comes out. **Bypass is the absence of all of that.** It is checked before the clock is read,
before `FlowInspector` touches the flow object, and before any lock is taken. A bypassed flow is
allowed and forgotten.

This is what makes it different from `Allow all`, which people will otherwise assume it duplicates:

| | Allow all | Bypass |
|---|---|---|
| Verdict when nothing matches | allow | allow |
| Can a global deny list override it? | **yes** | no |
| Can a per-app deny rule override it? | **yes** | no |
| Destinations recorded in Observed | **yes** | no |
| Appears in Recent flows | **yes** | no |
| Counted in the diagnostics counters | **yes** | no |
| Byte counts via `NEFilterReport` | **yes** | no |
| Cost per flow | full resolve | one set lookup |

Allow-all is a *permissive policy*. Bypass is *not having a policy*: the app is invisible to
Samaritan, and Samaritan is invisible to the app. Nothing below L0 can override it, because nothing
below L0 runs.

The set is keyed on the **raw `sourceAppIdentifier`, exactly as the flow carries it**. This is the
one place where the identity question in §1.3 is not merely academic: a bypass stored as a bundle ID
compiles, saves, displays as "on", and never fires. The UI therefore only ever stores identifiers
that came from a flow the providers actually recorded, and `BypassList.sanitise` drops
`<unattributed>` — a display-only pseudo-identifier that no flow carries.

**Delivery.** Bypass has its own file, `bypass.json`, not a section of `policy.bin`. The compiled
policy is reached through a throttled `stat(2)` behind the provider's lock; L0 has to answer before
either of those, so it is published separately as an immutable `Set<String>` swapped behind one
atomic pointer. The data provider reads it with an acquiring load and a hash lookup — no lock, no
`stat`, no allocation. It is refreshed off the hot path by a watch on the container directory, a
5-second timer, and `handleRulesChanged()`.

### 2.2 Blanket settings are only a default

The app's blanket setting is the **last** thing consulted, never an override:

| Blanket state | Means |
|---|---|
| **Allow all** | allow everything **not** banned by this app's deny list or by any global deny list |
| **Deny all** (default) | deny everything **not** permitted by this app's allow list or by any global allow list |

They are exact mirrors, and both lose to every tier above them. The stated core rule — *"DENY ALL,
everything else is an exception pyramid"* — is precisely the second row: it is the blanket default
for apps that have no blanket setting of their own.

This also collapses what were two separate tiers. **The Apple exemption is not a special tier — it
is `Allow all` shipped pre-enabled for `com.apple.*` apps.** [PROPOSED] Same code path, same
precedence, and it gains a useful property: the toggle stays writable, so Safari can be dropped to
default-deny and triaged like any other app when you want full control of web traffic. Nothing about
an Apple bundle ID is hardcoded into the resolver; it only sets the initial value of one toggle.

### 2.3 Why this order

The requirement said the global lists *"take priority over the whole app"*, and also that an allowed
domain is *"allowed for every app **unless it is specifically banned for that app**"*. Read literally
those contradict each other.

They reconcile if "priority over the whole app" means priority over the app's **blanket** setting
(the Allow-all toggle and the Apple exemption), not over the app's **specific** host rules. That is
the ladder above: L1 (specific, per app) beats L2/L3 (global lists), which beat L4 (blanket).
This satisfies the worked example exactly. **Confirmed.**

Two consequences, both confirmed:

- **The Apple exemption is a default, not an override.** Global lists and per-app rules apply to
  Apple apps, so Safari remains filterable. "`com.apple.*` → ALLOW ALL" means "Apple apps skip
  default-deny", not "Apple apps are untouchable".
- **Precedence is symmetric.** A per-app allow overrides a global deny, exactly mirroring a per-app
  deny overriding a global allow. L1 always wins in both directions.

### 2.4 Decision diagram

```mermaid
flowchart TD
    A[New flow] --> Z{"sourceAppIdentifier<br/>in the bypass set?"}
    Z -->|yes| BYPASS([ALLOW — nothing inspected,<br/>nothing recorded])
    Z -->|no| B[Normalise app / host / ip]
    B --> C{Per-app rule matches?}
    C -->|allow| ALLOW([ALLOW])
    C -->|deny| DENY([DROP])
    C -->|no match| D{Global user list matches?}
    D -->|allow| ALLOW
    D -->|deny| DENY
    D -->|no match| E{Global web list matches?}
    E -->|allow| ALLOW
    E -->|deny| DENY
    E -->|no match| F{"App blanket default<br/>(Apple apps ship Allow-all ON)"}
    F -->|Allow all| ALLOW
    F -->|Deny all| H[Record in Observed list]
    H --> DENY
```

### 2.5 Worked examples

Non-obvious outcomes, spelled out so they are not discovered later as bugs.

| # | Rules in play | Flow | Result | Why |
|---|---|---|---|---|
| 1 | global user list: ALLOW `apple.com`<br>Slack deny list: `apple.com` | Slack → `apple.com` | **DROP** | L1 beats L2. The stated example. |
| 2 | " | Mail → `apple.com` | **ALLOW** | No L1 rule for Mail, so L2 decides. |
| 3 | web list: DENY `tracker.example`<br>Slack allow list: `tracker.example` | Slack → `tracker.example` | **ALLOW** | L1 beats L3, symmetric with #1. |
| 4 | Slack: Allow all **ON**<br>web list: DENY `ads.example` | Slack → `ads.example` | **DROP** | L3 beats the blanket setting. |
| 5 | global user list: ALLOW `*.slack.com`<br>WhatsApp: no rules, deny-all | WhatsApp → `edge.slack.com` | **ALLOW** | A global allow reaches every app, including untriaged ones. |
| 6 | Slack allow list: `*.example.com`<br>web list: DENY `s1.example.com` | Slack → `s1.example.com` | **ALLOW** | **Tier beats specificity.** The broader per-app rule wins because L1 is consulted first. |
| 7 | global user list: DENY `*.google.com` | Safari → `google.com` | **ALLOW** | `*.x` is strictly subdomains — the apex needs its own rule. See below. |
| 8 | " | Safari → `www.google.com` | **DROP** | Subdomain, so it matches. |
| 9 | Slack allow list: `1.2.3.0/24` | Slack → `s1.slack.com`, address `::` | **DROP** | The flow carried no address, so an address rule cannot match; falls to deny-all. |
| 10 | Safari: Allow all **OFF** | Safari → anything | **DROP** + Observed | The Apple default is just a toggle value. |

**Example 7 matters for the test you already ran.** The milestone-1 experiment used a *substring*
rule (`google`), which caught `google.com`, `googleapis.com` and `googlevideo.com` alike. Under this
model, `*.google.com` blocks subdomains only — not the apex, and not `googleapis.com` at all. Getting
the same coverage needs several rules. Two consequences worth deciding later, neither in scope here:

- whether the substring rule type survives into the real engine as a first-class kind, and
- whether the popover should offer a "domain and all subdomains" one-tap action that writes both
  rules at once, since that is what people almost always mean.

### 2.6 Tie-breaking

Within a tier: [PROPOSED]

1. **Most specific match wins.** For domains, the longest matching suffix. For addresses, the
   longest matching prefix.
2. **A host rule and an address rule are not comparable.** If a flow matches an allow on one and a
   deny on the other in the same tier, **DENY wins** — fail safe.
3. Equal specificity, opposite actions: **DENY wins**.

---

## 3. Rule types

### 3.1 Domain rules

Two kinds:

| Kind | Written | Matches | Does **not** match |
|---|---|---|---|
| Exact | `s1.c1.status.example.com` | that name only | anything else |
| Subdomain | `*.example.com` | any descendant at any depth: `a.example.com`, `a.b.c.example.com` | `example.com` itself |

`*.X` is **strictly** subdomains — it never covers the apex. Covering both takes two rules.

The apex is still reachable from the UI: a flow *to* `example.com` produces its own chain
(`example.com`, then `*.com`), so the exact rule appears the moment the apex is actually contacted.
Nothing is unreachable; it just cannot be created pre-emptively from a subdomain's popover.

For a flow to `s1.c1.status.example.com`, the popover offers exactly the chain from the stated
requirement — the full name, then one entry per parent as labels are dropped from the left:

```
s1.c1.status.example.com      exact
*.c1.status.example.com       suffix
*.status.example.com          suffix
*.example.com                 suffix
*.com                         suffix     ← flagged as dangerous in the UI
```

`*.com` is a public suffix; a single tap would allow or deny roughly half the internet. It is
offered because it was specified, but the UI requires an extra confirmation for any suffix that is
a public suffix. [PROPOSED]

Matching is case-insensitive on the normalised form.

### 3.2 Address rules

Stored internally as **`(address, prefixLength)`** — always a CIDR prefix, never a wildcard string.
The octet-wildcard UI from the requirement is a *presentation* of four preset prefix lengths:

**CIDR is the canonical form everywhere**, including in the UI. For IPv4 the octet wildcard from the
original requirement is kept as a secondary label, because it reads more naturally at a glance:

| IPv4 preset | IPv6 preset |
|---|---|
| `8.8.8.8/32` — `8.8.8.8` | `2606:4700:4700::1111/128` |
| `8.8.8.0/24` — `8.8.8.x` | `2606:4700:4700::/64` |
| `8.8.0.0/16` — `8.8.x.x` | `2606:4700::/48` |
| `8.0.0.0/8` — `8.x.x.x` | `2606:4700::/32` |

The presets are shortcuts, not the whole vocabulary: the global list editor accepts any prefix
length. Storing prefixes rather than wildcard strings is what lets the same structure hold imported
CIDR feeds and, later, a radix trie, without a second rule format. [DERIVED]

### 3.3 What rules do *not* cover

Not specified, and deliberately out of scope for this revision: ports, transport protocol,
direction, time-of-day, and per-interface (Wi-Fi vs cellular vs VPN) conditions. Each is a plausible
later addition; none is implied by the current model. [PROPOSED]

---

## 4. Global lists

Both kinds hold the same rule types (domain and address) and each entry carries a polarity —
allow or deny.

**User lists** — created and edited on device. Fully mutable.

**Web lists** — subscriptions. The user supplies a URL and a polarity for the whole subscription;
entries are not individually editable. The user can disable or remove a whole subscription. [STATED]

Web list mechanics: [PROPOSED]

- **Fetched by the containing app only.** The data provider has no network access and cannot write
  to disk. [DERIVED]
- Format: one entry per line; `#` starts a comment; an entry is a domain, a `*.`-prefixed suffix,
  an IP, or a CIDR. Hosts-file format (`0.0.0.0 badhost.example`) is detected and the address column
  ignored.
- **A bare domain in a web list expands to exact + subdomains**, unlike a hand-written rule. [PROPOSED]
  Every blocklist in circulation writes `doubleclick.net` meaning "and everything under it"; applying
  the strict semantics of §3.1 to imported entries would under-block by a wide margin and silently.
  An explicit `*.x` entry in a list still means subdomains only. The list detail screen states which
  interpretation was applied.
- Refresh on a user-set interval, and on demand.
- **A subscription cannot be created until its first fetch succeeds.** The add-list flow is not
  completable against an unreachable or unparseable URL, so an empty-because-never-fetched list
  cannot exist.
- **A failed *refresh* keeps the last good copy** rather than dropping the list — dropping a deny
  list on a network error fails open. Since the first fetch is mandatory, there is always a last
  good copy. The list screen shows the last successful fetch time and flags a subscription whose
  refresh has been failing.
- A per-list cap on entry count, with truncation reported rather than silent.

---

## 5. Observability — how the app learns what happened

This is the hard part, and it is constrained by measured device behaviour rather than preference.

**The data provider cannot write anything, anywhere.** Not the App Group, not its own container.
It can only read. Its sole output is `OSLog`, which the containing app cannot read back. [DERIVED]

So the app cannot learn about flows from the data provider directly. Two channels exist:

| Channel | Cost | Covers |
|---|---|---|
| `NEFilterReport` → control provider, which **can** write | one report per flow, off the hot path | every flow with `shouldReport = true` |
| `.needRules()` → control provider | ~13 ms round trip, loses connection races | only flows we deliberately escalate |

**Design: the control provider is the recorder, and default-deny makes it cheap.** [PROPOSED]

The `.needRules()` cost that made it useless as a decision path is **irrelevant for a flow that is
being dropped**. There is nothing to be slow for. So the two channels split by outcome:

| Outcome | Channel | Why |
|---|---|---|
| **L6 default-deny** | `.needRules()` → control provider returns `.drop(withUpdateRules: false)` | Guaranteed delivery and guaranteed process wake-up. The 13 ms costs nothing on a flow with no future. |
| Allowed, or explicitly denied by a rule | `shouldReport = true` → `handle(_:)` | Off the hot path; no added latency on traffic that matters. |

That inverts the milestone-1 conclusion in a useful way: `.needRules()` is not merely "out-of-band
signalling", it is exactly the right mechanism for the one case where latency is free. It also
removes the risk that the control provider is never launched, because every undecided flow launches
it. [DERIVED]

1. The data provider decides in microseconds. Undecided → `.needRules()`. Decided → verdict with
   `shouldReport = true`.
2. The control provider appends `(app, host, ip, verdict, bytes, time)` to the App Group, from both
   `handleNewFlow` and `handle(_:)`.
3. The containing app reads that store to build the app list and each app's Observed list.

### 5.2 Verification harness

Both risks below are now testable on device without building any of the engine. See
`tools/escalation-report.py`.

1. Set **Deny mode** to `escalate` on the diagnostics screen and tap Apply. Every denied flow then
   returns `.needRules()` instead of `.drop()`.
2. Capture: `idevicesyslog -u "$(idevice_id -l | head -1)" -p "FilterData|FilterControl" -o ~/device.log`
3. Tap **Run escalation stress test (40×)** — forty concurrent requests at a denied host, so forty
   simultaneous round trips.
4. `tools/escalation-report.py ~/device.log`

The data provider logs `ESCALATE id=… t=…`; the control provider logs `CTLRECV id=… t=…` and
`CTLDONE id=… t=… verdict=…`. Both timestamps are `CLOCK_UPTIME_RAW`, which is system-wide
monotonic, so joining on flow id gives true cross-process latency rather than an estimate. The
script reports how many escalations never arrived, the round-trip distribution, and whether every
arrival produced a drop.

Pass conditions:

- The in-app result reads `PASS — every escalated flow was dropped`. If any request succeeded, a
  control-provider `.drop()` does not reliably drop and **§5 must change**.
- `never arrived` is zero. Anything else means escalation is lossy under load, deny has to be
  decided inline, and recording falls back to `NEFilterReport` only.

### 5.3 Measured results

40 concurrent requests at a denied host, `denyMode = escalate`, on device:

```
escalated by data provider : 41
reached control provider   : 41
never arrived              : 0
control returned a drop    : 41

data -> control round trip (ms)
  min    0.92   p50    1.36   p95    5.20   max   28.16
control provider own work (ms)
  min    0.06   p50    0.09   p95    0.27   max    1.11
```

App-side result: **PASS — every escalated flow was dropped.** Every one of the 40 requests failed on
the wire, none inconclusively.

- **A control-provider `.drop()` does drop the flow.** This was the untested half of the design;
  milestone 1 only ever exercised control verdicts of `allow`. §5 is now verified, not assumed.
- **Escalation is not lossy at this rate.** 41 of 41 arrived. The control provider kept up with 40
  simultaneous round trips.
- **The round trip is far cheaper than milestone 1 suggested.** The ~13 ms figure was a cold start
  including process launch; warm, the median is **1.36 ms** and the control provider's own work is
  **90 µs**. The 28 ms maximum is the first escalation of the run.
- Every escalated flow was answered `ctl-DROP`, and no `neverssl` flow was ever allowed or
  inline-dropped — all 41 took the `needRules` path.

Two findings from the same run:

- **Escalated flows produce no `NEFilterReport`.** `NEFilterControlVerdict` inherits `shouldReport`
  but nothing sets it, so no `flowClosed` event and no byte counts arrive for an escalated flow.
  Harmless for denial — a dropped flow moves no bytes — but it means the report channel cannot be
  used to confirm a drop actually happened.
- Because of that, the log alone proves 41 *verdicts* were issued, not 41 *failed connections*. The
  generator now writes its own conclusion to `OSLog` as `STRESSRESULT … verdict=PASS|LEAK|INVALID`,
  so evidence and conclusion live in the same capture.

### 5.4 Sustained load

Measured again with the engine live and a real app under permanent deny — Slack, blocked by its
blanket default, retrying for several minutes:

```
escalated by data provider : 2116
reached control provider   : 2116
never arrived              : 0
control returned a drop    : 2116

data -> control round trip (ms)   min 0.74   p50 1.58   p95 3.69   max 13.26
control provider own work (ms)    min 0.05   p50 0.13   p95 0.51   max  3.76
```

Escalation holds under sustained load, not just a burst. Latency is unchanged from the 40-flow
measurement, so the control provider is not accumulating a backlog.

**But 1839 of those were one app retrying one blocked destination**, and paying a cross-process round
trip for each is wasted work. The Observed list only needs a destination recorded once. The data
provider therefore keeps a bounded in-memory ledger of `(app, host)` pairs it has already escalated
and drops repeats inline — it cannot persist the ledger, but it does not need to: losing it on
restart costs one extra escalation per pair. The ledger is cleared whenever the policy generation
changes, so a rule edit re-records what it affects.

### 5.1 The Observed list ("sandbox")

Per app: destinations the app tried to reach that no rule decided, and which were therefore dropped
by L6. [STATED]

- **Keyed by hostname when one is available, otherwise by address.** [PROPOSED] The eight-IP
  Firebase burst must collapse to one row, not eight, so the hostname is the natural key. Each row
  keeps the set of addresses seen for it.
- Each row records: first seen, last seen, attempt count, addresses seen, ports.
- **Bounded per app** — a few hundred rows — evicting least-recently-seen, and **persisted across
  launches and reboots**. Under permanent deny an app retries indefinitely, so the bound is what
  stops the store growing without limit; coalescing by hostname is what stops one retry storm
  evicting everything else.

---

## 6. Policy delivery to the data provider

Measured working in milestone 1, and unchanged by this spec: [DERIVED]

1. The containing app compiles all rules — per-app, user lists, web lists — into a single immutable
   blob.
2. It writes the blob to the App Group container.
3. The data provider `mmap`s it **read-only** and matches against it in place.
4. The blob must be complete and self-describing: no scratch files, no lazily-built indexes, no
   on-device compaction, because the data provider cannot write.
5. Reload is driven by a throttled generation check on the hot path, not by `handleRulesChanged()`
   — that callback carries no payload and only fires as a side effect of a `.needRules()` round trip.

---

## 7. UI

### 7.1 App list

Apps that have initiated any network activity, most recent first. Each row: identity, counts of
allowed / denied / observed-pending, last activity.

**App icons and display names are not obtainable through any public iOS API.** [DERIVED]

**Decision: use the private `LSApplicationProxy` / `LSApplicationWorkspace` interface.** This build is
development-signed and will never be submitted to the App Store, so the usual objection does not
apply. Constraints on how it is used: [PROPOSED]

- Confined to a single file in the containing app — never in either extension, which have no
  business enumerating installed apps and would fail review of their own sandbox anyway.
- Reached through `NSClassFromString` / `NSSelectorFromString` with every result treated as
  optional, so an iOS release that changes or removes the interface degrades to bundle-ID-only
  display instead of crashing.
- Results cached in the App Group, keyed by bundle ID, so the private path is touched once per app
  rather than per render.
- A build flag can compile it out entirely, leaving the monogram fallback, so the project never
  *depends* on it.

### 7.2 App screen

Top to bottom: [STATED, plus bypass]

0. **Bypass all filters** — toggle, in its own section above everything else. Off by default and
   never offered for `<unattributed>`. While on: the Allow-all toggle is disabled (it is moot), the
   Observed section is headed *stale* and its rows carry the timestamp bypass was enabled, and the
   footer states plainly that **no destinations are recorded while bypass is on**. The screen must
   not let anyone believe this is a stronger Allow-all — the two footers say so in as many words.
1. **Allow all** — toggle. Default off, except for `com.apple.*` apps, which ship with it on.
   It means *allow everything I have not specifically denied, and that no global deny list bans* —
   not "allow everything". Turning it **off** for an Apple app is supported and puts that app under
   default-deny like any other.
2. **Same bundle, other identifiers** — shown only when they exist. Extensions, helper processes and
   re-signed builds produce separate identifiers for what a person thinks of as one app, and each is
   a separate policy. Listing them is what stops "I bypassed Netflix and it still doesn't play" from
   being a mystery; each carries a one-tap *Bypass too*.
3. **Allowed** — this app's allow rules.
4. **Denied** — this app's deny rules.
5. **Observed** — attempted, undecided, and therefore dropped.

A per-app **deny** entry is not redundant under a default-deny policy: its purpose is to override a
higher tier — a global allow list, the Allow-all toggle, or the Apple exemption. That is the only
reason it exists, and the UI should say so.

In the app list, a bypassed app is marked with a `BYPASSED` badge, its icon is dimmed, and its
allowed/denied counts are replaced by *not filtered — nothing recorded*, because those counts are
frozen at the moment bypass was switched on and would otherwise read as current.

### 7.3 The allow/deny popover

Opened by tapping any row in any of the three lists. Contents:

- **Action** — Allow or Deny.
- **Target** — the specificity chain from §3.1 (domains) or §3.2 (addresses).
- **Scope** — *This app only* or *All apps* (which writes into the global user list). [PROPOSED]
  The requirement describes both per-app rules and global lists but never says how a global rule
  gets created from an observed flow; this is the obvious path.

---

## 8. Consequences worth stating plainly

**Safari is filterable, and can be locked down entirely.** `com.apple.mobilesafari` ships with
Allow-all on, so it is unfiltered *by default* — but a global deny list still applies to it, which is
what the milestone-1 `google` test relied on, and that test still works under this model. Turning
Safari's Allow-all off puts all web traffic under default-deny and into the Observed list.

**Default-deny will break most third-party apps immediately.** That is the intent, but it means
first run is unusable until the user has worked through the Observed lists — accepted, see Q8.

**Local and link-local traffic is in scope.** `rapportd` reaching `fe80::` peers has no hostname and
no useful address rule; under default-deny, Handoff, AirDrop and AirPlay stop working. It is
`com.apple.rapportd`, so its pre-enabled Allow-all rescues it — and turning that toggle off is how
you would find out exactly what Continuity talks to. [DERIVED]

**Blocking a flow does not prevent the DNS lookup.** Name resolution happens in the system resolver,
not in the app's process, and is a separate flow attributed to a system daemon. Hostname rules
therefore stop the *connection*, not the *query*. [DERIVED]

**A rule can be unenforceable for a given flow.** A domain rule cannot match a flow that arrived
with no hostname, and an address rule cannot match one that arrived with no address. Under
default-deny this fails safe, but it means an app can appear to ignore an allow rule when the flow
simply lacked the field the rule keys on. The Observed list should show which fields were present.

---

## 9. Questions

**All nine resolved.** Q1 Apple exemption is a default, not an override · Q2 precedence is symmetric ·
Q3 `*.x` is strictly subdomains · Q4 CIDR is canonical · Q5 a web list must fetch before it can be
added · Q6 Observed list is bounded and persisted · Q7 private `LSApplicationProxy` for icons ·
Q8 no monitor mode · Q9 blanket settings are mirrors, consulted last.

The remaining `[PROPOSED]` items are implementation choices rather than product decisions, and the
`[VERIFY]` items in §5 are the only things that could still force a design change.

**[Q1] Apple exemption vs global lists — RESOLVED.**
The exemption is a blanket **default**, not an override: L4 sits below L2/L3, so global lists and
per-app rules apply to Apple apps and Safari remains filterable. "`com.apple.*` → ALLOW ALL" means
"skips default-deny".

**[Q2] Precedence symmetry — RESOLVED.**
Symmetric. L1 beats L2/L3 in both directions; a per-app allow overrides a global deny just as a
per-app deny overrides a global allow.

**[Q3] Suffix apex — RESOLVED: `*.example.com` does not cover `example.com`.**
Strict subdomain semantics. Covering both takes two rules. The apex is still reachable from the UI
because a flow to the apex generates its own chain. One consequence: imported web lists use the
opposite convention, so a bare domain in a list expands to exact + subdomains — see §4.

**[Q4] Address notation — RESOLVED: CIDR.**
CIDR is canonical everywhere, with the IPv4 octet wildcard kept as a secondary label. Presets are
`/32 /24 /16 /8` and `/128 /64 /48 /32`; the global list editor accepts any prefix length.

**[Q5] Web list failure — RESOLVED.**
A subscription cannot be added unless the first fetch succeeds, so the never-fetched case cannot
exist. Later refresh failures keep the last good copy and are surfaced on the list screen.

**[Q6] Observed list bounds — RESOLVED.**
Bounded per app at a few hundred rows, least-recently-seen eviction, persisted across launches and
reboots.

**[Q7] App icons and names — RESOLVED.**
Private `LSApplicationProxy`, with the isolation and fallback constraints in §7.1. The app is not
going to the App Store.

**[Q8] Monitor mode — RESOLVED: none.** The Apple exemption is the jump-start.

This holds, and the milestone-1 captures are the evidence. Every flow observed during several
minutes of normal use was attributed either to `com.apple.*` or to an identifiable third-party app;
**no flow arrived unattributed.** The system-critical traffic — push, DNS, iCloud, Mail, App Store,
Handoff, analytics, `symptomsd`, `rapportd` — is all `com.apple.*`, so L4 keeps the device fully
functional with no rules configured at all.

What this does mean, stated plainly:

- **Every third-party app is completely dead on first run**, including retry storms against a wall.
  Intended, but it makes the Observed list the *only* recovery path — which is why §5 routes
  default-denied flows through `.needRules()`, the one channel with guaranteed delivery.
- **`<unattributed>` was never observed**, but if it ever appears it is denied by L6 and could be
  something the OS needs. It should be surfaced prominently rather than buried in one app's list.
- Triaging from a deny-everything baseline shows you what an app *asks for*, not what it *needs*.
  Expect to over-allow at first and tighten later; the alternative was never going to be better.

**[Q9] Allow-all vs per-app deny — RESOLVED.**
Allow-all means *allow everything not banned by this app's deny list or by a global deny list*, and
Deny-all is its exact mirror: *deny everything not permitted by this app's allow list or by a global
allow list*. Both are blanket defaults consulted last. Consequently the Apple exemption is modelled
as `Allow all` pre-enabled rather than as a resolver tier of its own.

---

## 10. Not in this revision

Port and protocol conditions; direction-specific rules; time-based rules; per-interface rules;
rule import/export; multi-device sync; any traffic modification. The engine's internals (prefix trie
layout, blob format, matching cost) are a separate document.
