#!/usr/bin/env python3
"""Join a device log's escalation lines and report whether .needRules() holds up.

Milestone 1.5 asks two questions that only a device can answer:

  1. Does .needRules() followed by a control-provider .drop() actually drop the flow?
  2. Can the control provider keep up when escalation is the common case?

The data provider cannot write anything, so its side of the story exists only in OSLog. This joins
the two processes' lines by flow id. Both timestamps come from CLOCK_UPTIME_RAW, which is
system-wide monotonic, so the differences are real cross-process latencies rather than estimates.

    tools/escalation-report.py ~/device.log

Capture with:

    idevicesyslog -u "$(idevice_id -l | head -1)" -p "FilterData|FilterControl" -o ~/device.log
"""

import re
import sys
from collections import OrderedDict

ESCALATE = re.compile(r"ESCALATE id=(\S+) t=(\d+) app=(\S+) host=(\S+) rule=(\S+)")
RECV = re.compile(r"CTLRECV id=(\S+) t=(\d+)")
DONE = re.compile(r"CTLDONE id=(\S+) t=(\d+) verdict=(\S+)")


def percentile(values, fraction):
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1))))
    return ordered[index]


def main(path):
    escalated = OrderedDict()
    received, done = {}, {}

    with open(path, "r", errors="replace") as handle:
        for line in handle:
            if (m := ESCALATE.search(line)):
                escalated[m.group(1)] = {
                    "t": int(m.group(2)), "app": m.group(3),
                    "host": m.group(4), "rule": m.group(5),
                }
            elif (m := RECV.search(line)):
                received[m.group(1)] = int(m.group(2))
            elif (m := DONE.search(line)):
                done[m.group(1)] = (int(m.group(2)), m.group(3))

    if not escalated:
        print("No ESCALATE lines found.")
        print("Set deny mode to 'escalate' in the app, tap Apply, then generate blocked traffic.")
        return 1

    arrived = [fid for fid in escalated if fid in received]
    missing = [fid for fid in escalated if fid not in received]
    dropped = [fid for fid in arrived if done.get(fid, (0, ""))[1].endswith("DROP")]

    round_trips = [(received[f] - escalated[f]["t"]) / 1e6 for f in arrived]
    control_work = [(done[f][0] - received[f]) / 1e6 for f in arrived if f in done]

    print(f"escalated by data provider : {len(escalated)}")
    print(f"reached control provider   : {len(arrived)}")
    print(f"never arrived              : {len(missing)}"
          f"{'   <-- FAILURE MODE' if missing else ''}")
    print(f"control returned a drop    : {len(dropped)}")

    if round_trips:
        print()
        print("data -> control round trip (ms)")
        print(f"  min {min(round_trips):7.2f}   p50 {percentile(round_trips, .5):7.2f}"
              f"   p95 {percentile(round_trips, .95):7.2f}   max {max(round_trips):7.2f}")
    if control_work:
        print("control provider own work (ms)")
        print(f"  min {min(control_work):7.2f}   p50 {percentile(control_work, .5):7.2f}"
              f"   p95 {percentile(control_work, .95):7.2f}   max {max(control_work):7.2f}")

    if missing:
        print()
        print("Escalations the control provider never saw — these flows got no verdict from it:")
        for fid in missing[:10]:
            entry = escalated[fid]
            print(f"  {fid}  {entry['app']}  {entry['host']}  rule={entry['rule']}")
        if len(missing) > 10:
            print(f"  … and {len(missing) - 10} more")

    print()
    if missing:
        print("VERDICT: escalation is lossy. Deny must be decided inline; recording has to fall")
        print("         back to NEFilterReport only. See docs/firewall-rules.md section 5.")
    elif len(dropped) < len(arrived):
        print("VERDICT: every escalation arrived, but not every one produced a drop. Check the")
        print("         CTLDONE verdicts above before trusting the escalate path.")
    else:
        print("VERDICT: escalation is reliable at this rate. The design in")
        print("         docs/firewall-rules.md section 5 holds.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
