# CsvSessionGuard

**Detects and repairs permanently stuck Cluster Shared Volume SMB sessions on Windows Server
failover clusters.**

A single self-contained executable. No dependencies, no configuration file, no agent, no network
manager — because the network faults that produce stuck sessions are the same faults that cut a node
off from anything external.

---

## Why this matters: it ends in a cluster-wide CSV pause

> A stuck session silently removes one of the node's paths to its CSV **coordinator**. If that takes
> the count to **zero**, the next ordinary network transient makes the node lose its CSV session
> instead of failing over — which triggers a **CSV autopause**. A CSV pause is **volume-wide, not
> node-wide**, so **every VM on that volume, on every node, stalls.** In the measured estate: **62
> seconds** of frozen guest I/O, plus a second pause cycle on reconnect. Nodes with full channel
> counts rode through the same transient untouched.

The stuck session does not pause CSV by itself. It removes the redundancy that would have absorbed
the transient — and it does so **invisibly**: on a node with 51 simultaneously stuck sessions,
`Get-SmbMultichannelConnection` reported `Failed = False` on **every** row. Cluster validation won't
show it either.

## The fault in one paragraph

A CSV SMB session can enter a state the operating system never recovers from.

Adding an SMB channel normally reuses a **cached** Kerberos ticket for that peer — the warm path, and
it works. When nothing is cached, the bind falls back to the **full PKU2U certificate exchange**, and
**that cold path is the one that fails**: the client rejects its own peer's signed interim reply, logs
`SMBClient 31013` (`0xC0000016`), and retries the same connection on a 60-second timer **until
something external clears it**. The coordinator logs `SMBServer 551` (`0xC000000D`) for every attempt
— 7,470 per hour in the measured incident, for 21 hours.

Because it is a **cold-authentication** fault, it clusters around anything that forces a cold bind:
cluster start and node joins, reboots, NIC resets and link transients, cluster network role changes.
It is not load-related, and a steady-state cluster can run for weeks clean — four nodes were measured
at 34–40 days uptime with zero events.

**[Read ISSUE.md for the full research, the evidence, and the cluster risk in detail.](ISSUE.md)**

This is a **workaround for a Windows defect**, not a fix. No cluster misconfiguration causes it, and
none of the settings tested prevents it — though every cluster-enabled network adds another subnet on
which CSV binds channels, and therefore more exposure.

---

## Status

| | |
|---|---|
| Detection | Field-proven. Found 51 stuck sessions on a loaded node; correctly reported zero on three other loaded nodes |
| Repair | Field-proven once, on one real incident: 51 stuck sessions, 1 reset, storm ended and did not return |
| Reports | Verified on a live cluster node: an open report survives a restart and closes on its own; a foreign or unreadable state file is announced and replaced |
| Self-tests | 172 deterministic checks, several built from recorded production event sequences |
| Runtime | Four nodes, no errors, no watchdog expiries, no event-log query timeouts |
| Default behaviour | **Detect-only. Nothing is ever reset unless you pass `-repair`.** |

---

## Quick start

```cmd
build.cmd
```

Builds with the in-box .NET Framework compiler — no SDK, no NuGet, no project file — then runs the
self-tests. Then, **read-only, changes nothing**:

```cmd
CsvSessionGuard.exe -once
```

It prints the effective configuration, the reset control code and where it came from, how many
`31013` records are in the window, every session that meets the criteria, and **the distinct peer
addresses a repair would reset**. Exit code `0` = nothing stuck, `1` = stuck session found, `2` = bad
arguments, `3` = the event log could not be read (run it elevated), `4` = the event-log query timed
out, `9` = an unexpected error.

Before enabling repair, check the blast radius for yourself:

```powershell
Get-SmbMultichannelConnection -SmbInstance CSV |
  Group-Object ServerIpAddress |
  ForEach-Object { "{0,-16} {1}" -f $_.Name, (($_.Group|Measure-Object CurrentChannels -Sum).Sum) }
```

A scoped reset of one address drops only that address's channels. Everything else survives.

Then install as a service:

```cmd
CsvSessionGuard.exe -install -repair
```

**Install it on every node.** Detection is client-side only — a node that is the *server* of a stuck
session logs nothing and will correctly report "nothing stuck" while thousands of failed binds per
hour arrive at it. The guard only ever helps the node that is the stuck client, and any node can
become one.

---

## How detection works

A transient channel retry and a stuck loop look identical if you only count events. The
discriminator is **retries on a single connection that is never abandoned**. Measured over an hour
mid-incident: three local ports, unchanged for the full 59 minutes, carrying ~1,450 failed binds
each. A transient instead fails at most **2** times on a port and is done with it; the lowest stuck
session observed reached **3** ([ISSUE.md §2](ISSUE.md)).

The default threshold of 3 sits **one** above the transient ceiling. That margin of one is the
narrowest part of the design — tune it if your cluster differs, and use `-once` first.

All four must hold within the look-back window:

| Criterion | Default | Why |
|---|---|---|
| `31013` events for the session | ≥ 3 | floor only |
| **Retries on one local port** | **≥ 3** | **the real discriminator** — transients top out at 2 per port; the lowest observed stuck session reaches 3. Margin of one: tune it if your cluster differs |
| Loop duration | ≥ 20 s | backstop |
| Most recent event | within 120 s | the loop must still be live |

`ports=N maxPerPort=M` in the output is **per session, within the window** — not a lifetime count.
A session showing `maxPerPort=5` is not one that gives up after five attempts; the underlying
connection may have been retrying for hours.

This is deliberately conservative. In the field repair, post-reset rebind churn peaked at 165
events/minute and was correctly **not** classified as stuck, because no single session reached three
retries on one port.

Silence is only treated as evidence when the `SMBClient/Security` channel is present and enabled, so
a disabled or missing log cannot be mistaken for a healthy node.

---

## How repair works

Issues FSCTL `0x1401A8` on `\Device\SmbCsv` via `NtFsControlFile`, which disconnects this client's
CSV SMB connections to a named peer so the redirector rebuilds them. Byte-level calling convention
is in [ISSUE.md §7](ISSUE.md).

**The control code comes from Windows itself where it can.** The cluster service sends this same
request, from its own disconnect function in `C:\Windows\Cluster\clussvc.exe`. At start, the guard
reads the code from that function. It accepts the result only when exactly one function there passes
all three checks:

- it makes the call in two or more places, always with the same code;
- it checks the result for "server not found" (`0xC0000034`), which it does not report as a failure;
- its request is built with the layout the guard uses.

Anything else keeps the built-in `0x1401A8`: the file missing, unreadable or slow to read, or no
single match. Event 1002 names the code in use and where it came from. If the cluster service uses a
different code, a 4000 Warning says so and the guard follows the cluster service.

In 25 builds of `clussvc.exe` from 2016 to 2026 the code is always `0x1401A8`. The reader finds it in
every build from version 1903 onward. It finds no single match in older builds, so the built-in
value is used there. Across all those builds and the 6,372 64-bit binaries in a Windows 11
`System32`, it never returned a wrong number.

**Scoped by default.** One reset per distinct failing peer address, taken from each event's
`RemoteAddress`. Only that subnet's connections to that peer are dropped; connections to the same
peer on other cluster networks survive. Measured on a node with 19 CSV channels: a scoped reset
dropped **3** and retained **16**, and the in-use session holding 29 open handles stayed up.

If the events carry no usable remote address the repair is **skipped**, not silently widened.
`-allowwholepeer` opts into the wide form, which drops every CSV connection to the peer including
healthy ones.

**Deduplicated before any reset is issued.** Stuck sessions overwhelmingly share one peer address —
in the field case all 51 pointed at the same one. They are grouped by address and each address is
reset **once**, on its own thread, all dispatched together. Without this, 51 stuck sessions would
mean 51 identical resets of the same address.

**No repair limit and no queueing.** A detected session is always repaired. An unrepaired stuck
session is live exposure, so nothing throttles, caps or defers the work. The only gate is **one
in-flight repair per session**, released the moment its verification reaches a verdict — so a session
that still meets the criteria is repaired again at the next sweep rather than waiting out a timer. A
failsafe ceiling (`-verifydelay` + 120 s) releases an entry whose thread died without reaching a
verdict.

In the field this produced two rounds and then silence: round one at `20:03:08`, round two at
`20:06:00`; the session's last retry came at `20:18:00`, and nothing has qualified since. No runaway.

---

## Verification

A single pass is not a guaranteed fix — the reset destroys connections, never the session object,
and whether the session is then retired or rebuilt stuck is decided inside the kernel.

So every repair is observed, 90 seconds later, from the **times** of retry events relative to the
instant the FSCTL was issued. The result is an **interim** verdict, never the outcome:

| Events after the reset | Interim verdict |
|---|---|
| none | no retry seen (3001) |
| exactly one | ambiguous — a dead loop can leave one straggler. Looked at once more, decided on whether a **new** event arrives |
| two or more | retries continued (3004); another pass follows if the session still meets the criteria |

The 90-second floor is not arbitrary: the retry loop is a **60-second timer**, so a shorter
observation can see zero events from a loop that is perfectly alive.

The outcome is decided only by silence. A stuck-session report closes (2002, then 2005 or 2006) once
no retry remains in the look-back window and a second check, at least 100 seconds after the first
check that found none, confirms it, with the retry event channel enabled at both. The 100 seconds is
`max(-recent, 120)` less `-debounce`, never under half of it; event 1002 shows the value in effect.
At default settings a report closes about 12 to 14 minutes after its last retry.

---

## What it will never do

- Reset anything unless you pass `-repair`.
- Widen a scoped reset on its own. No address, no repair.
- Touch a VM, a cluster resource, a CSV coordinator, a network setting or a registry value.
- Write outside its own directory and its own event source.
- Reboot, drain, pause or fail over anything.
- Auto-register its event source against the wrong log.
- Send a reset with an empty peer name. The driver would apply an empty name to every server.
- Call `DeviceIoControl` on the control code (it would never reach the handler — see
  [ISSUE.md §7](ISSUE.md)).

Every external call — the event-log query, each log write, the channel check, each state-file read
and save, and the kernel call — runs under its own watchdog, so a wedged `EventLog` service, a hung
disk or a blocked kernel call cannot hang the service.

---

## Events

Written to the **`CsvSmbSessionGuard`** source in the **Application** log:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Application'; ProviderName='CsvSmbSessionGuard' }
```

Filter server-side with `-FilterHashtable`, not by piping the whole log into `Where-Object` — the
latter renders every event in the Application log before discarding it (measured 1.6 s versus 0.1 s
on a small log, and it scales with log size, not with the number of matches).

| ID | Level | Meaning |
|---|---|---|
| 1000 / 1001 | Information | service started / stopped |
| 1002 | Information | effective configuration at start, including when a report closes and the reset control code in use, with its source |
| 2000 | Warning | stuck session detected; carries its report number. A 15-minute reminder after resets names the reset count |
| 2001 | Information | detect-only: nothing was changed |
| 2002 | Information | a reported stuck session has no retry left in the look-back window; names the report and the warnings it supersedes |
| 2005 | Warning | **reports open**: every session reported stuck and not yet confirmed to have stopped, each with its observed state, plus sessions retrying in the window that are not reported |
| 2006 | Warning | **no report open**: names every report it closes and the earlier warnings they supersede |
| 3000 | Information / Warning | reset issued — includes the session count, the distinct address count, and the decoded control code; also "no connection to this peer address remained, so nothing was reset" |
| 3001 | Information | interim: no retry followed the reset during verification |
| 3002 | Error | a reset was refused (rejected, the control code or its request not accepted, or a blank peer name) or skipped for want of a peer address |
| 3003 | Information | repair not reissued — this session's own repair is still in flight |
| 3004 | Information | interim: retries continued after the reset; the repair is not yet confirmed |
| 4000 / 4001 | Warning or Error / Error | error / watchdog expiry; also the start notice, "could not be saved", "retry event channel disabled / could not be checked", and "the cluster service uses a different reset control code" |
| 5000 | Information | hourly summary: current state (reports by state, retries not reported, sessions under repair, channel), activity counters, guard health |

The newest **2005 or 2006** answers "which sessions are reported stuck now?" at a Warning filter.
They are Warnings so that they appear next to the warnings they supersede: for raise-only alerting,
raise on 2000 and 2005 and resolve on 2006. Two things to allow for in those rules:

- A `-console` run beside the service writes its own 2000, 2005 and 2006 to the same source. Every
  report-bearing event carries an `Instance` field (`service, process <pid>` or
  `console, process <pid>`); alert on the service's.
- While reports are open, stopping the service writes a 2005 whose `Trigger` is `stop`, and the
  next start writes one whose `Trigger` is `resume`, so a raise-on-2005 rule fires again across a
  restart.

If the event log cannot be written, entries go to `guard.log` beside the executable. Nothing is
written to `ProgramData`. The service keeps its open stuck-session reports in `guard.state` beside the
executable, so reports survive restarts. Each save writes `guard.state.tmp` and then swaps it in. A
state file the service cannot use (unreadable, or written on another node) is kept as
`guard.state.bad` for inspection, replacing any older one. `-uninstall` leaves these files in place,
so reinstalling with new options resumes the open reports.

### Event changes since the first release

If you run the first release, these changed:

1. **New Warnings 2005 and 2006**, including resolutions. Raise alerts on 2000/2005; resolve on 2006.
2. **3002 is no longer written at Warning.** Interim verdicts are 3004 Information.
3. **3001 is interim.** It no longer says "repaired successfully".
4. **2002 comes only after confirmed silence** — about 12 to 14 minutes after the last retry at
   default settings — and never when a session merely dips below the detection threshold.
5. **5000:** "Repairs confirmed" and "Repairs that did not hold" are removed. "Stuck sessions
   detected" becomes "Detection matches" (counted once per session per evaluation). A "Current state"
   section is new.
6. **Fewer repeats:** after a dip or a restart there are fewer 2000/2001/3003 events, and a 2000
   reminder names its reset count.
7. **"Matched nothing" is now 3000 Information**, not a 3002 Error, and so is a peer that had no
   connections left. The no-address 3002 follows the 15-minute announcement cadence.
8. **New 4000 messages:** the start notice ("Stuck-session reports from before this start, if any, are
   not tracked"), written once per node on the first start after this upgrade and again only if
   `guard.state` is lost or unreadable; "The stuck-session reports could not be saved"; and "The
   retry event channel is disabled / could not be checked, so no stuck-session report can close".
9. **Alerts left raised:** when the start notice ends tracking there is no 2006, so alerts raised on
   earlier 2000s or 2005s — and, after an upgrade, on the old binary's 3002 Warnings — must be
   cleared by hand.
10. **New file `guard.state`** (and `.tmp` / `.bad`) beside the executable, written by the service only.
11. **New fields:** `Report`, `Reported since`, `Verdict status`, `Final outcome`, `Supersedes`,
    `Instance`, `Trigger`, `Tracking`.
12. **`-once -repair`** prints the new verdict and 3000 texts.
13. **The reset control code is read from the cluster service at start**, falling back to the
    built-in `0x1401A8`. Event 1002 names the code and its source, and a 4000 Warning appears if the
    cluster service's code differs.

---

## Commands

```
CsvSessionGuard.exe -once [-repair]      evaluate once and exit; read-only unless -repair
CsvSessionGuard.exe -console [options]   run in the foreground, Ctrl+C to stop
CsvSessionGuard.exe -install [options]   create the event source and service, then start it
CsvSessionGuard.exe -uninstall           stop and delete the service, remove the event source
CsvSessionGuard.exe -selftest            run the built-in checks and exit
CsvSessionGuard.exe -help                full option list
```

`-install` accepts `-manual` (create it Manual rather than Automatic) and `-nostart` (create it
without starting, so the first start is deliberate). Service recovery is configured automatically:
restart after 60 s / 60 s / 300 s, failure count reset hourly.

Policy values are stored in the service ImagePath, so the running configuration is readable with
standard tools:

```cmd
sc qc CsvSessionGuard
```

To change options, uninstall and reinstall with the new ones.

---

## Options

| Option | Default | Effect |
|---|---|---|
| `-repair` | off | **enable repair. Without it the tool only detects.** |
| `-allowwholepeer` | off | permit the wide reset when no failing peer address is known |
| `-window N` | 10 | `31013` look-back, minutes |
| `-minevents N` | 3 | events required in the window |
| `-mineventsperport N` | 3 | retries on one connection before acting — the discriminator |
| `-minspan N` | 20 | loop must span this many seconds |
| `-recent N` | 120 | last event must be within this many seconds |
| `-sweep N` | 120 | timer cadence, seconds |
| `-debounce N` | 20 | minimum gap between evaluations, seconds |
| `-verifydelay N` | 90 | wait before judging a repair, seconds (floor 65) |
| `-verifygrace N` | 0 | treat events within N seconds of the reset as in-flight rather than as retries |
| `-fsctltimeout N` | 30 | watchdog on the kernel call, seconds |
| `-querytimeout N` | 45 | watchdog on the event-log query, seconds |
| `-logtimeout N` | 5 | watchdog on each log write, each state-file read or save, and the start-up read of `clussvc.exe`, seconds |
| `-heartbeat N` | 60 | summary cadence, minutes; 0 disables |

An unrecognised argument prints usage and exits `2`.

---

## Requirements

- Windows Server failover cluster node with Cluster Shared Volumes.
- .NET Framework 4.x — present by default on Windows Server 2012 R2 and later.
- Runs as **LocalSystem**. The kernel control code requires it.
- Developed and proven on **Windows Server 2025**. The same fault has also been observed on
  **Windows Server 2019**, where stuck sessions likewise had to be cleared by intervention rather
  than recovering on their own ([ISSUE.md §4](ISSUE.md)).

---

## Build

```cmd
build.cmd
```

Or directly:

```cmd
"%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe" ^
    /target:exe /platform:anycpu /optimize+ /warn:4 /out:CsvSessionGuard.exe ^
    /r:System.ServiceProcess.dll /r:System.Core.dll /r:System.Xml.dll ^
    src\CsvSessionGuard.cs src\CsvSessionGuardTests.cs
```

The full path is required — the .NET Framework compiler is **not on `PATH`** on a default Windows
Server install.

C# 5 against that in-box compiler, so no string interpolation, no null-conditional operator, no
`out var`, no expression-bodied members. Builds with **no warnings at `/warn:4`**.

**Always run `-selftest` after building.** The test suite is compiled into the executable precisely
so that the binary you deploy is the binary that was tested.

---

## Limitations

- **A workaround, not a fix.** The defect is in Windows. There is no vendor root-cause analysis.
- **The control code is undocumented and unsupported.** Verify on a test cluster first. The guard
  takes it from the cluster service when it can (see "How repair works"). The decoded device,
  function and method are logged on every call, so a Windows build that renumbers it can be
  identified from the log alone.
- **Reactive.** It repairs a stuck session once the retry loop is established; it does not stop the
  bind from sticking.
- **Field-proven on one cluster and one real incident.** Detection has broader coverage: it ran
  clean on four loaded production nodes with no false positives.
- **One observation remains unexplained.** After the field repair, the channel on the affected
  network did not re-establish; CSV continued on the other two cluster networks and the client
  stopped attempting the third. See [ISSUE.md §9](ISSUE.md).

---

## Contributing

The most valuable contributions are **data**:

- Confirmation or contradiction of the signature on other Windows versions and builds. It is
  confirmed on Server 2019 and Server 2025 in one estate; the boundaries are unmapped.
- Any case where the repair fails repeatedly on the same session.
- Any case where **two or more distinct peer addresses** are stuck at once. All field occurrences so
  far resolved to a single address, so the parallel reset path has unit-test coverage but no
  production exercise.
- Whether a reset channel re-establishes on your cluster.

Please include event IDs, status codes, exact timestamps and per-minute rates. Summarise SMB
authentication fields — **never paste raw authentication blobs** from `31013` or `551` events.
