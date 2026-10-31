# Stuck CSV SMB sessions on Windows Server Failover Clusters

**A Cluster Shared Volume SMB session can enter a broken state that the operating system never
recovers from.** Observed on Windows Server 2019 and Windows Server 2025.

## Why you should care: it ends in a cluster-wide CSV pause

The event-log noise is not the problem. This is the problem:

1. A stuck session is a **failed** session, so the node silently loses one of its paths to the CSV
   **coordinator**. Working sessions keep working, so nothing looks wrong.
2. **No health check shows it.** Measured on a node with 51 simultaneously stuck sessions,
   `Get-SmbMultichannelConnection` reported `Failed = False` on every row. Cluster validation won't
   show it either. You have lost N-1 resilience on the CSV path and nothing tells you.
3. If stuck sessions take a node's channel count to a coordinator to **zero**, the next ordinary
   network transient makes that node **lose its CSV session** instead of failing over to another
   channel.
4. Losing the session triggers a **CSV autopause** — and a CSV pause is **volume-wide, not
   node-wide.**
5. **Every VM on that volume, on every node in the cluster, stalls.** In this estate: **62 seconds**
   of frozen guest I/O, and the degraded node's slow reconnect triggered a **second** pause cycle.
   *(Steps 3–5 are from this estate's earlier incident investigation — see §5.2. Steps 1–2 were
   measured directly during the repair in §8.)*

Nodes that still had their full channel counts rode through the identical transient with no impact.

**So: the stuck session does not pause CSV by itself — it removes the redundancy that would have
absorbed a transient.** Transients are unavoidable. This defect is what turns a survivable blip into
a cluster-wide outage, and it does so invisibly. Sixty-two seconds of stalled guest I/O is long
enough to fail application timeouts, drop database connections, trigger guest-cluster failovers and
time out storage-backed workloads.

Full mechanism and evidence in [§5](#5-the-danger-to-the-cluster).

---

This document is the research behind [`CsvSessionGuard`](README.md). It is written so that another
administrator can recognise the fault on their own cluster, understand the risk, and decide whether
the workaround is worth running.

> **Provenance.** Field data comes from a production four-node Windows Server 2025 Hyper-V cluster
> with iSCSI storage, plus a four-node Server 2019 cluster in the same estate. Two classes of
> evidence are mixed here and are labelled where they appear:
>
> - **Directly measured** during the repair documented in §8 — event fields, status codes, per-minute
>   and per-hour rates, per-port counts, channel counts, uptimes, onset timings. These were read off
>   live systems and the queries are reproducible from §1.
> - **Reported** from the same estate's earlier investigation of this fault — the packet-capture
>   ratio in §3, the CSV-freeze incident in §5.2, the eliminated hypotheses in §6, and the FSCTL
>   buffer layout in §7. These are not re-verified in this document and are marked **[reported]**.
>
> Host names and IP addresses are replaced with documentation values (RFC 5737 `192.0.2.0/24`).
> Event IDs, status codes, field names, byte offsets, rates and timings are unaltered.

---

## 1. Do you have it? Two commands

Run on **every** node — the fault is visible on the client side only (see §5).

```powershell
# Client side. Each event is one failed attempt to bind a CSV SMB channel.
Get-WinEvent -LogName 'Microsoft-Windows-SMBClient/Security' `
             -FilterXPath '*[System[(EventID=31013)]]' -MaxEvents 20 |
  Select-Object TimeCreated, Id

# Server side, on the CSV coordinator. The mirror image of the same failures.
Get-WinEvent -LogName 'Microsoft-Windows-SMBServer/Security' `
             -FilterXPath '*[System[(EventID=551)]]' -MaxEvents 20 |
  Select-Object TimeCreated, Id
```

**A handful of events spread over months means past episodes, not an active loop** — but read §4
before concluding a quiet log means a healthy node. What identifies an *active* loop is the *rate*:

```powershell
$q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery(
      'Microsoft-Windows-SMBClient/Security','LogName',
      "*[System[(EventID=31013) and TimeCreated[timediff(@SystemTime) <= 600000]]]")
$r = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($q)
$n = 0; while ($r.ReadEvent()) { $n++ }
"31013 in the last 10 minutes: $n"
```

**A sustained rate of tens per minute means one or more sessions are stuck in a permanent retry
loop.** In the measured incident this sat at **72.5 per minute on the client and 124.5 per minute on
the server, unbroken for 21 hours.**

Do not use `Get-WinEvent | Measure-Object` on these channels. Message rendering makes it
pathologically slow at six-figure event counts. `EventLogReader` skips rendering.

---

## 2. The signature

### Client, `Microsoft-Windows-SMBClient/Security` event **31013**

Fields are under `Event/EventData`:

| Field | Value |
|---|---|
| `Smb2Command` | `1` — SESSION_SETUP |
| `Status` | `3221225494` = **`0xC0000016`** `STATUS_MORE_PROCESSING_REQUIRED` |
| `TreeId` | `0` — no share is reached; it fails during session setup |
| `ServerName` | `\fe80::…%N` — the peer's **NetFT** link-local address, with a leading backslash and the interface-zone suffix |
| `RemoteAddress` | 16-byte `sockaddr` hex, e.g. `020001BD C0000215 …` → family `0x0002` AF_INET, port `0x01BD` = **445**, address `192.0.2.21` — the coordinator being reached |
| `LocalAddress` | the same form for this node's own address |
| `MessageId` | increments per attempt |

### Server, `Microsoft-Windows-SMBServer/Security` event **551**

Fields are under `Event/UserData/EventData` — **not** `Event/EventData`. This difference will bite
any script that assumes one shape for both.

| Field | Value |
|---|---|
| `Status`, `TranslatedStatus` | **`0xC000000D`** `STATUS_INVALID_PARAMETER` |
| `ReasonCode` | `3` |
| `ClientName` | `\\192.0.2.18` — the stuck client |
| `ClientAddress` | `sockaddr` hex |
| `SessionGUID` | **a new GUID on every single attempt** |
| `UserNameLength` | `0` — authentication never completes, so no user is ever established |
| `SPN` | present |

That `SessionGUID` detail matters, and the two ends disagree in a way that is itself diagnostic. In
the same sampled hour:

| | |
|---|---|
| Server: events / distinct `SessionGUID` | 4,350 / **4,350** |
| Client: events / distinct `SessionId` | 4,350 / **51** |

The client is retrying 51 sessions. The server is minting a **brand-new session object for every
single attempt** and abandoning it. That asymmetry is why server-side counts cannot be used to
estimate how many client sessions are stuck.

### The cadence is a giveaway

The retry loop is driven by a **60-second timer, phase-locked to the wall clock minute.**

Two resolutions were measured, and they are stated separately because they prove different things:

- **Per minute**, over an 18-minute sampled window: a metronomic **50 / 95 / 50 / 95** alternation
  with no deviation at all.
- **Per hour**, across the whole storm: exactly **4,350** events/hour on the client for roughly
  sixteen consecutive hours (7,470/hour on the coordinator), before declining.

Nothing load-driven holds a figure that rigid for that long. If your per-minute counts alternate
between two fixed values, or your hourly counts repeat an identical number, you are looking at this
defect and not at congestion.

### The connection is never abandoned, and that is the detection key

A stuck session does **not** open a fresh connection per attempt and does not give up on one. It
keeps retrying the **same TCP connections indefinitely**.

Measured over one full hour taken from the middle of the storm, decoding the `LocalAddress` port out
of every event:

| | |
|---|---|
| Events in the hour | 4,350 |
| Distinct `SessionId` values | 51 |
| **Distinct local ports** | **3** |
| Events per port | 1,410 / 1,410 / 1,530 (mean 1,450) |
| **How long each port stayed in use** | **59 minutes — the whole slice** |

Three connections, unchanged for the entire hour, carrying ~1,450 failed binds each. SMB multiplexes
sessions over a connection, so all 51 stuck sessions shared those same three ports.

**Do not read "3 ports" as a signature.** That hour involved one peer. A different node in the same
cluster, measured over ten days and seven distinct peers, shows **452** distinct local ports. The
port count scales with elapsed time and with the number of affected peers; what is diagnostic is the
**number of retries on a single port**, not how many ports exist.

**This is what separates a stuck session from a transient, and why counting total events cannot.** A
busy cluster can produce a large event total from many harmless transients; only a stuck session
accumulates repeated retries on *one connection that is never abandoned*.

**[reported]** values from the source environment's earlier investigation:

| | retries on one local port |
|---|---|
| Ordinary transient channel retry | **at most 2**, then that port is done with |
| Lowest stuck session observed | **3** |

A threshold of **3** therefore sits immediately above the transient ceiling. **The margin is one.**
It is the narrowest part of the whole design, it is deliberately configurable, and a cluster whose
transients retry three times on a port will produce false positives — which is why the default mode
is detect-only and `-once` prints exactly what it would reset before you ever enable repair.

> **Reading the tool's own output:** `ports=N maxPerPort=M` is **per session, within the look-back
> window** (10 minutes by default), not a lifetime figure. In the incident above each session showed
> `ports=3 maxPerPort=5` — three channels, about five retries on each per ten minutes — while the
> underlying ports themselves had by then been retrying for twenty-one hours. Do not read `maxPerPort`
> as "it gives up after that many".

**[reported]** After a connection reset, a rebuilt connection is identifiable: a local port never
seen before, `MessageId` back to `1`, and a longer security blob.

---

## 3. The mechanism

### Why it happens at all: a cold bind has nothing cached to reuse

Adding an SMB channel to a CSV session normally **reuses a cached Kerberos ticket** for that peer.
That is the warm path, and it works.

When there is nothing cached for the target, the bind cannot take the warm path. It falls back to the
**full PKU2U certificate exchange** — an AS-REQ, negotiating authentication from scratch. **That cold
path is the one that fails.**

This single fact explains the fault's whole behaviour:

| Observation | Explanation |
|---|---|
| It concentrates at **cluster start and node joins** | Nothing is cached yet. The first `CSV$` session to each coordinator is a cold bind — **[reported]** roughly one in four stuck in this estate |
| A **node reboot** exposes it | The reboot discards the node's cached credential state, so every bind afterwards starts cold |
| A **NIC reset, link transient or network role change** exposes it | Each forces channels to rebind, and a rebind to a target with nothing cached is a cold bind. Measured: enabling a cluster network produced the first failure **one minute** later (§5.3) |
| A **steady-state cluster can run for weeks clean** | Nothing is binding cold. Measured: four nodes at 34–40 days uptime with **zero** events (§4) |
| It is **not** load-related | Volume of VM I/O does not create new channel binds |

So the fault is not random. **It is specifically a cold-authentication fault**, and every trigger in
§5.3 is simply a different way of forcing a cold bind.

On that cold path:

1. The client sends SESSION_SETUP.
2. The server replies with a **signed interim** response carrying
   `STATUS_MORE_PROCESSING_REQUIRED`.
3. **The client rejects its own peer's signed interim reply** and logs `31013`.
4. The client retries. The server rejects the retry with `STATUS_INVALID_PARAMETER` and logs `551`.
5. Go to 3. Forever.

**[reported]** Packet captures from the source environment's earlier investigation separate the two
paths cleanly:

| Channel bind path | Succeeded |
|---|---|
| **Warm** — cached ticket reused | **183 / 183** |
| **Cold** — full PKU2U exchange | **0 / 28** |

Every cold bind failed. Every warm bind succeeded. No exceptions either way. That is the whole
fault — and it is why the fix for *exposure* is to minimise how often channels bind cold, while the
fix for an *already stuck* session is to force the connection to rebuild.

**This is a Windows defect.** No cluster misconfiguration causes it, and none of the settings tested
in §6 prevents it.

What configuration *does* change is **how much exposure you have**: every cluster-enabled network is
another subnet on which CSV will bind channels, and therefore another chance to take the failing
path (§5.3). Reducing enabled networks reduces exposure. It does not remove the defect.

---

## 4. It is not version-specific, and it does not self-recover

The same signature was found on a four-node **Windows Server 2019** cluster in the same estate,
dating back to February 2024, as well as on the Windows Server 2025 cluster. Stuck sessions on the
2019 cluster were real, and they were cleared by **deliberate intervention** — a connection reset or
a node reboot — not by the operating system recovering on its own.

**There is no timeout, no retirement and no self-heal.** A stuck session retries until something
external clears it.

### Do not mistake a quiet log for a healed node

This is the practical trap. On every 2019 node examined, the newest `31013` event **predated that
node's current boot**, and no event had occurred in **34 to 40 days of continuous uptime** since:

| Node | Uptime | Newest `31013` | Events since boot |
|---|---|---|---|
| A | 34.6 days | 2026-09-23 | **0** |
| B | 40.4 days | 2026-09-16 | **0** |
| C | 34.7 days | 2024-04-12 | **0** |
| D | 35.3 days | 2026-09-23 | **0** |

A silent log after a reboot or a repair means the session was **cleared**, not that the fault expired.

### On reading event totals

Do not use retained totals to judge severity between clusters. The 2019 totals reflect that cluster's
exposure history and the interventions performed on it — not a milder defect. Its VM load had also
been migrated away, which reduces exposure.

What *is* directly comparable is the measured rate **while a session is stuck**, and that is the
number that matters: on the 2025 cluster it reached **72.5 events/minute on the client and 124.5 on
the coordinator, sustained for 21 hours**, ending only when the connection was reset.

---

## 5. The danger to the cluster

This is the part that matters, and it is not obvious from the event text.

### 5.1 It silently deletes redundancy, and every health check still passes

A Cluster Shared Volume has exactly one **coordinator** node. Every other node reaches the volume's
metadata over SMB to that coordinator (`CSV$`). Multichannel normally gives each node several
independent channels to the coordinator across several cluster networks.

A stuck session is a **failed** session. The sessions that already work keep working — so a node can
be serving VMs happily while quietly holding fewer paths to its coordinator than you believe.

**And the stuck sessions do not appear in the health cmdlets at all.** Measured on a node with 51
simultaneously stuck sessions:

```
Get-SmbMultichannelConnection -SmbInstance CSV
  →  every row:  Failed = False,  FailureCount = 0
```

Clean. No failures, no warnings, nothing red. The 51 broken sessions are session-setup objects that
never became connections, so they are not in that table. A cluster validation report will not show
them. SCOM will not show them. The only evidence is the event-log rate.

This is the core hazard: **you lose N-1 resilience on the CSV path and nothing tells you.**

### 5.2 Then one ordinary transient freezes every VM on the volume

**[reported]** — this incident is from the estate's earlier investigation, **not** from the repair
documented in §8. It is the reason the fault is treated as a cluster risk rather than as log noise.

A node whose channel count to a coordinator had dropped to **zero** hit a routine network transient.
The sequence:

1. The transient interrupts the coordinator briefly.
2. The degraded node has no surviving channel, so it **loses its CSV session** rather than failing
   over to another channel.
3. Losing the session triggers a **CSV autopause**.
4. The autopause is **volume-wide, not node-wide** — the volume pauses for the whole cluster.
5. **Every VM on that volume, on every node, stalls.** Measured: **62 seconds** of frozen guest I/O.
6. The degraded node's slow reconnect triggered a **second** pause cycle.

Nodes that still had their full channel counts rode through the identical transient with no impact
at all.

**The conclusion from that incident: a cluster-wide freeze needs two things — a transient, and a
degraded mesh. Transients are unavoidable. This defect is what supplies the degraded mesh.** It
converts a survivable blip into a cluster-wide outage.

A 62-second guest I/O stall is long enough to fail application timeouts, drop database connections,
trigger guest cluster failovers and time out SAN-backed workloads.

### 5.3 A routine, correct admin action can detonate it

This is not a dormant risk that waits for bad luck. In the source environment it was triggered by a
**normal, necessary configuration change**: enabling a cluster network for cluster communication
(`Role` `None` → `Cluster`), which is required for live migration to work.

| Time | Event |
|---|---|
| `22:26` | cluster network `Role` set to Cluster |
| `22:27` | **first `31013`** — one minute later |
| `22:27 → +21 h` | 4,350 events/hour client-side, 7,470/hour server-side, sustained |

CSV uses **every** cluster-enabled network. Enabling one caused CSV to immediately bind new channels
on that subnet; the new binds took the full PKU2U path; they stuck. ~250,000 events across two nodes
followed from one correct administrative action.

**Be precise about what the change did.** It did not introduce the fault — a third node in the same
cluster was already logging sustained episodes of ~240 events/hour, for up to fourteen hours at a
stretch, across seven peers, on the days *before* the change and while that network was disabled.
What enabling the network did was add a third exposed subnet and multiply the magnitude: from a few
hundred events/hour on one node to 4,350/hour on one node and 7,470/hour on another. The lesson is
that **each cluster-enabled network is an independent exposure surface**, and the fault does not need
any configuration change to occur.

**Any operation that forces CSV to rebind channels is an exposure event:** cluster start, node join,
node reboot, a NIC reset or link transient, a cluster network role or metric change.

**[reported]** At cluster start the exposure is roughly the **first `CSV$` session to each
coordinator** — observed at about **one in four** during the source environment's earlier
investigation. Not re-measured here.

### 5.4 It destroys the forensic record you will need

At 7,470 events per hour, the coordinator's 2 GB SMB server security log was reduced from months of
history to **about two weeks** — measured: 151,589 records retained, oldest 11 days old on a channel
that had previously spanned months.

**[reported]** Each failed bind also produces several `CLIUSR` logon events in the **Security** log,
which on a default-sized Security log was observed to cut retention to roughly **an hour**. Not
re-measured here.

So when you investigate the outage in §5.2, the logs covering it have already been overwritten — by
the defect that caused it.

---

## 6. What this is *not* — eliminated with evidence

**[reported]** Each of these was tested during the source environment's earlier investigation and
does not cause or prevent the fault. They are listed so that others do not repeat the work; they are
not re-verified here:

| Hypothesis | Result |
|---|---|
| Windows Firewall | All three profiles disabled on all nodes — **still reproduced** |
| Secure channel / machine account password | Passwords recently set; no rebuild involved |
| Group Policy | No relevant policy difference |
| Certificates | No expiry, no chain fault |
| Time synchronisation | All nodes within tolerance |
| Boot timing / service start order | A deliberately delayed Cluster service start was tested: **2 of 3 starts still produced a stuck session** |
| SMB signing defaults | Not the signing configuration; the signature predates any change |
| SMB dialect and feature flags | Candidates tested and eliminated |
| Restarting the host vNIC | **Does not clear a stuck session** |
| Cluster misconfiguration | No setting on the affected cluster was wrong |

Two things that are *not* remedies but are often reached for: a node reboot clears only **that
node's** client-side state, and moving a CSV coordinator does not repair existing stuck sessions
while creating a far larger risk of its own.

---

## 7. The repair

There is no supported API for this. The redirector does expose a file-system control that
disconnects a client's CSV SMB connections to a named peer, which forces a rebuild.

**Control code `0x1401A8` on `\Device\SmbCsv`.**

**[reported]** The byte-level layout below comes from the source environment's binary analysis of the
redirector, not from documentation. What **is** directly verified here is that a request built to
this layout returned `NTSTATUS = 0x00000000` and ended a 21-hour retry storm (§8), and that the
buffer construction is covered by the implementation's self-tests. How the driver (`mrxsmb.sys`)
treats the reason field, an empty peer name and a filter that matches nothing was also confirmed by
disassembling that node's driver with its public symbols.

The calling convention is exact. Each of these is required:

- **Issue it with `NtFsControlFile`, never `DeviceIoControl`.** The control code's device type is
  `0x14`, so Win32 `DeviceIoControl` raises `IRP_MJ_DEVICE_CONTROL`, while the handler is registered
  under `IRP_MJ_FILE_SYSTEM_CONTROL`. Via `DeviceIoControl` the request never reaches the handler.
- The reason field at **`+0x004` must be `0`.** A negative value is accepted and stored by the
  driver: every new connection to that peer then fails at once, until a later call clears it. `0`
  clears it.
- The peer name at **`+0x110`** needs a single leading backslash and the interface-zone suffix. The
  `31013` `ServerName` field already carries both, so it can be passed through verbatim. Its length
  in **bytes** goes at `+0x10C`. **It must never be empty:** the driver applies an empty name to
  every server.
- For a **scoped** reset, set the remote-address gate at **`+0x109`** and write **one plain
  `sockaddr`** at **`+0x088`**. Not a list, not a counted structure — one sockaddr.
- The kernel compares **address family and address only. It never reads the port.**
- Minimum buffer length `0x118`.

Decoded, `0x1401A8` is device `0x14` `FILE_DEVICE_NETWORK_FILE_SYSTEM`, function `0x06A`,
`METHOD_BUFFERED`, `FILE_ANY_ACCESS`.

Windows uses this request itself. The cluster service (`clussvc.exe`) sends it from its own
disconnect function, built with the same layout, and does not report "server not found"
(`0xC0000034`) as a failure. In 25 builds of `clussvc.exe` from 2016 to 2026 the code is always
`0x1401A8`. CsvSessionGuard reads the code from that function at start, and falls back to
`0x1401A8` when it cannot.

### Why scoping matters

Without the address filter, the reset drops **every** CSV connection to that peer, including healthy
ones carrying live file opens. With it, only the failing subnet's connections to that peer are
dropped.

Measured blast radius of one scoped reset on a node holding 19 CSV channels:

| | channels |
|---|---|
| Dropped — the one failing address | **3** |
| Retained — same peer, other cluster networks | 8 |
| Retained — other peers | 8 |

The in-use session to that peer — carrying between 19 and 29 open handles across the measurements —
**stayed up throughout**, because it kept its channels on the other two cluster networks.

A filter that matches nothing changes nothing, so a wrong address is inert rather than a silent wide
disconnect. It is not visible, though: the driver reports success either way.

### One pass is not guaranteed

The reset destroys **connections**, never the session object. Whether the session is then retired or
rebuilt stuck is decided inside the kernel. A pass can fail and a later pass on the same session can
succeed — so a failed verification should lead to another pass, not to an alarm.

Passes must not be bunched: a second reset inside the rebind window destroys the connections the
recovery needs.

---

## 8. Field result

One node, 52 running VMs, two CSVs coordinated locally.

| | Before | After |
|---|---|---|
| Stuck sessions | **51** | 0 |
| Distinct peer addresses behind them | **1** | — |
| FSCTL calls needed | — | **1** |
| Client `31013` | 72.5 / min | **0** |
| Coordinator `551` | 124.5 / min | **0** |
| Duration of the storm | 21 hours | ended |

Sequence: the reset was issued at `20:03:08` with `NTSTATUS = 0x00000000`, matched-nothing `0`,
rejected `0`. **The coordinator's last `551` is timestamped `20:03:00` and never recurred.**
Verification at `+91 s` counted **0** retry events against ~2 expected if unrepaired. One session
met the detection criteria again at `20:06:00` and was reset a second time. Three retries arrived in
the 151 seconds after that reset, and it kept retrying a few times a minute until its last retry at
`20:18:00`. Nothing has come from it since, and no further reset was issued. A verdict taken 90
seconds after a reset is an interim observation, not the outcome.

Throughout: all volumes Online, no CSV pause events, no slow-I/O reports, no VM interruption.

All 51 stuck sessions pointed at the **same** peer address, so one reset served all 51 — which is
what makes deduplication worth doing.

**Do not generalise that to "one peer".** Another node in the same cluster accumulated stuck sessions
against **seven** distinct peers over ten days. A single incident can be one-peer; the fault is not
limited to one.

---

## 9. What is still unknown

Stated plainly, because the workaround should not be mistaken for an explanation:

- **Why the cold path fails at all.** *Which* binds go cold is understood — those with nothing cached
  for the target (§3). What is unexplained is why Windows cannot complete that exchange against its
  own cluster peer: the client rejects a signed interim reply that its peer just sent it. Warm binds
  over the identical transport succeed 183/183.
- **Why** the redirector never gives up. There is no timeout, no session retirement and no cap on
  retries — a stuck session retries until something external clears it. Whether that is by design or
  an oversight is unknown.
- **Which Windows versions and builds are affected.** Confirmed on Server 2019 and Server 2025 in
  one estate. The boundaries are unmapped.
- **Whether a reset channel reliably re-establishes.** In the measured repair the channel on the
  affected network did **not** come back; CSV continued on the other two networks and the client
  stopped attempting the third. Not yet explained.
- **No vendor root-cause analysis exists.** This is reverse-engineered from binary analysis, packet
  captures and event correlation.

If you can add data on any of these, please open an issue.

---

## 10. Honest limitations

- **This is a workaround, not a fix.** The defect is in Windows. Running this does not make your
  cluster correct; it stops a known fault from removing your redundancy.
- **The control code is undocumented and unsupported.** It is verified against the build it was
  developed on and the decoded fields are logged on every call, so a Windows build that renumbers it
  can be identified from the log alone. Verify on a test cluster first.
- **Field-proven on one cluster, one real incident.** The implementation additionally carries 172
  deterministic self-tests, several built from recorded production event sequences.
- **It is reactive.** It repairs a stuck session after the retry loop is established — it does not
  prevent the bind from sticking in the first place.

See [README.md](README.md) for the implementation, its safety behaviour and how to run it.
