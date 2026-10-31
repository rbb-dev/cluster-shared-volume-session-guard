// CsvSessionGuard - deterministic self-tests.
//
// These exercise the detection criterion and the FSCTL request buffer with no event log, no
// cluster and no host state, so they run anywhere. Invoke the executable with -selftest; the
// exit code is the number of failures.
//
// Addresses used here are documentation addresses (RFC 5737) and are test data only - the
// running code takes every address verbatim from the event it is reacting to.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Threading;

namespace CsvSessionGuard
{
    internal static class SelfTest
    {
        private static int _fail;

        private static void Check(string name, bool ok, string detail)
        {
            if (!ok) _fail++;
            System.Console.WriteLine(string.Format(CultureInfo.InvariantCulture,
                "  [{0}] {1}{2}", ok ? "PASS" : "FAIL", name, detail == null ? "" : "   " + detail));
        }

        // ports x perPort reproduces a real observed session shape exactly.
        private static StuckSession Mk(string id, string srv, int ports, int perPort, double spanSec, double ageSec)
        {
            StuckSession s = new StuckSession();
            s.SessionId = id; s.ServerName = srv;
            s.Count = ports * perPort;
            s.Last = DateTime.Now.AddSeconds(-ageSec);
            s.First = s.Last.AddSeconds(-spanSec);
            for (int p = 0; p < ports; p++) { for (int e = 0; e < perPort; e++) { s.Note(49800 + p); } }
            return s;
        }

        internal static int Run()
        {
            _fail = 0;
            System.Console.WriteLine("CsvSessionGuard -selftest");

            // ---- the worker primitive ----
            Exception err;
            DateTime t0 = DateTime.Now;
            Worker.Result r = Worker.Run("t-ok", delegate() { }, 2000, out err);
            Check("worker: a normal body completes", r == Worker.Result.Completed && err == null, "got " + r);

            t0 = DateTime.Now;
            r = Worker.Run("t-hang", delegate() { Thread.Sleep(15000); }, 1000, out err);
            double waited = (DateTime.Now - t0).TotalSeconds;
            Check("worker: a BLOCKING body times out", r == Worker.Result.TimedOut, "got " + r);
            Check("worker: the timeout returns promptly (abandons, does not wait)",
                  waited < 4.0, string.Format(CultureInfo.InvariantCulture, "returned after {0:N2}s", waited));

            r = Worker.Run("t-throw", delegate() { throw new InvalidOperationException("boom"); }, 2000, out err);
            Check("worker: a throwing body faults and the exception is captured",
                  r == Worker.Result.Faulted && err != null && err.Message == "boom",
                  "got " + r + " / " + (err == null ? "no exception" : err.Message));

            // ---- the detection criterion ----
            // Each shape below reproduces a measured real-world session shape.
            Config c = new Config();
            List<StuckSession> all = new List<StuckSession>();
            all.Add(Mk("T-burst-a", "\\srv", 8, 2, 22, 5));    // 8 ports x 2 - observed 3 times
            all.Add(Mk("T-burst-b", "\\srv", 8, 2,  0, 5));    // same, span 0 (all inside a second)
            all.Add(Mk("S-min",     "\\srv", 8, 3, 124, 5));   // lowest real stuck session
            all.Add(Mk("S-7hour",   "\\srv", 8, 209, 24833, 5)); // the 7-hour one
            all.Add(Mk("S-stale",   "\\srv", 8, 209, 24833, 600)); // same but long finished
            List<StuckSession> picked = Detector.Select(all, c, DateTime.Now);

            Check("detect: the two transient 8x2 bursts are IGNORED",
                  !Contains(picked, "T-burst-a") && !Contains(picked, "T-burst-b"), "selected " + picked.Count);
            Check("detect: 8 ports x 2 events is below the per-port threshold",
                  Mk("x", "\\s", 8, 2, 22, 5).MaxPerPort == 2, "maxPerPort=" + Mk("x", "\\s", 8, 2, 22, 5).MaxPerPort);
            Check("detect: the LOWEST real stuck session (8x3) IS caught", Contains(picked, "S-min"), null);
            Check("detect: the 7-hour session (8x209) IS caught", Contains(picked, "S-7hour"), null);
            Check("detect: a finished loop (last event 10 min old) is IGNORED", !Contains(picked, "S-stale"), null);
            Check("detect: exactly two of five are selected", picked.Count == 2, "selected " + picked.Count);

            // A single stuck connection must be caught even with no other channels involved -
            // the port criterion must not depend on how many channels exist.
            List<StuckSession> one = new List<StuckSession>();
            one.Add(Mk("S-single", "\\srv", 1, 3, 40, 5));
            Check("detect: ONE connection retrying 3 times is caught (channel-count independent)",
                  Detector.Select(one, c, DateTime.Now).Count == 1, null);

            // Transient shape must stay ignored however many channels the host has.
            List<StuckSession> wide = new List<StuckSession>();
            wide.Add(Mk("T-wide", "\\srv", 32, 2, 30, 5));
            Check("detect: 32 ports x 2 (a wider host) is still IGNORED",
                  Detector.Select(wide, c, DateTime.Now).Count == 0, null);

            // ---- the FSCTL request buffer: WHOLE-PEER form (the -allowwholepeer fallback) ----
            string name = "\\fe80::1%13";
            byte[] b = Fsctl.BuildBuffer(name, null);
            int nameBytes = Encoding.Unicode.GetByteCount(name);
            Check("buffer: length is 0x110 + nameBytes + 2", b.Length == 0x110 + nameBytes + 2,
                  b.Length + " vs " + (0x110 + nameBytes + 2));
            Check("buffer: at least the documented minimum 0x118", b.Length >= 0x118, "0x" + b.Length.ToString("X"));
            Check("buffer: +0x004 status is 0 (0xC000022D is rejected by the handler)",
                  BitConverter.ToUInt32(b, 0x004) == 0, "0x" + BitConverter.ToUInt32(b, 0x004).ToString("X8"));
            Check("buffer: +0x108 local-address gate is 0", b[0x108] == 0, b[0x108].ToString());
            Check("buffer: whole-peer form leaves +0x109 at 0", b[0x109] == 0, b[0x109].ToString());
            Check("buffer: +0x10C name length is in BYTES",
                  BitConverter.ToUInt32(b, 0x10C) == (uint)nameBytes,
                  BitConverter.ToUInt32(b, 0x10C) + " vs " + nameBytes);
            Check("buffer: +0x110 holds the name with its leading backslash",
                  Encoding.Unicode.GetString(b, 0x110, nameBytes) == name,
                  Encoding.Unicode.GetString(b, 0x110, nameBytes));
            bool zeroed = true;
            for (int i = 0x008; i < 0x108; i++) { if (b[i] != 0) { zeroed = false; break; } }
            Check("buffer: whole-peer leaves the sockaddr fields +0x008..+0x107 all zero", zeroed, null);

            byte[] tiny = Fsctl.BuildBuffer("\\x", null);
            Check("buffer: a short name is padded to the 0x118 minimum", tiny.Length >= 0x118,
                  "0x" + tiny.Length.ToString("X"));

            // ---- the FSCTL request buffer: SCOPED form, which is what the repair sends ----
            // A peer address as the 31013 event renders it: family 0x0002, port 0x01BD (445), then
            // the four IPv4 address bytes. Documentation addresses (RFC 5737) are used here.
            const string Csv2Hex = "020001BDC000020F0000000000000000";
            const string Csv1Hex = "020001BDC00002100000000000000000";

            byte[] raw = Fsctl.HexToBytes(Csv2Hex);
            Check("hex: a 16-byte sockaddr parses to 16 bytes", raw != null && raw.Length == 16,
                  raw == null ? "null" : raw.Length.ToString());
            Check("hex: the address bytes decode to the right dotted quad",
                  Fsctl.DescribeSockAddr(raw) == "192.0.2.15 (IPv4)", Fsctl.DescribeSockAddr(raw));
            Check("hex: a truncated string is rejected rather than half-parsed",
                  Fsctl.HexToBytes("0200") == null, null);
            Check("hex: null in, null out", Fsctl.HexToBytes(null) == null, null);

            byte[] sc = Fsctl.BuildBuffer(name, raw);
            Check("scoped: +0x109 remote gate is SET", sc[0x109] == 1, sc[0x109].ToString());
            Check("scoped: +0x108 local gate stays 0", sc[0x108] == 0, sc[0x108].ToString());
            bool addrOk = true;
            for (int i = 0; i < raw.Length; i++) { if (sc[0x088 + i] != raw[i]) { addrOk = false; break; } }
            Check("scoped: the address sits at +0x088 byte-for-byte, verbatim from the event", addrOk, null);
            bool localZero = true;
            for (int i = 0x008; i < 0x088; i++) { if (sc[i] != 0) { localZero = false; break; } }
            Check("scoped: the unused LOCAL sockaddr +0x008..+0x087 stays zero", localZero, null);
            Check("scoped: +0x004 status is still 0", BitConverter.ToUInt32(sc, 0x004) == 0, null);
            Check("scoped: the name is unaffected by the filter",
                  Encoding.Unicode.GetString(sc, 0x110, nameBytes) == name, null);

            // An over-long sockaddr must be clamped, never allowed to overwrite the gate bytes -
            // a stray 1 at +0x108 would silently add a local-address filter that matches nothing.
            byte[] huge = new byte[0x200];
            for (int i = 0; i < huge.Length; i++) { huge[i] = 0xAB; }
            huge[0] = 2; huge[1] = 0;
            byte[] clamped = Fsctl.BuildBuffer(name, huge);
            Check("scoped: an over-long sockaddr is clamped and never reaches +0x108",
                  clamped[0x108] == 0 && clamped[0x109] == 1,
                  "gates " + clamped[0x108] + "/" + clamped[0x109]);

            // A sockaddr too short to be meaningful must fall back to whole-peer, not emit a
            // filter the kernel would compare against garbage.
            byte[] stub = Fsctl.BuildBuffer(name, new byte[] { 2, 0, 1, 0xBD });
            Check("scoped: a sockaddr under 8 bytes is refused and the gate stays 0",
                  stub[0x109] == 0, stub[0x109].ToString());

            // ---- target selection: how many FSCTLs one stuck session produces ----
            StuckSession two = Mk("S-two", "\\srv", 8, 3, 124, 5);
            for (int i = 0; i < 12; i++) { two.NoteRemote(Csv1Hex); }
            for (int i = 0; i < 12; i++) { two.NoteRemote(Csv2Hex); }
            Check("targets: 8 connections across 2 peer addresses yield exactly 2 filters",
                  two.DistinctRemotes == 2, "distinct=" + two.DistinctRemotes);

            // The port is ephemeral noise on this field and the kernel comparator ignores it, so
            // two events differing only in port are ONE filter target; otherwise a redundant
            // FSCTL would fire on every retry.
            StuckSession ports = Mk("S-ports", "\\srv", 8, 3, 124, 5);
            ports.NoteRemote("020001BDC000020F0000000000000000");
            ports.NoteRemote("0200FFFFC000020F0000000000000000");
            Check("targets: the same address on two ports collapses to ONE filter",
                  ports.DistinctRemotes == 1, "distinct=" + ports.DistinctRemotes);

            StuckSession none = Mk("S-none", "\\srv", 8, 3, 124, 5);
            Check("targets: a session with no RemoteAddress yields no filters (repair is skipped)",
                  none.DistinctRemotes == 0 && none.RemoteTargets().Count == 0, null);

            StuckSession ordered = Mk("S-order", "\\srv", 8, 3, 124, 5);
            for (int i = 0; i < 3; i++) { ordered.NoteRemote(Csv1Hex); }
            for (int i = 0; i < 30; i++) { ordered.NoteRemote(Csv2Hex); }
            List<string> ord = ordered.RemoteTargets();
            Check("targets: the worst-affected address is reset first",
                  ord.Count == 2 && StuckSession.RemoteKey(ord[0]) == StuckSession.RemoteKey(Csv2Hex),
                  ord.Count == 0 ? "none" : Fsctl.DescribeSockAddr(Fsctl.HexToBytes(ord[0])));
            Check("targets: a raw hex round-trips to the same bytes the event carried",
                  ord.Count == 2 && Fsctl.DescribeSockAddr(Fsctl.HexToBytes(ord[0])) == "192.0.2.15 (IPv4)",
                  null);

            // ---- the control code, as an operator reads it out of the log ----
            string decoded = Fsctl.DescribeCode(0x1401A8);
            Check("code: 0x1401A8 decodes to device 0x14, function 0x06A, METHOD_BUFFERED",
                  decoded.IndexOf("device 0x14", StringComparison.Ordinal) >= 0 &&
                  decoded.IndexOf("function 0x06A", StringComparison.Ordinal) >= 0 &&
                  decoded.IndexOf("METHOD_BUFFERED", StringComparison.Ordinal) >= 0, decoded);
            Check("fsctl: an empty or blank peer name is refused, because the driver applies it to every server",
                  Fsctl.RefuseReason(null) != null && Fsctl.RefuseReason("") != null && Fsctl.RefuseReason("   ") != null &&
                  Fsctl.RefuseReason("\\fe80::1%13") == null, null);
            Check("fsctl: no server entry for the peer (0xC0000034) and no endpoint matched (0xC0000225) both mean nothing to reset",
                  Fsctl.Classify(0xC0000034) == Fsctl.Outcome.NoMatch && Fsctl.Classify(0xC0000225) == Fsctl.Outcome.NoMatch, null);
            Check("fsctl: 0 is success, 0xC0000010 means the code or its request was not accepted, any other status is a rejection",
                  Fsctl.Classify(0) == Fsctl.Outcome.Success && Fsctl.Classify(0xC0000010) == Fsctl.Outcome.NotAccepted &&
                  Fsctl.Classify(0xC000000D) == Fsctl.Outcome.Rejected && Fsctl.Classify(0xC0000022) == Fsctl.Outcome.Rejected, null);

            // ---- verification configuration ----
            string problems;
            Config def = Config.Parse(new string[0], out problems);
            Check("config: the verify grace window defaults to 0 (every event after the reset counts)",
                  def.VerifyGraceSeconds == 0, "got " + def.VerifyGraceSeconds);
            Config shortDelay = Config.Parse(new string[] { "-verifydelay", "10" }, out problems);
            Check("config: -verifydelay is floored at 65s, above the loop's own 60s cadence",
                  shortDelay.VerifyDelaySeconds == 65, "got " + shortDelay.VerifyDelaySeconds);
            Config hugeDelay = Config.Parse(new string[] { "-verifydelay", "2147483647" }, out problems);
            Check("config: -verifydelay is capped, so delay+60 cannot overflow into a negative window",
                  hugeDelay.VerifyDelaySeconds == 3600, "got " + hugeDelay.VerifyDelaySeconds);
            // A grace window must leave a full 60s retry cadence of countable observation, or a
            // live loop has no chance to show itself and every repair reports success.
            Config swallowAll = Config.Parse(new string[] { "-verifydelay", "70", "-verifygrace", "60" }, out problems);
            Check("config: a grace window is capped to leave one full retry cadence countable",
                  swallowAll.VerifyDelaySeconds - swallowAll.VerifyGraceSeconds >= 60 && problems != null,
                  "grace=" + swallowAll.VerifyGraceSeconds + " delay=" + swallowAll.VerifyDelaySeconds);
            Config graceOk = Config.Parse(new string[] { "-verifydelay", "180", "-verifygrace", "30" }, out problems);
            Check("config: a grace window that leaves room is kept as given",
                  graceOk.VerifyGraceSeconds == 30 && problems == null, "grace=" + graceOk.VerifyGraceSeconds);

            // ---- silence is only evidence when the source could have spoken ----
            // This is the rule that keeps a successful repair from being reported as unknown: the
            // question is asked of the CHANNEL, never of how many records a query returned, because
            // on a node whose only stuck session is the repaired one, zero records is success.
            Check("verify: a verdict is available when the channel is enabled",
                  VerifyAnalysis.CanConclude(ChannelState.Available), null);
            Check("verify: a disabled channel yields no verdict, not a false success",
                  !VerifyAnalysis.CanConclude(ChannelState.Disabled), null);
            Check("verify: an unreadable channel yields no verdict either",
                  !VerifyAnalysis.CanConclude(ChannelState.Unavailable), null);

            int after, inFlight;
            Check("verify: with the channel up, silence after the reset is HELD",
                  VerifyAnalysis.Decide(new List<DateTime>(), null, At(9, 0, 0, 0), 0, out after, out inFlight)
                      == VerifyOutcome.Held && after == 0, "after=" + after);

            // ---- a recorded specimen of the fault ----
            // Timestamps are truncated to milliseconds, so two events that shared a millisecond
            // collapse under the de-duplication rule: 22 events present as 21 distinct instants.
            DateTime reset1 = At(8, 35, 30, 195);
            List<DateTime> p1 = new List<DateTime>();
            int[] burst1 = new int[] { 220, 226, 228, 234, 236, 239, 255, 261 };
            for (int i = 0; i < burst1.Length; i++) { p1.Add(At(8, 35, 30, burst1[i])); }
            int[] burst2 = new int[] { 51, 57, 60, 65, 73, 75, 78, 78 };
            for (int i = 0; i < burst2.Length; i++) { p1.Add(At(8, 36, 0, burst2[i])); }
            int[] burst3 = new int[] { 37, 50, 55, 58, 63, 66 };
            for (int i = 0; i < burst3.Length; i++) { p1.Add(At(8, 37, 0, burst3[i])); }
            Check("recorded specimen: the pass 1 window holds 22 events", p1.Count == 22, "got " + p1.Count);

            VerifyOutcome v1 = VerifyAnalysis.Decide(p1, null, reset1, 0, out after, out inFlight);
            Check("pass 1 (a loop that kept running) is judged FAILED",
                  v1 == VerifyOutcome.Failed && after == 21 && inFlight == 0,
                  "verdict=" + v1 + " after=" + after + " inFlight=" + inFlight);

            // Pass 2: three retries BEFORE the reset and one 19 ms after it, then silence. The old
            // rule reported this as "did not hold".
            DateTime reset2 = At(8, 51, 1, 248);
            List<DateTime> p2 = new List<DateTime>();
            p2.Add(At(8, 51, 0, 52)); p2.Add(At(8, 51, 0, 67)); p2.Add(At(8, 51, 0, 67));
            p2.Add(At(8, 51, 1, 267));
            VerifyOutcome v2 = VerifyAnalysis.Decide(p2, null, reset2, 0, out after, out inFlight);
            Check("pass 2: one event after the reset is AMBIGUOUS, not a failure",
                  v2 == VerifyOutcome.Inconclusive && after == 1, "verdict=" + v2 + " after=" + after);
            Check("pass 2: the three pre-reset retries are not charged to the repair",
                  after == 1 && inFlight == 0, "after=" + after + " inFlight=" + inFlight);

            // The second look re-reads an overlapping window, so it presents the same event again
            // and no new one. That is a loop that stopped, and it must resolve to HELD - being
            // unable to reach that verdict was the original defect.
            VerifyOutcome v2b = VerifyAnalysis.Decide(p2, p2, reset2, 0, out after, out inFlight);
            Check("pass 2 resolves to HELD on the second look (no NEW event arrived)",
                  v2b == VerifyOutcome.Held, "verdict=" + v2b + " after=" + after);
            Check("the rule this build replaces would have called that successful repair a failure",
                  LegacyWouldFail(p2, reset2) && v2b == VerifyOutcome.Held,
                  "legacy=" + LegacyWouldFail(p2, reset2) + " now=" + v2b);

            // A live loop produces a new event in the next minute, so the second look fails it.
            List<DateTime> p2live = new List<DateTime>(p2);
            p2live.Add(At(8, 52, 1, 300));
            Check("a live loop is judged FAILED on the second look (a new event arrived)",
                  VerifyAnalysis.Decide(p2, p2live, reset2, 0, out after, out inFlight) == VerifyOutcome.Failed,
                  "after=" + after);
            Check("without a second look the verdict stays AMBIGUOUS rather than guessing",
                  VerifyAnalysis.Decide(p2, null, reset2, 0, out after, out inFlight) == VerifyOutcome.Inconclusive,
                  null);

            // ---- boundaries and double counting ----
            DateTime fired = At(9, 10, 0, 0);
            List<DateTime> edges = new List<DateTime>();
            edges.Add(fired);                      // exactly at the reset: what was being repaired
            edges.Add(fired.AddSeconds(2));        // exactly at the grace boundary
            Check("boundary: events at the reset instant and at the grace edge are not retries",
                  VerifyAnalysis.Classify(edges, fired, 2, out after, out inFlight) == VerifyOutcome.Held
                  && after == 0 && inFlight == 1, "after=" + after + " inFlight=" + inFlight);
            Check("boundary: one millisecond past the grace edge IS a retry",
                  VerifyAnalysis.Classify(new List<DateTime>() { fired.AddSeconds(2).AddMilliseconds(1) },
                                          fired, 2, out after, out inFlight) == VerifyOutcome.Inconclusive,
                  "after=" + after);
            List<DateTime> dup = new List<DateTime>();
            DateTime once = fired.AddSeconds(30);
            dup.Add(once); dup.Add(once); dup.Add(once);
            Check("overlap: one event presented three times is counted once, not failed",
                  VerifyAnalysis.Classify(dup, fired, 0, out after, out inFlight) == VerifyOutcome.Inconclusive
                  && after == 1, "after=" + after);

            // ---- evidence belongs to ONE session, not to a peer name ----
            // Two stuck sessions to the same peer must not share a verdict: otherwise the other
            // session's later event becomes "the newest seen" and masks a genuinely new retry on
            // the repaired one, which would score a still-stuck session as repaired.
            StuckSession sa = new StuckSession();
            sa.SessionId = "111"; sa.ServerName = "\\peer";
            sa.NoteTime(At(8, 51, 1, 267));
            StuckSession sb = new StuckSession();
            sb.SessionId = "222"; sb.ServerName = "\\peer";          // same peer, different session
            sb.NoteTime(At(8, 51, 1, 267));
            sb.NoteTime(At(8, 52, 1, 300));                          // B is still retrying
            List<StuckSession> both = new List<StuckSession>();
            both.Add(sa); both.Add(sb);
            List<DateTime> onlyA = VerifyAnalysis.TimesFor(both, sa.Key);
            Check("evidence: times are selected by session key, not by peer name",
                  onlyA.Count == 1, "got " + onlyA.Count);
            Check("evidence: a second session to the same peer cannot fail A's repair",
                  VerifyAnalysis.Decide(onlyA, onlyA, reset2, 0, out after, out inFlight) == VerifyOutcome.Held,
                  "after=" + after);
            List<DateTime> onlyB = VerifyAnalysis.TimesFor(both, sb.Key);
            Check("evidence: B's own still-live loop is still judged FAILED",
                  VerifyAnalysis.Decide(onlyB, onlyB, reset2, 0, out after, out inFlight) == VerifyOutcome.Failed,
                  "after=" + after);

            ReportLedgerTests();
            ReportBuilderTests();
            PlannerTests();
            FieldReplayTests();
            StateFileTests();
            ReviewFixTests();
            ClusterCodeTests();

            System.Console.WriteLine(_fail == 0
                ? "  ALL TESTS PASSED"
                : string.Format(CultureInfo.InvariantCulture, "  {0} TEST(S) FAILED", _fail));
            return _fail;
        }

        private static DateTime At(int h, int m, int s, int ms)
        {
            return new DateTime(2026, 10, 28, h, m, s, ms, DateTimeKind.Local);
        }

        private static StuckSession MkAt(string id, string srv, DateTime first, DateTime last)
        {
            StuckSession s = new StuckSession();
            s.SessionId = id; s.ServerName = srv;
            s.First = first; s.Last = last; s.Count = 1;
            return s;
        }

        private sealed class StopFlag { public volatile bool Done; }

        private static readonly Dictionary<string, DateTime> NoClaims = new Dictionary<string, DateTime>(StringComparer.Ordinal);

        private static EpisodeLedger OpenA(out StuckSession a)
        {
            EpisodeLedger l = new EpisodeLedger();
            a = MkAt("A", "\\peer", At(20, 2, 7, 0), At(20, 3, 7, 0));
            bool o;
            l.NoteDetected(a, At(20, 3, 7, 0), 15, out o);
            return l;
        }

        private static List<string> Rec(EpisodeLedger l, List<string> sel, List<StuckSession> seen, bool complete,
                                        ChannelState ch, Dictionary<string, DateTime> claims, DateTime now, long mono)
        {
            return l.Reconcile(sel, seen, complete, ch, claims, now, mono, 120, 120, 210);
        }

        private static List<string> Keys(params string[] k) { return new List<string>(k); }

        private static List<StuckSession> Seen(params StuckSession[] s) { return new List<StuckSession>(s); }

        private static void ReportLedgerTests()
        {
            DateTime T0 = At(20, 3, 7, 0);
            bool o;
            StuckSession a;
            EpisodeLedger L = OpenA(out a);
            Check("report: the first detection opens a report, announces it and stamps the session",
                  a.ReportId != 0 && L.OpenCount == 1 && L.Get(a.Key) != null && L.Get(a.Key).Id == a.ReportId,
                  "id=" + a.ReportId + " open=" + L.OpenCount);
            Check("report: a re-detection inside 15 minutes is not announced again",
                  !L.NoteDetected(a, T0.AddMinutes(5), 15, out o) && !o, null);
            bool reminded = L.NoteDetected(a, T0.AddMinutes(15), 15, out o);
            Check("report: the 15-minute reminder cadence is kept",
                  reminded && !o && L.Get(a.Key).Announcements == 2, "announcements=" + L.Get(a.Key).Announcements);

            L = OpenA(out a);
            List<string> e1 = Rec(L, Keys(), Seen(), true, ChannelState.Available, NoClaims, T0.AddMinutes(11), 0);
            List<string> e2 = Rec(L, Keys(), Seen(), true, ChannelState.Available, NoClaims, T0.AddMinutes(13), 120000);
            Check("report: base scenario - absent at two complete reads 120 s apart closes it",
                  e1.Count == 0 && e2.Count == 1 && e2[0] == a.Key, "e1=" + e1.Count + " e2=" + e2.Count);

            L = OpenA(out a);
            Rec(L, Keys(), Seen(), true, ChannelState.Available, NoClaims, T0.AddMinutes(11), 0);
            e2 = Rec(L, Keys(), Seen(MkAt("A", "\\peer", T0, T0)), true, ChannelState.Available, NoClaims, T0.AddMinutes(13), 120000);
            Check("report: a session still in the window is never closed, however old its last retry",
                  e2.Count == 0 && L.Get(a.Key).State == ReportState.Quiet, "state=" + L.Get(a.Key).State);

            L = OpenA(out a);
            Rec(L, Keys(), Seen(), true, ChannelState.Available, NoClaims, T0.AddMinutes(11), 0);
            e2 = Rec(L, Keys(), Seen(), false, ChannelState.Available, NoClaims, T0.AddMinutes(13), 120000);
            List<string> e3 = Rec(L, Keys(), Seen(), true, ChannelState.Available, NoClaims, T0.AddMinutes(15), 240000);
            Check("report: an incomplete read neither closes nor restarts the confirmation",
                  e2.Count == 0 && e3.Count == 1, "e2=" + e2.Count + " e3=" + e3.Count);

            L = OpenA(out a);
            Rec(L, Keys(), Seen(), true, ChannelState.Available, NoClaims, T0.AddMinutes(11), 0);
            e2 = Rec(L, Keys(), Seen(), true, ChannelState.Disabled, NoClaims, T0.AddMinutes(13), 120000);
            e3 = Rec(L, Keys(), Seen(), true, ChannelState.Available, NoClaims, T0.AddMinutes(15), 240000);
            List<string> e4 = Rec(L, Keys(), Seen(), true, ChannelState.Available, NoClaims, T0.AddMinutes(17), 360000);
            Check("report: a disabled channel restarts the confirmation",
                  e2.Count == 0 && e3.Count == 0 && e4.Count == 1, "e2=" + e2.Count + " e3=" + e3.Count + " e4=" + e4.Count);

            L = OpenA(out a);
            Rec(L, Keys(), Seen(), true, ChannelState.Available, NoClaims, T0.AddMinutes(11), 0);
            e2 = Rec(L, Keys(), Seen(), true, ChannelState.Unavailable, NoClaims, T0.AddMinutes(13), 120000);
            Check("report: an unanswered channel probe blocks closure", e2.Count == 0, null);

            L = OpenA(out a);
            Rec(L, Keys(), Seen(), true, ChannelState.Available, NoClaims, T0.AddMinutes(11), 0);
            Dictionary<string, DateTime> young = new Dictionary<string, DateTime>(StringComparer.Ordinal);
            young[a.Key] = T0.AddMinutes(13).AddSeconds(-60);
            e2 = Rec(L, Keys(), Seen(), true, ChannelState.Available, young, T0.AddMinutes(13), 120000);
            Check("report: a repair in flight blocks closure", e2.Count == 0, null);

            L = OpenA(out a);
            Rec(L, Keys(), Seen(), true, ChannelState.Available, NoClaims, T0.AddMinutes(11), 0);
            Dictionary<string, DateTime> old = new Dictionary<string, DateTime>(StringComparer.Ordinal);
            old[a.Key] = T0.AddMinutes(13).AddSeconds(-300);
            e2 = Rec(L, Keys(), Seen(), true, ChannelState.Available, old, T0.AddMinutes(13), 120000);
            Check("report: an in-flight claim past its ceiling does not block closure forever", e2.Count == 1, null);

            L = OpenA(out a);
            Rec(L, Keys(), Seen(), true, ChannelState.Available, NoClaims, T0.AddMinutes(11), 0);
            e2 = Rec(L, Keys(), Seen(), true, ChannelState.Available, NoClaims, T0.AddMinutes(13), 119999);
            Check("report: confirmation needs the full time on the monotonic clock", e2.Count == 0, null);

            L = OpenA(out a);
            Rec(L, Keys(), Seen(), true, ChannelState.Available, NoClaims, T0.AddMinutes(11), 0);
            e2 = Rec(L, Keys(a.Key), Seen(MkAt("A", "\\peer", T0, T0.AddMinutes(12))), true, ChannelState.Available, NoClaims, T0.AddMinutes(13), 120000);
            Check("report: a selected session counts as present",
                  e2.Count == 0 && L.Get(a.Key).State == ReportState.Stuck, "state=" + L.Get(a.Key).State);

            L = OpenA(out a);
            Rec(L, Keys(), Seen(), true, ChannelState.Available, NoClaims, T0.AddMinutes(11), 0);
            e2 = Rec(L, Keys(a.Key), Seen(), true, ChannelState.Available, NoClaims, T0.AddMinutes(13), 120000);
            Check("report: a selected session with no seen events still counts as present",
                  e2.Count == 0 && L.Get(a.Key).AbsentSinceMs == -1, "absentSince=" + L.Get(a.Key).AbsentSinceMs);

            L = OpenA(out a);
            long firstId = a.ReportId;
            Rec(L, Keys(), Seen(), true, ChannelState.Available, NoClaims, T0.AddMinutes(11), 0);
            L.Close(Rec(L, Keys(), Seen(), true, ChannelState.Available, NoClaims, T0.AddMinutes(13), 120000));
            StuckSession again = MkAt("A", "\\peer", T0.AddMinutes(19), T0.AddMinutes(20));
            bool reopened = L.NoteDetected(again, T0.AddMinutes(20), 15, out o);
            Check("report: after closure the next detection opens a new report with a higher number",
                  reopened && o && again.ReportId > firstId && L.ClosedTotal == 1 && L.OpenedTotal == 2,
                  "first=" + firstId + " second=" + again.ReportId);

            L = OpenA(out a);
            Rec(L, Keys(a.Key), Seen(MkAt("A", "\\peer", T0, T0)), true, ChannelState.Available, NoClaims, T0, 0);
            Rec(L, Keys(), Seen(MkAt("A", "\\peer", T0, T0.AddSeconds(40))), true, ChannelState.Available, NoClaims, T0.AddSeconds(50), 50000);
            Check("report: the criteria class change is timed on the monotonic clock",
                  L.Get(a.Key).ClassSinceMs == 50000 && L.Get(a.Key).State == ReportState.Retrying,
                  "classSince=" + L.Get(a.Key).ClassSinceMs + " state=" + L.Get(a.Key).State);

            L = OpenA(out a);
            StuckSession b = MkAt("B", "\\peer", T0, T0);
            L.NoteDetected(b, T0, 15, out o);
            L.NoteReset(Seen(a, b), T0.AddSeconds(1));
            Check("report: a reset counts against every session it served",
                  L.Get(a.Key).Resets == 1 && L.Get(b.Key).Resets == 1, null);

            L = OpenA(out a);
            Rec(L, Keys(), Seen(), true, ChannelState.Available, NoClaims, T0.AddMinutes(11), 0);
            L.Close(Rec(L, Keys(), Seen(), true, ChannelState.Available, NoClaims, T0.AddMinutes(13), 120000));
            StuckSession a2 = MkAt("A", "\\peer", T0.AddMinutes(19), T0.AddMinutes(20));
            L.NoteDetected(a2, T0.AddMinutes(20), 15, out o);
            L.NoteReset(Seen(a), T0.AddMinutes(21));
            bool staleVerdict = L.NoteVerdict(a.Key, a.ReportId, 3004, T0.AddMinutes(21));
            Check("report: an old report number is ignored",
                  L.Get(a.Key).Resets == 0 && !staleVerdict && a.ReportId != a2.ReportId,
                  "resets=" + L.Get(a.Key).Resets + " attached=" + staleVerdict);

            L = OpenA(out a);
            bool v2 = L.NoteVerdict(a.Key, a.ReportId, 3004, T0.AddMinutes(3));
            bool v1 = L.NoteVerdict(a.Key, a.ReportId, 3001, T0.AddMinutes(1));
            Check("report: a verdict for an older reset attaches but does not overwrite a newer one",
                  v2 && v1 && L.Get(a.Key).VerdictId == 3004 && L.Get(a.Key).VerdictResetAt == T0.AddMinutes(3),
                  "verdict=" + L.Get(a.Key).VerdictId);

            L = OpenA(out a);
            long vBefore = L.Version;
            StuckSession stranger = MkAt("Z", "\\other", T0, T0);
            L.NoteReset(Seen(stranger), T0);
            bool attachedStranger = L.NoteVerdict("Z|\\other", 5, 3001, T0);
            Check("report: unknown sessions are ignored",
                  !attachedStranger && L.OpenCount == 1 && L.Version == vBefore, null);

            EpisodeLedger R = new EpisodeLedger();
            List<Episode> saved = new List<Episode>();
            Episode r7 = new Episode(); r7.Id = 7; r7.SessionId = "S7"; r7.ServerName = "\\p"; r7.Key = "S7|\\p"; r7.AbsentSinceMs = 5; r7.ClassSinceMs = 5;
            Episode r9 = new Episode(); r9.Id = 9; r9.SessionId = "S9"; r9.ServerName = "\\p"; r9.Key = "S9|\\p";
            saved.Add(r7); saved.Add(r9);
            R.Restore(saved);
            R.SeedNext(5);
            StuckSession fresh = MkAt("N", "\\p", T0, T0);
            R.NoteDetected(fresh, T0, 15, out o);
            Check("report: restore keeps report numbers and the next number continues above them",
                  R.OpenCount == 3 && fresh.ReportId == 10 && R.Get("S7|\\p").AbsentSinceMs == -1 && R.Get("S7|\\p").ClassSinceMs == -1,
                  "new id=" + fresh.ReportId);

            L = OpenA(out a);
            long next, version;
            List<Episode> snap = L.SnapshotForSave(out next, out version);
            L.NoteReset(Seen(a), T0.AddSeconds(5));
            Check("report: the save snapshot, next number and version are read together",
                  snap.Count == 1 && next == L.NextId && L.Version > version && snap[0].Resets == 0, null);

            L = OpenA(out a);
            long v0 = L.Version;
            Rec(L, Keys(), Seen(), false, ChannelState.Available, NoClaims, T0.AddMinutes(1), 1000);
            long vNoop = L.Version;
            L.NoteReset(Seen(a), T0.AddSeconds(5));
            Check("report: every change advances the version, a no-op does not",
                  vNoop == v0 && L.Version > vNoop, "v0=" + v0 + " noop=" + vNoop + " after=" + L.Version);

            L = OpenA(out a);
            Episode copy = L.Get(a.Key);
            copy.Resets = 99;
            List<Episode> snapCopy = L.Snapshot();
            snapCopy[0].Resets = 77;
            Check("report: Get and Snapshot hand out copies", L.Get(a.Key).Resets == 0, null);

            ConcurrencySmokeTest(T0);
        }

        private static Episode Ep(long id, string sid, ReportState st, DateTime opened, DateTime lastRetry,
                                  int resets, int verdictId, DateTime verdictResetAt)
        {
            Episode e = new Episode();
            e.Id = id; e.SessionId = sid; e.ServerName = "\\peer"; e.Key = sid + "|\\peer";
            e.OpenedAt = opened; e.LastAnnouncedAt = opened; e.LastRetryAt = lastRetry; e.StateSince = lastRetry;
            e.Announcements = 1; e.State = st; e.Resets = resets;
            e.VerdictId = verdictId; e.VerdictResetAt = verdictResetAt;
            return e;
        }

        private static bool LineWith(string text, string a, string b)
        {
            foreach (string line in text.Split(new string[] { "\r\n" }, StringSplitOptions.None))
            {
                if (line.IndexOf(a, StringComparison.Ordinal) >= 0 && line.IndexOf(b, StringComparison.Ordinal) >= 0) return true;
            }
            return false;
        }

        private static int LinesWith(string text, string a)
        {
            int n = 0;
            foreach (string line in text.Split(new string[] { "\r\n" }, StringSplitOptions.None))
            {
                if (line.IndexOf(a, StringComparison.Ordinal) >= 0) n++;
            }
            return n;
        }

        private static bool Has(string[] fields, string f) { return Array.IndexOf(fields, f) >= 0; }

        private static string FieldValue(string[] fields, string label)
        {
            foreach (string f in fields) { if (f.StartsWith(label + "|", StringComparison.Ordinal)) return f.Substring(label.Length + 1); }
            return "";
        }

        private static void ReportBuilderTests()
        {
            DateTime none = DateTime.MinValue;
            string[] baseFields = new string[] { "Session identifier|111", "Peer (SMB server name)|\\peer" };

            LogEntry vf = Reports.Verdict(VerifyOutcome.Failed, true, VerdictLink.Attached, 7, At(20, 3, 7, 0), baseFields, 10, "service, process 1");
            Check("verdict: retries after a reset are interim event 3004 at Information",
                  vf.Id == 3004 && vf.Type == EventLogEntryType.Information && vf.Id != Log.IdRepairFailed &&
                  LineWith(vf.Text, "Verdict status", "interim") && !vf.Text.Contains("did not hold") &&
                  vf.Text.StartsWith("Retries continued after the connection reset; the repair is not yet confirmed."),
                  "id=" + vf.Id + " type=" + vf.Type);

            LogEntry vh = Reports.Verdict(VerifyOutcome.Held, true, VerdictLink.Attached, 7, At(20, 3, 7, 0), baseFields, 10, "service, process 1");
            Check("verdict: silence after a reset is interim event 3001 at Information, not a confirmed repair",
                  vh.Id == 3001 && vh.Type == EventLogEntryType.Information && !vh.Text.Contains("successfully") &&
                  vh.Text.StartsWith("No retry followed the connection reset during verification."),
                  "id=" + vh.Id + " type=" + vh.Type);

            bool anyWarning = false;
            foreach (VerifyOutcome v in new VerifyOutcome[] { VerifyOutcome.Held, VerifyOutcome.Inconclusive, VerifyOutcome.Failed })
            {
                foreach (bool c in new bool[] { true, false })
                {
                    if (Reports.Verdict(v, c, VerdictLink.Attached, 7, none, baseFields, 10, "i").Type == EventLogEntryType.Warning) anyWarning = true;
                }
            }
            Check("verdict: no outcome is ever written at Warning", !anyWarning, null);

            LogEntry vi = Reports.Verdict(VerifyOutcome.Held, false, VerdictLink.Attached, 7, none, baseFields, 10, "i");
            Check("verdict: an incomplete read is event 4000 at Error, unknown, never held",
                  vi.Id == 4000 && vi.Type == EventLogEntryType.Error && vi.Text.Contains("unknown, not failed") &&
                  !vi.Text.Contains("Verdict status") && !vi.Text.Contains("Final outcome") && LineWith(vi.Text, "Report", "7"),
                  "id=" + vi.Id + " type=" + vi.Type);

            bool linksOk = Reports.Link(false, 7, true) == VerdictLink.NotTracked &&
                           Reports.Link(true, 0, false) == VerdictLink.Unattached &&
                           Reports.Link(true, 7, false) == VerdictLink.Superseded &&
                           Reports.Link(true, 7, true) == VerdictLink.Attached;
            string tNot = Reports.Verdict(VerifyOutcome.Failed, true, VerdictLink.NotTracked, 0, none, baseFields, 10, "i").Text;
            string tUn = Reports.Verdict(VerifyOutcome.Failed, true, VerdictLink.Unattached, 0, none, baseFields, 10, "i").Text;
            string tSup = Reports.Verdict(VerifyOutcome.Failed, true, VerdictLink.Superseded, 7, none, baseFields, 10, "i").Text;
            string tAtt = Reports.Verdict(VerifyOutcome.Failed, true, VerdictLink.Attached, 7, none, baseFields, 10, "i").Text;
            Check("link: -once is not tracked, report 0 is unattached, a closed report is superseded, an open one is attached",
                  linksOk && LineWith(tNot, "Final outcome", "not tracked by this process") &&
                  LineWith(tUn, "Final outcome", "not attached to a report") &&
                  LineWith(tSup, "Final outcome", "report 7 had already closed (event 2002)") &&
                  LineWith(tAtt, "Final outcome", "event 2002 when no retry remains in the 10-minute look-back window") &&
                  !tNot.Contains("Report  ") && LinesWith(tNot, "Report") == 0,
                  "links=" + linksOk);

            DateTime u = new DateTime(2026, 10, 30, 0, 0, 0, DateTimeKind.Utc);
            Check("numbering: the seed is minutes since 2000 UTC times 100, and one minute later it is 100 higher",
                  Reports.NumberSeed(u) == 1411056000L && Reports.NumberSeed(u.AddMinutes(1)) - Reports.NumberSeed(u) == 100,
                  "seed=" + Reports.NumberSeed(u));

            string[] nrFields = new string[] { "Peer (SMB server name)|\\peer", "Matched nothing|1" };
            LogEntry nr1 = Reports.NothingReset(1, 0, 0, nrFields);
            LogEntry nr2 = Reports.NothingReset(0, 0, 1, nrFields);
            Check("nothing reset: a refused reset is a 3002 Error",
                  nr1.Id == 3002 && nr1.Type == EventLogEntryType.Error &&
                  nr1.Text.StartsWith("Nothing was reset, so these stuck sessions were not repaired."), "id=" + nr1.Id);
            Check("nothing reset: matching nothing is 3000 Information",
                  nr2.Id == 3000 && nr2.Type == EventLogEntryType.Information &&
                  nr2.Text.StartsWith("No connection to this peer address remained, so nothing was reset."), "id=" + nr2.Id);

            Check("detected: a reminder after resets names them and keeps the existing prefix",
                  Reports.DetectedSummary(0) == "A stuck Cluster Shared Volume SMB session was detected." &&
                  Reports.DetectedSummary(2).StartsWith("A stuck Cluster Shared Volume SMB session") &&
                  Reports.DetectedSummary(2).Contains("after 2 connection resets.") &&
                  Reports.DetectedSummary(1).Contains("after 1 connection reset."),
                  Reports.DetectedSummary(2));

            Episode e1 = Ep(1, "111", ReportState.Stuck, At(20, 3, 7, 0), At(20, 3, 0, 0), 0, 0, none);
            Episode e2 = Ep(2, "222", ReportState.Retrying, At(20, 4, 0, 0), At(20, 12, 0, 0), 1, 0, none);
            List<LogEntry> r = Reports.Record("open", new List<Episode>() { e1, e2 }, new List<Episode>(), new List<StuckSession>(),
                                              "channel enabled", At(20, 12, 0, 0), null, "service, process 1", "NODE1");
            Check("record: 2005 lists every open report with its state",
                  r.Count == 1 && r[0].Id == 2005 && r[0].Type == EventLogEntryType.Warning &&
                  r[0].Text.StartsWith("2 CSV SMB sessions reported stuck are not yet confirmed to have stopped retrying.") &&
                  LineWith(r[0].Text, "Report 1 ", "meets the detection criteria") &&
                  LineWith(r[0].Text, "Report 2 ", "retrying below the detection criteria, last retry 2026-10-28 20:12:00") &&
                  LineWith(r[0].Text, "Trigger", "open"),
                  r.Count == 0 ? "none" : r[0].Text.Split('\r')[0]);

            Episode closedE = Ep(1, "111", ReportState.Clearing, At(20, 3, 7, 0), At(20, 18, 0, 0), 2, 3004, At(20, 6, 1, 0));
            List<LogEntry> r6 = Reports.Record("close", new List<Episode>(), new List<Episode>() { closedE }, new List<StuckSession>(),
                                               "channel enabled", At(20, 32, 0, 0), null, "service, process 1", "NODE1");
            Check("record: 2006 names what it closes",
                  r6.Count == 1 && r6[0].Id == 2006 && r6[0].Type == EventLogEntryType.Warning &&
                  r6[0].Text.StartsWith("No CSV SMB session is reported stuck.") && r6[0].Text.Contains("supersed") &&
                  LineWith(r6[0].Text, "Report 1 ", "verdict 3004 for the reset issued at 2026-10-28 20:06:01.000"),
                  r6.Count == 0 ? "none" : r6[0].Text.Split('\r')[0]);

            string[] r6Lines = r6.Count == 0 ? new string[0] : r6[0].Text.Split(new string[] { "\r\n" }, StringSplitOptions.None);
            int hi = Array.IndexOf(r6Lines, "Closed, superseding their earlier warnings");
            Check("record: the Closed list is set apart by blank lines, so the fields after it do not read as closed reports",
                  hi > 0 && hi + 2 < r6Lines.Length && r6Lines[hi - 1].Length == 0 && r6Lines[hi + 1].Contains("Report 1 ") && r6Lines[hi + 2].Length == 0,
                  hi <= 0 ? "heading at " + hi : "before=[" + r6Lines[hi - 1] + "] after=[" + (hi + 2 < r6Lines.Length ? r6Lines[hi + 2] : "") + "]");

            List<StuckSession> oneU = new List<StuckSession>() { MkAt("S9", "\\p9", At(20, 30, 0, 0), At(20, 31, 0, 0)) };
            List<StuckSession> twoU = new List<StuckSession>() { MkAt("S9", "\\p9", At(20, 30, 0, 0), At(20, 31, 0, 0)),
                                                                 MkAt("S8", "\\p8", At(20, 30, 0, 0), At(20, 31, 0, 0)) };
            string u1 = Reports.Record("close", new List<Episode>(), new List<Episode>() { closedE }, oneU, "x", At(20, 32, 0, 0), null, "i", "N")[0].Text;
            string u2 = Reports.Record("close", new List<Episode>(), new List<Episode>() { closedE }, twoU, "x", At(20, 32, 0, 0), null, "i", "N")[0].Text;
            Check("record: the all-clear names other sessions retrying in the window, with correct plurals",
                  u1.StartsWith("No CSV SMB session is reported stuck; 1 other session logged retries in the look-back window.") &&
                  u2.StartsWith("No CSV SMB session is reported stuck; 2 other sessions logged retries in the look-back window.") &&
                  LineWith(u1, "Session S9", "\\p9"),
                  u1.Split('\r')[0]);

            List<Episode> fiftyOne = new List<Episode>();
            for (int i = 1; i <= 51; i++) fiftyOne.Add(Ep(i, "11529215046068" + i.ToString("000", CultureInfo.InvariantCulture), ReportState.Stuck, At(20, 3, 7, 0), At(20, 3, 0, 0), 0, 0, none));
            List<LogEntry> r51 = Reports.Record("open", fiftyOne, new List<Episode>(), new List<StuckSession>(), "x", At(20, 3, 7, 0), null, "i", "N");
            bool all51 = r51.Count == 1;
            for (int i = 1; i <= 51 && all51; i++) { if (!LineWith(r51[0].Text, "Report " + i.ToString(CultureInfo.InvariantCulture) + " ", "session ")) all51 = false; }
            Check("record: 51 open reports, as in the measured incident, fit in one part and are all listed", all51, "parts=" + r51.Count);

            List<Episode> openMany = new List<Episode>();
            List<Episode> closedMany = new List<Episode>();
            for (int i = 1; i <= 300; i++) openMany.Add(Ep(i, "11529215046068" + i.ToString("000", CultureInfo.InvariantCulture), ReportState.Retrying, At(20, 3, 7, 0), At(20, 12, 0, 0), 3, 0, none));
            for (int i = 301; i <= 500; i++) closedMany.Add(Ep(i, "11529215046068" + i.ToString("000", CultureInfo.InvariantCulture), ReportState.Clearing, At(20, 3, 7, 0), At(20, 18, 0, 0), 2, 3004, At(20, 6, 1, 0)));
            List<LogEntry> parts = Reports.Record("open, close", openMany, closedMany, new List<StuckSession>(), "x", At(20, 32, 0, 0), null, "service, process 1", "NODE1");
            bool sizesOk = parts.Count > 1, labelled = true, allListed = true;
            for (int p = 0; p < parts.Count; p++)
            {
                if (parts[p].Text.Length > Reports.PartBudget) sizesOk = false;
                if (!LineWith(parts[p].Text, "Part", (p + 1).ToString(CultureInfo.InvariantCulture) + " of " + parts.Count.ToString(CultureInfo.InvariantCulture))) labelled = false;
                if (parts[p].Id != 2005 || parts[p].Type != EventLogEntryType.Warning) labelled = false;
            }
            for (int i = 1; i <= 500 && allListed; i++)
            {
                string label = "Report " + i.ToString(CultureInfo.InvariantCulture) + " ";
                bool found = false;
                foreach (LogEntry pe in parts) { if (LinesWith(pe.Text, label) > 0) { found = true; break; } }
                if (!found) allListed = false;
            }
            Check("record: 300 open and 200 closed split into parts under 15,000 characters, losing none",
                  sizesOk && labelled && allListed, "parts=" + parts.Count + " sizes=" + sizesOk + " labelled=" + labelled + " listed=" + allListed);

            List<StuckSession> sixty = new List<StuckSession>();
            for (int i = 0; i < 60; i++) sixty.Add(MkAt("U" + i.ToString(CultureInfo.InvariantCulture), "\\pu", At(20, 30, 0, 0), At(20, 31, 0, 0)));
            string capped = Reports.Record("close", new List<Episode>(), new List<Episode>() { closedE }, sixty, "x", At(20, 32, 0, 0), null, "i", "N")[0].Text;
            Check("record: more than 50 unreported sessions are capped with a count",
                  LinesWith(capped, "Session U") == 50 && LineWith(capped, "More", "10 not listed") && LineWith(capped, "not reported", "60"),
                  "listed=" + LinesWith(capped, "Session U"));

            string withT = Reports.Record("stop", new List<Episode>() { e1 }, new List<Episode>(), new List<StuckSession>(), "x", At(20, 12, 0, 0), "paused while the service is stopped", "i", "N")[0].Text;
            string withoutT = Reports.Record("open", new List<Episode>() { e1 }, new List<Episode>(), new List<StuckSession>(), "x", At(20, 12, 0, 0), null, "i", "N")[0].Text;
            Check("record: Tracking appears only when given",
                  LineWith(withT, "Tracking", "paused while the service is stopped") && LinesWith(withoutT, "Tracking") == 0, null);

            string stopNoRead = Reports.Record("stop", new List<Episode>() { e1 }, new List<Episode>(), null, "not checked", none, "paused; save not confirmed: busy", "i", "N")[0].Text;
            Check("record: a stop record built without a read says 'not read at stop' instead of zero",
                  LineWith(stopNoRead, "Retries in the window, not reported", "not read at stop") &&
                  LineWith(stopNoRead, "State as of", "not read at stop"), null);

            closedE.Announcements = 3;
            string[] cf = Reports.ClosureFields(closedE, "service, process 1", "NODE1");
            string sup = FieldValue(cf, "Supersedes");
            Check("closure: the legacy Session and peer field comes first, and the 2000 it supersedes is named",
                  cf.Length > 0 && cf[0] == "Session and peer|111|\\peer" &&
                  sup.Contains("report 1: event 2000 reported since 2026-10-28 20:03:07 and its 2 reminders") &&
                  sup.Contains("event 3004 for the reset issued at 2026-10-28 20:06:01.000") &&
                  Has(cf, "Report|1") && Has(cf, "Instance|service, process 1"),
                  sup);

            LogEntry sn = Reports.StartNotice("no saved state was found", true, 1, oneU, ChannelState.Available,
                                              "Microsoft-Windows-SMBClient/Security is enabled", "service, process 1", "NODE1");
            Check("start notice: event 4000 at Warning, listing unreported retries and the open count",
                  sn.Id == 4000 && sn.Type == EventLogEntryType.Warning && LineWith(sn.Text, "Reports open now", "1") &&
                  LineWith(sn.Text, "Session S9", "\\p9") && LineWith(sn.Text, "Reason", "no saved state was found"),
                  "id=" + sn.Id);
            string cleanStart = "Stuck-session reports from before this start, if any, are not tracked; no CSV SMB session logged retries in the look-back window.";
            string plainStart = "Stuck-session reports from before this start, if any, are not tracked.";
            LogEntry clean = Reports.StartNotice("r", true, 0, new List<StuckSession>(), ChannelState.Available, "enabled", "i", "N");
            LogEntry dirty1 = Reports.StartNotice("r", true, 0, new List<StuckSession>(), ChannelState.Disabled, "disabled", "i", "N");
            LogEntry dirty2 = Reports.StartNotice("r", false, 0, new List<StuckSession>(), ChannelState.Available, "enabled", "i", "N");
            LogEntry dirty3 = Reports.StartNotice("r", true, 1, new List<StuckSession>(), ChannelState.Available, "enabled", "i", "N");
            LogEntry dirty4 = Reports.StartNotice("r", true, 0, oneU, ChannelState.Available, "enabled", "i", "N");
            Check("start notice: says 'if any' and adds the clean-state clause only when the read was complete, the channel available and nothing open or retrying",
                  clean.Text.StartsWith(cleanStart) &&
                  dirty1.Text.StartsWith(plainStart) && dirty2.Text.StartsWith(plainStart) &&
                  dirty3.Text.StartsWith(plainStart) && dirty4.Text.StartsWith(plainStart),
                  clean.Text.Split('\r')[0]);
            Check("start notice: an incomplete read prints 'not read', never a zero",
                  LineWith(dirty2.Text, "Retries in the window, not reported", "not read") &&
                  !LineWith(dirty2.Text, "Retries in the window, not reported", "0"), null);

            LogEntry cnD = Reports.ChannelNotice(ChannelState.Disabled, "Microsoft-Windows-SMBClient/Security exists but is disabled", 1, "NODE1");
            LogEntry cnU = Reports.ChannelNotice(ChannelState.Unavailable, "a previous channel check has not returned", 1, "NODE1");
            Check("channel notice: disabled and could-not-be-checked read differently",
                  cnD.Id == 4000 && cnD.Type == EventLogEntryType.Warning && cnU.Type == EventLogEntryType.Warning &&
                  cnD.Text.StartsWith("The retry event channel is disabled, so no stuck-session report can close.") &&
                  cnU.Text.StartsWith("The retry event channel could not be checked, so no stuck-session report can close.") &&
                  LineWith(cnD.Text, "Reports waiting", "1"), null);

            LogEntry sf = Reports.SaveFailedNotice("C:\\guard\\guard.state", "access denied", "NODE1");
            Check("save notice: event 4000 at Warning",
                  sf.Id == 4000 && sf.Type == EventLogEntryType.Warning &&
                  sf.Text.StartsWith("The stuck-session reports could not be saved.") && LineWith(sf.Text, "Problem", "access denied"), null);

            List<Episode> four = new List<Episode>() {
                Ep(1, "111", ReportState.Stuck, At(20, 3, 7, 0), At(20, 3, 0, 0), 0, 0, none),
                Ep(2, "222", ReportState.Retrying, At(20, 3, 7, 0), At(20, 12, 0, 0), 0, 0, none),
                Ep(3, "333", ReportState.Quiet, At(20, 3, 7, 0), At(20, 12, 0, 0), 0, 0, none),
                Ep(4, "444", ReportState.Clearing, At(20, 3, 7, 0), At(20, 12, 0, 0), 0, 0, none) };
            string[] cs = Reports.CurrentStateFields(four, new List<StuckSession>(), 2, "enabled", At(20, 20, 0, 0), "service, process 1");
            Check("current state: counts reports by state",
                  Has(cs, "Reports open|4") && Has(cs, "Meeting the criteria|1") && Has(cs, "Retrying, below criteria|1") &&
                  Has(cs, "Quiet, still in window|1") && Has(cs, "Confirming no retry|1") && Has(cs, "Sessions under repair|2") &&
                  Has(cs, "Retries, not reported|0") && Has(cs, "State as of|2026-10-28 20:20:00"), null);
            string[] cs0 = Reports.CurrentStateFields(new List<Episode>(), null, 0, "not checked", none, "service, process 1");
            Check("current state: before any complete evaluation says so, and unread retries print 'not read'",
                  Has(cs0, "State as of|no complete evaluation yet") && Has(cs0, "Retries, not reported|not read"), null);
        }

        private static PlanInput In(List<StuckSession> selected, List<StuckSession> seen, bool complete, int opened,
                                    ChannelState ch, Dictionary<string, DateTime> claims, DateTime now, long mono)
        {
            return Reports.Input(selected, seen, null, complete, opened, ch, "channel enabled", claims, now, mono,
                                 false, null, "service, process 1", "NODE1");
        }

        private static int CountId(List<LogEntry> entries, int id)
        {
            int n = 0;
            foreach (LogEntry e in entries) { if (e.Id == id) n++; }
            return n;
        }

        private static LogEntry FirstId(List<LogEntry> entries, int id)
        {
            foreach (LogEntry e in entries) { if (e.Id == id) return e; }
            return null;
        }

        private static List<LogEntry> OpenAndRecord(EpisodeLedger l, ReportFlags f, Config cfg, StuckSession s, DateTime t, long mono)
        {
            bool o;
            l.NoteDetected(s, t, 15, out o);
            return Reports.Plan(l, f, In(Seen(s), Seen(s), true, o ? 1 : 0, ChannelState.Available, NoClaims, t, mono), cfg);
        }

        private static void PlannerTests()
        {
            DateTime T0 = At(20, 3, 7, 0);
            Config cfg = new Config();

            Dictionary<string, DateTime> claims = new Dictionary<string, DateTime>(StringComparer.Ordinal);
            claims["k"] = T0;
            List<StuckSession> sel = Seen(MkAt("A", "\\peer", T0, T0));
            List<StuckSession> seenAll = Seen(MkAt("A", "\\peer", T0, T0), MkAt("B", "\\peer", T0, T0));
            PlanInput pi = Reports.Input(sel, seenAll, null, true, 0, ChannelState.Available, "d", claims, T0, 0, false, null, "i", "n");
            PlanInput pe = Reports.Input(sel, seenAll, "query failed", true, 0, ChannelState.Available, "d", claims, T0, 0, false, null, "i", "n");
            PlanInput pp = Reports.Input(sel, seenAll, null, false, 0, ChannelState.Available, "d", claims, T0, 0, false, null, "i", "n");
            PlanInput pn = Reports.Input(null, null, null, true, 0, ChannelState.Available, "d", null, T0, 0, false, null, "i", "n");
            claims["k2"] = T0;
            Check("input: Seen is every session read, Selected is the selection, Complete needs no error and a complete read, and InFlight is copied",
                  pi.Seen == seenAll && pi.Selected == sel && pi.Complete && !pe.Complete && !pp.Complete &&
                  pn.Seen != null && pn.Selected != null && pn.InFlight != null && pi.InFlight.Count == 1, null);

            EpisodeLedger L = new EpisodeLedger();
            ReportFlags f = new ReportFlags();
            StuckSession a = MkAt("A", "\\peer", T0.AddMinutes(-1), T0);
            OpenAndRecord(L, f, cfg, a, T0, 0);
            List<LogEntry> p = Reports.Plan(L, f, In(Seen(), Seen(MkAt("A", "\\peer", T0, T0.AddMinutes(5).AddSeconds(-30))), true, 0,
                                            ChannelState.Available, NoClaims, T0.AddMinutes(5), 300000), cfg);
            Check("plan: last-seen comes from every session read, not only the selected ones",
                  CountId(p, 2002) == 0 && CountId(p, 2005) == 0 && CountId(p, 2006) == 0 && L.Get(a.Key).State == ReportState.Retrying,
                  "entries=" + p.Count + " state=" + L.Get(a.Key).State);

            L = new EpisodeLedger(); f = new ReportFlags();
            a = MkAt("A", "\\peer", T0.AddMinutes(-1), T0);
            OpenAndRecord(L, f, cfg, a, T0, 0);
            int closures = 0;
            for (int k = 1; k <= 20; k++)
            {
                p = Reports.Plan(L, f, In(Seen(), Seen(MkAt("A", "\\peer", T0.AddMinutes(-25), T0.AddMinutes(-20))), true, 0,
                                          ChannelState.Available, NoClaims, T0.AddMinutes(2 * k), 120000L * k), cfg);
                closures += CountId(p, 2002) + CountId(p, 2006);
            }
            Check("plan: a session still in the window is never closed, however old its last retry", closures == 0, "closures=" + closures);

            L = new EpisodeLedger(); f = new ReportFlags();
            a = MkAt("A", "\\peer", T0.AddMinutes(-1), T0);
            OpenAndRecord(L, f, cfg, a, T0, 0);
            long v = L.Version;
            p = Reports.Plan(L, f, In(Seen(), Seen(), false, 0, ChannelState.Available, NoClaims, T0.AddMinutes(11), 660000), cfg);
            Check("plan: an incomplete read writes nothing and changes nothing", p.Count == 0 && L.Version == v, "entries=" + p.Count);

            Config fast = new Config();
            fast.RecentSeconds = 30;
            L = new EpisodeLedger(); f = new ReportFlags();
            a = MkAt("A", "\\peer", T0.AddMinutes(-1), T0);
            OpenAndRecord(L, f, fast, a, T0, 0);
            List<LogEntry> c0 = Reports.Plan(L, f, In(Seen(), Seen(), true, 0, ChannelState.Available, NoClaims, T0.AddMinutes(11), 660000), fast);
            List<LogEntry> c60 = Reports.Plan(L, f, In(Seen(), Seen(), true, 0, ChannelState.Available, NoClaims, T0.AddMinutes(12), 720000), fast);
            List<LogEntry> c120 = Reports.Plan(L, f, In(Seen(), Seen(), true, 0, ChannelState.Available, NoClaims, T0.AddMinutes(13), 780000), fast);
            Check("plan: a short -recent does not shorten the confirmation",
                  CountId(c0, 2002) == 0 && CountId(c60, 2002) == 0 && CountId(c120, 2002) == 1, null);

            Config slowRecent = new Config();
            slowRecent.RecentSeconds = 300;
            Config longDebounce = new Config();
            longDebounce.DebounceSeconds = 100;
            Check("config: a closure is confirmed max(RecentSeconds, 120) seconds less the debounce, never under half of it",
                  cfg.ConfirmSeconds == 100 && fast.ConfirmSeconds == 100 && slowRecent.ConfirmSeconds == 280 && longDebounce.ConfirmSeconds == 60,
                  "default=" + cfg.ConfirmSeconds);

            L = new EpisodeLedger(); f = new ReportFlags();
            a = MkAt("A", "\\peer", T0.AddMinutes(-1), T0);
            OpenAndRecord(L, f, cfg, a, T0, 0);
            Reports.Plan(L, f, In(Seen(), Seen(), true, 0, ChannelState.Available, NoClaims, T0.AddMinutes(11), 660000), cfg);
            List<LogEntry> tooSoon = Reports.Plan(L, f, In(Seen(), Seen(), true, 0, ChannelState.Available, NoClaims, T0.AddMinutes(11).AddMilliseconds(99999), 759999), cfg);
            List<LogEntry> nextSweep = Reports.Plan(L, f, In(Seen(), Seen(), true, 0, ChannelState.Available, NoClaims, T0.AddMinutes(11).AddMilliseconds(119600), 779600), cfg);
            Check("plan: a sweep landing just under 120 seconds after the first absent check closes the report, one under 100 seconds does not",
                  CountId(tooSoon, 2002) == 0 && CountId(nextSweep, 2002) == 1 && CountId(nextSweep, 2006) == 1,
                  "tooSoon=" + CountId(tooSoon, 2002) + " nextSweep=" + CountId(nextSweep, 2002));

            L = new EpisodeLedger(); f = new ReportFlags();
            List<StuckSession> many = new List<StuckSession>();
            int opened51 = 0;
            for (int i = 0; i < 51; i++)
            {
                StuckSession s = MkAt("M" + i.ToString(CultureInfo.InvariantCulture), "\\peer", T0.AddMinutes(-1), T0);
                bool o;
                L.NoteDetected(s, T0, 15, out o);
                if (o) opened51++;
                many.Add(s);
            }
            p = Reports.Plan(L, f, In(many, many, true, opened51, ChannelState.Available, NoClaims, T0, 0), cfg);
            Check("plan: 51 detections in one evaluation write one 2005", CountId(p, 2005) == 1 && p.Count == 1, "entries=" + p.Count);

            L = new EpisodeLedger(); f = new ReportFlags();
            a = MkAt("A", "\\peer", T0.AddMinutes(-1), T0);
            OpenAndRecord(L, f, cfg, a, T0, 0);
            Reports.Plan(L, f, In(Seen(), Seen(), true, 0, ChannelState.Available, NoClaims, T0.AddMinutes(11), 660000), cfg);
            p = Reports.Plan(L, f, In(Seen(), Seen(), true, 0, ChannelState.Available, NoClaims, T0.AddMinutes(13), 780000), cfg);
            Check("plan: a closure writes 2002 Information, then 2006 Warning naming it",
                  p.Count == 2 && p[0].Id == 2002 && p[0].Type == EventLogEntryType.Information &&
                  p[1].Id == 2006 && p[1].Type == EventLogEntryType.Warning &&
                  LinesWith(p[1].Text, "Report " + a.ReportId.ToString(CultureInfo.InvariantCulture) + " ") == 1,
                  "entries=" + p.Count);

            L = new EpisodeLedger(); f = new ReportFlags();
            a = MkAt("A", "\\peer", T0.AddMinutes(-1), T0);
            StuckSession b = MkAt("B", "\\peer", T0.AddMinutes(-1), T0);
            bool oab;
            L.NoteDetected(a, T0, 15, out oab);
            L.NoteDetected(b, T0, 15, out oab);
            Reports.Plan(L, f, In(Seen(a, b), Seen(a, b), true, 2, ChannelState.Available, NoClaims, T0, 0), cfg);
            StuckSession bLive = MkAt("B", "\\peer", T0, T0.AddMinutes(11));
            Reports.Plan(L, f, In(Seen(bLive), Seen(bLive), true, 0, ChannelState.Available, NoClaims, T0.AddMinutes(11), 660000), cfg);
            bLive = MkAt("B", "\\peer", T0, T0.AddMinutes(13));
            p = Reports.Plan(L, f, In(Seen(bLive), Seen(bLive), true, 0, ChannelState.Available, NoClaims, T0.AddMinutes(13), 780000), cfg);
            Check("plan: a closure with another report open writes 2005, not 2006",
                  CountId(p, 2002) == 1 && CountId(p, 2005) == 1 && CountId(p, 2006) == 0, "entries=" + p.Count);

            L = new EpisodeLedger(); f = new ReportFlags();
            a = MkAt("A", "\\peer", T0.AddMinutes(-1), T0);
            OpenAndRecord(L, f, cfg, a, T0, 0);
            Reports.Plan(L, f, In(Seen(), Seen(MkAt("A", "\\peer", T0, T0.AddSeconds(190))), true, 0, ChannelState.Available, NoClaims, T0.AddSeconds(200), 200000), cfg);
            List<LogEntry> held99 = Reports.Plan(L, f, In(Seen(), Seen(MkAt("A", "\\peer", T0, T0.AddSeconds(290))), true, 0, ChannelState.Available, NoClaims, T0.AddSeconds(299), 299000), cfg);
            List<LogEntry> held100 = Reports.Plan(L, f, In(Seen(), Seen(MkAt("A", "\\peer", T0, T0.AddSeconds(295))), true, 0, ChannelState.Available, NoClaims, T0.AddSeconds(300), 300000), cfg);
            StuckSession aBack = MkAt("A", "\\peer", T0, T0.AddSeconds(305));
            Reports.Plan(L, f, In(Seen(aBack), Seen(aBack), true, 0, ChannelState.Available, NoClaims, T0.AddSeconds(310), 310000), cfg);
            aBack = MkAt("A", "\\peer", T0, T0.AddSeconds(415));
            List<LogEntry> again = Reports.Plan(L, f, In(Seen(aBack), Seen(aBack), true, 0, ChannelState.Available, NoClaims, T0.AddSeconds(420), 420000), cfg);
            Check("plan: an early refresh needs the class change to hold for max(Sweep/2, Sweep - Debounce), and happens once between other records",
                  CountId(held99, 2005) == 0 && CountId(held100, 2005) == 1 && CountId(again, 2005) == 0,
                  "99s=" + CountId(held99, 2005) + " 100s=" + CountId(held100, 2005) + " flipBack=" + CountId(again, 2005));

            L = new EpisodeLedger(); f = new ReportFlags();
            a = MkAt("A", "\\peer", T0.AddMinutes(-1), T0);
            OpenAndRecord(L, f, cfg, a, T0, 0);
            Reports.Plan(L, f, In(Seen(), Seen(MkAt("A", "\\peer", T0, T0)), true, 0, ChannelState.Available, NoClaims, T0.AddSeconds(60), 60000), cfg);
            List<LogEntry> early = Reports.Plan(L, f, In(Seen(), Seen(MkAt("A", "\\peer", T0, T0)), true, 0, ChannelState.Available, NoClaims, T0.AddSeconds(160), 160000), cfg);
            List<LogEntry> r1059 = Reports.Plan(L, f, In(Seen(), Seen(MkAt("A", "\\peer", T0, T0.AddSeconds(1050))), true, 0, ChannelState.Available, NoClaims, T0.AddSeconds(1059), 1059000), cfg);
            List<LogEntry> r1060 = Reports.Plan(L, f, In(Seen(), Seen(MkAt("A", "\\peer", T0, T0.AddSeconds(1055))), true, 0, ChannelState.Available, NoClaims, T0.AddSeconds(1060), 1060000), cfg);
            Check("plan: a regular refresh comes no sooner than 15 minutes after the newest record",
                  CountId(early, 2005) == 1 && CountId(r1059, 2005) == 0 && CountId(r1060, 2005) == 1,
                  "early=" + CountId(early, 2005) + " 1059=" + CountId(r1059, 2005) + " 1060=" + CountId(r1060, 2005));

            L = new EpisodeLedger(); f = new ReportFlags();
            a = MkAt("A", "\\peer", T0.AddMinutes(-1), T0);
            OpenAndRecord(L, f, cfg, a, T0, 0);
            int stuckRefreshes = 0;
            for (int k = 1; k <= 30; k++)
            {
                StuckSession live = MkAt("A", "\\peer", T0, T0.AddSeconds(120 * k - 5));
                L.NoteReset(Seen(a), T0.AddSeconds(120 * k - 30));
                stuckRefreshes += CountId(Reports.Plan(L, f, In(Seen(live), Seen(live), true, 0, ChannelState.Available, NoClaims,
                                                               T0.AddSeconds(120 * k), 120000L * k), cfg), 2005);
            }
            Check("plan: a reset-count change on a report that stays Stuck never refreshes",
                  stuckRefreshes == 0 && L.Get(a.Key).Resets == 30, "refreshes=" + stuckRefreshes);

            L = new EpisodeLedger(); f = new ReportFlags();
            a = MkAt("A", "\\peer", T0.AddMinutes(-1), T0);
            bool oa;
            L.NoteDetected(a, T0, 15, out oa);
            List<LogEntry> partial = Reports.Plan(L, f, In(Seen(a), Seen(a), false, 1, ChannelState.Available, NoClaims, T0, 0), cfg);
            int pendingAfterPartial = f.PendingOpened;
            List<LogEntry> next = Reports.Plan(L, f, In(Seen(a), Seen(a), true, 0, ChannelState.Available, NoClaims, T0.AddSeconds(30), 30000), cfg);
            Check("plan: a report opened during an incomplete read is announced by the next complete evaluation's 2005",
                  partial.Count == 0 && pendingAfterPartial == 1 && CountId(next, 2005) == 1 &&
                  LineWith(FirstId(next, 2005).Text, "Trigger", "open") && f.PendingOpened == 0, null);

            L = new EpisodeLedger(); f = new ReportFlags();
            a = MkAt("A", "\\peer", T0.AddMinutes(-1), T0);
            OpenAndRecord(L, f, cfg, a, T0, 0);
            b = MkAt("B", "\\peer", T0, T0.AddSeconds(10));
            L.NoteDetected(b, T0.AddSeconds(10), 15, out oa);
            StuckSession aLive = MkAt("A", "\\peer", T0, T0.AddSeconds(10));
            Reports.Plan(L, f, In(Seen(aLive, b), Seen(aLive, b), true, 0, ChannelState.Available, NoClaims, T0.AddSeconds(10), 10000), cfg);
            f.EarlyUsed = true;
            aLive = MkAt("A", "\\peer", T0, T0.AddSeconds(890));
            StuckSession bLive2 = MkAt("B", "\\peer", T0, T0.AddSeconds(890));
            List<LogEntry> p899 = Reports.Plan(L, f, In(Seen(aLive, bLive2), Seen(aLive, bLive2), true, 0, ChannelState.Available, NoClaims, T0.AddSeconds(899), 899000), cfg);
            p = Reports.Plan(L, f, In(Seen(aLive, bLive2), Seen(aLive, bLive2), true, 0, ChannelState.Available, NoClaims, T0.AddSeconds(900), 900000), cfg);
            Check("plan: a report missing from the newest record counts as changed",
                  CountId(p899, 2005) == 0 && CountId(p, 2005) == 1 &&
                  LinesWith(FirstId(p, 2005).Text, "Report " + b.ReportId.ToString(CultureInfo.InvariantCulture) + " ") == 1,
                  "899s=" + CountId(p899, 2005) + " 900s=" + CountId(p, 2005));

            L = new EpisodeLedger(); f = new ReportFlags();
            f.PendingClosed.Add(Ep(41, "441", ReportState.Clearing, T0, T0, 1, 0, DateTime.MinValue));
            p = Reports.Plan(L, f, In(Seen(), Seen(), true, 0, ChannelState.Available, NoClaims, T0, 0), cfg);
            Check("plan: a pending closure is written by the next complete evaluation",
                  CountId(p, 2006) == 1 && LinesWith(FirstId(p, 2006).Text, "Report 41 ") == 1 && f.PendingClosed.Count == 0, null);

            L = new EpisodeLedger(); f = new ReportFlags();
            a = MkAt("A", "\\peer", T0.AddMinutes(-1), T0);
            OpenAndRecord(L, f, cfg, a, T0, 0);
            int[] warnings = new int[7];
            long[] monos = new long[] { 660000, 780000, 840000, 900000, 960000, 1020000, 1080000 };
            ChannelState[] seq = new ChannelState[] { ChannelState.Unavailable, ChannelState.Unavailable, ChannelState.Available,
                                                      ChannelState.Unavailable, ChannelState.Available, ChannelState.Available, ChannelState.Unavailable };
            for (int k = 0; k < seq.Length; k++)
            {
                DateTime now = T0.AddMilliseconds(monos[k]);
                Dictionary<string, DateTime> hold = new Dictionary<string, DateTime>(StringComparer.Ordinal);
                hold[a.Key] = now.AddSeconds(-10);
                warnings[k] = CountId(Reports.Plan(L, f, In(Seen(), Seen(), true, 0, seq[k], hold, now, monos[k]), cfg), 4000);
            }
            Check("plan: an unavailable channel while a report is clearing warns once per 15 minutes, re-armed after two Available probes",
                  warnings[0] == 1 && warnings[1] == 0 && warnings[3] == 0 && warnings[6] == 1 && L.OpenCount == 1,
                  string.Join(",", Array.ConvertAll(warnings, delegate(int x) { return x.ToString(CultureInfo.InvariantCulture); })));

            L = new EpisodeLedger(); f = new ReportFlags();
            L.Restore(new List<Episode>() { Ep(5, "555", ReportState.Retrying, T0, T0, 1, 0, DateTime.MinValue) });
            f.Resumed = true;
            StuckSession five = MkAt("555", "\\peer", T0, T0.AddSeconds(5));
            List<LogEntry> resumed = Reports.Plan(L, f, In(Seen(), Seen(five), true, 0, ChannelState.Available, NoClaims, T0.AddSeconds(10), 10000), cfg);
            EpisodeLedger emptyL = new EpisodeLedger();
            ReportFlags emptyF = new ReportFlags();
            emptyF.Resumed = true;
            List<LogEntry> nothing = Reports.Plan(emptyL, emptyF, In(Seen(), Seen(), true, 0, ChannelState.Available, NoClaims, T0, 0), cfg);
            Check("plan: after a restore with reports open, the first complete evaluation writes one 2005 resume; with none open, nothing",
                  CountId(resumed, 2005) == 1 && LineWith(FirstId(resumed, 2005).Text, "Trigger", "resume") && nothing.Count == 0, null);

            L = new EpisodeLedger(); f = new ReportFlags();
            f.StartNotice = "no saved state was found";
            List<LogEntry> n1 = Reports.Plan(L, f, In(Seen(), Seen(), false, 0, ChannelState.Available, NoClaims, T0, 0), cfg);
            bool emittedKept = f.StartNoticeEmitted && f.StartNotice != null;
            Reports.AfterWrite(f, false);
            List<LogEntry> n2 = Reports.Plan(L, f, In(Seen(), Seen(), true, 0, ChannelState.Available, NoClaims, T0.AddSeconds(30), 30000), cfg);
            Check("plan: a start notice is written once, at the first evaluation, even when that read is incomplete",
                  CountId(n1, 4000) == 1 && FirstId(n1, 4000).Type == EventLogEntryType.Warning &&
                  LineWith(FirstId(n1, 4000).Text, "Retries in the window, not reported", "not read") && emittedKept && CountId(n2, 4000) == 0, null);

            L = new EpisodeLedger(); f = new ReportFlags();
            f.StartNotice = "no saved state was found";
            PlanInput stopIn = Reports.Input(null, null, null, false, 0, ChannelState.Available, "not checked", null, T0, 0, true,
                                             "paused while the service is stopped", "service, process 1", "NODE1");
            stopIn.UseLastRead = true;
            List<LogEntry> stopNotice = Reports.Plan(L, f, stopIn, cfg);
            Check("plan: the stop call never writes the start notice", CountId(stopNotice, 4000) == 0 && !f.StartNoticeEmitted, null);

            L = new EpisodeLedger(); f = new ReportFlags();
            a = MkAt("A", "\\peer", T0.AddMinutes(-1), T0);
            OpenAndRecord(L, f, cfg, a, T0, 0);
            f.LastUnreported = Seen(MkAt("S9", "\\p9", T0, T0));
            f.LastCompleteAt = At(20, 20, 0, 0);
            PlanInput stopOpen = Reports.Input(null, null, null, false, 0, ChannelState.Available, "not checked", null, T0.AddMinutes(30), 1800000, true,
                                               "paused while the service is stopped; resumes from guard.state", "service, process 1", "NODE1");
            stopOpen.UseLastRead = true;
            List<LogEntry> stopped = Reports.Plan(L, f, stopOpen, cfg);
            List<LogEntry> stoppedEmpty = Reports.Plan(new EpisodeLedger(), new ReportFlags(), stopOpen, cfg);
            Check("plan: stopping with reports open writes one 2005 with Trigger stop and the Tracking text; with nothing open, nothing",
                  CountId(stopped, 2005) == 1 && LineWith(FirstId(stopped, 2005).Text, "Trigger", "stop") &&
                  LineWith(FirstId(stopped, 2005).Text, "Tracking", "resumes from guard.state") && stoppedEmpty.Count == 0, null);
            Check("plan: a stop record under _gate uses the last complete read's unreported list and time",
                  CountId(stopped, 2005) == 1 && LineWith(FirstId(stopped, 2005).Text, "Session S9", "\\p9") &&
                  LineWith(FirstId(stopped, 2005).Text, "State as of", "2026-10-28 20:20:00"), null);
        }

        private static List<KeyValuePair<DateTime, int>> FieldStream()
        {
            List<KeyValuePair<DateTime, int>> ev = new List<KeyValuePair<DateTime, int>>();
            ev.Add(new KeyValuePair<DateTime, int>(At(19, 54, 50, 0), 50001));
            ev.Add(new KeyValuePair<DateTime, int>(At(19, 56, 50, 0), 50001));
            ev.Add(new KeyValuePair<DateTime, int>(At(19, 58, 50, 0), 50001));
            ev.Add(new KeyValuePair<DateTime, int>(At(20, 0, 50, 0), 50001));
            ev.Add(new KeyValuePair<DateTime, int>(At(20, 2, 50, 0), 50001));
            ev.Add(new KeyValuePair<DateTime, int>(At(20, 6, 0, 0), 50002));
            ev.Add(new KeyValuePair<DateTime, int>(At(20, 7, 0, 0), 50003));
            ev.Add(new KeyValuePair<DateTime, int>(At(20, 7, 40, 0), 50003));
            ev.Add(new KeyValuePair<DateTime, int>(At(20, 8, 20, 0), 50004));
            for (int i = 0; i < 14; i++) ev.Add(new KeyValuePair<DateTime, int>(At(20, 9, 20, 0).AddSeconds(40 * i), 50005 + i / 2));
            return ev;
        }

        private static List<StuckSession> FieldAt(List<KeyValuePair<DateTime, int>> stream, DateTime t)
        {
            StuckSession s = null;
            foreach (KeyValuePair<DateTime, int> e in stream)
            {
                if (e.Key < t.AddMinutes(-10) || e.Key > t) continue;
                if (s == null)
                {
                    s = new StuckSession();
                    s.SessionId = "S-field"; s.ServerName = "\\fe80::1%13";
                    s.First = e.Key; s.Last = e.Key; s.Count = 0;
                }
                s.Count++;
                if (e.Key < s.First) s.First = e.Key;
                if (e.Key > s.Last) s.Last = e.Key;
                s.NoteTime(e.Key);
                s.Note(e.Value);
            }
            List<StuckSession> seen = new List<StuckSession>();
            if (s != null) seen.Add(s);
            return seen;
        }

        private static void FieldReplayTests()
        {
            List<KeyValuePair<DateTime, int>> stream = FieldStream();
            List<DateTime> evals = new List<DateTime>() { At(20, 3, 7, 0), At(20, 5, 8, 0), At(20, 6, 0, 0), At(20, 7, 0, 0),
                                                          At(20, 7, 40, 0), At(20, 8, 20, 0), At(20, 9, 0, 0) };
            for (int m = 10; m <= 34; m += 2) evals.Add(At(20, m, 0, 0));
            DateTime start = At(20, 3, 7, 0);
            string key = "S-field|\\fe80::1%13";
            Config cfg = new Config();
            EpisodeLedger L = new EpisodeLedger();
            ReportFlags f = new ReportFlags();
            Dictionary<string, DateTime> claims = new Dictionary<string, DateTime>(StringComparer.Ordinal);
            StuckSession[] lastSel = new StuckSession[1];
            long[] reportId = new long[1];
            List<KeyValuePair<DateTime, Action>> actions = new List<KeyValuePair<DateTime, Action>>();
            actions.Add(new KeyValuePair<DateTime, Action>(At(20, 3, 8, 0), delegate() { L.NoteReset(Seen(lastSel[0]), At(20, 3, 8, 0)); }));
            actions.Add(new KeyValuePair<DateTime, Action>(At(20, 4, 38, 0), delegate() { L.NoteVerdict(key, reportId[0], 3001, At(20, 3, 8, 0)); claims.Remove(key); }));
            actions.Add(new KeyValuePair<DateTime, Action>(At(20, 6, 1, 0), delegate() { L.NoteReset(Seen(lastSel[0]), At(20, 6, 1, 0)); }));
            actions.Add(new KeyValuePair<DateTime, Action>(At(20, 8, 32, 0), delegate() { L.NoteVerdict(key, reportId[0], 3004, At(20, 6, 1, 0)); claims.Remove(key); }));

            List<string> selectedAt = new List<string>();
            List<string> warningsAt = new List<string>();
            Dictionary<string, List<LogEntry>> byTime = new Dictionary<string, List<LogEntry>>(StringComparer.Ordinal);
            int nextAction = 0;
            foreach (DateTime t in evals)
            {
                while (nextAction < actions.Count && actions[nextAction].Key <= t) { actions[nextAction].Value(); nextAction++; }
                List<StuckSession> seen = FieldAt(stream, t);
                List<StuckSession> sel = Detector.Select(seen, cfg, t);
                int opened = 0;
                foreach (StuckSession s in sel)
                {
                    bool o;
                    L.NoteDetected(s, t, 15, out o);
                    if (o) opened++;
                    selectedAt.Add(t.ToString("HH:mm:ss", CultureInfo.InvariantCulture));
                    lastSel[0] = s;
                    reportId[0] = s.ReportId;
                }
                if (t == At(20, 3, 7, 0) || t == At(20, 6, 0, 0)) claims[key] = t;
                List<LogEntry> entries = Reports.Plan(L, f, Reports.Input(sel, seen, null, true, opened, ChannelState.Available,
                    "channel enabled", claims, t, (long)(t - start).TotalMilliseconds, false, null, "service, process 1", "NODE1"), cfg);
                string hh = t.ToString("HH:mm:ss", CultureInfo.InvariantCulture);
                byTime[hh] = entries;
                foreach (LogEntry e in entries) { if (e.Type == EventLogEntryType.Warning) warningsAt.Add(hh + " " + e.Id.ToString(CultureInfo.InvariantCulture)); }
            }

            Check("field replay: Select picks the session at 20:03:07, 20:06:00, 20:07:00, 20:07:40 and 20:08:20, and at no other evaluation",
                  string.Join(",", selectedAt.ToArray()) == "20:03:07,20:06:00,20:07:00,20:07:40,20:08:20", string.Join(",", selectedAt.ToArray()));
            Check("field replay: one report, opened at 20:03:07 and closed once",
                  L.OpenedTotal == 1 && L.ClosedTotal == 1 && L.OpenCount == 0, "opened=" + L.OpenedTotal + " closed=" + L.ClosedTotal);
            int quietEntries = 0;
            foreach (string hh in new string[] { "20:05:08", "20:06:00", "20:07:00", "20:07:40", "20:08:20", "20:09:00" }) quietEntries += byTime[hh].Count;
            Check("field replay: nothing at all is written from 20:05:08 to 20:09:00, where 'no longer present' and 'did not hold' were logged",
                  quietEntries == 0, "entries=" + quietEntries);
            Check("field replay: the Warning entries are exactly a 2005 open at 20:03:07, 2005 refreshes at 20:12:00 and 20:28:00, and a 2006 at 20:32:00",
                  string.Join(",", warningsAt.ToArray()) == "20:03:07 2005,20:12:00 2005,20:28:00 2005,20:32:00 2006",
                  string.Join(",", warningsAt.ToArray()));
            LogEntry r12 = FirstId(byTime["20:12:00"], 2005);
            LogEntry r28 = FirstId(byTime["20:28:00"], 2005);
            Check("field replay: the 20:12:00 refresh reads 'retrying below the detection criteria, last retry 2026-10-28 20:12:00' and the 20:28:00 refresh reads 'no retry since 2026-10-28 20:18:00'",
                  r12 != null && r28 != null &&
                  r12.Text.Contains("retrying below the detection criteria, last retry 2026-10-28 20:12:00") &&
                  r28.Text.Contains("no retry since 2026-10-28 20:18:00") &&
                  LineWith(r12.Text, "Trigger", "refresh") && LineWith(r28.Text, "Trigger", "refresh"), null);
            List<LogEntry> closing = byTime["20:32:00"];
            Check("field replay: at 20:32:00 the 2002 Information comes before the 2006 Warning",
                  closing.Count == 2 && closing[0].Id == 2002 && closing[0].Type == EventLogEntryType.Information &&
                  closing[1].Id == 2006 && closing[1].Type == EventLogEntryType.Warning, "entries=" + closing.Count);
            Check("field replay: the 2006 supersedes the report and cites the 3004 for the reset issued at 2026-10-28 20:06:01.000",
                  closing.Count == 2 && closing[1].Text.Contains("supersed") &&
                  LineWith(closing[1].Text, "Report " + reportId[0].ToString(CultureInfo.InvariantCulture) + " ",
                           "verdict 3004 for the reset issued at 2026-10-28 20:06:01.000"), null);
        }

        private static bool SameEpisode(Episode x, Episode y)
        {
            return x.Id == y.Id && x.Key == y.Key && x.SessionId == y.SessionId && x.ServerName == y.ServerName &&
                   x.OpenedAt == y.OpenedAt && x.LastAnnouncedAt == y.LastAnnouncedAt && x.Announcements == y.Announcements &&
                   x.LastRetryAt == y.LastRetryAt && x.State == y.State && x.StateSince == y.StateSince &&
                   x.Resets == y.Resets && x.LastResetAt == y.LastResetAt &&
                   x.VerdictId == y.VerdictId && x.VerdictResetAt == y.VerdictResetAt;
        }

        private static bool Refused(string text, string node)
        {
            long next;
            List<Episode> back;
            string problem;
            return !StateFile.TryParse(text, node, out next, out back, out problem) && problem != null && back.Count == 0;
        }

        private static void StateFileTests()
        {
            Episode a = Ep(17, "1152921504606847001", ReportState.Retrying, At(20, 3, 7, 0), At(20, 12, 0, 0), 2, 3004, At(20, 6, 1, 123));
            a.LastAnnouncedAt = At(20, 18, 7, 0);
            a.Announcements = 2;
            a.StateSince = At(20, 9, 0, 0);
            a.LastResetAt = At(20, 6, 1, 123);
            a.AbsentSinceMs = 42;
            Episode b = Ep(18, "1152921504606847002", ReportState.Stuck, At(20, 4, 0, 0), At(20, 4, 0, 0), 0, 0, DateTime.MinValue);
            string text = StateFile.Serialize("NODE1", 19, new List<Episode>() { a, b });
            long next;
            List<Episode> back;
            string problem;
            bool ok = StateFile.TryParse(text, "NODE1", out next, out back, out problem);
            Check("state file: reports round-trip with every field, and the next number survives",
                  ok && next == 19 && back.Count == 2 && SameEpisode(a, back[0]) && SameEpisode(b, back[1]) &&
                  back[0].AbsentSinceMs == -1 && back[0].ClassSinceMs == -1, problem);

            string empty = StateFile.Serialize("NODE1", 5, new List<Episode>());
            bool emptyOk = StateFile.TryParse(empty, "NODE1", out next, out back, out problem);
            Check("state file: an empty set round-trips", emptyOk && next == 5 && back.Count == 0, problem);

            StateFile.TryParse(text, "NODE2", out next, out back, out problem);
            Check("state file: a file from another node is refused",
                  Refused(text, "NODE2") && problem != null && problem.Contains("written by node"), problem);

            string badNumber = text.Replace("report\t17\t", "report\tx17\t");
            string[] lines = text.Split(new string[] { "\r\n" }, StringSplitOptions.None);
            string missingField = text.Replace(lines[3], lines[3].Substring(0, lines[3].LastIndexOf('\t')));
            string badHeader = text.Replace("CsvSessionGuard reports 1", "CsvSessionGuard reports 9");
            Check("state file: a malformed line is refused, not half-read",
                  Refused(badNumber, "NODE1") && Refused(missingField, "NODE1") && Refused(badHeader, "NODE1") &&
                  Refused(null, "NODE1") && Refused("", "NODE1"), null);

            string badState = text.Replace("\tRetrying\t", "\t7\t");
            string numericState = text.Replace("\tRetrying\t", "\t0\t");
            string badDate = text.Replace(lines[3].Split('\t')[4], "not-a-date");
            string duplicate = text.Replace(lines[4] + "\r\n", lines[4] + "\r\n" + lines[4] + "\r\n").Replace("end\t2", "end\t3");
            Check("state file: a malformed date or state name, or a duplicate report, is refused without throwing",
                  Refused(badState, "NODE1") && Refused(numericState, "NODE1") && Refused(badDate, "NODE1") && Refused(duplicate, "NODE1"), null);

            string cut = text.Substring(0, text.IndexOf("end\t", StringComparison.Ordinal));
            string wrongCount = text.Replace("end\t2", "end\t3");
            string cutAtReport = text.Substring(0, text.IndexOf(lines[4], StringComparison.Ordinal));
            Check("state file: a file cut short before its end line is refused",
                  Refused(cut, "NODE1") && Refused(wrongCount, "NODE1") && Refused(cutAtReport, "NODE1"), null);

            Check("state file: the temporary copy is used only when the main file is absent",
                  StateFile.Pick("main", "tmp") == "main" && StateFile.Pick(null, "tmp") == "tmp" && StateFile.Pick(null, null) == null, null);
        }

        private static void ReviewFixTests()
        {
            DateTime T0 = At(20, 3, 7, 0);
            Config cfg = new Config();

            Exception err;
            bool started;
            Worker.Result r = Worker.Run("t-throw2", delegate() { throw new InvalidOperationException("boom"); }, 2000, out err, out started);
            bool startedOk;
            Worker.Result ok = Worker.Run("t-ok2", delegate() { }, 2000, out err, out startedOk);
            Check("worker: a body that ran reports it, so a caller never releases a slot the body already released",
                  r == Worker.Result.Faulted && started && ok == Worker.Result.Completed && startedOk, "result=" + r);

            long v = 5;
            Monotonic.Raise(ref v, 3);
            long afterLower = v;
            Monotonic.Raise(ref v, 9);
            Check("written version: a lower value never replaces a higher one", afterLower == 5 && v == 9, "v=" + v);

            ReportFlags g = new ReportFlags();
            g.StartNotice = "no saved state was found";
            EpisodeLedger gl = new EpisodeLedger();
            Reports.Plan(gl, g, In(Seen(), Seen(), false, 0, ChannelState.Available, NoClaims, T0, 0), cfg);
            PlanInput stopAfter = Reports.Input(null, null, null, false, 0, ChannelState.Available, "not checked", null, T0.AddSeconds(5), 5000,
                                                true, "paused while the service is stopped", "service, process 1", "NODE1");
            stopAfter.UseLastRead = true;
            Reports.Plan(gl, g, stopAfter, cfg);
            bool openedGate = Reports.AfterWrite(g, false);
            Check("after write: a notice whose entries were never written stays pending, and the gate stays shut",
                  !openedGate && g.StartNotice != null && !g.StartNoticeWritten, "open=" + openedGate);

            ReportFlags h = new ReportFlags();
            h.StartNotice = "no saved state was found";
            Reports.Plan(new EpisodeLedger(), h, In(Seen(), Seen(), false, 0, ChannelState.Available, NoClaims, T0, 0), cfg);
            bool openNow = Reports.AfterWrite(h, false);
            bool openAgain = Reports.AfterWrite(h, true);
            Check("after write: an emitted notice is marked written and opens the gate once",
                  openNow && h.StartNotice == null && h.StartNoticeWritten && !h.StartNoticeEmitted && !openAgain, null);

            Check("save gate: each refusal names its own reason, and an open gate refuses nothing",
                  Reports.SaveGateRefusal(false, false, false) == "the saved state has not been loaded yet" &&
                  Reports.SaveGateRefusal(true, true, false) == "the load reader is still running" &&
                  Reports.SaveGateRefusal(true, false, false) == "the start notice has not been written yet" &&
                  Reports.SaveGateRefusal(true, false, true) == null, null);

            Check("stop tracking: the text says what actually happened to the saved state",
                  Reports.StopTracking(false, "console", null) == "ended with this console instance; not saved" &&
                  Reports.StopTracking(true, "service", null) == "paused while the service is stopped; resumes from guard.state" &&
                  Reports.StopTracking(true, "service", "busy") == "paused; save not confirmed: busy", null);

            EpisodeLedger L = new EpisodeLedger();
            ReportFlags f = new ReportFlags();
            StuckSession a = MkAt("A", "\\peer", T0.AddMinutes(-1), T0);
            OpenAndRecord(L, f, cfg, a, T0, 0);
            PlanInput stopIncomplete = Reports.Input(Seen(), Seen(), null, false, 0, ChannelState.Available, "channel enabled", null,
                                                     T0.AddMinutes(5), 300000, true, "paused while the service is stopped", "service, process 1", "NODE1");
            List<LogEntry> rec = Reports.Plan(L, f, stopIncomplete, cfg);
            Check("plan: a stop record written from an incomplete read carries the last complete read's time",
                  CountId(rec, 2005) == 1 && LineWith(FirstId(rec, 2005).Text, "State as of", "2026-10-28 20:03:07"),
                  CountId(rec, 2005) == 1 ? FirstId(rec, 2005).Text.Split('\r')[0] : "no record");

            L = OpenA(out a);
            Rec(L, Keys(), Seen(), true, ChannelState.Available, NoClaims, T0.AddMinutes(11), 0);
            List<string> u2 = Rec(L, Keys(), Seen(), true, ChannelState.Unavailable, NoClaims, T0.AddMinutes(13), 120000);
            List<string> u3 = Rec(L, Keys(), Seen(), true, ChannelState.Available, NoClaims, T0.AddMinutes(15), 240000);
            List<string> u4 = Rec(L, Keys(), Seen(), true, ChannelState.Available, NoClaims, T0.AddMinutes(17), 360000);
            Check("report: an unanswered channel probe restarts the confirmation",
                  u2.Count == 0 && u3.Count == 0 && u4.Count == 1, "u2=" + u2.Count + " u3=" + u3.Count + " u4=" + u4.Count);

            LogEntry unknown = Reports.NothingReset(0, 1, 0, new string[] { "Peer (SMB server name)|\\peer" });
            Check("nothing reset: an unrecognised control code is a 3002 Error",
                  unknown.Id == 3002 && unknown.Type == EventLogEntryType.Error &&
                  unknown.Text.StartsWith("Nothing was reset"), "id=" + unknown.Id);

            Episode k1 = Ep(17, "111", ReportState.Stuck, T0, T0, 0, 0, DateTime.MinValue);
            Episode k2 = Ep(18, "111", ReportState.Stuck, T0, T0, 0, 0, DateTime.MinValue);
            Check("state file: two reports for one session are refused",
                  Refused(StateFile.Serialize("NODE1", 19, new List<Episode>() { k1, k2 }), "NODE1"), null);
            Episode d1 = Ep(17, "111", ReportState.Stuck, T0, T0, 0, 0, DateTime.MinValue);
            Episode d2 = Ep(17, "222", ReportState.Stuck, T0, T0, 0, 0, DateTime.MinValue);
            Check("state file: one report number used twice is refused",
                  Refused(StateFile.Serialize("NODE1", 19, new List<Episode>() { d1, d2 }), "NODE1"), null);
            Episode z = Ep(0, "333", ReportState.Stuck, T0, T0, 0, 0, DateTime.MinValue);
            Check("state file: report number 0 is refused",
                  Refused(StateFile.Serialize("NODE1", 19, new List<Episode>() { z }), "NODE1"), null);
        }

        private static void Put(byte[] b, int at, params byte[] bytes) { bytes.CopyTo(b, at); }

        private static byte[] SyntheticClusterService(uint first, uint second, bool notFoundCheck, bool remoteGate)
        {
            byte[] b = new byte[0x700];
            Put(b, 0, (byte)'M', (byte)'Z');
            BitConverter.GetBytes(0x80).CopyTo(b, 0x3C);
            BitConverter.GetBytes(0x00004550).CopyTo(b, 0x80);
            BitConverter.GetBytes((ushort)0x8664).CopyTo(b, 0x84);
            BitConverter.GetBytes((ushort)3).CopyTo(b, 0x86);
            BitConverter.GetBytes((ushort)0xF0).CopyTo(b, 0x94);
            BitConverter.GetBytes((ushort)0x20B).CopyTo(b, 0x98);
            BitConverter.GetBytes(16).CopyTo(b, 0x98 + 108);
            BitConverter.GetBytes(0x400).CopyTo(b, 0x98 + 112 + 8);
            BitConverter.GetBytes(40).CopyTo(b, 0x98 + 112 + 12);
            BitConverter.GetBytes(0x600).CopyTo(b, 0x98 + 112 + 24);
            BitConverter.GetBytes(36).CopyTo(b, 0x98 + 112 + 28);
            uint[] va = new uint[] { 0x200, 0x400, 0x600 }, size = new uint[] { 0x200, 0x200, 0x100 };
            uint[] chars = new uint[] { 0x60000020, 0x40000040, 0x40000040 };
            for (int i = 0; i < 3; i++)
            {
                int s = 0x188 + 40 * i;
                BitConverter.GetBytes(size[i]).CopyTo(b, s + 8);
                BitConverter.GetBytes(va[i]).CopyTo(b, s + 12);
                BitConverter.GetBytes(size[i]).CopyTo(b, s + 16);
                BitConverter.GetBytes(va[i]).CopyTo(b, s + 20);
                BitConverter.GetBytes(chars[i]).CopyTo(b, s + 36);
            }
            BitConverter.GetBytes(0x440).CopyTo(b, 0x400);
            BitConverter.GetBytes(0x480).CopyTo(b, 0x40C);
            BitConverter.GetBytes(0x460).CopyTo(b, 0x410);
            BitConverter.GetBytes(0x490L).CopyTo(b, 0x440);
            BitConverter.GetBytes(0x490L).CopyTo(b, 0x460);
            Encoding.ASCII.GetBytes("ntdll.dll").CopyTo(b, 0x480);
            Encoding.ASCII.GetBytes("NtFsControlFile").CopyTo(b, 0x492);
            Put(b, 0x200, 0xC7, 0x44, 0x24, 0x28);
            BitConverter.GetBytes(first).CopyTo(b, 0x204);
            Put(b, 0x208, 0xFF, 0x15);
            BitConverter.GetBytes(0x460 - 0x20E).CopyTo(b, 0x20A);
            Put(b, 0x20E, 0xC7, 0x44, 0x24, 0x28);
            BitConverter.GetBytes(second).CopyTo(b, 0x212);
            Put(b, 0x216, 0xFF, 0x15);
            BitConverter.GetBytes(0x460 - 0x21C).CopyTo(b, 0x218);
            if (notFoundCheck) Put(b, 0x21C, 0x81, 0xFB, 0x34, 0x00, 0x00, 0xC0);
            Put(b, 0x222, 0xC3);
            Put(b, 0x260, 0xC7, 0x06, 0x18, 0x01, 0x00, 0x00, 0xC6, 0x86, 0x08, 0x01, 0x00, 0x00, 0x01);
            if (remoteGate) Put(b, 0x26D, 0xC6, 0x86, 0x09, 0x01, 0x00, 0x00, 0x01);
            Put(b, 0x274, 0x89, 0x9E, 0x0C, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x8E, 0x10, 0x01, 0x00, 0x00, 0xC3);
            Put(b, 0x2A0, 0xE8);
            BitConverter.GetBytes(0x260 - 0x2A5).CopyTo(b, 0x2A1);
            Put(b, 0x2A5, 0xE8);
            BitConverter.GetBytes(0x200 - 0x2AA).CopyTo(b, 0x2A6);
            Put(b, 0x2AA, 0xC3);
            uint[] pdata = new uint[] { 0x200, 0x260, 0, 0x260, 0x2A0, 0, 0x2A0, 0x2C0, 0 };
            for (int i = 0; i < pdata.Length; i++) BitConverter.GetBytes(pdata[i]).CopyTo(b, 0x600 + 4 * i);
            return b;
        }

        private static void ClusterCodeTests()
        {
            Check("control code: read from the cluster service's disconnect call",
                  ClusterControlCode.Find(SyntheticClusterService(0x1401A8, 0x1401A8, true, true)) == 0x1401A8, null);
            Check("control code: a renumbered disconnect call is followed",
                  ClusterControlCode.Find(SyntheticClusterService(0x1401B8, 0x1401B8, true, true)) == 0x1401B8, null);
            Check("control code: two calls with different codes give no answer",
                  ClusterControlCode.Find(SyntheticClusterService(0x1401A8, 0x1401B8, true, true)) == 0, null);
            Check("control code: a call without the 'server not found' check gives no answer",
                  ClusterControlCode.Find(SyntheticClusterService(0x1401A8, 0x1401A8, false, true)) == 0, null);
            Check("control code: a buffer builder missing one layout field gives no answer",
                  ClusterControlCode.Find(SyntheticClusterService(0x1401A8, 0x1401A8, true, false)) == 0, null);
            Check("control code: another device type or METHOD_NEITHER gives no answer",
                  ClusterControlCode.Find(SyntheticClusterService(0x0901A8, 0x0901A8, true, true)) == 0 &&
                  ClusterControlCode.Find(SyntheticClusterService(0x1401AB, 0x1401AB, true, true)) == 0, null);
            byte[] good = SyntheticClusterService(0x1401A8, 0x1401A8, true, true);
            byte[] half = new byte[good.Length / 2];
            Array.Copy(good, half, half.Length);
            byte[] noise = new byte[4096];
            new Random(7).NextBytes(noise);
            Check("control code: no file, an empty or truncated image, or noise gives no answer and never throws",
                  ClusterControlCode.Find(null) == 0 && ClusterControlCode.Find(new byte[0]) == 0 &&
                  ClusterControlCode.Find(half) == 0 && ClusterControlCode.Find(noise) == 0, null);
            Check("control code: no answer falls back to the built-in 0x1401A8, an answer is used as read",
                  ClusterControlCode.Choose(0) == 0x1401A8 && ClusterControlCode.Choose(0x1401B8) == 0x1401B8 &&
                  Fsctl.BuiltinCode == 0x1401A8, null);
            Check("control code: the file is named by build and revision only, and not at all without a version",
                  ClusterControlCode.BuildOf(26100, 33648) == "build 26100.33648" && ClusterControlCode.BuildOf(0, 0) == null, null);
        }

        private static void ConcurrencySmokeTest(DateTime T0)
        {
            EpisodeLedger cl = new EpisodeLedger();
            List<StuckSession> eight = new List<StuckSession>();
            bool o;
            for (int i = 0; i < 8; i++)
            {
                StuckSession s = MkAt("C" + i.ToString(CultureInfo.InvariantCulture), "\\peer", T0, T0);
                cl.NoteDetected(s, T0, 15, out o);
                eight.Add(s);
            }
            ManualResetEvent go = new ManualResetEvent(false);
            Exception[] firstError = new Exception[1];
            object errLock = new object();
            StopFlag stop = new StopFlag();
            long[] sink = new long[1];
            List<Thread> workers = new List<Thread>();
            for (int w = 0; w < 4; w++)
            {
                workers.Add(new Thread(delegate()
                {
                    try { go.WaitOne(); for (int k = 0; k < 2000; k++) cl.NoteReset(eight, T0.AddSeconds(k)); }
                    catch (Exception ex) { lock (errLock) { if (firstError[0] == null) firstError[0] = ex; } }
                }));
            }
            workers.Add(new Thread(delegate()
            {
                try
                {
                    go.WaitOne();
                    for (int k = 0; k < 2000; k++) { foreach (StuckSession s in eight) cl.NoteVerdict(s.Key, s.ReportId, 3004, T0.AddSeconds(k)); }
                }
                catch (Exception ex) { lock (errLock) { if (firstError[0] == null) firstError[0] = ex; } }
            }));
            workers.Add(new Thread(delegate()
            {
                try
                {
                    go.WaitOne();
                    for (int k = 0; k < 2000; k++)
                    {
                        StuckSession x = MkAt("X" + k.ToString(CultureInfo.InvariantCulture), "\\peer", T0, T0);
                        bool ox;
                        cl.NoteDetected(x, T0, 15, out ox);
                        cl.Close(new List<string>() { x.Key });
                    }
                }
                catch (Exception ex) { lock (errLock) { if (firstError[0] == null) firstError[0] = ex; } }
            }));
            Thread snapper = new Thread(delegate()
            {
                try { go.WaitOne(); while (!stop.Done) { sink[0] += cl.Snapshot().Count + cl.OpenCount; } }
                catch (Exception ex) { lock (errLock) { if (firstError[0] == null) firstError[0] = ex; } }
            });
            foreach (Thread t in workers) { t.IsBackground = true; t.Start(); }
            snapper.IsBackground = true;
            snapper.Start();
            DateTime deadline = DateTime.UtcNow.AddSeconds(10);
            go.Set();
            bool joined = true;
            foreach (Thread t in workers)
            {
                if (!t.Join((int)Math.Max(0, (deadline - DateTime.UtcNow).TotalMilliseconds))) joined = false;
            }
            stop.Done = true;
            if (!snapper.Join((int)Math.Max(0, (deadline - DateTime.UtcNow).TotalMilliseconds))) joined = false;
            bool resetsOk = true;
            foreach (StuckSession s in eight)
            {
                Episode e = cl.Get(s.Key);
                if (e == null || e.Resets != 8000) resetsOk = false;
            }
            Check("report: concurrent access loses nothing and throws nothing (smoke test)",
                  joined && firstError[0] == null && resetsOk && cl.OpenCount == 8,
                  "joined=" + joined + " error=" + (firstError[0] == null ? "none" : firstError[0].Message) +
                  " resetsOk=" + resetsOk + " open=" + cl.OpenCount);
        }

        // The rule this build replaces, kept as an oracle so the regression test can SHOW what the
        // old code would have said rather than assert it by hand: it counted every retry in a query
        // window that reached back past the reset, and treated any non-zero count as a failure.
        private static bool LegacyWouldFail(List<DateTime> windowEvents, DateTime resetAt)
        {
            if (windowEvents == null || windowEvents.Count == 0) return false;
            DateTime last = DateTime.MinValue;
            foreach (DateTime t in windowEvents) { if (t > last) last = t; }
            return last > resetAt;
        }

        private static bool Contains(List<StuckSession> list, string id)
        {
            foreach (StuckSession s in list) { if (s.SessionId == id) return true; }
            return false;
        }
    }
}
