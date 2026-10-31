// CsvSessionGuard - detects and repairs stuck CSV SMB client sessions on a Windows failover cluster.
//
// THE FAULT
// A Cluster Shared Volume SMB session can enter a permanently stuck state when adding a channel
// requires a full PKU2U exchange: the client cannot verify the server's signed interim reply, logs
// SMBClient event 31013 (status 0xC0000016) and retries indefinitely at roughly four per minute.
// The session is invisible to aggregate health checks because it hides behind a healthy session to
// the same peer, so cluster, CSV and channel-count checks all report normal.
//
// DETECTION
// Event 31013 is read from Microsoft-Windows-SMBClient/Security and grouped by SessionId, which is
// stable for the lifetime of a stuck session. A session is reported only when the retry loop is
// sustained: a minimum event count within the window, a minimum span, recent activity, and - the
// discriminator that separates a real loop from a transient bind burst - a minimum number of
// retries on a single client connection, identified by its local ephemeral port.
//
// An event subscription supplies low latency but is only a TRIGGER: every verdict comes from
// re-reading the log window, so there is no incremental state to drift out of step and a lost
// subscription degrades to the timer sweep rather than going silent.
//
// REPAIR
// FSCTL 0x1401A8 on \Device\SmbCsv disconnects this client's SMB connections to a named peer so the
// redirector rebuilds them. It is issued once per distinct failing peer address and scoped by the
// remote-address filter, so only the connections on the affected subnet to that peer are dropped.
// The calling convention is exact; each of these is required:
//   * Issue it with NtFsControlFile. The control code is device type 0x14, so Win32
//     DeviceIoControl would raise IRP_MJ_DEVICE_CONTROL while the handler is registered under
//     IRP_MJ_FILE_SYSTEM_CONTROL, and the request never reaches it.
//   * The reason at +0x004 must be 0. A negative value is accepted and makes every new connection
//     to the peer fail until a later call clears it; 0 clears it.
//   * The peer name requires a single leading backslash and the interface-zone suffix. The 31013
//     ServerName field already carries both, so it is passed through verbatim. It is never sent
//     empty: the driver applies an empty name to every server.
//   * Set the remote-address gate and write one plain sockaddr for the peer address. The kernel
//     compares address family and address only, never the port. A filter that matches nothing
//     changes nothing, so a wrong address is inert rather than a silent wide disconnect; the
//     driver still reports success for it.
// The unscoped form - every CSV connection to the peer - is available only behind -allowwholepeer.
//
// A single pass is not a guaranteed fix. The reset destroys connections, never the session object,
// and whether the session is then retired or rebuilt stuck is decided inside the kernel. A pass can
// therefore fail and a later pass on the same session can succeed, which is why retries seen at
// verification lead to another pass at the next sweep rather than to an alarm. Passes must not be
// bunched: a second reset inside the rebind window destroys the connections the recovery needs.
//
// VERIFICATION
// A repair is judged from the TIMES of the retry events relative to the instant the FSCTL was
// issued, recorded by Repair. Two rules follow from the retry loop being a 60-second timer:
//   * no event after the reset        -> the loop stopped (no retry seen);
//   * exactly one                     -> ambiguous, because a dead loop can leave one straggler.
//                                        Look once more and decide on whether a NEW event arrives;
//   * two or more                     -> the loop is alive (still retrying).
// Silence is only evidence when the source could have spoken, so the SMBClient/Security channel is
// checked for being present and enabled before silence is counted. Counting the records the
// query returned cannot serve that purpose: on a node whose only stuck session is the repaired one,
// zero records is exactly what a successful repair looks like.
//
// CONTROL CODE
// 0x1401A8 is not a documented public FSCTL name. It decodes as device 0x14
// FILE_DEVICE_NETWORK_FILE_SYSTEM, function 0x06A, METHOD_BUFFERED, FILE_ANY_ACCESS, and those
// fields are written to the log at startup and on every attempt so that a build which renumbers it
// can be identified from the log alone. STATUS_INVALID_DEVICE_REQUEST is reported as "the device did
// not accept the code or its request" rather than as a rejection, because the two call for
// different responses.
// The cluster service sends the same request itself. At start-up the code is read from its
// disconnect call in clussvc.exe, and accepted only when exactly one function there matches the
// call, its "server not found" check and the request layout; otherwise the built-in 0x1401A8 stays.
// It is never a command-line switch: a wrong value handed to a kernel admin path is not worth one.
//
// DEPLOYMENT
// Runs locally on each node and depends on nothing outside it: no remote management, no file share,
// no configuration file. This is deliberate, because the network faults that produce stuck sessions
// are the same faults that can cut a node off from any external manager.
//
// Every policy value is a command-line argument and is therefore recorded in the service ImagePath,
// readable with "sc qc CsvSessionGuard", so the running policy is inspectable with standard tools.
//
// DEFAULT IS DETECT-ONLY. Repair is performed only when -repair is passed.
//
// LANGUAGE: C# 5, built with the in-box compiler at
//   %WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
// so no string interpolation, null-conditional operator, "out var", or expression-bodied members.
//
// Build:
//   build.cmd   compiles both source files with that compiler, then runs the self-tests
//
// Usage:
//   CsvSessionGuard.exe -once [-repair]      evaluate once and exit; read-only unless -repair
//   CsvSessionGuard.exe -console [options]   run in the foreground
//   CsvSessionGuard.exe -install [options]   create the event log and service, set recovery, start
//   CsvSessionGuard.exe -uninstall           stop and delete the service

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Xml;

namespace CsvSessionGuard
{
    // ---------------------------------------------------------------- configuration
    internal sealed class Config
    {
        public bool Repair = false;              // -repair          : false => detect only

        // The repair is SCOPED by default: one FSCTL per failing peer address, so only that
        // subnet's channels to that peer are dropped. If the 31013 events carry no usable
        // RemoteAddress there is nothing to aim at, and the repair is SKIPPED rather than
        // silently widened to the whole peer. -allowwholepeer opts back into the wide form, which
        // drops every CSV connection to the peer including healthy ones carrying live opens.
        public bool AllowWholePeer = false;      // -allowwholepeer  : permit the wide fallback
        public int WindowMinutes = 10;           // -window N        : 31013 look-back
        public int MinEvents = 3;                // -minevents N     : total events, a floor only
        // -mineventsperport N : the primary discriminator, and it requires no elapsed time.
        // A session forming normally fails a bounded number of times on EACH of its channels and
        // then succeeds; a stuck session retries the SAME connection indefinitely. Measured
        // transients top out at 2 failures per local port while the lowest observed stuck session
        // reaches 3, so 3 is the default. It stays configurable because that margin is narrow.
        public int MinEventsPerPort = 3;
        public int MinSpanSeconds = 20;          // -minspan N       : SECONDS, a backstop only
        public int RecentSeconds = 120;          // -recent N        : last event must be this fresh
        public int SweepSeconds = 120;           // -sweep N         : timer cadence
        public int DebounceSeconds = 20;         // -debounce N      : min gap between evaluations
        public int FsctlTimeoutSeconds = 30;     // -fsctltimeout N  : watchdog on the kernel call
        public int VerifyDelaySeconds = 90;      // -verifydelay N   : wait before judging a repair

        // Requests already on the wire when the reset was issued are aborted or completed BY the
        // reset, so their retry events are not a resumption. DEFAULT 0, deliberately: in the
        // recorded specimen the events right after a reset carry the connection-first signature (a
        // local port never seen before, MessageId 1, a longer security blob), i.e. they are retries
        // on REBUILT connections, so absorbing them by time would discard real evidence. A single
        // such event is resolved by the second observation instead, which is evidence rather than a
        // chosen constant. Raise this only for a build shown to log in-flight stragglers.
        public int VerifyGraceSeconds = 0;       // -verifygrace N   : absorb in-flight events
        public int HeartbeatMinutes = 60;        // -heartbeat N     : summary cadence (0 = off)
        public int QueryTimeoutSeconds = 45;     // -querytimeout N  : watchdog on the event-log query
        public int LogTimeoutSeconds = 5;        // -logtimeout N    : watchdog on each log write and file read or save

        // Failsafe for an in-flight entry left by a dead thread. Not a repair interval.
        public int InFlightCeilingSeconds { get { return VerifyDelaySeconds + 60 + 60; } }

        // Less the debounce, so a sweep that lands a moment early still confirms a closure.
        public int ConfirmSeconds { get { int c = Math.Max(RecentSeconds, 120); return Math.Max(c / 2, c - DebounceSeconds); } }

        public string Describe()
        {
            return string.Format(CultureInfo.InvariantCulture,
                "mode={0} window={1}m minEvents={2} minPerPort={13} minSpan={3}s recent={4}s sweep={5}s " +
                "debounce={6}s inFlightCeiling={7}s repairLimit={8} fsctlTimeout={9}s verifyDelay={10}s " +
                "queryTimeout={11}s logTimeout={12}s scope={14} verifyGrace={15}s",
                Repair ? "REPAIR" : "DETECT-ONLY", WindowMinutes, MinEvents, MinSpanSeconds,
                RecentSeconds, SweepSeconds, DebounceSeconds, InFlightCeilingSeconds, "NONE",
                FsctlTimeoutSeconds, VerifyDelaySeconds, QueryTimeoutSeconds, LogTimeoutSeconds, MinEventsPerPort,
                AllowWholePeer ? "SCOPED+whole-peer-fallback" : "SCOPED-ONLY", VerifyGraceSeconds);
        }

        // Never throws. An unparsable value keeps its default and is reported by the caller.
        public static Config Parse(string[] args, out string problems)
        {
            Config c = new Config();
            StringBuilder bad = new StringBuilder();
            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i].ToLowerInvariant();
                if (a == "-repair") { c.Repair = true; continue; }
                if (a == "-allowwholepeer") { c.AllowWholePeer = true; continue; }
                if (!a.StartsWith("-")) continue;
                string val = (i + 1 < args.Length) ? args[i + 1] : null;
                int n;
                bool want = (a == "-window" || a == "-minevents" || a == "-minspan" || a == "-recent" ||
                             a == "-sweep" || a == "-debounce" ||
                             a == "-fsctltimeout" || a == "-verifydelay" || a == "-heartbeat" ||
                             a == "-querytimeout" || a == "-logtimeout" || a == "-mineventsperport" ||
                             a == "-verifygrace");
                if (!want) continue;
                if (val == null || !int.TryParse(val, out n) || n < 0)
                {
                    bad.Append(a); bad.Append(' ');
                    continue;
                }
                i++;
                switch (a)
                {
                    case "-window": c.WindowMinutes = Math.Max(1, n); break;
                    case "-minevents": c.MinEvents = Math.Max(1, n); break;
                    case "-minspan": c.MinSpanSeconds = n; break;
                    case "-mineventsperport": c.MinEventsPerPort = Math.Max(2, n); break;
                    case "-recent": c.RecentSeconds = Math.Max(1, n); break;
                    case "-sweep": c.SweepSeconds = Math.Max(15, n); break;
                    case "-debounce": c.DebounceSeconds = n; break;
                    case "-fsctltimeout": c.FsctlTimeoutSeconds = Math.Max(5, n); break;
                    // Floor of 65s, not 5s: the retry loop is a 60-second timer, so a shorter
                    // observation can see zero events from a loop that is still perfectly alive and
                    // report it as repaired. Ceiling keeps RecentSeconds (delay + 60) from
                    // overflowing into a negative window, which would silently read as success.
                    case "-verifydelay": c.VerifyDelaySeconds = Math.Max(65, Math.Min(3600, n)); break;
                    case "-heartbeat": c.HeartbeatMinutes = n; break;
                    case "-querytimeout": c.QueryTimeoutSeconds = Math.Max(5, n); break;
                    case "-logtimeout": c.LogTimeoutSeconds = Math.Max(1, n); break;
                    case "-verifygrace": c.VerifyGraceSeconds = Math.Max(0, Math.Min(60, n)); break;
                }
            }
            // The grace window must leave at least one full retry cadence of countable observation,
            // or a live loop can produce nothing to count and every repair reports "held". Applied
            // after the loop because the two options can arrive in either order.
            if (c.VerifyGraceSeconds > c.VerifyDelaySeconds - 60)
            {
                c.VerifyGraceSeconds = Math.Max(0, c.VerifyDelaySeconds - 60);
                bad.Append("-verifygrace(capped) ");
            }
            problems = bad.Length == 0 ? null : bad.ToString().Trim();
            return c;
        }
    }

    // ---------------------------------------------------------------- the worker primitive
    // EVERY call that leaves this process runs through here: the event-log query (RPC to the
    // EventLog service), event-log writes (RPC), file writes (disk), and the FSCTL (kernel).
    // Any of them can block indefinitely, and none of them can be cancelled - Thread.Abort does
    // not interrupt a blocking kernel or RPC call. So an overrunning worker is ABANDONED, not
    // aborted. Because it is a background thread it costs one thread and dies when the process
    // exits, which is why a persistent timeout escalates to a deliberate Environment.Exit and the
    // SCM restarts us with clean thread state. Nothing here logs - callers log - so there is no
    // recursion back into the logger.
    internal static class Worker
    {
        internal enum Result { Completed, TimedOut, Faulted }

        internal static Result Run(string name, Action body, int timeoutMs, out Exception error)
        {
            bool started;
            return Run(name, body, timeoutMs, out error, out started);
        }

        internal static Result Run(string name, Action body, int timeoutMs, out Exception error, out bool started)
        {
            error = null;
            started = false;
            Exception captured = null;
            Thread t;
            try
            {
                t = new Thread(delegate()
                {
                    try { body(); }
                    catch (Exception ex) { captured = ex; }
                });
                t.IsBackground = true;
                t.Name = name;
                t.Start();
                started = true;
            }
            catch (Exception ex) { error = ex; return Result.Faulted; }

            bool done;
            try { done = t.Join(timeoutMs); }
            catch (Exception ex) { error = ex; return Result.Faulted; }

            if (!done) return Result.TimedOut;
            if (captured != null) { error = captured; return Result.Faulted; }
            return Result.Completed;
        }
    }

    internal static class Monotonic
    {
        internal static void Raise(ref long target, long value)
        {
            long seen = Interlocked.Read(ref target);
            while (value > seen)
            {
                long was = Interlocked.CompareExchange(ref target, value, seen);
                if (was == seen) return;
                seen = was;
            }
        }
    }

    // ---------------------------------------------------------------- event message formatting
    // Mirrors how in-box Windows providers lay out an event body (e.g. SMBClient 30833):
    //   a single summary sentence, a blank line, aligned "Label: value" fields grouped under
    //   optional section headings, then an Impact paragraph and a Guidance paragraph.
    // Field list conventions, so call sites stay readable:
    //   "Label|value"  -> an aligned field
    //   "Heading:"     -> a section heading (no pipe)
    //   ""             -> a blank line
    internal static class Fmt
    {
        private const int Wrap = 92;

        // Summary line, blank line, aligned "Label  value" fields. Nothing else - no explanatory
        // prose. An event log is a record, not documentation.
        internal static string Event(string summary, string[] fields)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(summary);

            if (fields != null && fields.Length > 0)
            {
                int w = 0;
                foreach (string f in fields)
                {
                    if (string.IsNullOrEmpty(f)) continue;
                    int c = f.IndexOf('|');
                    if (c > w) w = c;
                }
                sb.Append("\r\n");
                foreach (string f in fields)
                {
                    if (f == null || f.Length == 0) { sb.Append("\r\n"); continue; }
                    int c = f.IndexOf('|');
                    if (c < 0) { sb.Append("\r\n"); sb.Append(f); continue; }
                    sb.Append("\r\n    ");
                    sb.Append(f.Substring(0, c).PadRight(w));
                    sb.Append("  ");
                    sb.Append(f.Substring(c + 1));
                }
            }

            return sb.ToString();
        }

        internal static string Hex32(uint v) { return "0x" + v.ToString("X8", CultureInfo.InvariantCulture); }

        internal static string Duration(TimeSpan t)
        {
            if (t.TotalMinutes < 1) return string.Format(CultureInfo.InvariantCulture, "{0:N0} seconds", t.TotalSeconds);
            if (t.TotalHours  < 1) return string.Format(CultureInfo.InvariantCulture, "{0:N0} minutes", t.TotalMinutes);
            return string.Format(CultureInfo.InvariantCulture, "{0:N0} hours {1:N0} minutes", Math.Floor(t.TotalHours), t.Minutes);
        }
    }

    // ---------------------------------------------------------------- logging
    // Writes to the Application log under its own dedicated source name.
    // Writes state TRANSITIONS only - never per-31013, never a silent sweep - plus an hourly
    // summary so the thing is visibly alive. Logging can never throw into the caller: a failure
    // falls back to a file, and a failure of THAT is swallowed.
    internal static class Log
    {
        public const string LogName = "Application";
        // A source name is cached source->log by the running Event Log service. Rebinding an
        // existing name does not take effect until that service restarts, and writes to a stale
        // mapping are silently discarded, so this name must never be re-pointed at another log.
        public const string Source = "CsvSmbSessionGuard";
        public const string LegacySource = "CsvSessionGuard";
        private static readonly string FallbackFile = ResolveFallbackFile();

        private static string ResolveFallbackFile()
        {
            try
            {
                string dir = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
                if (!string.IsNullOrEmpty(dir)) return Path.Combine(dir, "guard.log");
            }
            catch { }
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                                "CsvSessionGuard\\guard.log");
        }
        public static bool Console_ = false;

        public const int IdServiceStart = 1000;
        public const int IdServiceStop = 1001;
        public const int IdConfig = 1002;
        public const int IdStuckDetected = 2000;
        public const int IdDetectOnly = 2001;
        public const int IdCleared = 2002;
        public const int IdReportsOpen = 2005;
        public const int IdNoReportOpen = 2006;
        public const int IdRepairAttempt = 3000;
        public const int IdVerifyNoRetry = 3001;
        public const int IdRepairFailed = 3002;
        public const int IdSuppressed = 3003;
        public const int IdVerifyRetrying = 3004;
        public const int IdError = 4000;
        public const int IdWatchdog = 4001;
        public const int IdHeartbeat = 5000;

        // Both the event-log write (an RPC that can block on a busy or wedged EventLog service)
        // and the file fallback (a hung disk) run on bounded workers. A log write can therefore
        // never stall the caller, and failing to log can never throw into it.
        public static int TimeoutMs = 5000;
        private static bool _sourceUsable;

        public static void Write(int id, EventLogEntryType type, string message)
        {
            string line = string.Format(CultureInfo.InvariantCulture, "{0:yyyy-MM-dd HH:mm:ss} [{1}] {2}: {3}",
                                        DateTime.Now, id, type, message);
            if (Console_)
            {
                try { System.Console.WriteLine(line); } catch { }
            }

            // Only write when the source already exists. EventLog.WriteEntry auto-creates a
            // missing source against the Application log, which pollutes it.
            if (_sourceUsable)
            {
                Exception e1;
                if (Worker.Run("log", delegate() { EventLog.WriteEntry(Source, message, type, id); },
                               TimeoutMs, out e1) == Worker.Result.Completed) return;
            }

            Exception e2;
            Worker.Run("logfile", delegate()
            {
                string dir = Path.GetDirectoryName(FallbackFile);
                if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
                File.AppendAllText(FallbackFile, line + Environment.NewLine);
            }, TimeoutMs, out e2);
        }

        // Decides whether writing to the event log is safe, without creating anything.
        public static void ProbeSource()
        {
            Exception err;
            bool ok = false;
            Worker.Run("logprobe", delegate() { ok = EventLog.SourceExists(Source); }, TimeoutMs, out err);
            _sourceUsable = ok;
        }

        public static void Info(int id, string m) { Write(id, EventLogEntryType.Information, m); }
        public static void Warn(int id, string m) { Write(id, EventLogEntryType.Warning, m); }
        public static void Err(int id, string m) { Write(id, EventLogEntryType.Error, m); }

        public static void Exception(string where, Exception ex)
        {
            try
            {
                Err(IdError, Fmt.Event(
                    "The CSV session guard handled an unexpected error and continued running.",
                    new string[] {
                        "Operation|" + where,
                        "Error type|" + ex.GetType().FullName,
                        "Message|" + ex.Message,
                        "Node|" + Environment.MachineName
                    }));
            }
            catch { try { Err(IdError, "Error details were unavailable for operation: " + where); } catch { } }
        }

        // Install-time only. A source name can belong to exactly one log, so if an earlier run
        // auto-registered it against the Application log it must be deleted and recreated, or the
        // intended log would never receive anything.
        public static void RemoveLegacySource()
        {
            try
            {
                if (EventLog.SourceExists(LegacySource))
                {
                    EventLog.DeleteEventSource(LegacySource);
                    System.Console.WriteLine("removed the obsolete event source '" + LegacySource + "'");
                }
            }
            catch (Exception ex)
            {
                System.Console.WriteLine("could not remove the obsolete source '" + LegacySource + "': " + ex.Message);
            }
        }

        public static bool EnsureSource(out string error)
        {
            error = null;
            try
            {
                if (EventLog.SourceExists(Source))
                {
                    string bound = null;
                    try { bound = EventLog.LogNameFromSourceName(Source, "."); }
                    catch { }
                    if (!string.Equals(bound, LogName, StringComparison.OrdinalIgnoreCase))
                    {
                        System.Console.WriteLine("source '" + Source + "' was bound to log '" +
                                                 (bound == null ? "?" : bound) + "' - rebinding to '" + LogName + "'");
                        try { EventLog.DeleteEventSource(Source); }
                        catch (Exception ex) { System.Console.WriteLine("  could not remove the old binding: " + ex.Message); }
                    }
                }
                if (!EventLog.SourceExists(Source))
                    EventLog.CreateEventSource(new EventSourceCreationData(Source, LogName));
                _sourceUsable = EventLog.SourceExists(Source);
                return _sourceUsable;
            }
            catch (Exception ex)
            {
                try { error = ex.GetType().Name + ": " + ex.Message; } catch { error = "unknown"; }
                return false;
            }
        }
    }

    // ---------------------------------------------------------------- the kernel call
    internal static class Fsctl
    {
        // See the CONTROL CODE note at the top of the file. Code holds the built-in value until
        // ClusterControlCode.Load replaces it, once, at start-up.
        internal const uint BuiltinCode = 0x1401A8;
        internal static uint Code = BuiltinCode;
        private const string DevicePath = "\\\\.\\GLOBALROOT\\Device\\SmbCsv";

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
            IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_STATUS_BLOCK { public IntPtr Status; public IntPtr Information; }

        [DllImport("ntdll.dll")]
        private static extern int NtFsControlFile(IntPtr FileHandle, IntPtr Event, IntPtr ApcRoutine,
            IntPtr ApcContext, out IO_STATUS_BLOCK IoStatusBlock, uint FsControlCode,
            byte[] InputBuffer, uint InputBufferLength, byte[] OutputBuffer, uint OutputBufferLength);

        // STATUS_NOT_FOUND: no endpoint matched the filter, so nothing changed. Build 26100 returns
        // success instead, so there an unmatched filter is harmless but not visible.
        internal const uint STATUS_NOT_FOUND = 0xC0000225;

        // STATUS_OBJECT_NAME_NOT_FOUND: no server entry has the peer name, so nothing was left to reset.
        internal const uint STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034;

        // STATUS_INVALID_DEVICE_REQUEST: the device does not handle the code, or the request failed
        // the handler's length checks. Either way the code or its request no longer fits this build.
        internal const uint STATUS_INVALID_DEVICE_REQUEST = 0xC0000010;

        // Decodes a control code into its CTL_CODE fields, so that a build which renumbers it can
        // be compared field by field against this one from the event log alone.
        internal static string DescribeCode(uint code)
        {
            uint device = (code >> 16) & 0xFFFFu;
            uint access = (code >> 14) & 0x3u;
            uint function = (code >> 2) & 0xFFFu;
            uint method = code & 0x3u;
            string[] methods = new string[] { "METHOD_BUFFERED", "METHOD_IN_DIRECT", "METHOD_OUT_DIRECT", "METHOD_NEITHER" };
            string[] accesses = new string[] { "FILE_ANY_ACCESS", "FILE_READ_ACCESS", "FILE_WRITE_ACCESS", "FILE_READ_WRITE_ACCESS" };
            return string.Format(CultureInfo.InvariantCulture,
                "0x{0:X8} (device 0x{1:X2}, function 0x{2:X3}, {3}, {4})",
                code, device, function, methods[method & 3], accesses[access & 3]);
        }

        // The remote sockaddr field runs from +0x088 to the gate byte at +0x109.
        private const int MaxSockAddr = 0x108 - 0x088;   // 0x80

        // SCOPED form (remoteSockAddr != null): the gate at +0x109 is set and the peer address
        // goes at +0x088, so the kernel drops only the endpoints whose remote address matches -
        // every other network to the same peer is left alone.
        // Two properties of the user-mode path matter here: +0x088 is ONE plain sockaddr, not a
        // counted list; and the comparison is on address family and address only, never the port,
        // so a single entry matches exactly the channels on one subnet to one peer.
        //
        // WHOLE-PEER form (remoteSockAddr == null): both gates 0, no sockaddr read, every CSV
        // connection to the peer is dropped. Retained only for the explicit -allowwholepeer
        // fallback; the repair path does not choose it on its own.
        internal static byte[] BuildBuffer(string serverName, byte[] remoteSockAddr)
        {
            byte[] name = Encoding.Unicode.GetBytes(serverName);
            int size = 0x110 + name.Length + 2;
            if (size < 0x118) size = 0x118;
            byte[] buf = new byte[size];
            BitConverter.GetBytes((uint)0).CopyTo(buf, 0x004);   // MUST be 0: negative locks the peer out
            buf[0x108] = 0;                                      // no local address filter
            if (remoteSockAddr != null && remoteSockAddr.Length >= 8)
            {
                int n = remoteSockAddr.Length;
                if (n > MaxSockAddr) n = MaxSockAddr;            // never reach the gate bytes
                Array.Copy(remoteSockAddr, 0, buf, 0x088, n);
                buf[0x109] = 1;                                  // consume the remote filter
            }
            else
            {
                buf[0x109] = 0;                                  // whole-peer
            }
            BitConverter.GetBytes((uint)name.Length).CopyTo(buf, 0x10C);  // length in BYTES
            name.CopyTo(buf, 0x110);
            return buf;
        }

        // The 31013 RemoteAddress/LocalAddress fields are a raw sockaddr rendered as hex.
        internal static byte[] HexToBytes(string hex)
        {
            try
            {
                if (string.IsNullOrEmpty(hex)) return null;
                int n = hex.Length / 2;
                if (n < 8) return null;                          // shorter than any sockaddr
                byte[] b = new byte[n];
                for (int i = 0; i < n; i++)
                {
                    b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
                }
                return b;
            }
            catch (Exception ex) { Log.Exception("HexToBytes", ex); return null; }
        }

        // For the event log, so an operator can see which subnet was reset.
        internal static string DescribeSockAddr(byte[] a)
        {
            try
            {
                if (a == null || a.Length < 8) return "(none)";
                int family = a[0] | (a[1] << 8);
                if (family == 2 && a.Length >= 8)
                {
                    return string.Format(CultureInfo.InvariantCulture, "{0}.{1}.{2}.{3} (IPv4)",
                                         a[4], a[5], a[6], a[7]);
                }
                if (family == 23 && a.Length >= 24)
                {
                    StringBuilder sb = new StringBuilder();
                    for (int i = 8; i < 24; i += 2)
                    {
                        if (sb.Length > 0) sb.Append(':');
                        sb.Append(a[i].ToString("x2", CultureInfo.InvariantCulture));
                        sb.Append(a[i + 1].ToString("x2", CultureInfo.InvariantCulture));
                    }
                    return sb.ToString() + " (IPv6)";
                }
                return string.Format(CultureInfo.InvariantCulture, "address family {0}, {1} bytes",
                                     family, a.Length);
            }
            catch (Exception ex) { Log.Exception("DescribeSockAddr", ex); return "(unreadable)"; }
        }

        // Runs on a worker thread under a watchdog. NtFsControlFile is issued on a synchronous
        // handle, so it blocks until the IRP completes, and a teardown under network stress can
        // take tens of seconds. The caller enforces the timeout; a blocked kernel call cannot be
        // aborted, so on timeout the process exits and the SCM restarts it clean.
        private sealed class Work
        {
            public string Server;
            public byte[] Remote;            // null => whole-peer; else the +0x088 filter
            public uint Status;
            public long Information;
            public int Win32;
            public bool Opened;
            public Exception Error;

            public void Run()
            {
                IntPtr h = IntPtr.Zero;
                try
                {
                    h = CreateFileW(DevicePath, 0xC0000000u, 3u, IntPtr.Zero, 3u, 0x80u, IntPtr.Zero);
                    if (h.ToInt64() == -1)
                    {
                        Win32 = Marshal.GetLastWin32Error();
                        Opened = false;
                        return;
                    }
                    Opened = true;
                    byte[] buf = BuildBuffer(Server, Remote);
                    IO_STATUS_BLOCK iosb;
                    int st = NtFsControlFile(h, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out iosb,
                                             Code, buf, (uint)buf.Length, null, 0);
                    Status = (uint)st;
                    Information = iosb.Information.ToInt64();
                }
                catch (Exception ex) { Error = ex; }
                finally
                {
                    try { if (h != IntPtr.Zero && h.ToInt64() != -1) CloseHandle(h); } catch { }
                }
            }
        }

        // NoMatch: nothing was left to reset, which is a normal, safe outcome rather than a rejection.
        // NotAccepted: STATUS_INVALID_DEVICE_REQUEST. Refused: never sent, see RefuseReason.
        internal enum Outcome { Success, NoMatch, DeviceOpenFailed, Rejected, NotAccepted, Refused, Faulted, TimedOut }

        internal static string RefuseReason(string serverName)
        {
            if (serverName == null || serverName.Trim().Length == 0)
                return "the peer name is empty, and the driver applies an empty name to every server";
            return null;
        }

        internal static Outcome Classify(uint status)
        {
            if (status == 0) return Outcome.Success;
            if (status == STATUS_NOT_FOUND || status == STATUS_OBJECT_NAME_NOT_FOUND) return Outcome.NoMatch;
            if (status == STATUS_INVALID_DEVICE_REQUEST) return Outcome.NotAccepted;
            return Outcome.Rejected;
        }

        // remoteSockAddr: the peer address to scope the drop to, or null for the whole-peer form.
        internal static Outcome Disconnect(string serverName, byte[] remoteSockAddr, int timeoutSeconds, out string detail)
        {
            detail = "";
            string refusal = RefuseReason(serverName);
            if (refusal != null) { detail = "not sent: " + refusal; return Outcome.Refused; }
            Work w = new Work();
            w.Server = serverName;
            w.Remote = remoteSockAddr;
            Thread t = null;
            try
            {
                t = new Thread(w.Run);
                t.IsBackground = true;
                t.Name = "fsctl";
                t.Start();
            }
            catch (Exception ex)
            {
                detail = "could not start worker: " + ex.Message;
                return Outcome.Faulted;
            }

            bool finished;
            try { finished = t.Join(TimeSpan.FromSeconds(timeoutSeconds)); }
            catch (Exception ex) { detail = "join failed: " + ex.Message; return Outcome.Faulted; }

            if (!finished)
            {
                detail = string.Format(CultureInfo.InvariantCulture,
                    "NtFsControlFile did not return within {0}s (blocking kernel call, cannot be aborted)",
                    timeoutSeconds);
                return Outcome.TimedOut;
            }
            if (w.Error != null) { detail = w.Error.GetType().Name + ": " + w.Error.Message; return Outcome.Faulted; }
            if (!w.Opened)
            {
                detail = string.Format(CultureInfo.InvariantCulture, "CreateFile({0}) failed, win32={1}", DevicePath, w.Win32);
                return Outcome.DeviceOpenFailed;
            }
            detail = string.Format(CultureInfo.InvariantCulture, "NTSTATUS=0x{0:X8} information={1} scope={2} code={3}",
                                   w.Status, w.Information,
                                   remoteSockAddr == null ? "whole-peer" : DescribeSockAddr(remoteSockAddr),
                                   DescribeCode(Code));
            return Classify(w.Status);
        }
    }

    // ---------------------------------------------------------------- the control code the cluster service sends
    internal static class ClusterControlCode
    {
        private sealed class Section { public uint Va, VSize, RawPtr, RawSize, Chars; }

        internal static string Source = "built in";

        internal static uint Choose(uint found) { return found != 0 ? found : Fsctl.BuiltinCode; }

        internal static string BuildOf(int build, int revision)
        {
            return build != 0 || revision != 0 ? string.Format(CultureInfo.InvariantCulture, "build {0}.{1}", build, revision) : null;
        }

        internal static string Load(int timeoutMs, out bool differs)
        {
            differs = false;
            Fsctl.Code = Fsctl.BuiltinCode;
            Source = "built in";
            try
            {
                string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Cluster\\clussvc.exe");
                bool exists = false;
                uint found = 0;
                string version = null;
                Exception werr;
                Worker.Result wr = Worker.Run("controlcode", delegate()
                {
                    exists = File.Exists(path);
                    if (!exists) return;
                    found = Find(File.ReadAllBytes(path));
                    // Under C:\Windows major.minor reads as 6.2 (the OS version lie) and the version string comes from the MUI file.
                    FileVersionInfo vi = FileVersionInfo.GetVersionInfo(path);
                    version = BuildOf(vi.FileBuildPart, vi.FilePrivatePart);
                }, timeoutMs, out werr);
                string file = path + (version != null ? ", " + version : "");
                if (wr == Worker.Result.TimedOut) Source = "built in; reading " + path + " did not finish within " + (timeoutMs / 1000) + " seconds";
                else if (wr != Worker.Result.Completed) Source = "built in; " + path + " could not be read: " + (werr != null ? werr.GetType().Name : "unknown");
                else if (!exists) Source = "built in; " + path + " is not present";
                else if (found == 0) Source = "built in; no single disconnect call matched in " + file;
                else
                {
                    Fsctl.Code = Choose(found);
                    differs = Fsctl.Code != Fsctl.BuiltinCode;
                    Source = (differs ? "read from " : "confirmed in ") + file;
                }
            }
            catch (Exception ex)
            {
                Fsctl.Code = Fsctl.BuiltinCode;
                differs = false;
                Source = "built in; " + ex.GetType().Name;
            }
            return Source;
        }

        internal static uint Find(byte[] image)
        {
            try { return FindCore(image); }
            catch { return 0; }
        }

        private static uint FindCore(byte[] b)
        {
            if (b == null || b.Length < 0x200 || b[0] != (byte)'M' || b[1] != (byte)'Z') return 0;
            int pe = BitConverter.ToInt32(b, 0x3C);
            if (pe < 0 || pe > b.Length - 24 || BitConverter.ToUInt32(b, pe) != 0x00004550 || BitConverter.ToUInt16(b, pe + 4) != 0x8664) return 0;
            int nsec = BitConverter.ToUInt16(b, pe + 6), optSize = BitConverter.ToUInt16(b, pe + 20), opt = pe + 24;
            if (optSize < 112 || opt + optSize > b.Length || BitConverter.ToUInt16(b, opt) != 0x20B) return 0;
            List<Section> secs = new List<Section>();
            for (int i = 0; i < nsec; i++)
            {
                int s = opt + optSize + 40 * i;
                if (s + 40 > b.Length) return 0;
                Section x = new Section();
                x.VSize = BitConverter.ToUInt32(b, s + 8);
                x.Va = BitConverter.ToUInt32(b, s + 12);
                x.RawSize = BitConverter.ToUInt32(b, s + 16);
                x.RawPtr = BitConverter.ToUInt32(b, s + 20);
                x.Chars = BitConverter.ToUInt32(b, s + 36);
                secs.Add(x);
            }
            long dirs = Math.Min(BitConverter.ToUInt32(b, opt + 108), (optSize - 112) / 8);
            HashSet<uint> slots = new HashSet<uint>();
            if (dirs > 1) Imports(b, secs, BitConverter.ToUInt32(b, opt + 120), slots);
            if (dirs > 13) DelayImports(b, secs, BitConverter.ToUInt32(b, opt + 216), slots);
            if (slots.Count == 0 || dirs <= 3) return 0;

            List<uint> begin = new List<uint>(), end = new List<uint>();
            uint pdSize = BitConverter.ToUInt32(b, opt + 140);
            int pd = Off(secs, BitConverter.ToUInt32(b, opt + 136), b.Length);
            for (uint k = 0; pd >= 0 && k + 12 <= pdSize && (long)pd + k + 12 <= b.Length; k += 12)
            {
                begin.Add(BitConverter.ToUInt32(b, pd + (int)k));
                end.Add(BitConverter.ToUInt32(b, pd + (int)k + 4));
            }

            Dictionary<uint, List<uint>> calls = new Dictionary<uint, List<uint>>();
            foreach (Section x in secs)
            {
                if ((x.Chars & 0x20000000) == 0 || x.RawPtr >= b.Length) continue;
                int start = (int)x.RawPtr, stop = (int)Math.Min((long)x.RawPtr + x.RawSize, b.Length);
                for (int i = start; i + 6 <= stop; i++)
                {
                    if (b[i] != 0xFF || b[i + 1] != 0x15) continue;
                    uint rva = x.Va + (uint)(i - start);
                    if (!slots.Contains((uint)((long)rva + 6 + BitConverter.ToInt32(b, i + 2)))) continue;
                    uint fn = FunctionOf(begin, end, rva);
                    if (fn == 0) continue;
                    uint code = 0;
                    for (int k = i - 8; k >= i - 64 && k >= start; k--)
                    {
                        if (b[k] == 0xC7 && b[k + 1] == 0x44 && b[k + 2] == 0x24 && b[k + 3] == 0x28) { code = BitConverter.ToUInt32(b, k + 4); break; }
                    }
                    List<uint> l;
                    if (!calls.TryGetValue(fn, out l)) { l = new List<uint>(); calls[fn] = l; }
                    l.Add(code);
                }
            }

            List<uint> candidates = new List<uint>();
            Dictionary<uint, uint> codeOf = new Dictionary<uint, uint>();
            foreach (KeyValuePair<uint, List<uint>> kv in calls)
            {
                uint code = kv.Value[0];
                if (kv.Value.Count < 2 || (code >> 16) != 0x14 || (code & 3) != 0 || ((code >> 14) & 3) != 0) continue;
                bool same = true;
                foreach (uint c in kv.Value) { if (c != code) same = false; }
                int idx = begin.IndexOf(kv.Key);
                if (!same || idx < 0 || !ComparesNotFound(b, secs, kv.Key, end[idx])) continue;
                candidates.Add(kv.Key);
                codeOf[kv.Key] = code;
            }
            if (candidates.Count == 0) return 0;

            HashSet<uint> builders = new HashSet<uint>();
            for (int i = 0; i < begin.Count; i++)
            {
                int s = Off(secs, begin[i], b.Length);
                if (s < 0 || end[i] <= begin[i]) continue;
                if (HasLayout(b, s, (int)Math.Min((long)s + (end[i] - begin[i]), b.Length))) builders.Add(begin[i]);
            }
            uint result = 0;
            int linked = 0;
            foreach (uint f in candidates)
            {
                if (builders.Count == 0 || !BuilderCallsPrecede(b, secs, f, builders)) continue;
                linked++;
                result = codeOf[f];
            }
            return linked == 1 ? result : 0;
        }

        private static bool ComparesNotFound(byte[] b, List<Section> secs, uint begin, uint end)
        {
            int s = Off(secs, begin, b.Length);
            if (s < 0 || end <= begin) return false;
            int e = (int)Math.Min((long)s + (end - begin), b.Length);
            for (int j = s + 2; j + 4 <= e; j++)
            {
                if (b[j] != 0x34 || b[j + 1] != 0x00 || b[j + 2] != 0x00 || b[j + 3] != 0xC0) continue;
                if (b[j - 1] == 0x3D) return true;
                if (b[j - 2] == 0x81 && (b[j - 1] & 0xF8) == 0xF8) return true;
            }
            return false;
        }

        private static bool HasLayout(byte[] b, int s, int e)
        {
            bool size = false, local = false, remote = false, length = false, name = false;
            for (int j = s; j + 7 <= e; j++)
            {
                byte op = b[j], m = b[j + 1];
                int mod = m >> 6, reg = (m >> 3) & 7, rm = m & 7;
                if (op == 0xC7 && reg == 0 && rm != 4 && ((mod == 0 && rm != 5 && BitConverter.ToUInt32(b, j + 2) == 0x118) ||
                                                          (mod == 1 && b[j + 2] == 0 && BitConverter.ToUInt32(b, j + 3) == 0x118))) size = true;
                if (mod != 2 || rm == 4) continue;
                uint disp = BitConverter.ToUInt32(b, j + 2);
                if (op == 0xC6 && reg == 0 && b[j + 6] == 1 && disp == 0x108) local = true;
                if (op == 0xC6 && reg == 0 && b[j + 6] == 1 && disp == 0x109) remote = true;
                if (op == 0x89 && disp == 0x10C) length = true;
                if (op == 0x8D && disp == 0x110) name = true;
            }
            return size && local && remote && length && name;
        }

        private static bool BuilderCallsPrecede(byte[] b, List<Section> secs, uint target, HashSet<uint> builders)
        {
            foreach (Section x in secs)
            {
                if ((x.Chars & 0x20000000) == 0 || x.RawPtr >= b.Length) continue;
                int start = (int)x.RawPtr, stop = (int)Math.Min((long)x.RawPtr + x.RawSize, b.Length);
                for (int i = start; i + 5 <= stop; i++)
                {
                    if (b[i] != 0xE8) continue;
                    uint rva = x.Va + (uint)(i - start);
                    if ((uint)((long)rva + 5 + BitConverter.ToInt32(b, i + 1)) != target) continue;
                    for (int k = i - 5; k >= i - 64 && k >= start; k--)
                    {
                        if (b[k] != 0xE8) continue;
                        uint kr = x.Va + (uint)(k - start);
                        if (builders.Contains((uint)((long)kr + 5 + BitConverter.ToInt32(b, k + 1)))) return true;
                    }
                }
            }
            return false;
        }

        private static uint FunctionOf(List<uint> begin, List<uint> end, uint rva)
        {
            int lo = 0, hi = begin.Count - 1;
            while (lo <= hi)
            {
                int mid = (lo + hi) / 2;
                if (rva < begin[mid]) hi = mid - 1;
                else if (rva >= end[mid]) lo = mid + 1;
                else return begin[mid];
            }
            return 0;
        }

        private static int Off(List<Section> secs, uint rva, int length)
        {
            foreach (Section x in secs)
            {
                uint size = Math.Max(x.VSize, x.RawSize);
                if (rva < x.Va || rva - x.Va >= size) continue;
                uint d = rva - x.Va;
                if (d >= x.RawSize) return -1;
                long o = (long)x.RawPtr + d;
                return o < length ? (int)o : -1;
            }
            return -1;
        }

        private static void Thunks(byte[] b, List<Section> secs, uint names, uint iat, HashSet<uint> slots)
        {
            int t = Off(secs, names, b.Length);
            for (uint i = 0; t >= 0 && t + 8 <= b.Length && i < 100000; i++, t += 8)
            {
                ulong v = BitConverter.ToUInt64(b, t);
                if (v == 0) break;
                if ((v & 0x8000000000000000UL) != 0 || v > uint.MaxValue) continue;
                int h = Off(secs, (uint)v, b.Length);
                if (h < 0) continue;
                StringBuilder sb = new StringBuilder();
                for (int c = h + 2; c < b.Length && c < h + 2 + 64 && b[c] != 0; c++) sb.Append((char)b[c]);
                string fn = sb.ToString();
                if (fn == "NtFsControlFile" || fn == "ZwFsControlFile") slots.Add(iat + i * 8);
            }
        }

        private static void Imports(byte[] b, List<Section> secs, uint rva, HashSet<uint> slots)
        {
            int d = Off(secs, rva, b.Length);
            for (int n = 0; d >= 0 && d + 20 <= b.Length && n < 4096; n++, d += 20)
            {
                uint oft = BitConverter.ToUInt32(b, d), name = BitConverter.ToUInt32(b, d + 12), ft = BitConverter.ToUInt32(b, d + 16);
                if (oft == 0 && name == 0 && ft == 0) break;
                Thunks(b, secs, oft != 0 ? oft : ft, ft, slots);
            }
        }

        private static void DelayImports(byte[] b, List<Section> secs, uint rva, HashSet<uint> slots)
        {
            int d = Off(secs, rva, b.Length);
            for (int n = 0; d >= 0 && d + 32 <= b.Length && n < 4096; n++, d += 32)
            {
                uint name = BitConverter.ToUInt32(b, d + 4), iat = BitConverter.ToUInt32(b, d + 12), nt = BitConverter.ToUInt32(b, d + 16);
                if (name == 0 && iat == 0) break;
                if ((BitConverter.ToUInt32(b, d) & 1) != 0) Thunks(b, secs, nt, iat, slots);
            }
        }
    }

    // ---------------------------------------------------------------- detection
    internal sealed class StuckSession
    {
        public string SessionId;
        public string ServerName;     // carries its leading backslash - pass to the FSCTL verbatim
        public int Count;
        public DateTime First;
        public DateTime Last;
        public string Key { get { return SessionId + "|" + ServerName; } }

        // Events per local ephemeral port. See Config.MinEventsPerPort for why this is the
        // primary discriminator: forming channels fail twice each, a stuck connection repeats.
        public Dictionary<int, int> PerPort = new Dictionary<int, int>();

        // Every event time seen for this session. A repair is judged against the reset instant, and
        // that needs the times themselves: a count of events in a query window includes the retries
        // the repair was issued to stop, because the window necessarily reaches back past the reset.
        public List<DateTime> Times = new List<DateTime>();

        // When the FSCTL was issued for this session; MinValue means nothing was reset. Verification
        // is judged against this instant and not against the moment the verifier wakes up, because
        // in -once mode every repair runs before every verification and the gap would be discarded.
        public DateTime LastResetAt = DateTime.MinValue;

        public long ReportId;

        public void NoteTime(DateTime when)
        {
            try { Times.Add(when); } catch (Exception ex) { Log.Exception("NoteTime", ex); }
        }

        public void Note(int port)
        {
            int c;
            if (PerPort.TryGetValue(port, out c)) { PerPort[port] = c + 1; }
            else { PerPort[port] = 1; }
        }

        public int DistinctPorts { get { return PerPort.Count; } }

        public int MaxPerPort
        {
            get { int m = 0; foreach (int v in PerPort.Values) { if (v > m) m = v; } return m; }
        }

        public int HottestPort
        {
            get
            {
                int p = 0, m = 0;
                foreach (KeyValuePair<int, int> kv in PerPort) { if (kv.Value > m) { m = kv.Value; p = kv.Key; } }
                return p;
            }
        }

        // The PEER addresses this session is failing to bind to. These are what the scoped FSCTL
        // aims at: one entry drops exactly the channels to that address and nothing else.
        // Keyed by the address with the port blanked, because the kernel comparison ignores the
        // port, so two events differing only in ephemeral detail are ONE filter target. The value
        // keeps the first raw hex seen, so the bytes handed to the kernel are verbatim from the
        // event rather than reformatted.
        private readonly Dictionary<string, string> _remoteRaw = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, int> _remoteHits = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        internal static string RemoteKey(string hex)
        {
            if (string.IsNullOrEmpty(hex) || hex.Length < 8) return hex;
            return hex.Substring(0, 4) + "0000" + hex.Substring(8);   // blank the port bytes
        }

        public void NoteRemote(string hex)
        {
            try
            {
                if (string.IsNullOrEmpty(hex) || hex.Length < 16) return;
                string k = RemoteKey(hex);
                int c;
                if (_remoteHits.TryGetValue(k, out c)) { _remoteHits[k] = c + 1; }
                else { _remoteHits[k] = 1; _remoteRaw[k] = hex; }
            }
            catch (Exception ex) { Log.Exception("NoteRemote", ex); }
        }

        public int DistinctRemotes { get { return _remoteRaw.Count; } }

        // One scoped FSCTL per entry, most-failing address first so the worst is cleared even if
        // a later call faults.
        public List<string> RemoteTargets()
        {
            List<string> keys = new List<string>(_remoteRaw.Keys);
            keys.Sort(delegate(string a, string b)
            {
                int ca = 0, cb = 0;
                _remoteHits.TryGetValue(a, out ca);
                _remoteHits.TryGetValue(b, out cb);
                if (cb != ca) return cb - ca;
                return string.CompareOrdinal(a, b);
            });
            List<string> raw = new List<string>();
            foreach (string k in keys) { raw.Add(_remoteRaw[k]); }
            return raw;
        }

        public int RemoteHits(string rawHex)
        {
            int c = 0;
            try { _remoteHits.TryGetValue(RemoteKey(rawHex), out c); } catch { c = 0; }
            return c;
        }

        public double SpanSeconds { get { return (Last - First).TotalSeconds; } }
        public double SpanMinutes { get { return (Last - First).TotalMinutes; } }
        public double RatePerMin
        {
            get { double s = SpanMinutes; return s <= 0.01 ? Count : Count / s; }
        }
        public override string ToString()
        {
            return string.Format(CultureInfo.InvariantCulture,
                "session {0} -> {1}  n={2} span={3:N1}min rate={4:N1}/min last={5:HH:mm:ss}",
                SessionId, ServerName, Count, SpanMinutes, RatePerMin, Last) +
                string.Format(CultureInfo.InvariantCulture, " ports={0} maxPerPort={1} peerAddrs={2}",
                              DistinctPorts, MaxPerPort, DistinctRemotes);
        }
    }

    internal static class Detector
    {
        private const string Channel = "Microsoft-Windows-SMBClient/Security";
        private const int EventId = 31013;
        private const string TargetStatus = "3221225494";   // 0xC0000016 STATUS_MORE_PROCESSING_REQUIRED

        // Returns candidates that satisfy ALL of: enough events, the loop has PERSISTED across a
        // span, and it is still live. The span requirement is what makes this boot-agnostic: a
        // transient burst at session formation produces a tight cluster of events inside a minute
        // and is correctly ignored, with no need for a boot grace period.
        internal static List<StuckSession> Find(Config cfg, out int rawCount, out string error)
        {
            List<StuckSession> seen;
            bool complete;
            return Find(cfg, out rawCount, out error, out seen, out complete);
        }

        internal static List<StuckSession> Find(Config cfg, out int rawCount, out string error,
                                                out List<StuckSession> seen, out bool complete)
        {
            rawCount = 0;
            error = null;
            seen = new List<StuckSession>();
            complete = true;
            List<StuckSession> result = new List<StuckSession>();
            Dictionary<string, StuckSession> map = new Dictionary<string, StuckSession>(StringComparer.Ordinal);
            EventLogReader reader = null;
            try
            {
                string xpath = string.Format(CultureInfo.InvariantCulture,
                    "*[System[(EventID={0}) and TimeCreated[timediff(@SystemTime) <= {1}]]]",
                    EventId, (long)cfg.WindowMinutes * 60L * 1000L);
                EventLogQuery q = new EventLogQuery(Channel, PathType.LogName, xpath);
                reader = new EventLogReader(q);

                for (; ; )
                {
                    EventRecord rec = null;
                    try { rec = reader.ReadEvent(); }
                    catch (Exception ex) { complete = false; Log.Exception("ReadEvent", ex); break; }
                    if (rec == null) break;
                    try
                    {
                        rawCount++;
                        string sid = null, srv = null, status = null, laddr = null, raddr = null;
                        string xml = rec.ToXml();
                        XmlDocument doc = new XmlDocument();
                        doc.LoadXml(xml);
                        XmlNodeList data = doc.GetElementsByTagName("Data");
                        for (int i = 0; i < data.Count; i++)
                        {
                            XmlElement el = data[i] as XmlElement;
                            if (el == null) continue;
                            string n = el.GetAttribute("Name");
                            if (n == "SessionId") sid = el.InnerText;
                            else if (n == "ServerName") srv = el.InnerText;
                            else if (n == "Status") status = el.InnerText;
                            else if (n == "LocalAddress") laddr = el.InnerText;
                            // The PEER address of the failing connection. This is the scoped
                            // FSCTL's filter value (+0x088) - without it a repair can only be
                            // whole-peer, so it is captured on every event.
                            else if (n == "RemoteAddress") raddr = el.InnerText;
                        }
                        if (sid == null || srv == null) continue;
                        if (status != TargetStatus) continue;

                        DateTime when = rec.TimeCreated.HasValue ? rec.TimeCreated.Value : DateTime.Now;
                        string key = sid + "|" + srv;
                        StuckSession s;
                        if (!map.TryGetValue(key, out s))
                        {
                            s = new StuckSession();
                            s.SessionId = sid; s.ServerName = srv;
                            s.First = when; s.Last = when; s.Count = 0;
                            map[key] = s;
                        }
                        s.Count++;
                        if (when < s.First) s.First = when;
                        if (when > s.Last) s.Last = when;
                        s.NoteTime(when);
                        // LocalAddress is a raw sockaddr_in in hex: family(2) port(2) addr(4).
                        // The port is the 2 bytes at offset 2, i.e. hex characters 4..7.
                        int lport = 0;
                        if (laddr != null && laddr.Length >= 8)
                        {
                            try { lport = Convert.ToInt32(laddr.Substring(4, 4), 16); }
                            catch { lport = 0; }
                        }
                        s.Note(lport);
                        s.NoteRemote(raddr);
                    }
                    catch (Exception ex) { complete = false; Log.Exception("parse 31013", ex); }
                    finally { try { if (rec != null) rec.Dispose(); } catch { } }
                }
            }
            catch (Exception ex)
            {
                complete = false;
                try { error = ex.GetType().Name + ": " + ex.Message; } catch { error = "unknown"; }
                return result;
            }
            finally { try { if (reader != null) reader.Dispose(); } catch { } }

            seen = new List<StuckSession>(map.Values);
            return Select(map.Values, cfg, DateTime.Now);
        }

        // Split out from Find so the criterion is testable without an event log; see -selftest.
        internal static List<StuckSession> Select(IEnumerable<StuckSession> candidates, Config cfg, DateTime now)
        {
            List<StuckSession> result = new List<StuckSession>();
            if (candidates == null) return result;
            foreach (StuckSession s in candidates)
            {
                try
                {
                    if (s == null) continue;
                    // PRIMARY: one connection has failed the same bind this many times. A session
                    // that is merely forming fails at most twice on any single local port.
                    if (s.MaxPerPort < cfg.MinEventsPerPort) continue;
                    if (s.Count < cfg.MinEvents) continue;                          // floor
                    if (s.SpanSeconds < cfg.MinSpanSeconds) continue;               // backstop
                    if ((now - s.Last).TotalSeconds > cfg.RecentSeconds) continue;  // still live
                    result.Add(s);
                }
                catch (Exception ex) { Log.Exception("evaluate candidate", ex); }
            }
            return result;
        }

        // Is the source of truth actually able to speak? A verdict of "held" rests on the ABSENCE
        // of events, so it is only evidence when the channel exists and is enabled. This must be
        // asked of the channel itself: counting the records a query returned cannot answer it,
        // because on a node whose only stuck session is the repaired one, zero records in the
        // window is exactly what a successful repair looks like.
        internal static ChannelState Availability(out string detail)
        {
            detail = "";
            try
            {
                EventLogConfiguration cfg = new EventLogConfiguration(Channel);
                if (!cfg.IsEnabled)
                {
                    detail = Channel + " exists but is disabled";
                    return ChannelState.Disabled;
                }
                detail = Channel + " is enabled";
                return ChannelState.Available;
            }
            catch (Exception ex)
            {
                detail = Channel + " could not be read: " + ex.GetType().Name + ": " + ex.Message;
                return ChannelState.Unavailable;
            }
        }
    }

    // Whether the 31013 source could have spoken during an observation. See Detector.Availability.
    internal enum ChannelState { Available, Disabled, Unavailable }

    // ---------------------------------------------------------------- verification verdict
    // Pure and side-effect free, so the whole policy is testable without an event log, a kernel or
    // a cluster. See the VERIFICATION note at the top of the file, and -selftest for the recorded
    // specimen: pass #1 genuinely failed, pass #2 genuinely held and the old rule misreported it.
    internal enum VerifyOutcome { Held, Inconclusive, Failed }

    internal static class VerifyAnalysis
    {
        // A verdict of "held" is read off silence, so it is only available when the source could
        // have spoken. Anything else is "unknown", which is deliberately NOT "failed": charging a
        // repair for our own inability to observe it would fabricate a failure.
        internal static bool CanConclude(ChannelState state)
        {
            return state == ChannelState.Available;
        }

        // Selects the retry events belonging to ONE session key. By key, never by peer name: a node
        // can hold two stuck sessions to the same peer, and merging them would both charge one
        // session's repair with the other's retries and let the other's later event mask a genuinely
        // new retry, turning a still-stuck session into a false "held".
        internal static List<DateTime> TimesFor(IEnumerable<StuckSession> sessions, string key)
        {
            List<DateTime> times = new List<DateTime>();
            if (sessions == null) return times;
            foreach (StuckSession a in sessions)
            {
                if (a == null) continue;
                if (string.Equals(a.Key, key, StringComparison.Ordinal)) times.AddRange(a.Times);
            }
            return times;
        }

        // Held         : nothing after the grace window - the loop stopped.
        // Inconclusive : exactly one event outside it - ambiguous, the caller looks again.
        // Failed       : two or more - the loop is still running.
        // inFlight counts events after the reset but inside the grace window.
        //
        // De-duplicated by timestamp: the second look re-reads an overlapping window, so the same
        // event can be presented twice, and counting it twice would turn one ambiguous event into a
        // fabricated failure.
        internal static VerifyOutcome Classify(IEnumerable<DateTime> eventTimes, DateTime fired,
                                               int graceSeconds, out int after, out int inFlight)
        {
            after = 0;
            inFlight = 0;
            DateTime boundary = fired.AddSeconds(graceSeconds < 0 ? 0 : graceSeconds);
            if (eventTimes != null)
            {
                Dictionary<DateTime, bool> seen = new Dictionary<DateTime, bool>();
                foreach (DateTime t in eventTimes)
                {
                    if (seen.ContainsKey(t)) continue;
                    seen[t] = true;
                    if (t > boundary) after++;
                    else if (t > fired) inFlight++;
                }
            }
            if (after == 0) return VerifyOutcome.Held;
            if (after == 1) return VerifyOutcome.Inconclusive;
            return VerifyOutcome.Failed;
        }

        // The full policy including the second observation, pure so that it can be tested directly.
        // first = events from the first observation; second = events from the second (null when no
        // second look was made); resetAt = the instant the FSCTL was issued.
        //
        // One retry after a reset is genuinely ambiguous, because the loop's own cadence is 60
        // seconds: a dead loop can leave one straggler and a live one keeps going. The
        // discriminator is therefore whether a NEW event appears, not the count so far. Only newly
        // observed events count in the second round - re-counting the overlap would make it
        // impossible for a draining tail ever to be recorded as held, which was the original defect.
        internal static VerifyOutcome Decide(IEnumerable<DateTime> first, IEnumerable<DateTime> second,
                                             DateTime resetAt, int graceSeconds,
                                             out int after, out int inFlight)
        {
            VerifyOutcome v = Classify(first, resetAt, graceSeconds, out after, out inFlight);
            if (v != VerifyOutcome.Inconclusive) return v;
            if (second == null) return v;                      // no second look: stay ambiguous
            DateTime newest = DateTime.MinValue;
            if (first != null) { foreach (DateTime t in first) { if (t > newest) newest = t; } }
            int fresh = 0;
            Dictionary<DateTime, bool> seen = new Dictionary<DateTime, bool>();
            foreach (DateTime t in second)
            {
                if (t <= newest) continue;                     // already counted in the first round
                if (seen.ContainsKey(t)) continue;
                seen[t] = true;
                if (t > resetAt) fresh++;
            }
            if (fresh == 0) return VerifyOutcome.Held;         // draining tail: it stopped
            after += fresh;
            return VerifyOutcome.Failed;
        }
    }

    // ---------------------------------------------------------------- repair dispatch plan
    // One reset per DISTINCT peer address, not per session: the kernel filter compares address
    // family and address only and ignores the port, so a single FSCTL serves every session that
    // failed against that address.
    internal sealed class RepairGroup
    {
        public string AddressHex;                  // the sockaddr to write at +0x088, verbatim
        public List<StuckSession> Sessions = new List<StuckSession>();
        public string ServerName;                  // peer name for the FSCTL, from the first session
    }

    internal static class RepairPlan
    {
        // Groups the sessions to repair by the distinct addresses that must be reset. Keyed on the
        // port-blanked sockaddr, because that is what the kernel actually compares.
        internal static List<RepairGroup> GroupByTarget(IEnumerable<StuckSession> sessions)
        {
            List<RepairGroup> groups = new List<RepairGroup>();
            Dictionary<string, RepairGroup> byKey = new Dictionary<string, RepairGroup>(StringComparer.OrdinalIgnoreCase);
            if (sessions == null) return groups;
            foreach (StuckSession s in sessions)
            {
                if (s == null) continue;
                foreach (string hex in s.RemoteTargets())
                {
                    if (string.IsNullOrEmpty(hex)) continue;
                    string key = StuckSession.RemoteKey(hex) + "|" + s.ServerName;
                    RepairGroup g;
                    if (!byKey.TryGetValue(key, out g))
                    {
                        g = new RepairGroup();
                        g.AddressHex = hex;
                        g.ServerName = s.ServerName;
                        byKey[key] = g;
                        groups.Add(g);
                    }
                    if (!g.Sessions.Contains(s)) g.Sessions.Add(s);
                }
            }
            return groups;
        }
    }

    // ---------------------------------------------------------------- stuck-session reports
    internal enum ReportState { Stuck, Retrying, Quiet, Clearing }

    internal sealed class Episode
    {
        public long Id;
        public string Key, SessionId, ServerName;
        public DateTime OpenedAt, LastAnnouncedAt, LastRetryAt, StateSince;
        public int Announcements, Resets, VerdictId;
        public ReportState State;
        public DateTime LastResetAt = DateTime.MinValue, VerdictResetAt = DateTime.MinValue;
        public long AbsentSinceMs = -1, ClassSinceMs = -1;

        public Episode Copy() { return (Episode)MemberwiseClone(); }
    }

    internal sealed class EpisodeLedger
    {
        private readonly object _lock = new object();
        private readonly Dictionary<string, Episode> _open = new Dictionary<string, Episode>(StringComparer.Ordinal);
        private long _next = 1;
        private long _version;
        private int _opened, _closed;

        internal int OpenCount { get { lock (_lock) { return _open.Count; } } }
        internal int OpenedTotal { get { lock (_lock) { return _opened; } } }
        internal int ClosedTotal { get { lock (_lock) { return _closed; } } }
        internal long NextId { get { lock (_lock) { return _next; } } }
        internal long Version { get { lock (_lock) { return _version; } } }

        internal bool NoteDetected(StuckSession s, DateTime at, int repeatMinutes, out bool opened)
        {
            opened = false;
            lock (_lock)
            {
                Episode e;
                if (!_open.TryGetValue(s.Key, out e))
                {
                    e = new Episode();
                    e.Id = _next++;
                    e.Key = s.Key; e.SessionId = s.SessionId; e.ServerName = s.ServerName;
                    e.OpenedAt = at; e.LastAnnouncedAt = at; e.StateSince = at;
                    e.Announcements = 1; e.LastRetryAt = s.Last; e.State = ReportState.Stuck;
                    _open[s.Key] = e;
                    _opened++;
                    _version++;
                    s.ReportId = e.Id;
                    opened = true;
                    return true;
                }
                s.ReportId = e.Id;
                if (s.Last > e.LastRetryAt) { e.LastRetryAt = s.Last; _version++; }
                e.AbsentSinceMs = -1;
                if ((at - e.LastAnnouncedAt).TotalMinutes < repeatMinutes) return false;
                e.LastAnnouncedAt = at;
                e.Announcements++;
                _version++;
                return true;
            }
        }

        internal void NoteReset(IEnumerable<StuckSession> served, DateTime resetAt)
        {
            if (served == null) return;
            lock (_lock)
            {
                foreach (StuckSession s in served)
                {
                    if (s == null || s.ReportId == 0) continue;
                    Episode e;
                    if (!_open.TryGetValue(s.Key, out e) || e.Id != s.ReportId) continue;
                    e.Resets++;
                    if (resetAt > e.LastResetAt) e.LastResetAt = resetAt;
                    _version++;
                }
            }
        }

        internal bool NoteVerdict(string key, long reportId, int eventId, DateTime resetAt)
        {
            if (key == null) return false;
            lock (_lock)
            {
                Episode e;
                if (!_open.TryGetValue(key, out e) || e.Id != reportId) return false;
                if (resetAt >= e.VerdictResetAt)
                {
                    e.VerdictId = eventId;
                    e.VerdictResetAt = resetAt;
                    _version++;
                }
                return true;
            }
        }

        internal List<string> Reconcile(ICollection<string> selected, IList<StuckSession> seen, bool complete,
            ChannelState channel, IDictionary<string, DateTime> inFlight, DateTime now, long monoMs,
            int recentSeconds, int confirmSeconds, int ceilingSeconds)
        {
            List<string> candidates = new List<string>();
            if (!complete) return candidates;
            Dictionary<string, StuckSession> byKey = new Dictionary<string, StuckSession>(StringComparer.Ordinal);
            if (seen != null)
            {
                foreach (StuckSession s in seen) { if (s != null && s.Key != null) byKey[s.Key] = s; }
            }
            lock (_lock)
            {
                foreach (Episode e in _open.Values)
                {
                    StuckSession s;
                    bool inSeen = byKey.TryGetValue(e.Key, out s);
                    bool sel = selected != null && selected.Contains(e.Key);
                    bool present = inSeen || sel;
                    if (inSeen && s.Last > e.LastRetryAt) { e.LastRetryAt = s.Last; _version++; }

                    ReportState state;
                    if (sel) state = ReportState.Stuck;
                    else if (present) state = (now - e.LastRetryAt).TotalSeconds <= recentSeconds ? ReportState.Retrying : ReportState.Quiet;
                    else state = ReportState.Clearing;

                    bool wasStuck = e.State == ReportState.Stuck;
                    if (state != e.State) { e.State = state; e.StateSince = now; _version++; }
                    if (e.ClassSinceMs < 0 || wasStuck != (state == ReportState.Stuck)) e.ClassSinceMs = monoMs;

                    if (present || channel != ChannelState.Available) { e.AbsentSinceMs = -1; continue; }
                    if (e.AbsentSinceMs < 0) e.AbsentSinceMs = monoMs;
                    if (monoMs - e.AbsentSinceMs < (long)confirmSeconds * 1000) continue;
                    DateTime claimed;
                    if (inFlight != null && inFlight.TryGetValue(e.Key, out claimed) &&
                        (now - claimed).TotalSeconds < ceilingSeconds) continue;
                    candidates.Add(e.Key);
                }
            }
            candidates.Sort(StringComparer.Ordinal);
            return candidates;
        }

        internal List<Episode> Close(ICollection<string> keys)
        {
            List<Episode> closed = new List<Episode>();
            if (keys == null) return closed;
            lock (_lock)
            {
                foreach (string k in keys)
                {
                    Episode e;
                    if (k == null || !_open.TryGetValue(k, out e)) continue;
                    _open.Remove(k);
                    _closed++;
                    _version++;
                    closed.Add(e.Copy());
                }
            }
            return closed;
        }

        internal void Restore(IList<Episode> reports)
        {
            if (reports == null) return;
            lock (_lock)
            {
                if (_open.Count > 0) throw new InvalidOperationException("the report ledger is not empty");
                foreach (Episode r in reports)
                {
                    if (r == null || r.Key == null) continue;
                    Episode e = r.Copy();
                    e.AbsentSinceMs = -1;
                    e.ClassSinceMs = -1;
                    _open[e.Key] = e;
                    if (e.Id >= _next) _next = e.Id + 1;
                }
                _version++;
            }
        }

        internal void SeedNext(long seed)
        {
            lock (_lock)
            {
                if (seed <= _next) return;
                _next = seed;
                _version++;
            }
        }

        internal List<Episode> SnapshotForSave(out long nextId, out long version)
        {
            lock (_lock)
            {
                nextId = _next;
                version = _version;
                return CopyOrdered();
            }
        }

        internal Episode Get(string key)
        {
            if (key == null) return null;
            lock (_lock)
            {
                Episode e;
                return _open.TryGetValue(key, out e) ? e.Copy() : null;
            }
        }

        internal List<Episode> Snapshot() { lock (_lock) { return CopyOrdered(); } }

        private List<Episode> CopyOrdered()
        {
            List<Episode> list = new List<Episode>(_open.Count);
            foreach (Episode e in _open.Values) list.Add(e.Copy());
            list.Sort(delegate(Episode a, Episode b) { return a.Id.CompareTo(b.Id); });
            return list;
        }
    }

    internal sealed class LogEntry
    {
        public int Id;
        public EventLogEntryType Type;
        public string Text;

        public LogEntry(int id, EventLogEntryType type, string text) { Id = id; Type = type; Text = text; }
    }

    internal enum VerdictLink { Attached, NotTracked, Unattached, Superseded }

    internal sealed class ReportFlags
    {
        public List<Episode> PendingClosed = new List<Episode>();
        public long LastRecordMs = long.MinValue;
        public Dictionary<string, string> LastRecordSignature = new Dictionary<string, string>(StringComparer.Ordinal);
        public Dictionary<string, bool> LastRecordStuck = new Dictionary<string, bool>(StringComparer.Ordinal);
        public bool EarlyUsed, Resumed;
        public int PendingOpened;
        public long ChannelWarnedMs = long.MinValue;
        public int AvailableStreak;
        public string StartNotice;
        public bool StartNoticeWritten, StartNoticeEmitted;
        public List<StuckSession> LastUnreported;
        public DateTime LastCompleteAt = DateTime.MinValue;
        public string LastChannelDetail = "not checked";
    }

    internal sealed class PlanInput
    {
        public List<StuckSession> Selected, Seen;
        public bool Complete, Stopping;
        public int Opened;
        public ChannelState Channel;
        public string ChannelDetail;
        public bool UseLastRead;
        public Dictionary<string, DateTime> InFlight;
        public DateTime Now;
        public long MonoMs;
        public string Tracking, Instance, Node;
    }

    internal static class Reports
    {
        internal const int PartBudget = 15000;
        internal const int UnreportedCap = 50;
        internal const int ReminderMinutes = 15;
        internal const string ClosureSummary = "A reported stuck CSV SMB session has no retry left in the look-back window.";
        internal const string TrackingPaused = "paused while the service is stopped";
        private const string ClosedHeading = "Closed, superseding their earlier warnings";
        private static readonly DateTime Epoch2000 = new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        internal static long NumberSeed(DateTime utcNow)
        {
            double minutes = (utcNow - Epoch2000).TotalMinutes;
            return minutes <= 0 ? 0 : (long)Math.Floor(minutes) * 100;
        }

        internal static int VerdictId(VerifyOutcome v)
        {
            return v == VerifyOutcome.Held ? Log.IdVerifyNoRetry : Log.IdVerifyRetrying;
        }

        internal static VerdictLink Link(bool tracking, long reportId, bool attached)
        {
            if (!tracking) return VerdictLink.NotTracked;
            if (reportId == 0) return VerdictLink.Unattached;
            return attached ? VerdictLink.Attached : VerdictLink.Superseded;
        }

        internal static string DetectedSummary(int resets)
        {
            if (resets <= 0) return "A stuck Cluster Shared Volume SMB session was detected.";
            return "A stuck Cluster Shared Volume SMB session still meets the detection criteria after " +
                   Count(resets, "connection reset", "connection resets") + ".";
        }

        internal static LogEntry Verdict(VerifyOutcome v, bool complete, VerdictLink link, long reportId,
            DateTime reportedSince, string[] fields, int windowMinutes, string instance)
        {
            List<string> f = new List<string>();
            if (fields != null) f.AddRange(fields);
            string report = reportId <= 0 ? null
                : Num(reportId) + (reportedSince == DateTime.MinValue ? "" : ", reported since " + T(reportedSince));
            if (!complete)
            {
                f.Add("Reason|the event log read did not complete");
                if (report != null) f.Add("Report|" + report);
                f.Add("Instance|" + instance);
                return new LogEntry(Log.IdError, EventLogEntryType.Error,
                    Fmt.Event("The repair could not be verified. Its outcome is unknown, not failed.", f.ToArray()));
            }
            if (report != null) f.Add("Report|" + report);
            f.Add("Verdict status|interim");
            f.Add("Final outcome|" + FinalOutcome(link, reportId, windowMinutes));
            f.Add("Instance|" + instance);
            string summary = v == VerifyOutcome.Held
                ? "No retry followed the connection reset during verification."
                : "Retries continued after the connection reset; the repair is not yet confirmed.";
            return new LogEntry(VerdictId(v), EventLogEntryType.Information, Fmt.Event(summary, f.ToArray()));
        }

        private static string FinalOutcome(VerdictLink link, long reportId, int windowMinutes)
        {
            switch (link)
            {
                case VerdictLink.NotTracked: return "not tracked by this process";
                case VerdictLink.Unattached: return "not attached to a report";
                case VerdictLink.Superseded: return "report " + Num(reportId) + " had already closed (event 2002)";
                default: return "event 2002 when no retry remains in the " + Num(windowMinutes) + "-minute look-back window";
            }
        }

        internal static LogEntry NothingReset(int rejected, int unknownCode, int noMatch, string[] fields)
        {
            if (rejected + unknownCode > 0)
            {
                return new LogEntry(Log.IdRepairFailed, EventLogEntryType.Error,
                    Fmt.Event("Nothing was reset, so these stuck sessions were not repaired.", fields));
            }
            return new LogEntry(Log.IdRepairAttempt, EventLogEntryType.Information,
                Fmt.Event("No connection to this peer address remained, so nothing was reset.", fields));
        }

        internal static string StateLine(Episode e)
        {
            switch (e.State)
            {
                case ReportState.Stuck: return "meets the detection criteria";
                case ReportState.Retrying: return "retrying below the detection criteria, last retry " + T(e.LastRetryAt);
                case ReportState.Quiet: return "no retry since " + T(e.LastRetryAt);
                default:
                    return "last retry " + T(e.LastRetryAt) + "; none in the look-back window since " + T(e.StateSince) + "; confirming";
            }
        }

        internal static List<LogEntry> Record(string trigger, List<Episode> open, List<Episode> closed,
            List<StuckSession> unreported, string channel, DateTime stateAsOf, string tracking, string instance, string node)
        {
            if (open == null) open = new List<Episode>();
            if (closed == null) closed = new List<Episode>();
            int id = open.Count > 0 ? Log.IdReportsOpen : Log.IdNoReportOpen;
            string summary;
            if (open.Count == 1) summary = "1 CSV SMB session reported stuck is not yet confirmed to have stopped retrying.";
            else if (open.Count > 1) summary = Num(open.Count) + " CSV SMB sessions reported stuck are not yet confirmed to have stopped retrying.";
            else if (unreported == null || unreported.Count == 0) summary = "No CSV SMB session is reported stuck.";
            else summary = "No CSV SMB session is reported stuck; " + Count(unreported.Count, "other session", "other sessions") +
                           " logged retries in the look-back window.";

            List<string> openLines = new List<string>();
            foreach (Episode e in open) openLines.Add(OpenLine(e));
            List<string> closedLines = new List<string>();
            foreach (Episode e in closed) closedLines.Add(ClosedLine(e));
            List<string> unreportedBlock = UnreportedBlock(unreported, "not read at stop");
            List<string> trailer = new List<string>();
            trailer.Add("Retry event channel|" + channel);
            trailer.Add("State as of|" + (stateAsOf == DateTime.MinValue ? "not read at stop" : T(stateAsOf)));
            if (tracking != null) trailer.Add("Tracking|" + tracking);
            trailer.Add("Instance|" + instance);
            trailer.Add("Node|" + node);

            string[] header = new string[] { "Trigger|" + trigger, "Reports open|" + Num(open.Count), "Part|999 of 999" };
            int w = 0;
            foreach (List<string> group in new List<string>[] { openLines, closedLines, unreportedBlock, trailer, new List<string>(header) })
            {
                foreach (string f in group) { int c = f.IndexOf('|'); if (c > w) w = c; }
            }
            int fixedCost = summary.Length + Cost(header, w) + Cost(trailer, w);
            int headingCost = Cost("", w) + Cost(ClosedHeading, w) + Cost("", w);

            List<List<string>> bodies = new List<List<string>>();
            List<string> cur = new List<string>();
            int curCost = fixedCost + Cost(unreportedBlock, w);
            foreach (string line in openLines)
            {
                int c = Cost(line, w);
                if (cur.Count > 0 && curCost + c > PartBudget) { bodies.Add(cur); cur = new List<string>(); curCost = fixedCost; }
                cur.Add(line);
                curCost += c;
            }
            bool headed = false;
            foreach (string line in closedLines)
            {
                int c = Cost(line, w) + (headed ? 0 : headingCost);
                if (cur.Count > 0 && curCost + c > PartBudget)
                {
                    bodies.Add(cur);
                    cur = new List<string>();
                    curCost = fixedCost;
                    headed = false;
                    c = Cost(line, w) + headingCost;
                }
                if (!headed) { cur.Add(""); cur.Add(ClosedHeading); headed = true; }
                cur.Add(line);
                curCost += c;
            }
            bodies.Add(cur);

            List<LogEntry> parts = new List<LogEntry>();
            for (int i = 0; i < bodies.Count; i++)
            {
                List<string> f = new List<string>();
                f.Add(header[0]);
                f.Add(header[1]);
                if (bodies.Count > 1) f.Add("Part|" + Num(i + 1) + " of " + Num(bodies.Count));
                f.AddRange(bodies[i]);
                if (bodies[i].Contains(ClosedHeading)) f.Add("");
                if (i == 0) f.AddRange(unreportedBlock);
                f.AddRange(trailer);
                parts.Add(new LogEntry(id, EventLogEntryType.Warning, Fmt.Event(summary, f.ToArray())));
            }
            return parts;
        }

        internal static PlanInput Input(List<StuckSession> stuck, List<StuckSession> seen, string error, bool complete,
            int opened, ChannelState channel, string channelDetail, IDictionary<string, DateTime> inFlight,
            DateTime now, long monoMs, bool stopping, string tracking, string instance, string node)
        {
            PlanInput p = new PlanInput();
            p.Selected = stuck ?? new List<StuckSession>();
            p.Seen = seen ?? new List<StuckSession>();
            p.Complete = error == null && complete;
            p.Opened = opened;
            p.Channel = channel;
            p.ChannelDetail = channelDetail;
            p.InFlight = inFlight == null
                ? new Dictionary<string, DateTime>(StringComparer.Ordinal)
                : new Dictionary<string, DateTime>(inFlight, StringComparer.Ordinal);
            p.Now = now;
            p.MonoMs = monoMs;
            p.Stopping = stopping;
            p.Tracking = tracking;
            p.Instance = instance;
            p.Node = node;
            return p;
        }

        internal static List<LogEntry> Plan(EpisodeLedger ledger, ReportFlags flags, PlanInput input, Config cfg)
        {
            List<LogEntry> entries = new List<LogEntry>();
            flags.StartNoticeEmitted = false;
            flags.PendingOpened += input.Opened;
            bool stopCall = input.Stopping && !input.Complete;
            if (flags.StartNotice != null && !stopCall)
            {
                entries.Add(StartNotice(flags.StartNotice, input.Complete, ledger.OpenCount, Unreported(ledger, input.Seen),
                                        input.Channel, input.ChannelDetail, input.Instance, input.Node));
                flags.StartNoticeEmitted = true;
            }
            if (!input.Complete && !input.Stopping) return entries;

            List<StuckSession> unreported = null;
            if (input.Complete)
            {
                List<string> selectedKeys = new List<string>();
                foreach (StuckSession s in input.Selected) { if (s != null) selectedKeys.Add(s.Key); }
                List<string> candidates = ledger.Reconcile(selectedKeys, input.Seen, true, input.Channel, input.InFlight,
                    input.Now, input.MonoMs, cfg.RecentSeconds, cfg.ConfirmSeconds, cfg.InFlightCeilingSeconds);
                foreach (Episode e in ledger.Close(candidates))
                {
                    flags.PendingClosed.Add(e);
                    entries.Add(new LogEntry(Log.IdCleared, EventLogEntryType.Information,
                        Fmt.Event(ClosureSummary, ClosureFields(e, input.Instance, input.Node))));
                }

                int clearing = 0;
                foreach (Episode e in ledger.Snapshot()) { if (e.State == ReportState.Clearing) clearing++; }
                if (input.Channel == ChannelState.Available)
                {
                    flags.AvailableStreak++;
                    if (flags.AvailableStreak >= 2) flags.ChannelWarnedMs = long.MinValue;
                }
                else
                {
                    flags.AvailableStreak = 0;
                    if (clearing > 0 && Due(flags.ChannelWarnedMs, input.MonoMs, ReminderMinutes * 60000L))
                    {
                        entries.Add(ChannelNotice(input.Channel, input.ChannelDetail, clearing, input.Node));
                        flags.ChannelWarnedMs = input.MonoMs;
                    }
                }

                unreported = Unreported(ledger, input.Seen);
                flags.LastUnreported = unreported;
                flags.LastCompleteAt = input.Now;
                flags.LastChannelDetail = input.ChannelDetail;
            }

            List<Episode> open = ledger.Snapshot();
            List<string> reasons = new List<string>();
            if (flags.PendingOpened > 0) reasons.Add("open");
            if (flags.PendingClosed.Count > 0) reasons.Add("close");
            if (flags.Resumed && open.Count > 0) reasons.Add("resume");
            if (input.Stopping && (open.Count > 0 || flags.PendingClosed.Count > 0)) reasons.Add("stop");

            bool earlyDue = false, regularDue = false;
            if (reasons.Count == 0 && input.Complete)
            {
                bool changed = false;
                long earlyMs = (long)Math.Max(cfg.SweepSeconds / 2, cfg.SweepSeconds - cfg.DebounceSeconds) * 1000;
                foreach (Episode e in open)
                {
                    bool stuckNow = e.State == ReportState.Stuck;
                    string sig;
                    if (!flags.LastRecordSignature.TryGetValue(e.Key, out sig))
                    {
                        changed = true;
                    }
                    else
                    {
                        int bar = sig.IndexOf('|');
                        string recordedState = bar < 0 ? sig : sig.Substring(0, bar);
                        string recordedResets = bar < 0 ? "" : sig.Substring(bar + 1);
                        bool stuckBoth = stuckNow && recordedState == ReportState.Stuck.ToString();
                        if (recordedState != e.State.ToString() || (!stuckBoth && recordedResets != Num(e.Resets))) changed = true;
                    }
                    bool wasStuck;
                    bool classDiffers = !flags.LastRecordStuck.TryGetValue(e.Key, out wasStuck) || wasStuck != stuckNow;
                    if (!flags.EarlyUsed && classDiffers && e.ClassSinceMs >= 0 && input.MonoMs - e.ClassSinceMs >= earlyMs) earlyDue = true;
                }
                regularDue = changed && Due(flags.LastRecordMs, input.MonoMs, ReminderMinutes * 60000L);
                if (regularDue || earlyDue) reasons.Add("refresh");
            }

            if (reasons.Count > 0)
            {
                bool loneRefresh = reasons.Count == 1 && reasons[0] == "refresh";
                bool useLast = input.UseLastRead || !input.Complete;
                List<StuckSession> u = useLast ? flags.LastUnreported : unreported;
                DateTime asOf = useLast ? flags.LastCompleteAt : input.Now;
                string channel = useLast ? flags.LastChannelDetail : input.ChannelDetail;
                entries.AddRange(Record(string.Join(", ", reasons.ToArray()), open, flags.PendingClosed, u, channel, asOf,
                                        input.Stopping ? input.Tracking : null, input.Instance, input.Node));
                flags.PendingClosed = new List<Episode>();
                flags.PendingOpened = 0;
                flags.Resumed = false;
                flags.LastRecordMs = input.MonoMs;
                flags.LastRecordSignature.Clear();
                flags.LastRecordStuck.Clear();
                foreach (Episode e in open)
                {
                    flags.LastRecordSignature[e.Key] = e.State.ToString() + "|" + Num(e.Resets);
                    flags.LastRecordStuck[e.Key] = e.State == ReportState.Stuck;
                }
                flags.EarlyUsed = loneRefresh && earlyDue && !regularDue;
            }
            return entries;
        }

        internal static bool AfterWrite(ReportFlags flags, bool saveAllowed)
        {
            if (flags.StartNoticeEmitted)
            {
                flags.StartNotice = null;
                flags.StartNoticeEmitted = false;
                flags.StartNoticeWritten = true;
            }
            return flags.StartNoticeWritten && !saveAllowed;
        }

        internal static string SaveGateRefusal(bool loaded, bool loadBusy, bool saveAllowed)
        {
            if (!loaded) return "the saved state has not been loaded yet";
            if (loadBusy) return "the load reader is still running";
            if (!saveAllowed) return "the start notice has not been written yet";
            return null;
        }

        internal static string StopTracking(bool persist, string kind, string problem)
        {
            if (!persist) return "ended with this " + kind + " instance; not saved";
            if (problem == null) return TrackingPaused + "; resumes from " + StateFile.FileName;
            return "paused; save not confirmed: " + problem;
        }

        private static bool Due(long lastMs, long nowMs, long intervalMs)
        {
            return lastMs == long.MinValue || nowMs - lastMs >= intervalMs;
        }

        private static List<StuckSession> Unreported(EpisodeLedger ledger, List<StuckSession> seen)
        {
            List<StuckSession> u = new List<StuckSession>();
            if (seen == null) return u;
            foreach (StuckSession s in seen) { if (s != null && ledger.Get(s.Key) == null) u.Add(s); }
            return u;
        }

        internal static string[] ClosureFields(Episode e, string instance, string node)
        {
            List<string> f = new List<string>();
            f.Add("Session and peer|" + e.Key);
            f.Add("Report|" + Num(e.Id));
            f.Add("Session identifier|" + e.SessionId);
            f.Add("Peer (SMB server name)|" + e.ServerName);
            f.Add("Reported since|" + T(e.OpenedAt));
            f.Add("Last retry seen|" + T(e.LastRetryAt));
            f.Add("Resets issued while reported|" + Num(e.Resets));
            if (e.LastResetAt != DateTime.MinValue) f.Add("Last reset|" + Tf(e.LastResetAt));
            if (e.VerdictId != 0) f.Add("Last interim verdict|event " + Num(e.VerdictId) + " for the reset issued at " + Tf(e.VerdictResetAt));
            int reminders = e.Announcements - 1;
            f.Add("Supersedes|report " + Num(e.Id) + ": event 2000 reported since " + T(e.OpenedAt) +
                  (reminders > 0 ? " and its " + Count(reminders, "reminder", "reminders") : "") +
                  (e.VerdictId == Log.IdVerifyRetrying ? "; event 3004 for the reset issued at " + Tf(e.VerdictResetAt) : ""));
            f.Add("Instance|" + instance);
            f.Add("Node|" + node);
            return f.ToArray();
        }

        internal static LogEntry StartNotice(string reason, bool readComplete, int openNow, List<StuckSession> unreported,
            ChannelState channel, string channelDetail, string instance, string node)
        {
            bool clean = readComplete && channel == ChannelState.Available && openNow == 0 &&
                         unreported != null && unreported.Count == 0;
            string summary = clean
                ? "Stuck-session reports from before this start, if any, are not tracked; no CSV SMB session logged retries in the look-back window."
                : "Stuck-session reports from before this start, if any, are not tracked.";
            List<string> f = new List<string>();
            f.Add("Reason|" + reason);
            f.Add("Reports open now|" + Num(openNow));
            f.AddRange(UnreportedBlock(readComplete ? unreported : null, "not read"));
            f.Add("Retry event channel|" + channelDetail);
            f.Add("Instance|" + instance);
            f.Add("Node|" + node);
            return new LogEntry(Log.IdError, EventLogEntryType.Warning, Fmt.Event(summary, f.ToArray()));
        }

        internal static LogEntry ChannelNotice(ChannelState state, string detail, int waiting, string node)
        {
            string summary = state == ChannelState.Disabled
                ? "The retry event channel is disabled, so no stuck-session report can close."
                : "The retry event channel could not be checked, so no stuck-session report can close.";
            return new LogEntry(Log.IdError, EventLogEntryType.Warning, Fmt.Event(summary, new string[] {
                "Retry event channel|" + detail, "Reports waiting|" + Num(waiting), "Node|" + node }));
        }

        internal static LogEntry SaveFailedNotice(string file, string problem, string node)
        {
            return new LogEntry(Log.IdError, EventLogEntryType.Warning, Fmt.Event(
                "The stuck-session reports could not be saved.",
                new string[] { "File|" + file, "Problem|" + problem, "Node|" + node }));
        }

        internal static string[] CurrentStateFields(List<Episode> open, List<StuckSession> unreported, int underRepair,
            string channel, DateTime stateAsOf, string instance)
        {
            if (open == null) open = new List<Episode>();
            int stuck = 0, retrying = 0, quiet = 0, clearing = 0;
            foreach (Episode e in open)
            {
                if (e.State == ReportState.Stuck) stuck++;
                else if (e.State == ReportState.Retrying) retrying++;
                else if (e.State == ReportState.Quiet) quiet++;
                else clearing++;
            }
            List<string> f = new List<string>();
            f.Add("Reports open|" + Num(open.Count));
            f.Add("Meeting the criteria|" + Num(stuck));
            f.Add("Retrying, below criteria|" + Num(retrying));
            f.Add("Quiet, still in window|" + Num(quiet));
            f.Add("Confirming no retry|" + Num(clearing));
            f.Add("Retries, not reported|" + (unreported == null ? "not read" : Num(unreported.Count)));
            f.Add("Sessions under repair|" + Num(underRepair));
            f.Add("Retry event channel|" + channel);
            f.Add("State as of|" + (stateAsOf == DateTime.MinValue ? "no complete evaluation yet" : T(stateAsOf)));
            f.Add("Instance|" + instance);
            int used = 0, listed = 0;
            foreach (Episode e in open)
            {
                string line = OpenLine(e);
                if (used + line.Length + 40 > PartBudget) break;
                f.Add(line);
                used += line.Length + 40;
                listed++;
            }
            if (open.Count > listed) f.Add("More|" + Num(open.Count - listed) + " not listed (see event 2005)");
            return f.ToArray();
        }

        private static string OpenLine(Episode e)
        {
            return "Report " + Num(e.Id) + "|session " + e.SessionId + ", peer " + e.ServerName + ", opened " + T(e.OpenedAt) +
                   ", " + StateLine(e) + ", resets " + Num(e.Resets);
        }

        private static string ClosedLine(Episode e)
        {
            return "Report " + Num(e.Id) + "|session " + e.SessionId + ", peer " + e.ServerName + ", opened " + T(e.OpenedAt) +
                   ", last retry " + T(e.LastRetryAt) + ", resets " + Num(e.Resets) +
                   (e.VerdictId == Log.IdVerifyRetrying ? ", verdict 3004 for the reset issued at " + Tf(e.VerdictResetAt) : "");
        }

        private static List<string> UnreportedBlock(List<StuckSession> unreported, string notRead)
        {
            List<string> f = new List<string>();
            if (unreported == null) { f.Add("Retries in the window, not reported|" + notRead); return f; }
            f.Add("Retries in the window, not reported|" + Num(unreported.Count));
            int n = 0;
            foreach (StuckSession s in unreported)
            {
                if (n == UnreportedCap) break;
                f.Add("Session " + s.SessionId + "|" + s.ServerName + ", last retry " + T(s.Last) + ", " +
                      Count(s.Count, "retry", "retries") + " in the window");
                n++;
            }
            if (unreported.Count > n) f.Add("More|" + Num(unreported.Count - n) + " not listed");
            return f;
        }

        private static int Cost(string f, int w)
        {
            int c = f.IndexOf('|');
            return c < 0 ? 2 + f.Length : 8 + w + (f.Length - c - 1);
        }

        private static int Cost(IEnumerable<string> fields, int w)
        {
            int total = 0;
            foreach (string f in fields) total += Cost(f, w);
            return total;
        }

        private static string T(DateTime t) { return t.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture); }

        private static string Tf(DateTime t) { return t.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture); }

        private static string Num(long n) { return n.ToString(CultureInfo.InvariantCulture); }

        private static string Count(long n, string one, string many) { return Num(n) + " " + (n == 1 ? one : many); }
    }

    internal static class StateFile
    {
        internal const string FileName = "guard.state";
        private const string Header = "CsvSessionGuard reports 1";
        private const string Crlf = "\r\n";

        internal static string Serialize(string node, long nextId, IList<Episode> reports)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(Header).Append(Crlf);
            sb.Append("node\t").Append(node).Append(Crlf);
            sb.Append("next\t").Append(nextId.ToString(CultureInfo.InvariantCulture)).Append(Crlf);
            int count = 0;
            if (reports != null)
            {
                foreach (Episode e in reports)
                {
                    sb.Append("report\t").Append(e.Id.ToString(CultureInfo.InvariantCulture));
                    sb.Append('\t').Append(e.SessionId).Append('\t').Append(e.ServerName);
                    sb.Append('\t').Append(O(e.OpenedAt)).Append('\t').Append(O(e.LastAnnouncedAt));
                    sb.Append('\t').Append(e.Announcements.ToString(CultureInfo.InvariantCulture));
                    sb.Append('\t').Append(O(e.LastRetryAt)).Append('\t').Append(e.State.ToString());
                    sb.Append('\t').Append(O(e.StateSince)).Append('\t').Append(e.Resets.ToString(CultureInfo.InvariantCulture));
                    sb.Append('\t').Append(O(e.LastResetAt)).Append('\t').Append(e.VerdictId.ToString(CultureInfo.InvariantCulture));
                    sb.Append('\t').Append(O(e.VerdictResetAt)).Append(Crlf);
                    count++;
                }
            }
            sb.Append("end\t").Append(count.ToString(CultureInfo.InvariantCulture)).Append(Crlf);
            return sb.ToString();
        }

        internal static bool TryParse(string text, string node, out long nextId, out List<Episode> reports, out string problem)
        {
            nextId = 0;
            reports = new List<Episode>();
            problem = null;
            try
            {
                if (string.IsNullOrEmpty(text)) { problem = "the file is empty"; return false; }
                string[] lines = text.Split(new string[] { Crlf }, StringSplitOptions.None);
                int n = lines.Length;
                if (n > 0 && lines[n - 1].Length == 0) n--;
                if (n < 4 || lines[0] != Header) { problem = "the header is not recognised"; return false; }
                string[] nodeLine = lines[1].Split('\t');
                if (nodeLine.Length != 2 || nodeLine[0] != "node") { problem = "line 2 is malformed"; return false; }
                if (!string.Equals(nodeLine[1], node, StringComparison.OrdinalIgnoreCase))
                {
                    problem = "written by node " + nodeLine[1];
                    return false;
                }
                string[] nextLine = lines[2].Split('\t');
                long next;
                if (nextLine.Length != 2 || nextLine[0] != "next" ||
                    !long.TryParse(nextLine[1], NumberStyles.None, CultureInfo.InvariantCulture, out next))
                {
                    problem = "line 3 is malformed";
                    return false;
                }
                string[] endLine = lines[n - 1].Split('\t');
                int count;
                if (endLine.Length != 2 || endLine[0] != "end" ||
                    !int.TryParse(endLine[1], NumberStyles.None, CultureInfo.InvariantCulture, out count))
                {
                    problem = "the end line is missing";
                    return false;
                }
                if (count != n - 4)
                {
                    problem = "the end line counts " + count.ToString(CultureInfo.InvariantCulture) + " reports but " +
                              (n - 4).ToString(CultureInfo.InvariantCulture) + " are present";
                    return false;
                }
                List<Episode> parsed = new List<Episode>();
                HashSet<string> keys = new HashSet<string>(StringComparer.Ordinal);
                HashSet<long> ids = new HashSet<long>();
                for (int i = 3; i < n - 1; i++)
                {
                    Episode e;
                    string why;
                    string where = "line " + (i + 1).ToString(CultureInfo.InvariantCulture) + ": ";
                    if (!TryParseReport(lines[i], out e, out why)) { problem = where + why; return false; }
                    if (!keys.Add(e.Key) || !ids.Add(e.Id)) { problem = where + "duplicate report"; return false; }
                    parsed.Add(e);
                }
                nextId = next;
                reports = parsed;
                return true;
            }
            catch (Exception ex)
            {
                reports = new List<Episode>();
                problem = "unreadable: " + ex.GetType().Name;
                return false;
            }
        }

        internal static string Pick(string mainText, string tmpText) { return mainText ?? tmpText; }

        private static bool TryParseReport(string line, out Episode e, out string why)
        {
            e = null;
            string[] f = line.Split('\t');
            if (f.Length != 14 || f[0] != "report") { why = "not a report line"; return false; }
            Episode r = new Episode();
            if (!long.TryParse(f[1], NumberStyles.None, CultureInfo.InvariantCulture, out r.Id) || r.Id <= 0) { why = "bad report number"; return false; }
            if (f[2].Length == 0 || f[3].Length == 0) { why = "missing session or peer"; return false; }
            r.SessionId = f[2];
            r.ServerName = f[3];
            r.Key = r.SessionId + "|" + r.ServerName;
            if (!TryTime(f[4], out r.OpenedAt) || !TryTime(f[5], out r.LastAnnouncedAt) || !TryTime(f[7], out r.LastRetryAt) ||
                !TryTime(f[9], out r.StateSince) || !TryTime(f[11], out r.LastResetAt) || !TryTime(f[13], out r.VerdictResetAt))
            {
                why = "bad time";
                return false;
            }
            if (!int.TryParse(f[6], NumberStyles.None, CultureInfo.InvariantCulture, out r.Announcements) ||
                !int.TryParse(f[10], NumberStyles.None, CultureInfo.InvariantCulture, out r.Resets) ||
                !int.TryParse(f[12], NumberStyles.None, CultureInfo.InvariantCulture, out r.VerdictId))
            {
                why = "bad count";
                return false;
            }
            if (!Enum.IsDefined(typeof(ReportState), f[8]) || !Enum.TryParse(f[8], out r.State)) { why = "bad state"; return false; }
            e = r;
            why = null;
            return true;
        }

        private static bool TryTime(string s, out DateTime t)
        {
            return DateTime.TryParseExact(s, "o", CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out t);
        }

        private static string O(DateTime t) { return t.ToString("o", CultureInfo.InvariantCulture); }
    }

    // ---------------------------------------------------------------- the guard
    internal sealed class Guard : IDisposable
    {
        private readonly Config _cfg;
        private readonly object _gate = new object();
        // Sessions whose own reset is issued but not yet judged. Released on verdict, so a failed
        // repair retries at once. The stored time is only a ceiling against a thread that dies.
        private readonly Dictionary<string, DateTime> _inFlight = new Dictionary<string, DateTime>(StringComparer.Ordinal);
        // Log de-duplication only.
        private const int AnnounceRepeatMinutes = 15;
        private const string SaveBusy = "a previous save has not finished";
        private DateTime _lastEval = DateTime.MinValue;
        private DateTime _lastHeartbeat = DateTime.Now;
        private DateTime _lastEvalDoneUtc = DateTime.UtcNow;
        private int _sweeps, _detections, _errors;
        private int _resetsAccepted, _resetsNoMatch, _resetsRefused, _repairsSkipped, _verdictNoRetry, _verdictRetrying;
        private int _queryTimeouts;
        private Timer _timer;
        private Timer _watchdog;
        private EventLogWatcher _watcher;
        private volatile bool _stopping;
        private readonly EpisodeLedger _ledger = new EpisodeLedger();
        private readonly ReportFlags _flags = new ReportFlags();
        private readonly Stopwatch _mono = Stopwatch.StartNew();
        private readonly string _kind, _instance, _statePath;
        private readonly bool _persist;
        private volatile bool _tracking, _loaded, _saveAllowed;
        private volatile string _badFile;
        private long _writtenVersion = -1;
        private int _probeBusy, _saveBusy, _loadBusy, _renameBad, _renameDone, _saveFailing, _stopOnce, _busySkips, _gateBlocks;

        public Guard(Config cfg) : this(cfg, "console", false) { }

        public Guard(Config cfg, string kind, bool persist)
        {
            _cfg = cfg;
            Log.TimeoutMs = cfg.LogTimeoutSeconds * 1000;
            _kind = kind;
            _instance = kind + ", process " + ProcessId();
            _statePath = persist ? StatePath() : null;
            _persist = _statePath != null;
            _ledger.SeedNext(Reports.NumberSeed(DateTime.UtcNow));
        }

        private static string ProcessId()
        {
            try { return Process.GetCurrentProcess().Id.ToString(CultureInfo.InvariantCulture); }
            catch { return "unknown"; }
        }

        private static string StatePath()
        {
            try
            {
                string dir = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
                return string.IsNullOrEmpty(dir) ? null : Path.Combine(dir, StateFile.FileName);
            }
            catch { return null; }
        }

        public void Start()
        {
            _tracking = true;
            try
            {
                _timer = new Timer(OnTimer, null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(_cfg.SweepSeconds));
            }
            catch (Exception ex) { Log.Exception("start timer", ex); }

            // The self-watchdog. Nothing outside this process supervises whether we are actually
            // DOING anything - SCM only knows we exist. If evaluations stop completing we exit
            // deliberately and let the SCM recovery actions restart us clean.
            try
            {
                _watchdog = new Timer(OnWatchdog, null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
            }
            catch (Exception ex) { Log.Exception("start watchdog", ex); }

            // Fast path. Only a TRIGGER - all truth comes from re-reading the log in Evaluate,
            // so there is no dual accounting to get out of step. If the subscription cannot be
            // created the timer sweep still covers everything.
            try
            {
                string xpath = string.Format(CultureInfo.InvariantCulture, "*[System[(EventID={0})]]", 31013);
                EventLogQuery q = new EventLogQuery("Microsoft-Windows-SMBClient/Security", PathType.LogName, xpath);
                _watcher = new EventLogWatcher(q);
                _watcher.EventRecordWritten += OnEvent;
                _watcher.Enabled = true;
            }
            catch (Exception ex)
            {
                Log.Warn(Log.IdError, Fmt.Event(
                    "The event subscription could not be created. Detection continues on the timer sweep alone.",
                    new string[] {
                        "Error type|" + ex.GetType().FullName,
                        "Message|" + ex.Message,
                        "Sweep interval|" + _cfg.SweepSeconds + " seconds",
                        "Node|" + Environment.MachineName
                    }));
            }
        }

        private void OnEvent(object sender, EventRecordWrittenEventArgs e)
        {
            try
            {
                if (e != null && e.EventRecord != null) { try { e.EventRecord.Dispose(); } catch { } }
                Evaluate("event");
            }
            catch (Exception ex) { Bump(); Log.Exception("OnEvent", ex); }
        }

        private void OnTimer(object state)
        {
            try { Evaluate("sweep"); }
            catch (Exception ex) { Bump(); Log.Exception("OnTimer", ex); }
        }

        private void Bump() { try { Interlocked.Increment(ref _errors); } catch { } }

        // Bounded lock acquisition. A plain lock() would turn one wedged evaluation into infinite
        // thread accumulation as every timer tick and event callback queued behind it.
        private void Evaluate(string trigger)
        {
            if (_stopping) return;
            // WAIT for the sweep, never skip it. Dropping an evaluation because another was in
            // progress means a stuck session sits unrepaired until the next sweep. The repairs
            // themselves run on their own threads, so this lock is only held for detection.
            bool got = false;
            try { Monitor.Enter(_gate); got = true; }
            catch (Exception ex) { Bump(); Log.Exception("Evaluate enter", ex); return; }
            try { if (!_stopping) EvaluateLocked(trigger); }
            catch (Exception ex) { Bump(); Log.Exception("Evaluate", ex); }
            finally { if (got) { try { Monitor.Exit(_gate); } catch { } } }
        }

        private void EvaluateLocked(string trigger)
        {
            {
                try
                {
                    DateTime now = DateTime.Now;
                    if ((now - _lastEval).TotalSeconds < _cfg.DebounceSeconds && trigger == "event") return;
                    _lastEval = now;
                    _sweeps++;
                    if (_persist && !_loaded) LoadState();

                    // The event-log query is an RPC to the EventLog service and can block on a
                    // wedged service or a damaged log. On a worker, with a timeout.
                    int raw = 0; string err = null;
                    List<StuckSession> stuck = null;
                    List<StuckSession> seen = null;
                    bool complete = false;
                    Exception werr;
                    Worker.Result wr = Worker.Run("detect", delegate()
                    {
                        int r; string e; List<StuckSession> sn; bool c;
                        stuck = Detector.Find(_cfg, out r, out e, out sn, out c);
                        raw = r; err = e; seen = sn; complete = c;
                    }, _cfg.QueryTimeoutSeconds * 1000, out werr);

                    if (wr == Worker.Result.TimedOut)
                    {
                        _queryTimeouts++;
                        Log.Err(Log.IdWatchdog, Fmt.Event(
                            "An event log query did not return within its timeout and was abandoned.",
                            new string[] {
                                "Query timeout|" + _cfg.QueryTimeoutSeconds + " seconds",
                                "Consecutive timeouts|" + _queryTimeouts,
                                "Node|" + Environment.MachineName
                            }));
                        return;
                    }
                    if (wr == Worker.Result.Faulted)
                    {
                        Bump();
                        Log.Exception("detection worker", werr != null ? werr : new Exception("unknown"));
                        _lastEvalDoneUtc = DateTime.UtcNow;
                        return;
                    }
                    _queryTimeouts = 0;
                    _lastEvalDoneUtc = DateTime.UtcNow;
                    if (stuck == null) stuck = new List<StuckSession>();
                    if (err != null) { Bump(); Log.Err(Log.IdError, Fmt.Event(
                        "The stuck-session detection query reported an error.",
                        new string[] { "Error|" + err, "Node|" + Environment.MachineName })); }

                    int opened = 0;
                    HashSet<string> announced = new HashSet<string>(StringComparer.Ordinal);
                    List<StuckSession> toRepair = new List<StuckSession>();
                    foreach (StuckSession s in stuck)
                    {
                        try { if (Handle(s, now, ref opened, announced)) toRepair.Add(s); }
                        catch (Exception ex) { Bump(); Log.Exception("handle " + s.Key, ex); }
                    }
                    if (toRepair.Count > 0)
                    {
                        try { DispatchRepairs(toRepair, now, announced); }
                        catch (Exception ex) { Bump(); Log.Exception("dispatch repairs", ex); }
                    }

                    UpdateReports(stuck, seen, err, complete, opened, now);

                    Heartbeat(now);
                }
                catch (Exception ex) { Bump(); Log.Exception("Evaluate", ex); }
            }
        }

        // Returns true when this session needs its address reset. Announcing and detect-only are
        // handled here; the reset itself is dispatched per address by DispatchRepairs.
        private bool Handle(StuckSession s, DateTime now, ref int opened, HashSet<string> announced)
        {
            _detections++;

            // Anti-spam on the LOG only, never on the repair.
            bool fresh = true;
            Episode report = null;
            try
            {
                bool o;
                fresh = _ledger.NoteDetected(s, DateTime.Now, AnnounceRepeatMinutes, out o);
                if (o) opened++;
                report = _ledger.Get(s.Key);
            }
            catch (Exception ex) { Bump(); Log.Exception("report ledger", ex); }
            if (fresh)
            {
                announced.Add(s.Key);
                string summary = "A stuck Cluster Shared Volume SMB session was detected.";
                string[] reportFields = new string[0];
                try
                {
                    if (report != null)
                    {
                        string detected = Reports.DetectedSummary(report.Resets);
                        reportFields = new string[] {
                            "Report|" + report.Id.ToString(CultureInfo.InvariantCulture),
                            "Reported since|" + report.OpenedAt.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
                            "Resets issued while reported|" + report.Resets.ToString(CultureInfo.InvariantCulture),
                            "Instance|" + _instance };
                        summary = detected;
                    }
                }
                catch (Exception ex) { Bump(); Log.Exception("report fields", ex); reportFields = new string[0]; }
                List<string> fields = new List<string>(
                    new string[] {
                        "Session identifier|" + s.SessionId,
                        "Peer (SMB server name)|" + s.ServerName,
                        "Status|0xC0000016 (STATUS_MORE_PROCESSING_REQUIRED)",
                        "SMB command|1 (SESSION_SETUP)",
                        "",
                        "Observed retry behaviour",
                        "Failed bind attempts|" + s.Count,
                        "Distinct connections affected|" + s.DistinctPorts + " local ports",
                        "Retries on the worst connection|" + s.MaxPerPort + " (local port " + s.HottestPort + ")",
                        "First attempt seen|" + s.First.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
                        "Most recent attempt|" + s.Last.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
                        "Elapsed|" + Fmt.Duration(s.Last - s.First),
                        "Retry rate|" + string.Format(CultureInfo.InvariantCulture, "{0:N1} per minute", s.RatePerMin),
                        "",
                        "Local context",
                        "Node|" + Environment.MachineName,
                        "Operating mode|" + (_cfg.Repair ? "Repair enabled" : "Detect only")
                    });
                fields.InsertRange(2, reportFields);
                Log.Warn(Log.IdStuckDetected, Fmt.Event(summary, fields.ToArray()));
            }

            if (!_cfg.Repair)
            {
                if (fresh) Log.Info(Log.IdDetectOnly, Fmt.Event(
                    "No repair was attempted because the service is in detect-only mode.",
                    new string[] {
                        "Session identifier|" + s.SessionId,
                        "Peer (SMB server name)|" + s.ServerName,
                        "Node|" + Environment.MachineName
                    }));
                return false;
            }

            // The only gate. A session whose own reset is still being judged is not reset again:
            // a second reset inside the recovery window destroys the bindings the recovery needs.
            DateTime started;
            if (_inFlight.TryGetValue(s.Key, out started))
            {
                if ((now - started).TotalSeconds < _cfg.InFlightCeilingSeconds)
                {
                    if (fresh) Log.Info(Log.IdSuppressed, Fmt.Event(
                        "Repair was not reissued because this session's own repair is still in flight.",
                        new string[] {
                            "Session identifier|" + s.SessionId,
                            "Peer (SMB server name)|" + s.ServerName,
                            "Reset issued at|" + started.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
                            "Released|as soon as its verification reaches a verdict",
                            "Failsafe ceiling|" + _cfg.InFlightCeilingSeconds + " seconds"
                        }));
                    return false;
                }
                // Ceiling passed: the owning thread is gone without a verdict. Allow a fresh attempt.
                _inFlight.Remove(s.Key);
            }
            return true;
        }

        // Groups the sessions by distinct peer address and resets each address on its own thread.
        // Dedup happens HERE, before any thread starts, so the kernel never sees a duplicate and
        // each thread owns exactly one address with nothing to contend over.
        private void DispatchRepairs(List<StuckSession> sessions, DateTime now, HashSet<string> announced)
        {
            List<RepairGroup> groups = RepairPlan.GroupByTarget(sessions);
            if (groups.Count == 0)
            {
                foreach (StuckSession s in sessions)
                {
                    Interlocked.Increment(ref _repairsSkipped);
                    if (!announced.Contains(s.Key)) continue;
                    Log.Err(Log.IdRepairFailed, Fmt.Event(
                        "The repair was skipped because the failing peer address could not be determined.",
                        new string[] {
                            "Session identifier|" + s.SessionId,
                            "Peer (SMB server name)|" + s.ServerName,
                            "Reason|No usable RemoteAddress was present on any of this session's 31013 events",
                            "Node|" + Environment.MachineName
                        }));
                }
                return;
            }

            Log.Info(Log.IdRepairAttempt, Fmt.Event(
                "Resetting the CSV SMB connections of stuck sessions.",
                new string[] {
                    "Stuck sessions to repair|" + sessions.Count,
                    "Distinct peer addresses to reset|" + groups.Count,
                    "Concurrency|one thread per address, all dispatched at once",
                    "Node|" + Environment.MachineName
                }));

            foreach (StuckSession s in sessions) { _inFlight[s.Key] = now; }

            foreach (RepairGroup g in groups)
            {
                RepairGroup target = g;
                try
                {
                    Thread t = new Thread(delegate() { RepairAddress(target); });
                    t.IsBackground = true;
                    t.Name = "repair";
                    t.Start();
                }
                catch (Exception ex)
                {
                    Bump(); Log.Exception("start repair thread", ex);
                    foreach (StuckSession s in target.Sessions) { try { _inFlight.Remove(s.Key); } catch { } }
                }
            }
        }

        // The only thing that can tell a wedged service from an idle one. SCM knows we exist; it
        // does not know whether we are working. Exit codes: 3 = repeated query timeouts,
        // 4 = no evaluation completed in time. Both are recovered by the SCM restart actions.
        private void OnWatchdog(object state)
        {
            try
            {
                if (_stopping) return;

                if (_queryTimeouts >= 3)
                {
                    Log.Err(Log.IdWatchdog, Fmt.Event(
                        "The event log query has timed out repeatedly. The service is restarting itself.",
                        new string[] {
                            "Consecutive timeouts|" + _queryTimeouts,
                            "Query timeout|" + _cfg.QueryTimeoutSeconds + " seconds",
                            "Process exit code|3",
                            "Node|" + Environment.MachineName
                        }));
                    Environment.Exit(3);
                    return;
                }

                int limit = Math.Max(300, _cfg.SweepSeconds * 3);
                double stale = (DateTime.UtcNow - _lastEvalDoneUtc).TotalSeconds;
                if (stale > limit)
                {
                    Log.Err(Log.IdWatchdog, Fmt.Event(
                        "No evaluation has completed within the permitted interval. The service is restarting itself.",
                        new string[] {
                            "Time since last completed evaluation|" + string.Format(CultureInfo.InvariantCulture, "{0:N0} seconds", stale),
                            "Permitted maximum|" + limit + " seconds",
                            "Sweep interval|" + _cfg.SweepSeconds + " seconds",
                            "Process exit code|4",
                            "Node|" + Environment.MachineName
                        }));
                    Environment.Exit(4);
                    return;
                }
            }
            catch { }
        }

        // Resets ONE peer address, on its own thread, for every stuck session that failed against
        // it. Runs outside the sweep lock, so a slow kernel call never delays detection or another
        // address. Releases each session's in-flight claim once its verdict is known.
        private void RepairAddress(RepairGroup g)
        {
            StuckSession s = g.Sessions[0];
            bool wide = (g.AddressHex == null);
            List<string> targets = new List<string>();
            targets.Add(g.AddressHex);

            Log.Warn(Log.IdRepairAttempt, Fmt.Event(
                "Resetting the CSV SMB connections for one peer address.",
                new string[] {
                    "Peer (SMB server name)|" + g.ServerName,
                    "Stuck sessions served by this reset|" + g.Sessions.Count,
                    "Lead session identifier|" + s.SessionId,
                    "",
                    "Action being taken",
                    "Method|File system control code " + Fsctl.DescribeCode(Fsctl.Code),
                    "Device|\\Device\\SmbCsv (the CSV SMB instance)",
                    "Scope|" + (wide
                        ? "All CSV SMB connections to the named peer (whole-peer form)"
                        : "Only the connections to this one failing peer address"),
                    "Watchdog timeout|" + _cfg.FsctlTimeoutSeconds + " seconds",
                    "Node|" + Environment.MachineName
                }));

            int reset = 0, nomatch = 0, rejected = 0, unknownCode = 0;

            // The instant the reset is issued. Verification is judged against this, not against the
            // moment the verifier wakes up, because events can arrive in between.
            DateTime resetAt = DateTime.Now;

            foreach (string rawHex in targets)
            {
                byte[] addr = (rawHex == null) ? null : Fsctl.HexToBytes(rawHex);
                string shown = (addr == null) ? "none (whole-peer)" : Fsctl.DescribeSockAddr(addr);
                int hits = (rawHex == null) ? s.Count : s.RemoteHits(rawHex);

                string detail;
                Fsctl.Outcome o = Fsctl.Disconnect(s.ServerName, addr, _cfg.FsctlTimeoutSeconds, out detail);

                if (o == Fsctl.Outcome.TimedOut)
                {
                    Log.Err(Log.IdWatchdog, Fmt.Event(
                        "The connection reset did not return within its timeout. The service is restarting itself.",
                        new string[] {
                            "Peer (SMB server name)|" + s.ServerName,
                            "Address filter|" + shown,
                            "Timeout|" + _cfg.FsctlTimeoutSeconds + " seconds",
                            "Detail|" + detail,
                            "Process exit code|2",
                            "Node|" + Environment.MachineName
                        }));
                    Environment.Exit(2);
                    return;
                }

                if (o == Fsctl.Outcome.Success)
                {
                    reset++;
                    Log.Info(Log.IdRepairAttempt, Fmt.Event(
                        "The connection reset was accepted for one peer address.",
                        new string[] {
                            "Peer (SMB server name)|" + s.ServerName,
                            "Address filter|" + shown,
                            "Failed binds on this address|" + hits,
                            "Result|" + detail
                        }));
                }
                else if (o == Fsctl.Outcome.NoMatch)
                {
                    nomatch++;
                    Log.Info(Log.IdRepairAttempt, Fmt.Event(
                        "No connection to this peer address remained, so nothing was changed.",
                        new string[] {
                            "Peer (SMB server name)|" + s.ServerName,
                            "Address filter|" + shown,
                            "Meaning|The connections to this address had already gone. This is not a failure.",
                            "Result|" + detail
                        }));
                }
                else if (o == Fsctl.Outcome.NotAccepted)
                {
                    unknownCode++;
                    // Said explicitly, because the generic "rejected" wording would send an operator
                    // looking at permissions or session state when the code or its request is what
                    // no longer matches this build.
                    Log.Err(Log.IdRepairFailed, Fmt.Event(
                        "The device did not accept the reset control code or its request, so nothing was changed.",
                        new string[] {
                            "Session identifier|" + s.SessionId,
                            "Peer (SMB server name)|" + s.ServerName,
                            "Address filter|" + shown,
                            "Status|0xC0000010 STATUS_INVALID_DEVICE_REQUEST",
                            "Control code in use|" + Fsctl.DescribeCode(Fsctl.Code),
                            "Meaning|This Windows build does not accept that code, or that request, on this device",
                            "Detail|" + detail,
                            "Node|" + Environment.MachineName
                        }));
                }
                else
                {
                    rejected++;
                    Log.Err(Log.IdRepairFailed, Fmt.Event(
                        "The connection reset was rejected for one peer address.",
                        new string[] {
                            "Session identifier|" + s.SessionId,
                            "Peer (SMB server name)|" + s.ServerName,
                            "Address filter|" + shown,
                            "Outcome|" + o,
                            "Detail|" + detail,
                            "Node|" + Environment.MachineName
                        }));
                }
            }

            if (reset == 0)
            {
                try
                {
                    LogEntry e = Reports.NothingReset(rejected, unknownCode, nomatch,
                        new string[] {
                            "Peer (SMB server name)|" + g.ServerName,
                            "Sessions affected|" + g.Sessions.Count,
                            "Matched nothing|" + nomatch,
                            "Rejected|" + rejected,
                            "Code or request not accepted|" + unknownCode,
                            "Node|" + Environment.MachineName
                        });
                    Log.Write(e.Id, e.Type, e.Text);
                    if (e.Id == Log.IdRepairFailed) Interlocked.Increment(ref _resetsRefused);
                    else Interlocked.Increment(ref _resetsNoMatch);
                }
                catch (Exception ex) { Bump(); Log.Exception("nothing reset", ex); }
                ReleaseInFlight(g);
                return;
            }

            foreach (StuckSession x in g.Sessions) { x.LastResetAt = resetAt; }
            try { _ledger.NoteReset(g.Sessions, resetAt); }
            catch (Exception ex) { Bump(); Log.Exception("report reset", ex); }
            Interlocked.Increment(ref _resetsAccepted);

            Log.Info(Log.IdRepairAttempt, Fmt.Event(
                "The connection reset was accepted by the SMB client.",
                new string[] {
                    "Peer (SMB server name)|" + g.ServerName,
                    "Sessions served by this reset|" + g.Sessions.Count,
                    "Matched nothing|" + nomatch,
                    "Rejected|" + rejected,
                    "Code or request not accepted|" + unknownCode,
                    "Reset issued at|" + resetAt.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture),
                    "Verification due in|" + _cfg.VerifyDelaySeconds + " seconds"
                }));

            // Verify on this same thread: it already owns this address and nothing else is waiting
            // on it. Other addresses are being reset concurrently on their own threads.
            try { Verify(s); }
            catch (Exception ex) { Bump(); Log.Exception("verify " + s.Key, ex); }
            finally { ReleaseInFlight(g); }
        }

        // Frees the sessions of a group for a fresh repair as soon as their verdict is known.
        private void ReleaseInFlight(RepairGroup g)
        {
            lock (_gate)
            {
                foreach (StuckSession x in g.Sessions)
                {
                    try { _inFlight.Remove(x.Key); } catch { }
                }
            }
        }

        // Re-reads the retry stream and returns this session's event TIMES. Returns null when the
        // query could not be made, which is "unknown" and must never be scored as a failure.
        private List<DateTime> QueryEventTimes(StuckSession s, Config probe, out string error, out bool complete)
        {
            error = null;
            complete = false;
            List<StuckSession> found = null;
            string err = null;
            bool full = false;
            Exception werr;
            Worker.Result wr = Worker.Run("verifyquery", delegate()
            {
                int r; string e; List<StuckSession> sn; bool c;
                found = Detector.Find(probe, out r, out e, out sn, out c);
                err = e; full = c;
            }, _cfg.QueryTimeoutSeconds * 1000, out werr);

            if (wr != Worker.Result.Completed || found == null)
            {
                error = "the verification query did not complete: " + wr;
                return null;
            }
            if (err != null) { error = err; return null; }
            complete = full;
            return VerifyAnalysis.TimesFor(found, s.Key);
        }

        // Verifies one repair. The reference instant is when the FSCTL was issued, recorded on the
        // session by Repair - not when this method starts: in -once mode every repair runs before
        // every verification, so "now" would silently discard everything in between.
        private void Verify(StuckSession s)
        {
            try
            {
                DateTime resetAt = s.LastResetAt;
                if (resetAt == DateTime.MinValue) return;        // nothing was reset for this session
                int wait = _cfg.VerifyDelaySeconds;
                for (int i = 0; i < wait && !_stopping; i++) Thread.Sleep(1000);
                if (_stopping)
                {
                    // Say so, rather than leaving a 3000 "verification due" with no verdict ever.
                    Log.Warn(Log.IdError, Fmt.Event(
                        "Verification was abandoned because the service is stopping. The outcome is unknown.",
                        new string[] {
                            "Session identifier|" + s.SessionId,
                            "Peer (SMB server name)|" + s.ServerName,
                            "Reset issued at|" + resetAt.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture),
                            "Node|" + Environment.MachineName
                        }));
                    return;
                }

                // Silence only counts as success if the source could have spoken. Asked of the
                // channel, not of the record count: zero records is also what success looks like.
                string chDetail;
                ChannelState channel = Detector.Availability(out chDetail);
                if (!VerifyAnalysis.CanConclude(channel))
                {
                    Log.Warn(Log.IdError, Fmt.Event(
                        "The repair could not be verified because the retry event source is unavailable.",
                        new string[] {
                            "Session identifier|" + s.SessionId,
                            "Peer (SMB server name)|" + s.ServerName,
                            "Event channel|" + chDetail,
                            "Meaning|Silence is not evidence when the channel cannot report retries",
                            "Outcome|unknown, not failed",
                            "Node|" + Environment.MachineName
                        }));
                    return;
                }

                Config probe = new Config();
                probe.WindowMinutes = Math.Max(2, (_cfg.VerifyDelaySeconds / 60) + 1);
                probe.MinEvents = 1;
                probe.MinSpanSeconds = 0;
                probe.MinEventsPerPort = 1;
                probe.RecentSeconds = _cfg.VerifyDelaySeconds + 60;

                string err;
                bool c1, c2 = true;
                List<DateTime> times = QueryEventTimes(s, probe, out err, out c1);
                if (times == null)
                {
                    Bump();
                    Log.Err(Log.IdError, Fmt.Event(
                        "The repair could not be verified. Its outcome is unknown, not failed.",
                        new string[] {
                            "Session identifier|" + s.SessionId,
                            "Peer (SMB server name)|" + s.ServerName,
                            "Reason|" + err,
                            "Node|" + Environment.MachineName
                        }));
                    return;
                }

                int afterCount, inFlight;
                VerifyOutcome verdict = VerifyAnalysis.Decide(times, null, resetAt,
                                                              _cfg.VerifyGraceSeconds, out afterCount, out inFlight);
                int looks = 1;

                // One retry after the reset is ambiguous at this cadence: a dead loop can leave a
                // straggler. Look again and decide on whether a NEW event arrives.
                if (verdict == VerifyOutcome.Inconclusive)
                {
                    for (int i = 0; i < 60 && !_stopping; i++) Thread.Sleep(1000);
                    if (_stopping) return;
                    string err2;
                    List<DateTime> later = QueryEventTimes(s, probe, out err2, out c2);
                    if (later == null)
                    {
                        // Our own inability to look is not the repair's failure.
                        Log.Err(Log.IdError, Fmt.Event(
                            "The repair could not be verified. Its outcome is unknown, not failed.",
                            new string[] {
                                "Session identifier|" + s.SessionId,
                                "Peer (SMB server name)|" + s.ServerName,
                                "Retries after the reset|1 (ambiguous, a second look was attempted)",
                                "Reason|" + err2,
                                "Node|" + Environment.MachineName
                            }));
                        return;
                    }
                    looks = 2;
                    verdict = VerifyAnalysis.Decide(times, later, resetAt,
                                                    _cfg.VerifyGraceSeconds, out afterCount, out inFlight);
                }

                double expected = s.RatePerMin * (_cfg.VerifyDelaySeconds / 60.0);
                double observedFor = Math.Max(0, (DateTime.Now - resetAt).TotalSeconds);
                bool readComplete = c1 && (looks == 1 || c2);
                int id = Reports.VerdictId(verdict);
                bool attached = false;
                if (readComplete && _tracking && s.ReportId != 0)
                {
                    try { attached = _ledger.NoteVerdict(s.Key, s.ReportId, id, resetAt); }
                    catch (Exception ex) { Bump(); Log.Exception("report verdict", ex); }
                }
                VerdictLink link = Reports.Link(_tracking, s.ReportId, attached);
                DateTime since = DateTime.MinValue;
                Episode report = _ledger.Get(s.Key);
                if (report != null && report.Id == s.ReportId) since = report.OpenedAt;
                string[] fields;
                if (verdict == VerifyOutcome.Held)
                {
                    fields =
                        new string[] {
                            "Session identifier|" + s.SessionId,
                            "Peer (SMB server name)|" + s.ServerName,
                            "",
                            "Verification",
                            "Reset issued at|" + resetAt.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture),
                            "Observation period|" + string.Format(CultureInfo.InvariantCulture, "{0:N0} seconds after the reset", observedFor),
                            "Observations made|" + looks,
                            "Retry events after the reset|" + afterCount,
                            "In-flight requests absorbed|" + inFlight,
                            // Legacy field name, kept so existing saved queries keep matching.
                            "Retry events observed|" + afterCount,
                            "Retry events expected if unrepaired|" + string.Format(CultureInfo.InvariantCulture, "approximately {0:N0}", expected),
                            "Previous retry rate|" + string.Format(CultureInfo.InvariantCulture, "{0:N1} per minute", s.RatePerMin),
                            "Event channel|" + chDetail,
                            "Total failed attempts before repair|" + s.Count
                        };
                }
                else
                {
                    fields =
                        new string[] {
                            "Session identifier|" + s.SessionId,
                            "Peer (SMB server name)|" + s.ServerName,
                            "",
                            "Verification",
                            "Reset issued at|" + resetAt.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture),
                            "Observation period|" + string.Format(CultureInfo.InvariantCulture, "{0:N0} seconds after the reset", observedFor),
                            "Observations made|" + looks,
                            "Retry events after the reset|" + afterCount,
                            "In-flight requests absorbed|" + inFlight,
                            // Legacy field name, kept so existing saved queries keep matching.
                            "Retry events observed|" + afterCount,
                            "Previous retry rate|" + string.Format(CultureInfo.InvariantCulture, "{0:N1} per minute", s.RatePerMin),
                            "Next action|another pass if it meets the detection criteria again"
                        };
                }
                LogEntry e = Reports.Verdict(verdict, readComplete, link, s.ReportId, since, fields, _cfg.WindowMinutes, _instance);
                Log.Write(e.Id, e.Type, e.Text);
                if (e.Id == Log.IdVerifyNoRetry) Interlocked.Increment(ref _verdictNoRetry);
                else if (e.Id == Log.IdVerifyRetrying) Interlocked.Increment(ref _verdictRetrying);
                else Bump();
            }
            catch (Exception ex) { Bump(); Log.Exception("Verify", ex); }
        }

        private void Heartbeat(DateTime now)
        {
            try
            {
                if (_cfg.HeartbeatMinutes <= 0) return;
                if ((now - _lastHeartbeat).TotalMinutes < _cfg.HeartbeatMinutes) return;
                _lastHeartbeat = now;
                List<string> fields = new List<string>();
                fields.Add("Node|" + Environment.MachineName);
                fields.Add("Operating mode|" + (_cfg.Repair ? "Repair enabled" : "Detect only"));
                fields.Add("");
                fields.Add("Current state");
                fields.AddRange(Reports.CurrentStateFields(_ledger.Snapshot(), _flags.LastUnreported, UnderRepair(now),
                                                           _flags.LastChannelDetail, _flags.LastCompleteAt, _instance));
                fields.Add("");
                fields.Add("Activity since the service started");
                fields.Add("Evaluations completed|" + _sweeps);
                fields.Add("Detection matches|" + _detections);
                fields.Add("Reports opened|" + _ledger.OpenedTotal);
                fields.Add("Reports closed|" + _ledger.ClosedTotal);
                fields.Add("Resets accepted|" + _resetsAccepted);
                fields.Add("Resets matching nothing|" + _resetsNoMatch);
                fields.Add("Resets refused|" + _resetsRefused);
                fields.Add("Skips, no peer address|" + _repairsSkipped);
                fields.Add("Verdicts, no retry seen|" + _verdictNoRetry);
                fields.Add("Verdicts, retries continued|" + _verdictRetrying);
                fields.Add("");
                fields.Add("Health of the guard itself");
                fields.Add("Errors handled|" + _errors);
                fields.Add("Event log query timeouts|" + _queryTimeouts);
                Log.Info(Log.IdHeartbeat, Fmt.Event("CSV session guard periodic status report.", fields.ToArray()));
            }
            catch (Exception ex) { Bump(); Log.Exception("Heartbeat", ex); }
        }

        private int UnderRepair(DateTime now)
        {
            int n = 0;
            foreach (DateTime started in _inFlight.Values)
            {
                if ((now - started).TotalSeconds < _cfg.InFlightCeilingSeconds) n++;
            }
            return n;
        }

        private void UpdateReports(List<StuckSession> stuck, List<StuckSession> seen, string err, bool complete, int opened, DateTime now)
        {
            try
            {
                ChannelState ch = ChannelState.Available;
                string detail = _flags.LastChannelDetail;
                if (_flags.StartNotice != null || (err == null && complete && _ledger.OpenCount > 0)) ch = ProbeChannel(out detail);
                string tracking = !_stopping ? null
                    : _persist ? Reports.TrackingPaused
                    : Reports.StopTracking(false, _kind, null);
                PlanInput input = Reports.Input(stuck, seen, err, complete, opened, ch, detail, _inFlight, now,
                                                _mono.ElapsedMilliseconds, _stopping, tracking, _instance, Environment.MachineName);
                List<LogEntry> entries = Reports.Plan(_ledger, _flags, input, _cfg);
                List<Episode> saved;
                long savedVersion;
                if (_persist && _ledger.Version != Interlocked.Read(ref _writtenVersion))
                {
                    if (SaveState(out saved, out savedVersion) == SaveBusy && _stopping)
                    {
                        DateTime until = DateTime.UtcNow.AddSeconds(_cfg.LogTimeoutSeconds);
                        while (Interlocked.CompareExchange(ref _saveBusy, 0, 0) != 0 && DateTime.UtcNow < until) Thread.Sleep(50);
                        SaveState(out saved, out savedVersion);
                    }
                }
                foreach (LogEntry e in entries) Log.Write(e.Id, e.Type, e.Text);
                if (Reports.AfterWrite(_flags, _saveAllowed) && _persist)
                {
                    if (_badFile != null)
                    {
                        Interlocked.Exchange(ref _renameDone, 0);
                        Interlocked.Exchange(ref _renameBad, 1);
                    }
                    _saveAllowed = true;
                    SaveState(out saved, out savedVersion);
                }
            }
            catch (Exception ex) { Bump(); Log.Exception("report state", ex); }
        }

        private ChannelState ProbeChannel(out string detail)
        {
            if (Interlocked.CompareExchange(ref _probeBusy, 1, 0) != 0)
            {
                detail = "a previous channel check has not returned";
                return ChannelState.Unavailable;
            }
            ChannelState state = ChannelState.Unavailable;
            string found = null;
            Exception werr;
            bool started;
            Worker.Result wr = Worker.Run("channel", delegate()
            {
                try { string d; state = Detector.Availability(out d); found = d; }
                finally { Interlocked.Exchange(ref _probeBusy, 0); }
            }, Math.Min(_cfg.QueryTimeoutSeconds, 15) * 1000, out werr, out started);
            if (!started) Interlocked.Exchange(ref _probeBusy, 0);
            if (wr != Worker.Result.Completed)
            {
                detail = "the channel check did not complete: " + wr;
                return ChannelState.Unavailable;
            }
            detail = found ?? "unknown";
            return state;
        }

        private void LoadState()
        {
            string reason = null;
            string path = _statePath;
            try
            {
                string main = null, tmp = null;
                Interlocked.Exchange(ref _loadBusy, 1);
                Exception werr;
                bool started;
                Worker.Result wr = Worker.Run("loadstate", delegate()
                {
                    try
                    {
                        if (File.Exists(path)) main = File.ReadAllText(path);
                        else if (File.Exists(path + ".tmp")) tmp = File.ReadAllText(path + ".tmp");
                    }
                    finally { Interlocked.Exchange(ref _loadBusy, 0); }
                }, _cfg.LogTimeoutSeconds * 1000, out werr, out started);
                if (!started) Interlocked.Exchange(ref _loadBusy, 0);
                if (wr != Worker.Result.Completed)
                {
                    _badFile = path;
                    reason = wr == Worker.Result.TimedOut
                        ? "the saved state could not be read within " + _cfg.LogTimeoutSeconds + " seconds"
                        : "the saved state could not be read: " + (werr != null ? werr.GetType().Name + ": " + werr.Message : "unknown");
                    return;
                }
                string text = StateFile.Pick(main, tmp);
                if (text == null) { reason = "no saved state was found"; return; }
                long next;
                List<Episode> reports;
                string problem;
                if (!StateFile.TryParse(text, Environment.MachineName, out next, out reports, out problem))
                {
                    _badFile = main != null ? path : path + ".tmp";
                    reason = "the saved state could not be read: " + problem;
                    return;
                }
                _ledger.Restore(reports);
                _ledger.SeedNext(next);
                _flags.Resumed = reports.Count > 0;
                Monotonic.Raise(ref _writtenVersion, _ledger.Version);
                _saveAllowed = true;
            }
            catch (Exception ex)
            {
                Bump();
                Log.Exception("load reports", ex);
                reason = "the saved state could not be read: " + ex.GetType().Name;
            }
            finally
            {
                if (reason != null) _flags.StartNotice = reason;
                _loaded = true;
            }
        }

        private string SaveState(out List<Episode> saved, out long savedVersion)
        {
            saved = null;
            savedVersion = -1;
            string refusal = Reports.SaveGateRefusal(_loaded, Interlocked.CompareExchange(ref _loadBusy, 0, 0) != 0, _saveAllowed);
            if (refusal != null)
            {
                bool due = _ledger.Version != Interlocked.Read(ref _writtenVersion);
                if (due && Interlocked.Increment(ref _gateBlocks) >= 3) SaveFailed(refusal);
                return refusal;
            }
            Interlocked.Exchange(ref _gateBlocks, 0);
            if (Interlocked.CompareExchange(ref _saveBusy, 1, 0) != 0)
            {
                if (Interlocked.Increment(ref _busySkips) >= 3) SaveFailed(SaveBusy);
                return SaveBusy;
            }
            Interlocked.Exchange(ref _busySkips, 0);
            bool started = false;
            try
            {
                long next, version;
                List<Episode> snapshot = _ledger.SnapshotForSave(out next, out version);
                if (version <= Interlocked.Read(ref _writtenVersion))
                {
                    saved = snapshot;
                    savedVersion = version;
                    Interlocked.Exchange(ref _saveFailing, 0);
                    return null;
                }
                string text = StateFile.Serialize(Environment.MachineName, next, snapshot);
                string path = _statePath;
                string badFile = _badFile;
                bool rename = Interlocked.CompareExchange(ref _renameDone, 0, 0) == 0 &&
                              Interlocked.Exchange(ref _renameBad, 0) == 1;
                Exception werr;
                Worker.Result wr = Worker.Run("savestate", delegate()
                {
                    try
                    {
                        if (rename && badFile != null && File.Exists(badFile))
                        {
                            string bad = path + ".bad";
                            if (File.Exists(bad)) File.Delete(bad);
                            File.Move(badFile, bad);
                            Interlocked.Exchange(ref _renameDone, 1);
                        }
                        string tmp = path + ".tmp";
                        byte[] bytes = Encoding.UTF8.GetBytes(text);
                        using (FileStream fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
                        {
                            fs.Write(bytes, 0, bytes.Length);
                            fs.Flush(true);
                        }
                        if (File.Exists(path)) File.Replace(tmp, path, null);
                        else File.Move(tmp, path);
                        Monotonic.Raise(ref _writtenVersion, version);
                    }
                    finally { Interlocked.Exchange(ref _saveBusy, 0); }
                }, _cfg.LogTimeoutSeconds * 1000, out werr, out started);
                if (wr == Worker.Result.Completed)
                {
                    saved = snapshot;
                    savedVersion = version;
                    Interlocked.Exchange(ref _saveFailing, 0);
                    return null;
                }
                if (rename && Interlocked.CompareExchange(ref _renameDone, 0, 0) == 0) Interlocked.Exchange(ref _renameBad, 1);
                string why = wr == Worker.Result.TimedOut
                    ? "the save did not complete within " + _cfg.LogTimeoutSeconds + " seconds"
                    : (werr != null ? werr.GetType().Name + ": " + werr.Message : "the save failed");
                SaveFailed(why);
                return why;
            }
            finally
            {
                if (!started) Interlocked.Exchange(ref _saveBusy, 0);
            }
        }

        private void SaveFailed(string reason)
        {
            if (Interlocked.Exchange(ref _saveFailing, 1) != 0) return;
            LogEntry notice = Reports.SaveFailedNotice(_statePath, reason, Environment.MachineName);
            Log.Write(notice.Id, notice.Type, notice.Text);
        }

        public void Stop()
        {
            if (Interlocked.Exchange(ref _stopOnce, 1) != 0) return;
            _stopping = true;
            try { if (_watcher != null) { _watcher.Enabled = false; _watcher.EventRecordWritten -= OnEvent; } }
            catch (Exception ex) { Log.Exception("stop watcher", ex); }
            try { if (_timer != null) _timer.Change(Timeout.Infinite, Timeout.Infinite); }
            catch (Exception ex) { Log.Exception("stop timer", ex); }
            try { if (_watchdog != null) _watchdog.Change(Timeout.Infinite, Timeout.Infinite); }
            catch (Exception ex) { Log.Exception("stop watchdog", ex); }
            if (!_tracking) return;

            List<Episode> saved = null;
            long savedVersion = -1;
            string problem = null;
            bool got = false;
            try
            {
                if (_persist) problem = SaveState(out saved, out savedVersion);
                try { got = Monitor.TryEnter(_gate, _cfg.LogTimeoutSeconds * 1000); } catch { got = false; }
                if (got && _persist && (problem != null || _ledger.Version != Interlocked.Read(ref _writtenVersion)))
                {
                    List<Episode> again;
                    long againVersion;
                    problem = SaveState(out again, out againVersion);
                    if (again != null) { saved = again; savedVersion = againVersion; }
                }
                string tracking = Reports.StopTracking(_persist, _kind, problem);
                List<LogEntry> entries;
                if (got)
                {
                    PlanInput input = Reports.Input(null, null, null, false, 0, ChannelState.Available, _flags.LastChannelDetail, null,
                                                    DateTime.Now, _mono.ElapsedMilliseconds, true, tracking, _instance, Environment.MachineName);
                    input.UseLastRead = true;
                    entries = Reports.Plan(_ledger, _flags, input, _cfg);
                }
                else
                {
                    List<Episode> list;
                    if (saved != null && Interlocked.Read(ref _writtenVersion) != savedVersion)
                    {
                        list = _ledger.Snapshot();
                        tracking = Reports.TrackingPaused;
                    }
                    else list = saved ?? _ledger.Snapshot();
                    entries = list.Count == 0 ? new List<LogEntry>()
                        : Reports.Record("stop", list, new List<Episode>(), null, "not checked", DateTime.MinValue, tracking,
                                         _instance, Environment.MachineName);
                }
                foreach (LogEntry e in entries) Log.Write(e.Id, e.Type, e.Text);
            }
            catch (Exception ex) { Bump(); Log.Exception("stop record", ex); }
            finally { if (got) { try { Monitor.Exit(_gate); } catch { } } }
        }

        public void Dispose()
        {
            try { if (_watcher != null) _watcher.Dispose(); } catch { }
            try { if (_timer != null) _timer.Dispose(); } catch { }
            try { if (_watchdog != null) _watchdog.Dispose(); } catch { }
        }

        // Single evaluation for -once. Never repairs unless cfg.Repair is set.
        public int RunOnce()
        {
            System.Console.WriteLine("CsvSessionGuard -once on " + Environment.MachineName);
            System.Console.WriteLine("  " + _cfg.Describe());
            System.Console.WriteLine("  reset control code " + Fsctl.DescribeCode(Fsctl.Code) + "; " + ClusterControlCode.Source);

            int raw = 0; string err = null;
            List<StuckSession> stuck = null;
            Exception werr;
            Worker.Result wr = Worker.Run("detect", delegate()
            {
                int r; string e;
                stuck = Detector.Find(_cfg, out r, out e);
                raw = r; err = e;
            }, _cfg.QueryTimeoutSeconds * 1000, out werr);

            if (wr == Worker.Result.TimedOut)
            {
                System.Console.WriteLine("  DETECTION TIMED OUT after " + _cfg.QueryTimeoutSeconds +
                                         "s (the event-log query did not return)");
                return 4;
            }
            if (wr == Worker.Result.Faulted || stuck == null)
            {
                System.Console.WriteLine("  DETECTION FAULTED: " + (werr != null ? werr.Message : "unknown"));
                return 3;
            }
            if (err != null) { System.Console.WriteLine("  DETECTION ERROR: " + err); return 3; }
            System.Console.WriteLine(string.Format(CultureInfo.InvariantCulture,
                "  31013 records read in the last {0} min: {1}", _cfg.WindowMinutes, raw));
            if (stuck.Count == 0)
            {
                System.Console.WriteLine("  no stuck session meets the criteria (needs n>=" + _cfg.MinEvents +
                                         ", maxPerPort>=" + _cfg.MinEventsPerPort + ", span>=" + _cfg.MinSpanSeconds + "s, last<=" + _cfg.RecentSeconds + "s)");
                return 0;
            }
            foreach (StuckSession s in stuck)
            {
                System.Console.WriteLine("  *** STUCK: " + s.ToString());
                List<string> t = s.RemoteTargets();
                if (t.Count == 0)
                {
                    System.Console.WriteLine("        no peer address captured - a scoped repair is NOT possible for this session");
                }
                else
                {
                    foreach (string hex in t)
                    {
                        System.Console.WriteLine(string.Format(CultureInfo.InvariantCulture,
                            "        would reset {0}  ({1} failed binds)",
                            Fsctl.DescribeSockAddr(Fsctl.HexToBytes(hex)), s.RemoteHits(hex)));
                    }
                }
            }
            if (!_cfg.Repair) { System.Console.WriteLine("  detect-only: nothing was changed."); return 1; }

            // The same dedup and concurrency the service uses: one reset per DISTINCT address, each
            // on its own thread. -once then waits for them, because its process exits on return.
            List<RepairGroup> groups = RepairPlan.GroupByTarget(stuck);
            System.Console.WriteLine(string.Format(CultureInfo.InvariantCulture,
                "  {0} stuck session(s) -> {1} distinct peer address(es) to reset", stuck.Count, groups.Count));
            List<Thread> threads = new List<Thread>();
            foreach (RepairGroup g in groups)
            {
                RepairGroup target = g;
                Thread t = new Thread(delegate()
                {
                    try { RepairAddress(target); }
                    catch (Exception ex) { System.Console.WriteLine("  repair threw: " + ex.Message); }
                });
                t.IsBackground = true;
                t.Name = "repair";
                threads.Add(t);
                t.Start();
            }
            foreach (Thread t in threads) { try { t.Join(); } catch { } }
            return 1;
        }
    }

    // ---------------------------------------------------------------- service plumbing
    internal sealed class GuardService : ServiceBase
    {
        private Guard _guard;
        private readonly Config _cfg;
        public GuardService(Config cfg) { _cfg = cfg; ServiceName = Installer.ServiceName; CanShutdown = true; }

        protected override void OnStart(string[] args)
        {
            try
            {
                Log.Info(Log.IdServiceStart, Fmt.Event(
                    "The CSV session guard service started successfully.",
                    new string[] {
                        "Node|" + Environment.MachineName,
                        "Operating mode|" + (_cfg.Repair ? "Repair enabled" : "Detect only - no repair will be attempted"),
                        "Executable|" + Installer.ExePath(),
                    }));

                bool codeDiffers;
                string codeSource = ClusterControlCode.Load(_cfg.LogTimeoutSeconds * 1000, out codeDiffers);
                Log.Info(Log.IdConfig, Fmt.Event(
                    "CSV session guard configuration in effect.",
                    new string[] {
                        "Detection",
                        "Look-back window|" + _cfg.WindowMinutes + " minutes",
                        "Minimum 31013 events|" + _cfg.MinEvents,
                        "Minimum retries on one connection|" + _cfg.MinEventsPerPort,
                        "Minimum loop duration|" + _cfg.MinSpanSeconds + " seconds",
                        "Most recent event within|" + _cfg.RecentSeconds + " seconds",
                        "Sweep interval|" + _cfg.SweepSeconds + " seconds",
                        "Evaluation debounce|" + _cfg.DebounceSeconds + " seconds",
                        "",
                        "Repair",
                        "Repair enabled|" + (_cfg.Repair ? "Yes" : "No"),
                        "Reset scope|" + (_cfg.AllowWholePeer
                            ? "Scoped to the failing peer addresses, falling back to the whole peer if none is known"
                            : "Scoped to the failing peer addresses only; skipped if none is known"),
                        "Repair limit|none; a detected session is always repaired",
                        "Repair gate|one in-flight repair per session, released on verdict",
                        "In-flight failsafe ceiling|" + _cfg.InFlightCeilingSeconds + " seconds",
                        "Repair concurrency|one thread per distinct peer address, dispatched together",
                        "Verification delay|" + _cfg.VerifyDelaySeconds + " seconds",
                        "Verification grace window|" + _cfg.VerifyGraceSeconds + " seconds (0 = count every event after the reset)",
                        "Report closes after|no retry in the " + _cfg.WindowMinutes + "-minute look-back window, confirmed by a check at least " +
                            _cfg.ConfirmSeconds + " seconds after the first check that found none, with the retry event channel enabled",
                        "Reset control code|" + Fsctl.DescribeCode(Fsctl.Code) + "; " + codeSource,
                        "",
                        "Watchdog timeouts",
                        "Event log query|" + _cfg.QueryTimeoutSeconds + " seconds",
                        "Event log write|" + _cfg.LogTimeoutSeconds + " seconds",
                        // This is the timeout on the reset call, not a control code. The old label
                        // said "Disconnect control code" against a value in seconds.
                        "Connection reset call|" + _cfg.FsctlTimeoutSeconds + " seconds"
                    }));
                if (codeDiffers)
                {
                    Log.Warn(Log.IdError, Fmt.Event(
                        "The cluster service uses a different reset control code from the built-in one, so the guard uses the cluster service's code.",
                        new string[] {
                            "Code in use|" + Fsctl.DescribeCode(Fsctl.Code),
                            "Built-in code|" + Fsctl.DescribeCode(Fsctl.BuiltinCode),
                            "Source|" + codeSource,
                            "Node|" + Environment.MachineName
                        }));
                }
                _guard = new Guard(_cfg, "service", true);
                _guard.Start();
            }
            catch (Exception ex) { Log.Exception("OnStart", ex); }
        }

        // Every wait in Guard.Stop is bounded. A blocked FSCTL worker is a background thread and dies
        // with the process, so we never hold up host shutdown waiting on a kernel call.
        protected override void OnStop()
        {
            try { if (_guard != null) { _guard.Stop(); _guard.Dispose(); } }
            catch (Exception ex) { Log.Exception("OnStop", ex); }
            try { Log.Info(Log.IdServiceStop, Fmt.Event(
                "The CSV session guard service stopped.",
                new string[] { "Node|" + Environment.MachineName })); } catch { }
        }

        protected override void OnShutdown() { try { OnStop(); } catch { } }
    }

    // ---------------------------------------------------------------- self-install
    // Direct advapi32 calls, so the exe installs itself with no sc.exe, no PowerShell, no .msi.
    internal static class Installer
    {
        public const string ServiceName = "CsvSessionGuard";
        public const string DisplayName = "CSV SMB Session Guard";

        private const uint SC_MANAGER_ALL = 0xF003F;
        private const uint SERVICE_ALL_ACCESS = 0xF01FF;
        private const uint SERVICE_WIN32_OWN_PROCESS = 0x10;
        private const uint SERVICE_AUTO_START = 0x2;
        private const uint SERVICE_DEMAND_START = 0x3;
        private const uint SERVICE_ERROR_NORMAL = 0x1;
        private const uint SERVICE_CONTROL_STOP = 0x1;
        private const int SERVICE_CONFIG_DESCRIPTION = 1;
        private const int SERVICE_CONFIG_FAILURE_ACTIONS = 2;

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenSCManagerW(string machine, string database, uint access);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateServiceW(IntPtr scm, string name, string display, uint access,
            uint type, uint start, uint error, string binaryPath, string group, IntPtr tagId,
            string deps, string user, string password);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenServiceW(IntPtr scm, string name, uint access);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool StartServiceW(IntPtr svc, int argc, IntPtr argv);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool DeleteService(IntPtr svc);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CloseServiceHandle(IntPtr h);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool ControlService(IntPtr svc, uint control, byte[] status);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool ChangeServiceConfig2W(IntPtr svc, int infoLevel, IntPtr info);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct SERVICE_DESCRIPTION { public string lpDescription; }
        [StructLayout(LayoutKind.Sequential)]
        private struct SC_ACTION { public int Type; public uint Delay; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct SERVICE_FAILURE_ACTIONS
        {
            public uint dwResetPeriod; public string lpRebootMsg; public string lpCommand;
            public int cActions; public IntPtr lpsaActions;
        }

        public static int Install(string[] args)
        {
            Log.RemoveLegacySource();
            string err;
            if (!Log.EnsureSource(out err))
                System.Console.WriteLine("WARNING: could not create the event log source (" + err +
                                         "). The service will fall back to a log file.");
            else
                System.Console.WriteLine("event log '" + Log.LogName + "' source '" + Log.Source + "' ready");

            // -manual  : create the service Manual (demand) instead of Automatic, so a node that
            //            fails while the service is running does not start it again on reboot.
            // -nostart : create the service without starting it, so the first start is deliberate.
            bool manual = false, noStart = false;
            for (int i = 0; i < args.Length; i++)
            {
                if (string.Equals(args[i], "-manual", StringComparison.OrdinalIgnoreCase)) manual = true;
                else if (string.Equals(args[i], "-nostart", StringComparison.OrdinalIgnoreCase)) noStart = true;
            }

            // Rebuild the service command line from everything except the install-time verbs.
            StringBuilder sb = new StringBuilder();
            sb.Append('"'); sb.Append(ExePath()); sb.Append('"');
            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i];
                if (string.Equals(a, "-install", StringComparison.OrdinalIgnoreCase)) continue;
                if (string.Equals(a, "-manual", StringComparison.OrdinalIgnoreCase)) continue;
                if (string.Equals(a, "-nostart", StringComparison.OrdinalIgnoreCase)) continue;
                sb.Append(' ');
                sb.Append(a.IndexOf(' ') >= 0 ? "\"" + a + "\"" : a);
            }
            string binPath = sb.ToString();

            IntPtr scm = IntPtr.Zero, svc = IntPtr.Zero;
            try
            {
                scm = OpenSCManagerW(null, null, SC_MANAGER_ALL);
                if (scm == IntPtr.Zero) { System.Console.WriteLine("OpenSCManager failed, win32=" + Marshal.GetLastWin32Error()); return 5; }

                svc = CreateServiceW(scm, ServiceName, DisplayName, SERVICE_ALL_ACCESS,
                                     SERVICE_WIN32_OWN_PROCESS,
                                     manual ? SERVICE_DEMAND_START : SERVICE_AUTO_START,
                                     SERVICE_ERROR_NORMAL,
                                     binPath, null, IntPtr.Zero, null, null, null);
                if (svc == IntPtr.Zero)
                {
                    int e = Marshal.GetLastWin32Error();
                    if (e == 1073) { System.Console.WriteLine("service already exists - run -uninstall first"); return 6; }
                    System.Console.WriteLine("CreateService failed, win32=" + e); return 5;
                }
                System.Console.WriteLine("service created (" + (manual ? "Manual" : "Automatic") + "): " + binPath);

                SetDescription(svc, "Detects stuck CSV SMB sessions (SMBClient 31013 / 0xC0000016) and, when " +
                                    "repair is enabled, resets the peer's CSV SMB connections with the control code the " +
                                    "cluster service itself uses (built in: " + Fsctl.DescribeCode(Fsctl.BuiltinCode) + "). " +
                                    "Runs locally; no external dependencies.");
                SetRecovery(svc);

                if (noStart) System.Console.WriteLine("not started (-nostart); start it deliberately when ready");
                else if (StartServiceW(svc, 0, IntPtr.Zero)) System.Console.WriteLine("service started");
                else System.Console.WriteLine("service created but did not start, win32=" + Marshal.GetLastWin32Error());
                return 0;
            }
            catch (Exception ex) { System.Console.WriteLine("install failed: " + ex.Message); return 5; }
            finally
            {
                try { if (svc != IntPtr.Zero) CloseServiceHandle(svc); } catch { }
                try { if (scm != IntPtr.Zero) CloseServiceHandle(scm); } catch { }
            }
        }

        private static void SetDescription(IntPtr svc, string text)
        {
            IntPtr p = IntPtr.Zero;
            try
            {
                SERVICE_DESCRIPTION d = new SERVICE_DESCRIPTION();
                d.lpDescription = text;
                p = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SERVICE_DESCRIPTION)));
                Marshal.StructureToPtr(d, p, false);
                ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, p);
            }
            catch { }
            finally { try { if (p != IntPtr.Zero) Marshal.FreeHGlobal(p); } catch { } }
        }

        // Restart after 60s on the first two failures, then every 5 min, with an hourly reset.
        // This is what turns the watchdog's deliberate Environment.Exit into a clean restart.
        private static void SetRecovery(IntPtr svc)
        {
            IntPtr acts = IntPtr.Zero, p = IntPtr.Zero;
            try
            {
                SC_ACTION[] a = new SC_ACTION[3];
                a[0].Type = 1; a[0].Delay = 60000;
                a[1].Type = 1; a[1].Delay = 60000;
                a[2].Type = 1; a[2].Delay = 300000;
                int one = Marshal.SizeOf(typeof(SC_ACTION));
                acts = Marshal.AllocHGlobal(one * a.Length);
                for (int i = 0; i < a.Length; i++)
                    Marshal.StructureToPtr(a[i], new IntPtr(acts.ToInt64() + i * one), false);

                SERVICE_FAILURE_ACTIONS f = new SERVICE_FAILURE_ACTIONS();
                // Reset the failure count HOURLY, not daily. With a daily reset the SCM stops
                // restarting after three failures and the guard stays dead for the rest of the
                // day - the opposite of surviving. Hourly keeps it self-recovering indefinitely
                // while still capping the restart rate at 3/hour.
                f.dwResetPeriod = 3600; f.lpRebootMsg = null; f.lpCommand = null;
                f.cActions = a.Length; f.lpsaActions = acts;
                p = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SERVICE_FAILURE_ACTIONS)));
                Marshal.StructureToPtr(f, p, false);
                if (ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, p))
                    System.Console.WriteLine("recovery set: restart after 60s/60s/300s, failure count reset hourly");
            }
            catch { }
            finally
            {
                try { if (p != IntPtr.Zero) Marshal.FreeHGlobal(p); } catch { }
                try { if (acts != IntPtr.Zero) Marshal.FreeHGlobal(acts); } catch { }
            }
        }

        public static int Uninstall()
        {
            IntPtr scm = IntPtr.Zero, svc = IntPtr.Zero;
            try
            {
                scm = OpenSCManagerW(null, null, SC_MANAGER_ALL);
                if (scm == IntPtr.Zero) { System.Console.WriteLine("OpenSCManager failed, win32=" + Marshal.GetLastWin32Error()); return 5; }
                svc = OpenServiceW(scm, ServiceName, SERVICE_ALL_ACCESS);
                if (svc == IntPtr.Zero) { System.Console.WriteLine("service not installed"); return 0; }
                try { ControlService(svc, SERVICE_CONTROL_STOP, new byte[36]); System.Console.WriteLine("stop requested"); } catch { }
                Thread.Sleep(3000);
                if (DeleteService(svc)) {
                    System.Console.WriteLine("service deleted");
                    Log.RemoveLegacySource();
                    return 0;
                }
                System.Console.WriteLine("DeleteService failed, win32=" + Marshal.GetLastWin32Error());
                return 5;
            }
            catch (Exception ex) { System.Console.WriteLine("uninstall failed: " + ex.Message); return 5; }
            finally
            {
                try { if (svc != IntPtr.Zero) CloseServiceHandle(svc); } catch { }
                try { if (scm != IntPtr.Zero) CloseServiceHandle(scm); } catch { }
            }
        }

        public static string ExePath()
        {
            try { return Process.GetCurrentProcess().MainModule.FileName; }
            catch { try { return System.Reflection.Assembly.GetExecutingAssembly().Location; } catch { return "CsvSessionGuard.exe"; } }
        }
    }

    // ---------------------------------------------------------------- entry point
    internal static class Program
    {
        private static int Main(string[] args)
        {
            try
            {
                AppDomain.CurrentDomain.UnhandledException += OnUnhandled;
            }
            catch { }

            try
            {
                bool has = false;
                string verb = "";
                for (int i = 0; i < args.Length; i++)
                {
                    string a = args[i].ToLowerInvariant();
                    if (a == "-install" || a == "-uninstall" || a == "-console" || a == "-once" ||
                        a == "-selftest" || a == "-help" || a == "-?")
                    { verb = a; has = true; break; }
                }

                string problems;
                Config cfg = Config.Parse(args, out problems);

                if (verb == "-help" || verb == "-?") { Usage(); return 0; }

                // Decide whether the event log is writable without creating anything, so a run
                // before -install cannot auto-register the source against the Application log.
                if (verb != "-install") Log.ProbeSource();
                if (verb == "-selftest") { Log.Console_ = true; return SelfTest.Run(); }
                if (verb == "-install") { if (problems != null) System.Console.WriteLine("ignored arguments: " + problems); return Installer.Install(args); }
                if (verb == "-uninstall") return Installer.Uninstall();

                if (verb == "-once")
                {
                    Log.Console_ = true;
                    if (problems != null) System.Console.WriteLine("ignored arguments: " + problems);
                    bool differs;
                    ClusterControlCode.Load(cfg.LogTimeoutSeconds * 1000, out differs);
                    Guard g = new Guard(cfg, "-once", false);
                    try { return g.RunOnce(); } finally { try { g.Dispose(); } catch { } }
                }

                if (verb == "-console")
                {
                    Log.Console_ = true;
                    if (problems != null) System.Console.WriteLine("ignored arguments: " + problems);
                    System.Console.WriteLine("CsvSessionGuard console mode. " + cfg.Describe());
                    bool differs;
                    string source = ClusterControlCode.Load(cfg.LogTimeoutSeconds * 1000, out differs);
                    System.Console.WriteLine("Reset control code " + Fsctl.DescribeCode(Fsctl.Code) + "; " + source);
                    System.Console.WriteLine("Ctrl+C to stop.");
                    Guard g = new Guard(cfg, "console", false);
                    ManualResetEvent quit = new ManualResetEvent(false);
                    System.Console.CancelKeyPress += delegate(object s, ConsoleCancelEventArgs e)
                    { try { e.Cancel = true; quit.Set(); } catch { } };
                    try { g.Start(); quit.WaitOne(); }
                    finally { try { g.Stop(); g.Dispose(); } catch { } }
                    return 0;
                }

                if (!has)
                {
                    // No verb: SCM launch. Interactive means a mistyped verb.
                    if (Environment.UserInteractive)
                    {
                        System.Console.WriteLine("unrecognised arguments: " + string.Join(" ", args));
                        Usage();
                        return 2;
                    }
                    ServiceBase.Run(new ServiceBase[] { new GuardService(cfg) });
                    return 0;
                }
                Usage();
                return 0;
            }
            catch (Exception ex)
            {
                Log.Exception("Main", ex);
                try { System.Console.WriteLine("fatal: " + ex.Message); } catch { }
                return 9;
            }
        }

        private static void OnUnhandled(object sender, UnhandledExceptionEventArgs e)
        {
            try
            {
                Exception ex = e.ExceptionObject as Exception;
                if (ex != null) Log.Exception("UnhandledException", ex);
                else Log.Err(Log.IdError, Fmt.Event(
                    "An unhandled error that was not an exception object reached the process handler.",
                    new string[] { "Node|" + Environment.MachineName }));
            }
            catch { }
        }

        private static void Usage()
        {
            System.Console.WriteLine("CsvSessionGuard - stuck CSV SMB session detector/repairer (local, no dependencies)");
            System.Console.WriteLine("  -once      [opts]  evaluate once and exit. READ-ONLY unless -repair is given.");
            System.Console.WriteLine("  -console   [opts]  run in the foreground");
            System.Console.WriteLine("  -install   [opts]  create the event log + service, set recovery, and start it");
            System.Console.WriteLine("       -manual       with -install: create it Manual instead of Automatic, so a");
            System.Console.WriteLine("                     node that fails while running does not start it again on boot");
            System.Console.WriteLine("       -nostart      with -install: create it but do not start, so the first");
            System.Console.WriteLine("                     start is deliberate");
            System.Console.WriteLine("  -uninstall         stop and delete the service");
            System.Console.WriteLine("  -selftest          run the built-in checks (no event log, no kernel) and exit");
            System.Console.WriteLine("Options (stored in the service ImagePath, readable with 'sc qc CsvSessionGuard'):");
            System.Console.WriteLine("  -repair            enable repair. WITHOUT THIS THE TOOL ONLY DETECTS.");
            System.Console.WriteLine("  -allowwholepeer    permit the WIDE reset (every CSV connection to the peer) when no");
            System.Console.WriteLine("                     failing peer address is known. Default: skip the repair instead.");
            System.Console.WriteLine("  -window N          31013 look-back, minutes (default 10)");
            System.Console.WriteLine("  -minevents N       events required in the window (default 3, a floor only)");
            System.Console.WriteLine("  -mineventsperport N  retries on ONE connection before acting (default 3, the discriminator)");
            System.Console.WriteLine("  -minspan N         backstop: loop must span this many SECONDS (default 20)");
            System.Console.WriteLine("  -recent N          last event must be within N seconds (default 120)");
            System.Console.WriteLine("  -sweep N           timer cadence, seconds (default 120)");
            System.Console.WriteLine("  -debounce N        minimum gap between evaluations, seconds (default 20)");
            System.Console.WriteLine("  -fsctltimeout N    watchdog on the kernel call, seconds (default 30)");
            System.Console.WriteLine("  -verifydelay N     wait before judging a repair, seconds (default 90, floor 65:");
            System.Console.WriteLine("                     the retry loop is a 60-second timer)");
            System.Console.WriteLine("  -verifygrace N     treat events within N seconds of the reset as in-flight rather");
            System.Console.WriteLine("                     than as retries, seconds (default 0)");
            System.Console.WriteLine("  -heartbeat N       summary cadence, minutes; 0 disables (default 60)");
            System.Console.WriteLine("  -querytimeout N    watchdog on the event-log query, seconds (default 45)");
            System.Console.WriteLine("  -logtimeout N      watchdog on each log write, each state-file read or save, and the");
            System.Console.WriteLine("                     start-up read of clussvc.exe, seconds (default 5)");
            System.Console.WriteLine("Exit codes: 0 clean, 1 stuck session found, 2 unrecognised arguments,");
            System.Console.WriteLine("            3 detection faulted, 4 detection timed out, 9 fatal.");
        }
    }
}












