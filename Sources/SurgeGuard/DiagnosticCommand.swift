import Foundation
import Darwin
import SurgeGuardCore

enum DiagnosticCommand {
    static func run(_ arguments: [String]) throws {
        let options = try DiagnosticOptions(arguments)
        guard geteuid() != 0 else { throw GuardError("Run diagnose as your normal user; only fixed private-log reads use sudo") }
        try UserPaths.prepare()
        let lock: Int32
        do { lock = try UserPaths.lock(at: UserPaths.directory + "/diagnostic.lock") }
        catch { throw GuardError("Cannot acquire diagnostic writer lock; another collection may be active: \(error)") }
        defer { close(lock) }
        var report = DiagnosticReport(minutes: options.minutes)
        collectSnapshots(into: &report, stage: "start")
        for suffix in [".1", ""] {
            let source = "guard_events" + suffix
            do {
                // The user-owned collector/formatter never runs as root.
                let result = try Command.run("/usr/bin/sudo", ["-n", "/usr/bin/tail", "-c", "1048577", Paths.eventsLog + suffix], timeout: 3)
                guard result.status == 0 else { throw GuardError(result.diagnostics) }
                let (text, partial) = try DiagnosticReport.boundedTail(result.outputData)
                report.ingest(text, source: source, jsonLines: true, tailOnly: partial)
            } catch { report.unavailable(source, error: "\(error); private logs may require sudo authentication") }
            do {
                guard let data = try UserPaths.readPrivate(UserPaths.log + suffix, maximumBytes: Int64(DiagnosticReport.maximumInputBytes)) else {
                    throw GuardError("event_file_not_retained")
                }
                report.ingest(String(decoding: data, as: UTF8.self), source: "gate_events" + suffix, jsonLines: true)
            } catch { report.unavailable("gate_events" + suffix, error: String(describing: error)) }
        }
        let logs = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/Surge")
        do {
            let files = try FileManager.default.contentsOfDirectory(atPath: logs.path)
                .filter { $0.hasPrefix("Surge-") && $0.hasSuffix(".log") }.sorted().suffix(4)
            if files.isEmpty { report.unavailable("surge_files", error: "no_retained_surge_logs") }
            for name in files {
                do {
                    let (text, partial) = try DiagnosticReport.readTail(logs.appendingPathComponent(name).path)
                    report.ingest(text, source: name, jsonLines: false, tailOnly: partial)
                } catch { report.unavailable(name, error: String(describing: error)) }
            }
        } catch { report.unavailable("surge_files", error: String(describing: error)) }
        if options.watchSeconds > 0 {
            fputs("Read-only diagnostic window: \(options.watchSeconds)s; private checkpoints: \(DiagnosticReport.path); no PF/DNS changes.\n", stderr)
            let deadline = SystemClock.seconds + Double(options.watchSeconds)
            try report.save()
            var nextCheckpoint = SystemClock.seconds + 10
            repeat {
                do {
                    guard getuid() == (try Probe.consoleUID()), try Probe.trustedSurgePID() != nil else {
                        throw GuardError("No verified Surge process in the current user session")
                    }
                    let remaining = deadline - SystemClock.seconds
                    if remaining <= 0 { break }
                    let output = try Command.checked(Probe.surgeCLI, ["--raw", "log", "memory", "2000"], timeout: min(2, remaining))
                    try report.ingestMemory(output)
                } catch { report.unavailable("surge_memory", error: String(describing: error)) }
                if SystemClock.seconds >= nextCheckpoint {
                    try report.save(rotatePrevious: false)
                    nextCheckpoint = SystemClock.seconds + 10
                }
                let remaining = deadline - SystemClock.seconds
                if remaining > 0 { Thread.sleep(forTimeInterval: min(2, remaining)) }
            } while SystemClock.seconds < deadline
            collectSnapshots(into: &report, stage: "end")
        }
        report.finish()
        try report.save(rotatePrevious: options.watchSeconds == 0)
        print(options.json ? try report.encoded() : report.render() + "\n私有报告：" + DiagnosticReport.path)
    }

    private static func collectSnapshots(into report: inout DiagnosticReport, stage: String) {
        var snapshots: [String: Any] = [:]
        func object(_ text: String) throws -> [String: Any] {
            guard text.utf8.count <= 65_536,
                  let value = try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else {
                throw GuardError("Invalid or oversized diagnostic status")
            }
            return value
        }
        do { snapshots["guard"] = try object(JSON.encode(StatusReport.read())) }
        catch { report.unavailable("guard_" + stage, error: String(describing: error)) }
        for (source, binary, arguments) in [
            ("gate", UserPaths.binary, ["status", "--json"]),
            ("packet_audit", PacketAudit.binary, ["audit-status", "--json"])
        ] {
            do { snapshots[source] = try object(Command.checked(binary, arguments, timeout: 3)) }
            catch { report.unavailable(source + "_" + stage, error: String(describing: error)) }
        }
        do {
            guard getuid() == (try Probe.consoleUID()), let pid = try Probe.trustedSurgePID(),
                  let identity = try SurgeProcess.read(pid: pid) else {
                throw GuardError("No verified Surge process in the current user session")
            }
            var status = try object(Command.checked(Probe.surgeCLI, ["--raw", "status"]))
            guard try Probe.trustedSurgePID() == pid, try SurgeProcess.read(pid: pid) == identity else {
                throw GuardError("Surge process changed during diagnostic status query")
            }
            status["observed_process"] = try object(JSON.encode(identity))
            snapshots["surge"] = status
        } catch { report.unavailable("surge_" + stage, error: String(describing: error)) }
        report.snapshots[stage] = snapshots
    }
}
