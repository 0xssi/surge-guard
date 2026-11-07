import Foundation
import Darwin
import SurgeGuardCore

final class PacketAuditService {
    let task = Process()
    let pipe: Pipe
    let lock: RuntimeLock
    var snapshot: PacketAuditSnapshot
    var statistics = PacketCaptureStatistics()
    var listening = false
    var captureReadyUptime: Double?
    var stopping = false
    var failed = false
    var stopDeadline: Double = 0
    var lastGuard = ""
    var lastAuditState = ""
    var queryingSurge = false
    var surgeHistory = SurgeRequestAuditHistory()
    var surgeFailure = ""
    var nextSurgeFailureLog: Double = 0
    var timer: Timer?
    var signals: [DispatchSourceSignal] = []

    init() throws {
        try PacketAudit.prepare()
        try RootFiles.preparePublicState()
        let configuration = try PacketAuditConfiguration.load()
        snapshot = PacketAuditSnapshot(capacityMegabytes: configuration.capacityMegabytes)
        snapshot.timeZone = configuration.timeZone
        let fd = open(PacketAudit.directory + "/capture.lock", O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600)
        lock = try RuntimeLock(taking: fd)
        try RootFiles.verify(PacketAudit.directory + "/capture.lock")
        pipe = Pipe()
    }

    deinit { try? pipe.fileHandleForReading.close(); try? pipe.fileHandleForWriting.close() }

    func publish() throws {
        snapshot.checkedAt = Date()
        snapshot.checkedUptime = SystemClock.seconds
        try RootFiles.write(try JSON.encode(snapshot), to: PacketAudit.snapshot, mode: 0o644)
    }

    func event(_ name: String, _ message: String, _ details: [String: Any] = [:]) throws {
        var details = details
        details["run_id"] = snapshot.runId
        try PacketAudit.event(name, message: message, details: details, timeZone: snapshot.timeZone)
    }

    func fail(_ error: Error) {
        guard !failed else { return }
        failed = true
        snapshot.captureHistoryHasGaps = true
        snapshot.state = "incomplete"
        snapshot.reason = String(describing: error)
        NSLog("surge-guard packet audit incomplete: %@", snapshot.reason)
        try? event("audit_capture_failed", snapshot.reason)
        try? publish()
        stop()
    }

    func stop() {
        guard !stopping else { return }
        stopping = true
        stopDeadline = SystemClock.seconds + 3
        if !failed {
            snapshot.state = "stopping"
            snapshot.reason = "capture_stopping; subsequent_coverage_unavailable"
            do { try event("audit_stop_requested", snapshot.reason); try publish() }
            catch { failed = true; snapshot.state = "incomplete" }
        }
        if task.isRunning { kill(task.processIdentifier, SIGTERM) }
    }

    func ingest(_ line: String) throws {
        let numericCounter = UInt64(line.split(separator: " ").first ?? "") != nil &&
            ["packets captured", "packets received by filter", "packets dropped by kernel",
             "packet captured", "packet received by filter", "packet dropped by kernel"].contains(where: { line.hasSuffix($0) })
        if line.contains("listening on"), line.contains("PKTAP") {
            listening = true
            captureReadyUptime = SystemClock.seconds
            snapshot.captureReadyAt = Date()
            try event("audit_capture_ready", "PKTAP capture opened; attribution and end-to-end completeness remain unverified")
        }
        if let counters = statistics.consume(line) {
            let previous = snapshot.counters
            if let previous, !counters.follows(previous) {
                snapshot.captureHistoryHasGaps = true
                try event("audit_capture_statistics_reset", "Capture counters decreased or wrapped; prior statistical continuity is unverified, packet recording continues",
                          ["previous_counters": try JSONSerialization.jsonObject(with: Data(JSON.encode(previous).utf8)),
                           "current_counters": try JSONSerialization.jsonObject(with: Data(JSON.encode(counters).utf8))])
            }
            snapshot.counters = counters
            snapshot.countersUptime = SystemClock.seconds
            if counters.droppedByKernel > (previous?.droppedByKernel ?? 0) {
                snapshot.captureHistoryHasGaps = true
                snapshot.reason = "kernel_capture_drops"
                try event("audit_capture_drops", "Kernel capture buffer reported dropped packets; this interval is incomplete",
                          ["dropped_by_kernel": counters.droppedByKernel])
            }
        } else if line.hasSuffix("packets dropped by interface"), let count = UInt64(line.split(separator: " ").first ?? "") {
            let previous = snapshot.droppedByInterface ?? 0
            snapshot.droppedByInterface = count
            if count > previous {
                snapshot.captureHistoryHasGaps = true
                try event("audit_capture_drops", "Interface reported dropped packets", ["dropped_by_interface": count])
            }
        } else if !line.isEmpty, !line.contains("listening on"), !line.contains("data link type"),
                  !numericCounter {
            // Unknown tool diagnostics are evidence, not silently discarded capture success.
            try event("audit_capture_diagnostic", line)
        }
    }

    func tick() throws {
        let now = SystemClock.seconds
        if stopping {
            if task.isRunning, now >= stopDeadline {
                failed = true
                snapshot.state = "incomplete"
                snapshot.reason = "capture_stop_timeout"
                kill(task.processIdentifier, SIGKILL)
            }
            return
        }
        if task.isRunning, listening { kill(task.processIdentifier, SIGINFO) }
        if listening, let checked = snapshot.countersUptime, now >= checked, now - checked < 10 {
            snapshot.state = (snapshot.counters?.droppedByKernel ?? 0) == 0 && (snapshot.droppedByInterface ?? 0) == 0 ? "capturing" : "incomplete"
            snapshot.reason = snapshot.state == "capturing" ? "capture_running; packet_path_attribution_unverified" : "capture_drops_reported"
        } else {
            snapshot.state = "incomplete"
            snapshot.reason = listening ? "capture_statistics_unavailable" : "waiting_for_pktap_capture"
            if let ready = captureReadyUptime, now - ready >= 10 { snapshot.captureHistoryHasGaps = true }
        }
        let guardReport = StatusReport.read()
        snapshot.guardState = guardReport.firewallVerified || guardReport.maintenanceVerified ? guardReport.state : "unknown"
        snapshot.guardRunId = guardReport.snapshot?.runId
        snapshot.guardCheckedUptime = guardReport.snapshot?.checkedUptime
        querySurgeRequests()
        if let checked = snapshot.surgeRequestsUptime, now - checked >= 8 { snapshot.surgeRequestsState = "stale" }
        let guardKey = snapshot.guardState + "|" + (snapshot.guardRunId ?? "")
        if guardKey != lastGuard {
            try event("audit_guard_state", "Guard status at audit observation; not a per-packet decision",
                      ["guard_state": snapshot.guardState, "guard_run_id": snapshot.guardRunId ?? "unknown",
                       "guard_checked_uptime": snapshot.guardCheckedUptime ?? 0])
            lastGuard = guardKey
        }
        let stateKey = snapshot.state + "|" + snapshot.reason
        if stateKey != lastAuditState {
            try event("audit_state_changed", snapshot.reason, ["state": snapshot.state, "no_bypass_verified": false])
            lastAuditState = stateKey
        }
        try publish()
    }

    func querySurgeRequests() {
        guard !queryingSurge else { return }
        queryingSurge = true
        DispatchQueue.global(qos: .utility).async {
            let result = Result { () throws -> SurgeRequestAuditBatch in
                let uid = try Probe.consoleUID()
                try RootFiles.verify(PacketAudit.binary)
                let response = try Command.checked("/bin/launchctl", ["asuser", String(uid), PacketAudit.binary,
                                                    "audit-request-probe", String(uid)], timeout: 8)
                guard uid == (try Probe.consoleUID()) else { throw GuardError("Console user changed during request audit") }
                return try JSON.decode(SurgeRequestAuditBatch.self, from: Data(response.utf8))
            }
            DispatchQueue.main.async {
                self.queryingSurge = false
                guard !self.stopping else { return }
                do {
                    switch result {
                    case .failure(let error):
                        let reason = String(describing: error)
                        self.snapshot.surgeRequestsState = "unavailable"
                        self.snapshot.surgeHistoryHasGaps = true
                        if self.surgeFailure.isEmpty || SystemClock.seconds >= self.nextSurgeFailureLog {
                            try self.event("audit_surge_unavailable", reason)
                            self.nextSurgeFailureLog = SystemClock.seconds + 300
                        }
                        self.surgeFailure = reason
                    case .success(let batch):
                        if !self.surgeFailure.isEmpty { try self.event("audit_surge_recovered", "Surge request queries recovered; prior gaps remain unverified") }
                        self.surgeFailure = ""
                        self.snapshot.surgeRequestsState = "recording"
                        self.snapshot.surgeRequestsUptime = batch.queryCompletedUptime
                        let changes = self.surgeHistory.changes(batch)
                        self.snapshot.recentRequestWindowOverlap = self.surgeHistory.recentWindowOverlap
                        if self.surgeHistory.recentWindowOverlap.hasPrefix("missing") || self.surgeHistory.recentWindowOverlap == "surge_process_changed" {
                            self.snapshot.surgeHistoryHasGaps = true
                            try self.event("audit_surge_history_gap", self.surgeHistory.recentWindowOverlap,
                                           ["surge_pid": batch.surgePid, "query_started_uptime": batch.queryStartedUptime])
                        }
                        try RootFiles.write(try JSON.encode(batch), to: PacketAudit.requestSnapshot)
                        for request in changes {
                            let timestamp = ISO8601DateFormatter(); timestamp.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
                            let record: [String: Any] = ["time": timestamp.string(from: Date()), "display_time_zone": self.snapshot.timeZone,
                                "component": "PacketAudit", "event": "audit_surge_request",
                                "pid": getpid(), "boot_id": SystemClock.bootID, "monotonic_uptime": SystemClock.seconds,
                                "details": ["run_id": self.snapshot.runId, "surge_pid": batch.surgePid,
                                            "query_started_uptime": batch.queryStartedUptime, "query_completed_uptime": batch.queryCompletedUptime,
                                            "byte_counts": "lifetime_at_observation; not_per_interval",
                                            "request": try JSONSerialization.jsonObject(with: Data(JSON.encode(request).utf8))]]
                            let data = try JSONSerialization.data(withJSONObject: record, options: [.sortedKeys, .withoutEscapingSlashes])
                            try EventFile.append(data, to: PacketAudit.requests, owner: 0, lockPath: PacketAudit.directory + "/requests.lock")
                        }
                    }
                    try self.publish()
                } catch { self.fail(error) }
            }
        }
    }

    func finish() {
        snapshot.state = failed || !stopping || task.terminationStatus != 0 ? "incomplete" : "stopped"
        snapshot.reason = snapshot.state == "stopped" ? "capture_stopped; subsequent_traffic_not_recorded" : "capture_exited_or_failed"
        try? event("audit_capture_stopped", snapshot.reason, ["exit_status": task.terminationStatus, "state": snapshot.state,
                   "counters": (try? JSON.encode(snapshot.counters)) ?? "null", "coverage_after_exit": "unavailable"])
        try? publish()
        exit(snapshot.state == "stopped" ? 0 : 1)
    }

    func run() throws {
        umask(0o077)
        guard getpgrp() == getpid() else { throw GuardError("Packet audit requires its own supervisor process group") }
        snapshot.processGroup = getpgrp()
        guard let identity = try SurgeProcess.read(pid: getpid()) else { throw GuardError("Cannot identify audit supervisor") }
        snapshot.supervisorIdentity = identity
        if let previous = try? String(contentsOfFile: PacketAudit.snapshot) {
            try event("audit_capture_gap", "New capture session; traffic between sessions and overwritten history cannot be reconstructed",
                      ["previous_snapshot": String(previous.prefix(8192))])
        }
        try event("audit_capture_started", "Starting continuous all-interface packet capture; never a no-bypass certificate",
                  ["capacity_megabytes": snapshot.capacityMegabytes, "snapshot_bytes": 256, "scope": "pktap,all",
                   "retention": snapshot.retention, "payload_note": "first 256 captured bytes may include payload"])
        try publish()
        try RootFiles.verify(PacketAudit.binary)
        task.executableURL = URL(fileURLWithPath: PacketAudit.binary)
        task.arguments = ["audit-capture"]
        task.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "LANG": "C"]
        task.standardInput = FileHandle.nullDevice
        task.standardOutput = FileHandle.nullDevice
        task.standardError = pipe
        do { try task.run() }
        catch {
            try? pipe.fileHandleForWriting.close(); try? pipe.fileHandleForReading.close()
            fail(error)
            throw error
        }
        pipe.fileHandleForWriting.closeFile()
        snapshot.capturePid = task.processIdentifier
        do { try publish() } catch { fail(error) }
        DispatchQueue.global(qos: .utility).async {
            do {
                try PacketAudit.readDiagnostics(self.pipe.fileHandleForReading) { line in
                    // Backpressure bounds both pipe data and main-queue work.
                    try DispatchQueue.main.sync { try self.ingest(line) }
                }
            } catch { DispatchQueue.main.sync { self.fail(error) } }
            try? self.pipe.fileHandleForReading.close()
            self.task.waitUntilExit()
            DispatchQueue.main.async { self.finish() }
        }
        for number in [SIGTERM, SIGINT] {
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: .main)
            source.setEventHandler { self.stop() }
            source.resume()
            signals.append(source)
        }
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in
            do { try self.tick() } catch { self.fail(error) }
        }
        CFRunLoopRun()
    }
}
