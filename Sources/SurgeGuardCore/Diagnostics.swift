import Foundation
import Darwin

public enum SystemClock {
    public static var seconds: Double {
        var scale = mach_timebase_info_data_t()
        mach_timebase_info(&scale)
        return Double(mach_continuous_time()) * Double(scale.numer) / Double(scale.denom) / 1_000_000_000
    }

    public static func elapsedSeconds(since start: Double, now: Double) -> Int? {
        guard start.isFinite, now.isFinite, start >= 0, now >= start else { return nil }
        return Int(exactly: (now - start).rounded(.down))
    }

    public static var bootID: String {
        var size = 0
        guard sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) == 0, size > 1 else { return "" }
        var bytes = [CChar](repeating: 0, count: size)
        guard sysctlbyname("kern.bootsessionuuid", &bytes, &size, nil, 0) == 0 else { return "" }
        return String(cString: bytes)
    }
}

public struct GuardSnapshot: Codable {
    public var version = 1
    public var bootId: String
    public var runId: String
    public var pid: Int32
    public var checkedAt: Date
    public var checkedUptime: Double
    public var firewallVerifiedUptime: Double
    public var allowed: Bool
    public var configurationMode: String
    public var readiness: Readiness?
    public var session: SessionObservation?
    public var reasons: [String]
    public var enforcement = "surge_readiness_gate"
    public var lanTcpEnabled: Bool?
    public var lanTcpBindings: [LANTCPBinding]?
    public var usbTcpBindings: [USBTCPBinding]?
    public var localTcpErrors: [String]?
    public var capabilities: [String]? = ["os_update_v1"]
    public var systemUpdateId: UUID?

    public init(runId: String, firewallVerifiedUptime: Double, allowed: Bool, configurationMode: String,
                readiness: Readiness?, session: SessionObservation?, reasons: [String],
                enforcement: String = "surge_readiness_gate", lanTcpEnabled: Bool? = nil, lanTcpBindings: [LANTCPBinding]? = nil,
                systemUpdateId: UUID? = nil, usbTcpBindings: [USBTCPBinding]? = nil, localTcpErrors: [String]? = nil) {
        bootId = SystemClock.bootID
        self.runId = runId
        pid = getpid()
        checkedAt = Date()
        checkedUptime = SystemClock.seconds
        self.firewallVerifiedUptime = firewallVerifiedUptime
        self.allowed = allowed
        self.configurationMode = configurationMode
        self.readiness = readiness
        self.session = session
        self.reasons = reasons
        self.enforcement = enforcement
        // Old readers must reject maintenance instead of reporting its empty rules as blocked.
        version = enforcement == "os_update_maintenance" ? 2 : 1
        self.lanTcpEnabled = lanTcpEnabled
        self.lanTcpBindings = lanTcpBindings
        self.systemUpdateId = systemUpdateId
        self.usbTcpBindings = usbTcpBindings
        self.localTcpErrors = localTcpErrors
    }

    public func fresh(boot: String = SystemClock.bootID, now: Double = SystemClock.seconds) -> Bool {
        !boot.isEmpty && version == (enforcement == "os_update_maintenance" ? 2 : 1) &&
            bootId == boot && checkedUptime <= now && now - checkedUptime < 8 &&
            firewallVerifiedUptime <= now && now - firewallVerifiedUptime < 8
    }
}

public struct StatusReport: Codable {
    public var state: String
    public var daemonRunning: Bool
    public var snapshot: GuardSnapshot?
    public var reason: String
    public var systemUpdate: SystemUpdate?

    public var firewallVerified: Bool {
        daemonRunning && ["allowed", "blocked"].contains(state) && snapshot?.fresh() == true &&
            snapshot?.enforcement != "os_update_maintenance"
    }

    public var maintenanceVerified: Bool {
        daemonRunning && state == "maintenance" && snapshot?.fresh() == true &&
            snapshot?.enforcement == "os_update_maintenance" && systemUpdate?.phase == .active &&
            snapshot?.systemUpdateId == systemUpdate?.id
    }

    public func withSystemUpdate(_ record: SystemUpdate?) -> StatusReport {
        var report = self
        report.systemUpdate = record
        if record?.phase == .active {
            if daemonRunning, snapshot?.fresh() == true, snapshot?.enforcement == "os_update_maintenance",
               snapshot?.systemUpdateId == record?.id, ["allowed", "blocked", "maintenance"].contains(state) {
                report.state = "maintenance"
                report.reason = "system_update_maintenance: protection suspended; all applications may connect directly"
            } else {
                report.state = "unknown"
                report.reason = "system_update_maintenance_unverified: " + reason
            }
        } else if snapshot?.enforcement == "os_update_maintenance" {
            report.state = "unknown"
            report.reason = "system_update_restoration_not_verified"
        }
        return report
    }

    public var stoppedExplanation: String {
        state == "unlocked" ? "已记录本次启动期间的手动解除保护；当前 PF 规则需重新核验" :
            "守护已停止；遗留 PF 规则和当前联网状态未经核验"
    }

    public static func read() -> StatusReport {
        let maintenance: SystemUpdate?
        do { maintenance = try SystemUpdate.load() }
        catch { return StatusReport(state: "unknown", daemonRunning: false, snapshot: nil, reason: "system_update_invalid: \(error)") }
        let service: CommandResult
        let serviceRunning: Bool
        do {
            service = try Command.run("/bin/launchctl", ["print", "system/" + Paths.label])
            serviceRunning = try self.serviceRunning(service)
        } catch {
            return StatusReport(state: "unknown", daemonRunning: false, snapshot: nil, reason: "service_query_failed: \(error)").withSystemUpdate(maintenance)
        }
        if maintenance == nil, !serviceRunning, let marker = try? readUnlockMarker(), marker == SystemClock.bootID, !marker.isEmpty {
            return StatusReport(state: "unlocked", daemonRunning: false, snapshot: nil, reason: "manual_unlock_until_start_or_reboot")
        }
        do {
            try RootFiles.verify(Paths.publicState, directory: true)
            try RootFiles.verify(Paths.snapshot)
            let snapshot = try JSON.decode(GuardSnapshot.self, from: Data(contentsOf: URL(fileURLWithPath: Paths.snapshot)))
            return diagnoseConfiguration(try evaluate(service: service, snapshot: snapshot).withSystemUpdate(maintenance))
        } catch {
            return diagnoseConfiguration(StatusReport(state: "unknown", daemonRunning: serviceRunning, snapshot: nil, reason: "status_unavailable: \(error)").withSystemUpdate(maintenance))
        }
    }

    private static func diagnoseConfiguration(_ report: StatusReport) -> StatusReport {
        guard report.systemUpdate == nil, ["unknown", "stopped"].contains(report.state),
              (try? RootFiles.verify(Paths.pfConfig)) != nil,
              let file = try? FileHandle(forReadingFrom: URL(fileURLWithPath: Paths.pfConfig)) else { return report }
        defer { try? file.close() }
        guard let data = try? file.read(upToCount: 65_537), data.count <= 65_536,
              let config = String(data: data, encoding: .utf8) else { return report }
        return report.diagnosingConfiguration(config)
    }

    public func diagnosingConfiguration(_ config: String) -> StatusReport {
        guard ["unknown", "stopped"].contains(state) else { return self }
        var result = self
        do {
            let base = try Policy.removingAttachment(from: config)
            if base == config {
                result.reason = "pf_attachment_missing: managed disk configuration is missing; " + reason
            }
        } catch {
            result.reason = "pf_attachment_invalid: \(error); " + reason
        }
        return result
    }

    public static func evaluate(service: CommandResult, snapshot: GuardSnapshot) throws -> StatusReport {
        guard let pid = try servicePID(service) else {
            return StatusReport(state: "stopped", daemonRunning: false, snapshot: snapshot, reason: "daemon_not_running")
        }
        guard pid == snapshot.pid else {
            return StatusReport(state: "unknown", daemonRunning: true, snapshot: snapshot, reason: "status_process_mismatch")
        }
        guard snapshot.fresh() else {
            return StatusReport(state: "unknown", daemonRunning: true, snapshot: snapshot, reason: "status_or_pf_audit_expired")
        }
        return StatusReport(state: snapshot.allowed ? "allowed" : "blocked", daemonRunning: true,
                            snapshot: snapshot, reason: snapshot.reasons.joined(separator: "; "))
    }

    public static func serviceLoaded(_ service: CommandResult) throws -> Bool {
        _ = try serviceRunning(service)
        return service.status == 0
    }

    public static func serviceRunning(_ service: CommandResult, pid: Int32? = nil) throws -> Bool {
        guard let actual = try servicePID(service) else { return false }
        return pid.map { $0 == actual } ?? true
    }

    public static func servicePID(_ service: CommandResult) throws -> Int32? {
        guard service.status == 0 else {
            if service.status == 113 && service.combined.contains("Could not find service") { return nil }
            throw GuardError("launchctl status \(service.status): \(service.combined.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
        let lines = service.output.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
        let states = lines.filter { $0.hasPrefix("state = ") }
        guard states.count == 1, states[0].count > "state = ".count else { throw GuardError("Service has no unique state") }
        guard states[0] == "state = running" else { return nil }
        let pids = lines.filter { $0.hasPrefix("pid = ") }
        guard pids.count == 1, let pid = Int32(pids[0].dropFirst(6)), pid > 1 else {
            throw GuardError("Running service has no unique valid PID")
        }
        return pid
    }

    private static func readUnlockMarker() throws -> String {
        try RootFiles.verify(Paths.publicState, directory: true)
        try RootFiles.verify(Paths.unlockMarker)
        let data = try Data(contentsOf: URL(fileURLWithPath: Paths.unlockMarker))
        let object = try JSONSerialization.jsonObject(with: data) as? [String: String]
        return object?["boot_id"] ?? ""
    }
}

public enum EventLog {
    public static func write(_ event: String, level: String = "info", message: String, details: [String: Any] = [:]) {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let timestamp = formatter.string(from: Date())
        let record: [String: Any] = ["time": timestamp, "component": "SurgeGuard", "level": level, "event": event,
                                     "pid": getpid(), "boot_id": SystemClock.bootID, "monotonic_uptime": SystemClock.seconds,
                                     "message": message, "details": details]
        guard let data = try? JSONSerialization.data(withJSONObject: record, options: [.sortedKeys, .withoutEscapingSlashes]) else { return }
        let line = String(decoding: data, as: UTF8.self) + "\n"
        NSLog("surge-guard: %@", line)
        guard geteuid() == 0 else { return }
        do {
            try RootFiles.prepareRuntime()
            try EventFile.append(data, to: Paths.eventsLog, owner: 0, lockPath: Paths.runtime + "/events.lock")
        } catch { NSLog("surge-guard: LOGGING ERROR: %@", String(describing: error)) }
    }
}
