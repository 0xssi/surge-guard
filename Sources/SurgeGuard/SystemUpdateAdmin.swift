import Foundation
import Darwin
import SurgeGuardCore

enum SystemUpdateAdmin {
    @discardableResult
    static func waitForVerification(_ record: SystemUpdate) throws -> StatusReport {
        let deadline = SystemClock.seconds + 20
        var report = StatusReport.read()
        repeat {
            if record.verified(by: report) { return report }
            usleep(100_000)
            report = StatusReport.read()
        } while SystemClock.seconds < deadline
        throw GuardError("System update \(record.phase.rawValue) is saved but not verified: \(report.state): \(report.reason). Retry the same command; do not assume completion.")
    }

    static func waitForGate(_ record: SystemUpdate) throws {
        let deadline = SystemClock.seconds + 20
        repeat {
            guard record.userID == (try Probe.consoleUID()) else { throw GuardError("Console user changed during maintenance preparation") }
            // Only our installed helper starts as root; it drops privileges before reading user state.
            let response = try Command.checked("/bin/launchctl", ["asuser", String(record.userID), Paths.binary,
                "os-update-gate-probe", String(record.userID), record.id.uuidString], timeout: 5)
            let result = try JSON.decode([String: Bool].self, from: Data(response.utf8))
            if result == ["acknowledged": true], record.userID == (try Probe.consoleUID()) { return }
            usleep(200_000)
        } while SystemClock.seconds < deadline
        throw GuardError("Gate has not acknowledged system update pause. Upgrade/start Gate and settle pending launches or power requests, then retry os-update-begin; protection has not been released. Use os-update-end to cancel preparation.")
    }

    static func begin() throws {
        var record = try SystemUpdate.load()
        if record?.phase == .restoring { throw GuardError("Protection restoration is pending; retry os-update-end") }
        if record == nil {
            let status = StatusReport.read()
            guard status.firewallVerified, status.snapshot?.capabilities?.contains("os_update_v1") == true else {
                throw GuardError("Start the upgraded Guard and verify its PF status before preparing macOS maintenance")
            }
            let uid = try Probe.consoleUID()
            let backup = try Recovery.save(kind: "update")
            try Recovery.validate(backup)
            record = SystemUpdate(userID: uid, backupID: backup.id)
            try record!.save()
            EventLog.write("system_update_preparing", level: "warning", message: "Waiting for Gate before releasing protection", details: ["request_id": record!.id.uuidString])
        }
        guard var record else { throw GuardError("Missing system update maintenance request") }
        if record.phase == .preparing {
            try waitForGate(record)
            try Admin.stop()
            do {
                let lock = try RuntimeLock(timeout: 20)
                defer { withExtendedLifetime(lock) {} }
                record.phase = .active
                try record.save()
                try Firewall().suspendForSystemUpdate()
            }
        }
        try Admin.start()
        try waitForVerification(record)
        EventLog.write("system_update_active", level: "warning", message: "Own disk/live rules verified empty; protection suspended across reboot until explicit os-update-end", details: ["request_id": record.id.uuidString, "backup_id": record.backupID])
        print("VERIFIED MAINTENANCE: SurgeGuard protection is suspended for ALL applications, including across reboots. Complete or cancel macOS updating, then run sudo \(Paths.binary) os-update-end. Surge was not quit; other PF anchors and policy are unchanged.")
    }

    static func end() throws {
        let prepared = try SystemUpdate.prepareRestoration(stop: { try Admin.stop() }, save: { record in
            try record.save()
            EventLog.write("system_update_restoring", message: "Explicitly restoring original protection; Gate remains paused until PF verification", details: ["request_id": record.id.uuidString])
        }, protect: {
            try RootFiles.verify(Policy.anchorPath)
            let anchor = try String(contentsOfFile: Policy.anchorPath)
            guard anchor == Policy.blocked || anchor == SystemUpdate.suspendedAnchor else {
                throw GuardError("Unexpected managed anchor contents; review before restoring protection")
            }
            try RootFiles.write(Policy.blocked, to: Policy.anchorPath, mode: 0o644)
            let firewall = Firewall()
            try firewall.prepareAttachment()
            try firewall.block()
        })
        guard let record = prepared else {
            print("No system update maintenance record. Inspect status for current protection.")
            return
        }
        try Admin.start()
        let report = try waitForVerification(record)
        guard try SystemUpdate.load() == record else { throw GuardError("Maintenance request changed during restoration") }
        try RootFiles.verify(SystemUpdate.path)
        try FileManager.default.removeItem(atPath: SystemUpdate.path)
        EventLog.write("system_update_completed", message: "PF protection verified; original Gate update preference is retained", details: ["request_id": record.id.uuidString, "state": report.state])
        print("Protection restored: \(report.state). A blocked result waits for Surge and the original policy; it is not a networking-success claim. Gate's previous Surge-update pause preference was preserved.")
    }
}
