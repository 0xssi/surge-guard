import Foundation
import SurgeGuardCore
import Darwin

enum Admin {
    static var plist: String { """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0"><dict>
      <key>Label</key><string>\(Paths.label)</string>
      <key>ProgramArguments</key><array><string>\(Paths.binary)</string><string>run</string></array>
      <key>RunAtLoad</key><true/>
      <key>KeepAlive</key><true/>
      <key>ThrottleInterval</key><integer>3</integer>
      <key>Umask</key><integer>63</integer>
    </dict></plist>

    """ }

    static func loaded() throws -> Bool {
        let result = try Command.run("/bin/launchctl", ["print", "system/" + Paths.label])
        return try StatusReport.serviceLoaded(result)
    }

    static func prepareDedicatedGroup() throws {
        try RootFiles.prepareRuntime()
        try RootFiles.verify(DedicatedEgress.launcher)
        let gid: gid_t
        if let existing = getgrnam(DedicatedEgress.groupName) {
            gid = existing.pointee.gr_gid
            try RootFiles.verify(DedicatedEgress.groupRecord)
            let record = try JSON.decode([String: UInt32].self, from: Data(contentsOf: URL(fileURLWithPath: DedicatedEgress.groupRecord)))
            guard record == ["gid": gid], (60_000...60_999).contains(gid), existing.pointee.gr_mem.pointee == nil else {
                throw GuardError("Existing dedicated group does not match the protected installation record")
            }
        } else {
            var record: [String: UInt32]?
            var info = stat()
            if lstat(DedicatedEgress.groupRecord, &info) == 0 {
                try RootFiles.verify(DedicatedEgress.groupRecord)
                record = try JSON.decode([String: UInt32].self, from: Data(contentsOf: URL(fileURLWithPath: DedicatedEgress.groupRecord)))
            } else if errno != ENOENT { throw GuardError("Cannot inspect dedicated group record") }
            gid = try DedicatedEgress.availableGroup(record: record, occupied: { getgrgid($0) != nil })
            // Reserve the identity before directory-service mutation so interrupted installation can retry.
            try RootFiles.write(try JSON.encode(["gid": gid]), to: DedicatedEgress.groupRecord)
            try Command.checked("/usr/sbin/dseditgroup", ["-o", "create", "-i", String(gid),
                                                         "-r", "Surge Guard dedicated TCP egress", DedicatedEgress.groupName], timeout: 10)
        }
        guard chown(DedicatedEgress.launcher, 0, gid) == 0, chmod(DedicatedEgress.launcher, 0o2755) == 0 else {
            throw GuardError("Cannot set dedicated launcher group/permissions")
        }
        _ = try DedicatedEgress.group()
    }

    static func install() throws {
        let upgrading = try loaded()
        for path in ["/Library/PrivilegedHelperTools", "/Library/LaunchDaemons", "/private/etc", "/private/etc/pf.anchors"] {
            if !FileManager.default.fileExists(atPath: path) {
                try RootFiles.verify(URL(fileURLWithPath: path).deletingLastPathComponent().path, directory: true)
                try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: false,
                                                        attributes: [.posixPermissions: 0o755])
            }
            try RootFiles.verify(path, directory: true)
        }
        try RootFiles.verify(Paths.pfConfig)
        let original = try String(contentsOfFile: Paths.pfConfig)
        let updated = try Policy.attaching(to: original)
        try RootFiles.preparePublicState()
        let configuration = try Configuration.forInstallation()
        // A signed/compiled source executable may be user-owned; it is copied
        // once into the protected system path. No root-executed user script.
        let source = URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL.resolvingSymlinksInPath().path
        let launcherSource = URL(fileURLWithPath: source).deletingLastPathComponent().appendingPathComponent("surge-guard-launch").path
        guard FileManager.default.isExecutableFile(atPath: launcherSource) else { throw GuardError("Build surge-guard-launch before installing") }
        guard source != Paths.binary else { throw GuardError("Install using the freshly built binary, not the installed copy") }
        var existing = stat()
        if lstat(Paths.binary, &existing) == 0 { try RootFiles.verify(Paths.binary) }
        try Command.checked("/sbin/pfctl", ["-n", "-f", "-"], input: Policy.installationPreview(updated))
        let stagedBinary = Paths.binary + ".new." + UUID().uuidString
        try Command.checked("/usr/bin/install", ["-o", "root", "-g", "wheel", "-m", "755", source, stagedBinary])
        defer { try? FileManager.default.removeItem(atPath: stagedBinary) }
        if upgrading, let config = try? Configuration.load(), config.mode == "routes" {
            // Verify the new privilege-drop/CLI path before stopping the old gate.
            _ = try Probe.privilegedSession(configuration: config, helperPath: stagedBinary)
            EventLog.write("upgrade_probe_verified", message: "New user-session probe succeeded before service replacement")
        }
        let backup = FileManager.default.fileExists(atPath: Paths.binary) ? try Recovery.save(kind: "update") : nil
        if let backup { try Recovery.validate(backup) }
        let expectAllowed = try CLI.check(configuration: configuration, helperPath: stagedBinary).ready
        do {
            if upgrading { try stop() }
            do {
                let lock = try RuntimeLock(timeout: 20)
                defer { withExtendedLifetime(lock) {} }
                if upgrading {
                    let firewall = Firewall()
                    try firewall.prepareAttachment()
                    try firewall.block()
                }
                try RootFiles.write(Policy.blocked, to: Policy.anchorPath, mode: 0o644)
                let backup = Paths.pfConfig + ".surge-guard.backup"
                if !FileManager.default.fileExists(atPath: backup) { try RootFiles.write(original, to: backup) }
                guard rename(stagedBinary, Paths.binary) == 0 else { throw GuardError("Cannot atomically replace installed binary") }
                let stagedLauncher = DedicatedEgress.launcher + ".new." + UUID().uuidString
                defer { try? FileManager.default.removeItem(atPath: stagedLauncher) }
                try Command.checked("/usr/bin/install", ["-o", "root", "-g", "wheel", "-m", "755", launcherSource, stagedLauncher])
                if FileManager.default.fileExists(atPath: DedicatedEgress.launcher) { try RootFiles.verify(DedicatedEgress.launcher) }
                guard rename(stagedLauncher, DedicatedEgress.launcher) == 0 else { throw GuardError("Cannot install Surge launcher") }
                try prepareDedicatedGroup()
                try RootFiles.write(updated, to: Paths.pfConfig, mode: 0o644)
                try RootFiles.write(plist, to: Paths.plist, mode: 0o644)
                if !FileManager.default.fileExists(atPath: Paths.configuration) {
                    try RootFiles.write(try configuration.encoded(), to: Paths.configuration, mode: 0o644)
                }
            }
            if upgrading {
                try start()
                try waitForStatus(expectAllowed: expectAllowed)
            }
        } catch {
            let failure = String(describing: error)
            EventLog.write("upgrade_failed", level: "error", message: failure)
            if let backup {
                do {
                    try restore(backup, startService: upgrading)
                    EventLog.write("rollback_completed", level: "warning", message: "Upgrade failed; previous files and service state restored", details: ["backup_id": backup.id])
                } catch {
                    // Report rollback failures separately; never silently unlock.
                    EventLog.write("rollback_failed", level: "critical", message: "\(error)", details: ["backup_id": backup.id])
                    throw GuardError("Upgrade failed: \(failure). Rollback failed: \(error). Use SwiftBar → Emergency recovery → Temporarily remove block.")
                }
                throw GuardError("Upgrade failed: \(failure). Previous files\(upgrading ? " and service" : "") restored. Inspect logs before retrying.")
            }
            throw error
        }
        EventLog.write(upgrading ? "installation_updated" : "installation_created", message: "Root components installed; existing policy retained")
        print(upgrading ? "Updated and restarted. Verify status." : "Installed. Start with: sudo \(Paths.binary) start")
        print("Recovery is available offline in SwiftBar. Previous files: \(backup.map { Paths.backups + "/" + $0.id } ?? "no previous installation")")
    }

    static func stop() throws {
        if try loaded() { try Command.checked("/bin/launchctl", ["bootout", "system/" + Paths.label], timeout: 15) }
        // bootout can return before TERM cleanup releases the daemon's flock.
        let lock = try RuntimeLock(timeout: 20)
        defer { withExtendedLifetime(lock) {} }
        guard try !loaded() else { throw GuardError("Surge Guard service is still loaded") }
    }

    static func waitForStatus(expectAllowed: Bool = false, previousPID: Int32? = nil) throws {
        let deadline = SystemClock.seconds + 20
        var last = StatusReport.read()
        while SystemClock.seconds < deadline {
            last = StatusReport.read()
            if let snapshot = last.snapshot, snapshot.pid != previousPID,
               ["allowed", "blocked"].contains(last.state), !expectAllowed || last.state == "allowed" {
                print("Verified: \(last.state.uppercased()), pid=\(snapshot.pid)\(last.reason.isEmpty ? "" : ", " + last.reason)")
                return
            }
            usleep(200_000)
        }
        throw GuardError("Service did not reach verified \(expectAllowed ? "ALLOWED" : "PF status") within 20s: \(last.state) \(last.reason)")
    }

    static func restore(_ backup: BackupManifest, startService: Bool = true) throws {
        try Recovery.validate(backup) // Refuse a damaged backup before stopping anything.
        try stop()
        do {
            let lock = try RuntimeLock(timeout: 20)
            defer { withExtendedLifetime(lock) {} }
            try Recovery.restore(backup)
        }
        if startService {
            try start()
            let help = try Command.checked(Paths.binary, ["--help"])
            if help.contains("swiftbar") { try waitForStatus() }
            else {
                let deadline = SystemClock.seconds + 20
                let firewall = Firewall()
                while SystemClock.seconds < deadline {
                    if try loaded(), try firewall.attached(), try firewall.enabled() {
                        let rules = try firewall.readRules().trimmingCharacters(in: .whitespacesAndNewlines)
                        if try Probe.readiness().ready ? rules.isEmpty : rules.contains("surge-guard-block") {
                            print("Previous legacy service and PF recovered. WARNING: this version has no routing gate; verify its capabilities.")
                            return
                        }
                    }
                    usleep(200_000)
                }
                throw GuardError("Previous legacy service did not recover verified PF within 20s")
            }
        }
    }

    static func start() throws {
        let service = try Command.run("/bin/launchctl", ["print", "system/" + Paths.label])
        if try StatusReport.serviceLoaded(service) {
            if try !StatusReport.serviceRunning(service) {
                try Command.checked("/bin/launchctl", ["kickstart", "system/" + Paths.label])
            }
            print("Service is loaded; start requested if stopped. Verify with sudo \(Paths.binary) status")
            return
        }
        try RootFiles.verify(Paths.binary)
        try RootFiles.verify(Paths.plist)
        try RootFiles.verify(Policy.anchorPath)
        do {
            let lock = try RuntimeLock(timeout: 20)
            defer { withExtendedLifetime(lock) {} }
            if try SystemUpdate.load()?.phase != .active { try Firewall().prepareAttachment() }
            if FileManager.default.fileExists(atPath: Paths.unlockMarker) {
                try RootFiles.verify(Paths.unlockMarker)
                try FileManager.default.removeItem(atPath: Paths.unlockMarker)
            }
        }
        // Clear a persisted launchd disable override so subsequent boots load it.
        try Command.checked("/bin/launchctl", ["enable", "system/" + Paths.label])
        try Command.checked("/bin/launchctl", ["bootstrap", "system", Paths.plist], timeout: 10)
        print("Service loaded. Verify with sudo \(Paths.binary) status")
    }

    static func unlock() throws {
        if try loaded() {
            try Command.checked("/bin/launchctl", ["bootout", "system/" + Paths.label], timeout: 15)
        }
        // Serialize with the daemon's final block operation before flushing.
        let lock = try RuntimeLock(timeout: 20)
        defer { withExtendedLifetime(lock) {} }
        guard try !loaded() else { throw GuardError("Surge Guard service is still loaded; refusing to clear its anchor") }
        try Firewall().unlock()
        try? FileManager.default.removeItem(atPath: Paths.snapshot)
        try RootFiles.preparePublicState()
        let marker = try JSONSerialization.data(withJSONObject: ["boot_id": SystemClock.bootID])
        try RootFiles.write(String(decoding: marker, as: UTF8.self), to: Paths.unlockMarker, mode: 0o644)
        EventLog.write("manual_unlock", level: "warning", message: "Service stopped and gate removed; start/reboot re-arms protection")
        print("Surge Guard unloaded and its block removed. Other firewall rules are untouched.")
        print("This is temporary: start or reboot arms protection again. Use uninstall to remove it permanently.")
    }

    static func restart() throws {
        let expectAllowed = (try? CLI.check(["check"]).ready) == true
        if try !loaded() {
            try start()
            try waitForStatus(expectAllowed: expectAllowed)
            return
        }
        let previous = try StatusReport.servicePID(Command.run("/bin/launchctl", ["print", "system/" + Paths.label]))
        guard let previous else {
            try Command.checked("/bin/launchctl", ["kickstart", "system/" + Paths.label])
            try waitForStatus(expectAllowed: expectAllowed)
            return
        }
        // launchd sends TERM, allowing the daemon to install block rules.
        try Command.checked("/bin/launchctl", ["kill", "SIGTERM", "system/" + Paths.label])
        EventLog.write("restart_requested", message: "Requested normal stop; launchd KeepAlive restarts the service")
        try waitForStatus(expectAllowed: expectAllowed, previousPID: previous)
    }

    static func uninstall() throws {
        try RootFiles.verify(Paths.pfConfig)
        let config = try String(contentsOfFile: Paths.pfConfig)
        let updated = try Policy.removingAttachment(from: config)
        guard config != updated else { throw GuardError("No exact managed attachment found; refusing automatic uninstall") }
        try Command.checked("/sbin/pfctl", ["-n", "-f", "-"], input: updated)
        try unlock()
        try RootFiles.write(updated, to: Paths.pfConfig, mode: 0o644)
        // The now-empty live anchor is harmless until PF is next reloaded.
        // Avoid reloading the main ruleset just to remove this empty call.
        for path in [Paths.plist, Policy.anchorPath, Paths.binary, DedicatedEgress.launcher] {
            if FileManager.default.fileExists(atPath: path) {
                try RootFiles.verify(path)
                try FileManager.default.removeItem(atPath: path)
            }
        }
        print("Removed binary, LaunchDaemon, anchor file and managed pf.conf lines. Original backup retained at \(Paths.pfConfig).surge-guard.backup")
    }
}
