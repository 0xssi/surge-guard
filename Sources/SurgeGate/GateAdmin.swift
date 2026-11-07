import Foundation
import AppKit
import Darwin
import SurgeGuardCore

func migrateLegacy() throws {
    let legacy = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".surge_gate")
    let legacyConfig = legacy.appendingPathComponent("config.json")
    guard !FileManager.default.fileExists(atPath: UserPaths.config), FileManager.default.fileExists(atPath: legacyConfig.path) else { return }
    guard let object = try JSONSerialization.jsonObject(with: Data(contentsOf: legacyConfig)) as? [String: Any] else {
        throw GuardError("Invalid legacy config; original files retained")
    }
    var known: [String: String] = [:]
    let roots = ["/Applications", "/System/Applications", "/System/Applications/Utilities", FileManager.default.homeDirectoryForCurrentUser.path + "/Applications"]
    for root in roots {
        for name in (try? FileManager.default.contentsOfDirectory(atPath: root)) ?? [] where name.hasSuffix(".app") {
            let url = URL(fileURLWithPath: root).appendingPathComponent(name)
            guard let bundle = Bundle(url: url), let id = bundle.bundleIdentifier else { continue }
            for value in [url.deletingPathExtension().lastPathComponent, bundle.object(forInfoDictionaryKey: "CFBundleName") as? String, bundle.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String].compactMap({ $0 }) {
                known[value] = id
            }
        }
    }
    func resolve(_ name: String) -> String? {
        if GateConfiguration.validBundleID(name), NSWorkspace.shared.urlForApplication(withBundleIdentifier: name) != nil { return name }
        if let id = known[name] { return id }
        event("migration_app_unresolved", "Legacy application name needs a bundle ID", app: name)
        return nil
    }
    func list(_ key: String) -> [String] {
        var seen = Set<String>()
        return (object[key] as? [String] ?? []).compactMap(resolve).filter { seen.insert($0).inserted }
    }
    var config = GateConfiguration.standard
    config.priorityOrder = list("priority_startup_order")
    config.excludedApps = list("ignored_apps").filter { $0 != "com.nssurge.surge-mac" && $0 != "com.apple.finder" }
    config.startupApps = list("always_launch_after_surge").filter { !config.excludedApps.contains($0) && $0 != "com.nssurge.surge-mac" }
    config.restoreSession = object["restore_previous_apps_on_reboot"] as? Bool ?? true
    config.delayBetweenAppsSeconds = object["delay_between_apps_seconds"] as? Double ?? 1
    config.quitTimeoutSeconds = object["app_quit_timeout_seconds"] as? Double ?? 30
    try config.validate()
    let session = legacy.appendingPathComponent("last_session_apps.json")
    var importedSession: GateSession?
    if FileManager.default.fileExists(atPath: session.path), !FileManager.default.fileExists(atPath: UserPaths.session) {
        guard let previous = try JSONSerialization.jsonObject(with: Data(contentsOf: session)) as? [String: Any],
              let names = previous["apps"] as? [String] else { throw GuardError("Invalid legacy session; original files retained") }
        importedSession = GateSession(apps: names.compactMap(resolve), pending: [])
    }
    if let importedSession { try UserPaths.write(try importedSession.encoded(), to: UserPaths.session) }
    try UserPaths.write(try JSON.encode(config, pretty: true), to: UserPaths.config)
    event("legacy_migrated", "Imported legacy config/session; original files retained")
}

func install() throws {
    try UserPaths.prepare()
    try migrateLegacy()
    if !FileManager.default.fileExists(atPath: UserPaths.config) {
        try UserPaths.write(try JSON.encode(GateConfiguration.standard, pretty: true), to: UserPaths.config)
    }
    _ = try GateConfiguration.load()
    let source = URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL.resolvingSymlinksInPath().path
    try UserPaths.prepare(UserPaths.directory + "/bin")
    let staged = UserPaths.binary + ".new." + UUID().uuidString
    defer { try? FileManager.default.removeItem(atPath: staged) }
    if source != UserPaths.binary {
        try FileManager.default.copyItem(atPath: source, toPath: staged)
        guard chmod(staged, 0o700) == 0 else { throw GuardError("Cannot protect staged user binary") }
    }
    let domain = "gui/\(getuid())"
    for label in [UserPaths.label, "com.user.surgegate"] {
        if try StatusReport.serviceLoaded(Command.run("/bin/launchctl", ["print", "\(domain)/\(label)"])) {
            try Command.checked("/bin/launchctl", ["bootout", "\(domain)/\(label)"], timeout: 10)
        }
    }
    let oldPlist = FileManager.default.homeDirectoryForCurrentUser.path + "/Library/LaunchAgents/com.user.surgegate.plist"
    if FileManager.default.fileExists(atPath: oldPlist) {
        let backup = FileManager.default.fileExists(atPath: oldPlist + ".migrated-backup") ? oldPlist + ".migrated-backup." + UUID().uuidString : oldPlist + ".migrated-backup"
        try FileManager.default.moveItem(atPath: oldPlist, toPath: backup)
    }
    do {
        let fd = try lock("gate.lock", timeout: 10)
        defer { close(fd) }
        if source != UserPaths.binary {
            guard rename(staged, UserPaths.binary) == 0 else { throw GuardError("Cannot install user binary") }
        }
    }
    let agents = URL(fileURLWithPath: UserPaths.plist).deletingLastPathComponent()
    try FileManager.default.createDirectory(at: agents, withIntermediateDirectories: true)
    let plist: [String: Any] = ["Label": UserPaths.label, "ProgramArguments": [UserPaths.binary, "run"],
                               "RunAtLoad": true, "KeepAlive": true, "ThrottleInterval": 10,
                               "ProcessType": "Interactive",
                               "StandardOutPath": "/dev/null", "StandardErrorPath": "/dev/null"]
    try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0).write(to: URL(fileURLWithPath: UserPaths.plist), options: .atomic)
    try Command.checked("/bin/launchctl", ["enable", domain + "/" + UserPaths.label])
    try Command.checked("/bin/launchctl", ["bootstrap", domain, UserPaths.plist], timeout: 10)
    print("SurgeGate installed. Configuration: \(UserPaths.config)")
}

@discardableResult func ensureServiceLoaded(waitForRunning: Bool = false) throws -> Bool {
    let domain = "gui/\(getuid())"
    let service = "\(domain)/\(UserPaths.label)"
    let probe = try Command.run("/bin/launchctl", ["print", service])
    let wasLoaded = try StatusReport.serviceLoaded(probe)
    if !wasLoaded {
        guard FileManager.default.fileExists(atPath: UserPaths.plist) else { throw GuardError("SurgeGate plist not found; run install first") }
        try Command.checked("/bin/launchctl", ["enable", service])
        try Command.checked("/bin/launchctl", ["bootstrap", domain, UserPaths.plist], timeout: 10)
    }
    if wasLoaded, !(try StatusReport.serviceRunning(probe)) {
        try Command.checked("/bin/launchctl", ["kickstart", service])
    }
    if waitForRunning {
        let deadline = SystemClock.seconds + 15
        while !(try StatusReport.serviceRunning(Command.run("/bin/launchctl", ["print", service]))) && SystemClock.seconds < deadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.1))
        }
        guard try StatusReport.serviceRunning(Command.run("/bin/launchctl", ["print", service])) else {
            throw GuardError("SurgeGate service must be running")
        }
    }
    return !wasLoaded
}

func stopService() throws {
    let service = "gui/\(getuid())/\(UserPaths.label)"
    if try StatusReport.serviceLoaded(Command.run("/bin/launchctl", ["print", service])) {
        try Command.checked("/bin/launchctl", ["bootout", service], timeout: 10)
    }
    let fd = try lock("gate.lock", timeout: 10)
    defer { close(fd) }
    guard !(try StatusReport.serviceLoaded(Command.run("/bin/launchctl", ["print", service]))) else {
        throw GuardError("SurgeGate is still loaded; stop is not confirmed")
    }
    try GateShutdownRequest.cancel()
    try publish("stopped", "Stopped by user; current network and PF rules are unchanged",
                pending: (try? GateSession.load().pending) ?? [], surge: surgeIdentity(), update: try? GateUpdate.load())
    event("gate_stopped", "User stopped SurgeGate service; current network and PF rules unchanged")
    print("SurgeGate service stopped. Current network and PF protection are unchanged.")
}

func waitForFreshService(after previousPID: Int32? = nil) throws {
    let deadline = SystemClock.seconds + 20
    repeat {
        let report = try readStatus()
        if report.fresh, report.status.pid != previousPID { return }
        RunLoop.current.run(until: Date().addingTimeInterval(0.1))
    } while SystemClock.seconds < deadline
    throw GuardError("SurgeGate did not publish fresh status; service startup/restart is not confirmed")
}

func restartService() throws {
    let service = "gui/\(getuid())/\(UserPaths.label)"
    let previous = try readStatus()
    let started = try ensureServiceLoaded(waitForRunning: true)
    if started || !previous.running {
        try waitForFreshService()
        print("SurgeGate was stopped; service startup confirmed.")
    } else {
        try Command.checked("/bin/launchctl", ["kill", "SIGTERM", service])
        try waitForFreshService(after: previous.servicePID)
        print("SurgeGate restart confirmed by fresh service status.")
    }
}

func queueShutdown(_ action: String) throws {
    let request = try GateShutdownRequest(action: action)
    let fd = try lock("request.lock")
    do {
        defer { close(fd) }
        try SystemUpdate.requireNormalOperation()
        let report = try readStatus()
        let quitting = report.servicePID == report.status.pid && report.status.bootId == SystemClock.bootID && report.status.state == "shutting_down"
        try GateShutdownRequest.validate(paused: GateUpdate.load()?.paused == true, pendingLaunch: GatePendingLaunch.load(),
                                         phase: quitting ? .quitting : .idle)
        guard try GateShutdownRequest.load() == nil else { throw GuardError("A shutdown request is already queued") }
        // Publish before bootstrap so a new service cannot restore applications first.
        try UserPaths.write(try JSON.encode(request), to: shutdownPath)
    }
    do { try ensureServiceLoaded(waitForRunning: true) }
    catch {
        let fd = try lock("request.lock", timeout: 2)
        defer { close(fd) }
        let withdrawn = try request.withdraw()
        throw GuardError("Service startup failed: \(error). \(withdrawn ? "Queued shutdown withdrawn; retry when the service is available." : "Request already consumed; inspect status/logs before retrying.")")
    }
    print("Queued normal shutdown. Unsaved-document dialogs may need your attention; after macOS cancels a submitted request, explicitly retry or restart Gate to resume recovery.")
}

func recoverLaunch(_ id: UUID) throws {
    let fd = try lock("request.lock", timeout: 2)
    defer { close(fd) }
    let report = try readStatus()
    guard report.fresh, ["launch_recovery_required", "os_update_waiting"].contains(report.status.state), report.status.pendingLaunch?.id == id,
          let observer = report.status.runId else { throw GuardError("Inspect fresh Gate status for the exact orphaned launch ID") }
    try GatePendingLaunch.recover(id: id, observer: observer)
    event("launch_recovery_confirmed", "User confirmed the orphaned launch finished, failed or was cancelled; Gate may resume", details: ["request_id": id.uuidString])
    print("Orphaned launch cleared on your explicit confirmation. Inspect Gate status; an existing update pause remains in effect.")
}

func uninstallService() throws {
    let service = "gui/\(getuid())/\(UserPaths.label)"
    if try StatusReport.serviceLoaded(Command.run("/bin/launchctl", ["print", service])) { try Command.checked("/bin/launchctl", ["bootout", service], timeout: 10) }
    let fd = try lock("gate.lock", timeout: 10)
    defer { close(fd) }
    guard !(try StatusReport.serviceLoaded(Command.run("/bin/launchctl", ["print", service]))) else { throw GuardError("SurgeGate is still loaded") }
    try GateShutdownRequest.cancel()
    for path in [UserPaths.plist, UserPaths.binary] where FileManager.default.fileExists(atPath: path) { try FileManager.default.removeItem(atPath: path) }
    print("User service removed; configuration/session/logs retained. System guard is separate.")
}
