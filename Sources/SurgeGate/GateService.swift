import Foundation
import AppKit
import Darwin
import SurgeGuardCore

func event(_ code: String, _ message: String, app: String? = nil, level: String? = nil, details: [String: Any] = [:]) {
    do {
        try UserPaths.prepare()
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let record: [String: Any] = ["time": formatter.string(from: Date()), "uptime": SystemClock.seconds,
                                    "run_id": gateRunID.uuidString, "component": "SurgeGate", "event": code,
                                    "level": level ?? (code.contains("failed") || code.contains("error") || code.contains("aborted") ? "error" : "info"),
                                    "message": message, "app": app ?? "", "pid": getpid(), "boot_id": SystemClock.bootID, "details": details]
        let data = try JSONSerialization.data(withJSONObject: record, options: [.sortedKeys, .withoutEscapingSlashes])
        try EventFile.append(data, to: UserPaths.log, owner: getuid(), lockPath: UserPaths.log + ".lock")
    } catch { NSLog("SurgeGate event %@: %@; logging failed: %@", code, message, String(describing: error)) }
}

func applications() throws -> [NSRunningApplication] {
    let all = NSWorkspace.shared.runningApplications
    guard !all.isEmpty else { throw GuardError("Application inventory unavailable; previous session retained") }
    return all.filter { $0.activationPolicy == .regular && !$0.isTerminated && $0.bundleIdentifier != nil }
}

func appIDs(_ config: GateConfiguration) throws -> [String] {
    let excluded = Set(config.excludedApps + ["com.apple.finder", "com.nssurge.surge-mac"])
    return Array(Set(try applications().compactMap(\.bundleIdentifier))).filter { !excluded.contains($0) }.sorted()
}

var workspaceLaunches = Set<UUID>()
let gateRunID = UUID()

func pendingLaunchState() throws -> (request: GatePendingLaunch, disposition: GatePendingLaunch.Disposition)? {
    guard var request = try GatePendingLaunch.load() else { return nil }
    if workspaceLaunches.contains(request.id) { return (request, .inFlight) }
    if request.launchd == true {
        let job = try GateLaunchJob.state(request.id)
        if case .running(let pid) = job, let child = try SurgeProcess.read(pid: pid) {
            guard request.child == nil || request.child == child else { throw GuardError("Launchd job process identity changed") }
            if request.child == nil {
                request.child = child
                try request.save(requireExisting: true)
            }
            try observeSurgeJob(request, child: child)
        }
        let child = try request.child.flatMap { try SurgeProcess.read(pid: $0.pid) }
        let identity = surgeIdentity()
        let verified = identity.satisfiesPolicy && identity.pid == child?.pid ? child : nil
        if let verified { surgeExitObserver?.verifiedStartup(matching: verified) }
        let submissionRunning: Bool?
        if let submission = request.submission {
            submissionRunning = try SurgeProcess.read(pid: submission.pid) == submission
        } else if request.observer == gateRunID, surgeSubmission?.id == request.id {
            submissionRunning = surgeSubmission?.task.isRunning
        } else { submissionRunning = nil }
        return (request, request.launchdDisposition(job: job, submissionRunning: submissionRunning,
                                                    verifiedApp: verified, childIdentity: child))
    }
    let appRunning: Bool
    if request.app == "com.nssurge.surge-mac" {
        let identity = surgeIdentity()
        appRunning = identity.satisfiesPolicy
    } else {
        appRunning = NSRunningApplication.runningApplications(withBundleIdentifier: request.app).contains(where: { !$0.isTerminated })
    }
    if appRunning { return (request, .settled) }
    let child = try request.child.flatMap { try SurgeProcess.read(pid: $0.pid) }
    return (request, request.disposition(observer: gateRunID, callbackPending: false, appRunning: false, childIdentity: child))
}

@discardableResult func launch(_ id: String) throws -> Bool {
    try SystemUpdate.requireNormalOperation()
    if NSRunningApplication.runningApplications(withBundleIdentifier: id).contains(where: { !$0.isTerminated }) { return false }
    guard let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: id) else { throw GuardError("Application is not installed") }
    let config = NSWorkspace.OpenConfiguration()
    config.activates = false
    let request = GatePendingLaunch(app: id, observer: gateRunID)
    try request.save()
    workspaceLaunches.insert(request.id)
    var result: Result<Void, Error>?
    NSWorkspace.shared.openApplication(at: url, configuration: config) { _, error in
        DispatchQueue.main.async {
            workspaceLaunches.remove(request.id)
            do {
                try request.complete()
                result = error.map { .failure($0) } ?? .success(())
            } catch { result = .failure(error) }
        }
    }
    let deadline = SystemClock.seconds + 10
    while result == nil && SystemClock.seconds < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.05)) }
    guard let result else { throw GuardError("Application launch timed out") }
    try result.get()
    return true
}

var surgeSubmission: (id: UUID, task: Process)?
var surgeExitObserver: GateChildExitObserver?
var surgeObservedChild: (id: UUID, child: SurgeProcess)?
enum SurgeLaunchResult { case unchanged, launched, waitingForBlock, waitingForNetwork, updatePaused }

func observeSurgeJob(_ request: GatePendingLaunch, child: SurgeProcess) throws {
    if surgeObservedChild?.id == request.id, surgeObservedChild?.child == child { return }
    let observer = GateChildExitObserver(launchID: request.id)
    try observer.attachToLaunchdProcess(child) { details in
        event("surge_job_process_exited", "Launchd-owned launcher/Surge exited; exit status and sender are unavailable to Gate",
              level: "warning", details: details)
    }
    surgeExitObserver = observer
    surgeObservedChild = (request.id, child)
    event("surge_job_process_observed", "Launchd owns the dedicated launcher; Surge startup is not yet verified",
          details: ["launch_id": request.id.uuidString, "job_label": GateLaunchJob.label(request.id),
                    "child_pid": child.pid, "child_started_seconds": child.startedSeconds,
                    "child_started_microseconds": child.startedMicroseconds, "process_relationship": "launchd_child"])
}

func requestSurgeQuit(_ app: NSRunningApplication, reason: String) -> Bool {
    var details: [String: Any] = ["quit_request_id": UUID().uuidString, "reason": reason,
                                  "surge_pid": app.processIdentifier, "birth_time_available": false]
    do {
        if let identity = try SurgeProcess.read(pid: app.processIdentifier) {
            details["birth_time_available"] = true
            details["surge_started_seconds"] = identity.startedSeconds
            details["surge_started_microseconds"] = identity.startedMicroseconds
        }
    } catch { details["identity_error"] = String(describing: error) }
    event("surge_quit_requested", "Gate is requesting normal Surge termination", details: details)
    let accepted = app.terminate()
    details["accepted"] = accepted
    event("surge_quit_result", "Normal quit request returned; process exit is not confirmed",
          level: accepted ? "info" : "warning", details: details)
    return accepted
}

func surgeIdentity() -> GateSurgeIdentity {
    var result = GateSurgeIdentity()
    do {
        let policy = try Configuration.load()
        result.pid = try Probe.trustedSurgePID()
        guard let pid = result.pid else { result.reason = "Surge absent, untrusted or multiple instances"; return result }
        if policy.usesPersistentTCP {
            let group = try DedicatedEgress.group()
            result.expectedGroup = group
            result.verified = try DedicatedEgress.identityMatches(pid: pid, uid: getuid(), group: group)
            result.reason = result.verified ? "dedicated_group_verified" : "surge_egress_identity_mismatch"
        } else { result.reason = "dedicated_group_not_required" }
    } catch { result.reason = String(describing: error) }
    return result
}

func ensureSurge(quitTimeout: Double) throws -> SurgeLaunchResult {
    if try SystemUpdate.load() != nil { return .updatePaused }
    if try GateUpdate.load()?.paused == true { return .updatePaused }
    let policy = try Configuration.load()
    guard policy.usesPersistentTCP else {
        if NSRunningApplication.runningApplications(withBundleIdentifier: "com.nssurge.surge-mac").contains(where: { !$0.isTerminated }) { return .unchanged }
        guard try Probe.startupNetworkReady() else { return .waitingForNetwork }
        return try launch("com.nssurge.surge-mac") ? .launched : .unchanged
    }
    let group = try DedicatedEgress.group()
    let apps = NSRunningApplication.runningApplications(withBundleIdentifier: "com.nssurge.surge-mac").filter { !$0.isTerminated }
    if let pid = try Probe.trustedSurgePID(), (apps.isEmpty || (apps.count == 1 && apps[0].processIdentifier == pid)),
       try DedicatedEgress.identityMatches(pid: pid, uid: getuid(), group: group) { return .unchanged }
    if !apps.isEmpty {
        guard StatusReport.read().state == "blocked" else {
            return .waitingForBlock
        }
        if try SystemUpdate.load() != nil || GateUpdate.load()?.paused == true { return .updatePaused }
        for app in apps {
            guard requestSurgeQuit(app, reason: "identity_repair") else { throw GuardError("Surge declined normal quit; dedicated launch cancelled") }
        }
        let deadline = SystemClock.seconds + quitTimeout
        while apps.contains(where: { !$0.isTerminated }) && SystemClock.seconds < deadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.05))
        }
        guard apps.allSatisfy(\.isTerminated) else { throw GuardError("Surge did not finish normal quit; no forced termination") }
    }
    if try SystemUpdate.load() != nil || GateUpdate.load()?.paused == true { return .updatePaused }
    guard try GatePendingLaunch.load() == nil else { return .unchanged }
    guard try Probe.startupNetworkReady() else { return .waitingForNetwork }
    var request = GatePendingLaunch(app: "com.nssurge.surge-mac", observer: gateRunID)
    request.launchd = true
    let data = try PropertyListSerialization.data(fromPropertyList: GateLaunchJob.plist(request.id), format: .xml, options: 0)
    try UserPaths.write(String(decoding: data, as: UTF8.self), to: GateLaunchJob.plistPath)
    try request.save()
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/bin/launchctl")
    task.arguments = ["bootstrap", "gui/\(getuid())", GateLaunchJob.plistPath]
    task.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
    task.standardInput = FileHandle.nullDevice
    task.standardOutput = FileHandle.nullDevice
    task.standardError = FileHandle.nullDevice
    do { try task.run() }
    catch { try request.complete(); throw error }
    surgeSubmission = (request.id, task)
    request.submission = try SurgeProcess.read(pid: task.processIdentifier)
    if request.submission != nil { try request.save(requireExisting: true) }
    event("surge_job_submitted", "Submitted a one-shot GUI launchd job; submission is not verified Surge startup",
          details: ["launch_id": request.id.uuidString, "job_label": GateLaunchJob.label(request.id),
                    "submission_pid": task.processIdentifier, "submission_birth_time_available": request.submission != nil])
    let deadline = SystemClock.seconds + 10
    while SystemClock.seconds < deadline {
        if let state = try pendingLaunchState() {
            if state.disposition == .settled { try state.request.complete(); return .launched }
            if state.disposition == .failed {
                try state.request.complete()
                let status = task.isRunning ? "unavailable" : String(task.terminationStatus)
                throw GuardError("One-shot Surge job exited without verified startup (launchctl status \(status))")
            }
        }
        RunLoop.current.run(until: Date().addingTimeInterval(0.1))
    }
    throw GuardError("Dedicated Surge startup timed out; networking remains gated")
}

struct GateStatus: Codable {
    var state: String
    var message: String
    var pending: [String]
    var surge: GateSurgeIdentity?
    var update: GateUpdate?
    var pendingLaunch: GatePendingLaunch?
    var runId: UUID? = gateRunID
    var capabilities = ["update_pause_v1", "launch_recovery_v1", "os_update_v1"]
    var systemUpdateId: UUID?
    var bootId = SystemClock.bootID
    var checkedUptime = SystemClock.seconds
    var pid = getpid()
}

func publish(_ state: String, _ message: String, pending: [String], surge: GateSurgeIdentity? = nil, update: GateUpdate? = nil,
             pendingLaunch: GatePendingLaunch? = nil, systemUpdateId: UUID? = nil) throws {
    try UserPaths.write(try JSON.encode(GateStatus(state: state, message: message, pending: pending, surge: surge, update: update,
                                                 pendingLaunch: pendingLaunch, systemUpdateId: systemUpdateId)), to: UserPaths.status)
}

func readStatus() throws -> (status: GateStatus, running: Bool, fresh: Bool, servicePID: Int32?) {
    let service = try Command.run("/bin/launchctl", ["print", "gui/\(getuid())/\(UserPaths.label)"])
    let pid = try StatusReport.servicePID(service)
    let running = pid != nil
    do {
        guard let data = try UserPaths.readPrivate(UserPaths.status, maximumBytes: GateSession.maximumBytes) else {
            return (GateStatus(state: running ? "waiting" : "stopped", message: running ? "Initializing" : "Service is not running", pending: []), running, false, pid)
        }
        let status = try JSON.decode(GateStatus.self, from: data)
        let fresh = pid == status.pid && !status.bootId.isEmpty && status.bootId == SystemClock.bootID && SystemClock.seconds >= status.checkedUptime &&
            SystemClock.seconds - status.checkedUptime < 15
        return (status, running, fresh, pid)
    } catch {
        return (GateStatus(state: "unknown", message: "Status unavailable: \(error)", pending: []), running, false, pid)
    }
}

func updateMode(paused: Bool) throws {
    let fd = try lock("request.lock")
    let update = GateUpdate(paused: paused)
    do {
        defer { close(fd) }
        try SystemUpdate.requireNormalOperation()
        let previous = try readStatus()
        guard previous.fresh, !["shutting_down", "shutdown_requested"].contains(previous.status.state),
              try GateShutdownRequest.load() == nil else {
            throw GuardError("SurgeGate must be running with fresh status and no ordered shutdown")
        }
        try UserPaths.write(try JSON.encode(update), to: GateUpdate.path)
    }
    let deadline = SystemClock.seconds + 20
    while SystemClock.seconds < deadline {
        let report = try readStatus()
        if update.acknowledged(by: report.status.update, state: report.status.state, fresh: report.fresh) {
            print(paused ? "SurgeGate confirmed update pause. Finish or cancel the official update before resuming. Guard/PF were not changed." :
                "SurgeGate confirmed automatic recovery enabled. Network readiness: \(StatusReport.read().state).")
            return
        }
        RunLoop.current.run(until: Date().addingTimeInterval(0.1))
    }
    throw GuardError("Update mode saved but not acknowledged within 20s; do not start updating yet. Inspect Gate status/logs. The saved mode remains in effect.")
}

func lock(_ name: String, timeout: TimeInterval = 0) throws -> Int32 {
    try UserPaths.lock(at: UserPaths.directory + "/" + name, timeout: timeout)
}

func saveSession(_ config: GateConfiguration, pending: [String], preserveSavedApps: Bool = false) throws {
    let existing = preserveSavedApps ? try GateSession.load().apps : []
    let excluded = Set(config.excludedApps + ["com.apple.finder", "com.nssurge.surge-mac"])
    let apps = Array(Set(try appIDs(config) + existing)).filter { !excluded.contains($0) }.sorted()
    try UserPaths.write(try GateSession(apps: apps, pending: pending).encoded(), to: UserPaths.session)
}

let shutdownPath = GateShutdownRequest.path

func shutdown(_ action: String, config: GateConfiguration, pending: [String], preserveSavedApps: Bool = false) throws {
    try SystemUpdate.requireNormalOperation()
    guard ["restart", "shutdown"].contains(action) else { throw GuardError("Invalid shutdown action") }
    guard ["allowed", "blocked"].contains(StatusReport.read().state) else {
        throw GuardError("System guard state is not verified; no applications were asked to quit")
    }
    try saveSession(config, pending: pending, preserveSavedApps: preserveSavedApps)
    event("shutdown_started", "Requesting normal application quits; no force termination")
    let excluded = Set(config.excludedApps + ["com.apple.finder", "com.nssurge.surge-mac"])
    let apps = try applications().filter { !excluded.contains($0.bundleIdentifier ?? "") }
    for app in apps {
        guard app.terminate() else { throw GuardError("Application declined to quit: \(app.bundleIdentifier ?? "unknown")") }
    }
    let deadline = SystemClock.seconds + config.quitTimeoutSeconds
    while apps.contains(where: { !$0.isTerminated }) && SystemClock.seconds < deadline {
        RunLoop.current.run(until: Date().addingTimeInterval(0.2))
    }
    let remaining = apps.filter { !$0.isTerminated }.compactMap(\.bundleIdentifier)
    guard remaining.isEmpty else { throw GuardError("Quit cancelled or timed out; shutdown aborted: \(remaining.joined(separator: ", "))") }
    let surge = NSRunningApplication.runningApplications(withBundleIdentifier: "com.nssurge.surge-mac")
    for app in surge {
        guard requestSurgeQuit(app, reason: "ordered_" + action) else { throw GuardError("Surge declined to quit; shutdown aborted") }
    }
    let blockDeadline = SystemClock.seconds + config.quitTimeoutSeconds
    while SystemClock.seconds < blockDeadline {
        let status = StatusReport.read()
        if status.state == "blocked", surge.allSatisfy(\.isTerminated) { break }
        RunLoop.current.run(until: Date().addingTimeInterval(0.2))
    }
    guard StatusReport.read().state == "blocked", surge.allSatisfy(\.isTerminated) else {
        throw GuardError("Cannot confirm blocked firewall after Surge quit; shutdown aborted")
    }
    let verb = action == "restart" ? "restart" : "shut down"
    try Command.checked("/usr/bin/osascript", ["-e", "tell application \"System Events\" to \(verb)"], timeout: 30)
    event("shutdown_requested", "macOS accepted the request; session snapshots paused until next service start")
}

func run() throws {
    let fd = try lock("gate.lock")
    defer { close(fd) }
    let initial = try GateConfiguration.load()
    let saved = try GateSession.load()
    // Keep the run loop alive even if AppKit has no active event sources.
    let keepAlive = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in }
    defer { keepAlive.invalidate() }
    var pending = initial.targets(saved: saved.pending + saved.apps)
    try UserPaths.write(try GateSession(apps: saved.apps, pending: pending).encoded(), to: UserPaths.session)
    var lastMessage = ""
    var lastGuardState: String?
    var lastSnapshot: Double = 0
    var nextLaunch: Double = 0
    var surgeRetry = GateRetry()
    var lastUpdate: GateUpdate?
    var acknowledgedPause: UUID?
    var shutdownPhase = GateShutdownPhase.idle
    var shutdownFailure: String?
    var lastMaintenanceID: UUID?
    event("gate_started", "Waiting for fresh verified system guard status")
    event("surge_exit_observation_scope", "One-shot launchd process exits are observed without exit codes/signals. Existing Surge processes without a pending job, NSWorkspace launches and exits after Gate stops are not covered.",
          details: ["launch_method": "launchd_once", "exit_status_available": false])
    while true {
        do {
            let config = try GateConfiguration.load()
            let update = try GateUpdate.load()
            if update != lastUpdate {
                surgeRetry = GateRetry()
                lastUpdate = update
                if let update {
                    event(update.paused ? "update_pause_requested" : "update_resume_requested",
                          update.paused ? "Update pause requested; waiting for in-flight operations to settle" : "Automatic recovery requested; awaiting service confirmation",
                          details: ["request_id": update.id.uuidString])
                }
            }
            var launchState = try pendingLaunchState()
            if let settled = launchState, settled.disposition == .settled || settled.disposition == .failed {
                try settled.request.complete()
                if settled.disposition == .failed {
                    let message = "Earlier launcher exited without verified application startup; retrying no earlier than 30 seconds"
                    if settled.request.app == "com.nssurge.surge-mac" { surgeRetry.failed(message, at: SystemClock.seconds) }
                    else { nextLaunch = SystemClock.seconds + 30 }
                    event("launch_failed_after_restart", message, app: settled.request.app)
                }
                launchState = nil
            }
            // Submission and consumption share a short lock; command waiters do not hold it.
            let requestLock = try lock("request.lock")
            var request: GateShutdownRequest?
            var maintenance: SystemUpdate?
            var maintenanceSettled = false
            let preserve = shutdownPhase.preservesSession
            do {
                defer { close(requestLock) }
                // Recovery may have cleared the observed marker before we obtained this lock.
                guard try GatePendingLaunch.observationIsCurrent(launchState?.request) else { continue }
                maintenance = try SystemUpdate.load()
                let queuedRequest = try GateShutdownRequest.load()
                request = queuedRequest
                if let queued = request {
                    let declined = try queued.consume(maintenance: maintenance != nil) {
                        try GateShutdownRequest.validate(paused: GateUpdate.load()?.paused == true,
                                                         pendingLaunch: launchState?.request, phase: shutdownPhase)
                    }
                    if let reason = declined {
                        request = nil
                        event("shutdown_declined", "\(reason). No applications were asked to quit; this request was removed", level: "error",
                              details: ["request_id": queued.id.uuidString])
                    } else {
                        try publish("shutting_down", "Waiting for applications to quit", pending: pending)
                    }
                }
                maintenanceSettled = try launchState == nil && GateShutdownRequest.load() == nil && shutdownPhase == .idle
            }
            if let maintenance {
                if maintenanceSettled, lastMaintenanceID != maintenance.id {
                    if maintenance.phase == .preparing { try saveSession(config, pending: pending, preserveSavedApps: true) }
                    event("system_update_paused", "System update maintenance suspends automatic launches and session checkpoints; Surge update preference is unchanged",
                          details: ["request_id": maintenance.id.uuidString])
                    lastMaintenanceID = maintenance.id
                }
                try publish(maintenanceSettled ? "os_update_paused" : "os_update_waiting",
                            maintenanceSettled ? "macOS maintenance; finish or cancel updating, then explicitly restore protection" :
                                "Maintenance not acknowledged: settle pending launches/power requests first; protection must not be released",
                            pending: pending, update: update, pendingLaunch: launchState?.request,
                            systemUpdateId: maintenanceSettled ? maintenance.id : nil)
                RunLoop.current.run(until: Date().addingTimeInterval(1))
                continue
            }
            lastMaintenanceID = nil
            if let unsettled = launchState {
                let orphaned = unsettled.disposition == .orphaned
                let message = orphaned ?
                    "Launch result unknown after Gate restart (\(unsettled.request.app)). Verify the old launch finished, failed or was cancelled, then run surge-gate recover-launch \(unsettled.request.id.uuidString) --confirm-settled. Absence or timeout alone does not prove cancellation." :
                    "An earlier launch is still in flight; update pause is not yet acknowledged. Waiting for callback, verified app startup or recorded launcher exit."
                try publish(orphaned ? "launch_recovery_required" : update?.paused == true ? "update_pausing" : "launch_pending",
                            message, pending: pending, update: update, pendingLaunch: unsettled.request)
                if message != lastMessage {
                    event(orphaned ? "launch_recovery_required" : "launch_pending", message, app: unsettled.request.app, level: "warning")
                    lastMessage = message
                }
                RunLoop.current.run(until: Date().addingTimeInterval(1))
                continue
            }
            if let request {
                shutdownFailure = nil
                shutdownPhase = .quitting
                do {
                    try shutdown(request.action, config: config, pending: pending, preserveSavedApps: preserve)
                    shutdownPhase = .submitted
                } catch {
                    shutdownPhase = .aborted
                    shutdownFailure = "\(error). Session retained; save documents and retry ordered shutdown, or restart SurgeGate to resume recovery"
                    event("shutdown_aborted", shutdownFailure!)
                }
            }
            if shutdownPhase.preservesSession {
                try publish(shutdownFailure == nil ? "shutdown_requested" : "error",
                            shutdownFailure ?? "macOS request submitted, completion is not confirmed. If cancelled, retry ordered shutdown or restart Gate to resume recovery; snapshots remain paused", pending: pending)
            } else if update?.paused == true {
                try publish("update_paused", update!.reason, pending: pending, surge: surgeIdentity(), update: update)
                if acknowledgedPause != update!.id {
                    event("update_paused", update!.reason)
                    acknowledgedPause = update!.id
                }
            } else {
                pending.removeAll { config.excludedApps.contains($0) }
                var identity = surgeIdentity()
                var waitingForIdentity = false
                var waitingForNetwork = false
                let needsSurge = identity.pid == nil || identity.reason == "surge_egress_identity_mismatch"
                if !needsSurge, identity.satisfiesPolicy {
                    surgeRetry.succeeded(at: SystemClock.seconds, launched: false)
                }
                if needsSurge, surgeRetry.canAttempt(at: SystemClock.seconds) {
                    do {
                        let result = try ensureSurge(quitTimeout: config.quitTimeoutSeconds)
                        waitingForIdentity = result == .waitingForBlock
                        waitingForNetwork = result == .waitingForNetwork
                        surgeRetry.succeeded(at: SystemClock.seconds, launched: result == .launched)
                        if result == .launched {
                            event("surge_launch_requested", "Surge identity/startup verified; still waiting for enhanced mode and policy")
                        }
                    } catch {
                        surgeRetry.failed(String(describing: error), at: SystemClock.seconds)
                        event("surge_recovery_failed", "\(error). Retrying no earlier than 30 seconds")
                    }
                    identity = surgeIdentity()
                }
                // A pause arriving during a bounded operation is acknowledged only after that operation settles.
                if try SystemUpdate.load() != nil || GateUpdate.load()?.paused == true || GatePendingLaunch.load() != nil { continue }
                // Identity checks can outlive a status snapshot; read authorization immediately before restoring apps.
                var status = StatusReport.read()
                if !waitingForNetwork, status.state == "allowed", status.firewallVerified, let target = pending.first, SystemClock.seconds >= nextLaunch {
                    switch Result(catching: { try launch(target) }) {
                    case .success(let requestedLaunch):
                        pending.removeFirst()
                        event(requestedLaunch ? "application_restored" : "application_already_running",
                              requestedLaunch ? "Application launch request completed" : "Application was already running; no launch requested",
                              app: target, details: ["pending_count": pending.count])
                        nextLaunch = SystemClock.seconds + config.delayBetweenAppsSeconds
                        try saveSession(config, pending: pending)
                    case .failure(let error):
                        event("application_restore_failed", String(describing: error), app: target)
                        // Rotate failed apps so an unavailable app cannot starve the rest.
                        pending.append(pending.removeFirst())
                        nextLaunch = SystemClock.seconds + 30
                    }
                    status = StatusReport.read()
                }
                let state = surgeRetry.failure != nil ? "recovery_failed" : waitingForIdentity ? "waiting_identity" :
                    waitingForNetwork ? "waiting_network" :
                    status.state == "unknown" ? "unknown" : status.state == "allowed" ? (pending.isEmpty ? "ready" : "restoring") : "waiting"
                let message = surgeRetry.failure.map { "\($0); next attempt in \(max(0, Int(ceil(surgeRetry.nextAttempt - SystemClock.seconds))))s" } ??
                    (waitingForIdentity ? "Waiting for verified blocking before correcting Surge's egress identity" :
                        waitingForNetwork ? "Waiting for macOS primary IPv4 network before starting Surge; DHCP or captive evaluation may still be in progress" :
                        status.state == "allowed" ? "\(pending.count) application(s) pending" : "\(status.state): \(status.reason)")
                try publish(state, message, pending: pending, surge: identity, update: update)
                if message != lastMessage, surgeRetry.failure == nil {
                    let code: String
                    if waitingForNetwork { code = "gate_waiting_network" }
                    else if status.state == "unknown" { code = "gate_status_unavailable" }
                    else if lastGuardState == "unknown" { code = "gate_status_recovered" }
                    else if status.state != "allowed" { code = "gate_waiting" }
                    else { code = pending.isEmpty ? "gate_ready" : "gate_restore_progress" }
                    event(code, message, level: status.state == "unknown" ? "warning" : "info",
                          details: ["pending_count": pending.count, "guard_state": status.state,
                                    "reason": status.reason, "previous_guard_state": lastGuardState ?? "initial"])
                    lastMessage = message
                    lastGuardState = status.state
                }
                if SystemClock.seconds - lastSnapshot >= 30 {
                    try saveSession(config, pending: pending)
                    lastSnapshot = SystemClock.seconds
                }
            }
        } catch {
            let message = String(describing: error)
            try? publish("error", message, pending: pending)
            if message != lastMessage { event("gate_error", message); lastMessage = message }
        }
        RunLoop.current.run(until: Date().addingTimeInterval(1))
    }
}
