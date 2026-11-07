import Foundation
import Darwin
import SurgeGuardCore

func gateLaunchTests() throws {
    let requestID = UUID(), plist = GateLaunchJob.plist(requestID)
    try check(plist["ProgramArguments"] as? [String] == [DedicatedEgress.launcher] &&
              plist["RunAtLoad"] as? Bool == true && plist["LaunchOnlyOnce"] as? Bool == true &&
              plist["KeepAlive"] as? Bool == false && plist["ProcessType"] as? String == "Interactive",
              "Dedicated launch job lost its fixed launcher or one-shot lifetime")
    try check(GateLaunchJob.label(requestID) != GateLaunchJob.label(UUID()) &&
              GateLaunchJob.service(requestID).hasPrefix("gui/\(getuid())/"), "Launch job is not request-bound in the user domain")
    for key in ["StandardInPath", "StandardOutPath", "StandardErrorPath"] {
        try check(plist[key] as? String == "/dev/null", "Job created an unbounded output file or input pipe")
    }
    try check(try GateLaunchJob.state(Command.run("/bin/launchctl", ["print", "system/io.github.surge-guard.nonexistent-test"])) == .absent,
              "Known missing job was not recognized")
    try check(try GateLaunchJob.state(Command.run("/usr/bin/printf", ["state = spawn scheduled\n"])) == .pending,
              "Queued job was mistaken for a completed launch")
    try check(try GateLaunchJob.state(Command.run("/usr/bin/printf", ["state = running\npid = 123\n"])) == .running(123),
              "Running job PID lost")
    for result in [try Command.run("/usr/bin/false", []),
                   try Command.run("/usr/bin/awk", ["BEGIN { print \"Could not find domain\"; exit 113 }"]),
                   try Command.run("/usr/bin/printf", ["state = running\n"])] {
        try rejects { _ = try GateLaunchJob.state(result) }
    }

    var request = GatePendingLaunch(app: "com.nssurge.surge-mac", observer: UUID())
    request.launchd = true
    let child = SurgeProcess(pid: 123, startedSeconds: 100, startedMicroseconds: 1)
    let reused = SurgeProcess(pid: 123, startedSeconds: 101, startedMicroseconds: 1)
    let cases: [(GateLaunchJob.State, Bool?, SurgeProcess?, SurgeProcess?, GatePendingLaunch.Disposition)] = [
        (.pending, false, nil, nil, .inFlight), (.running(123), false, nil, nil, .inFlight),
        (.absent, true, nil, nil, .inFlight), (.absent, false, nil, nil, .failed),
        (.absent, nil, nil, nil, .orphaned)
    ]
    for (job, submission, verified, native, expected) in cases {
        try check(request.launchdDisposition(job: job, submissionRunning: submission, verifiedApp: verified, childIdentity: native) == expected,
                  "Submission completion/observer loss incorrectly settled a launch")
    }
    request.child = child
    for (job, submission, verified, native, expected) in [
        (GateLaunchJob.State.running(123), true, child, child, GatePendingLaunch.Disposition.inFlight),
        (.running(123), false, child, child, .settled), (.absent, nil, child, child, .settled),
        (.absent, false, nil, child, .inFlight), (.absent, false, reused, reused, .failed),
        (.pending, false, nil, nil, .inFlight), (.absent, false, nil, nil, .failed),
        (.absent, false, reused, child, .inFlight)
    ] {
        try check(request.launchdDisposition(job: job, submissionRunning: submission, verifiedApp: verified, childIdentity: native) == expected,
                  "Job/child evidence allowed an unrelated app, reused PID or active submission to settle a launch")
    }

    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("gate-job-tests-" + UUID().uuidString)
    try UserPaths.prepare(directory.path)
    defer { try? FileManager.default.removeItem(at: directory) }
    let path = directory.appendingPathComponent("pending.json").path
    request.submission = SurgeProcess(pid: 124, startedSeconds: 100, startedMicroseconds: 2)
    try request.save(at: path)
    try check(try GatePendingLaunch.load(from: path) == request, "Job identity/submission did not survive Gate restart")
    try request.complete(at: path)
    try rejects { try request.save(at: path, requireExisting: true) }
    try check(try GatePendingLaunch.load(from: path) == nil, "Late child observation resurrected a recovered launch")
    var recordedSubmission = request
    recordedSubmission.child = nil
    try recordedSubmission.save(at: path)
    try rejects { try GatePendingLaunch.recover(id: recordedSubmission.id, observer: UUID(), at: path) }
    try check(try GatePendingLaunch.load(from: path) == recordedSubmission, "Manual recovery discarded a recorded submission")
    try recordedSubmission.complete(at: path)
    let legacy = GatePendingLaunch(app: "com.example.fixture", observer: UUID())
    let encoded = try JSON.encode(legacy)
    try check(!encoded.contains("launchd") && !encoded.contains("submission"), "Legacy marker gained incompatible placeholder fields")
    try legacy.save(at: path)
    let previous = try Data(contentsOf: URL(fileURLWithPath: path))
    var malformed = legacy
    malformed.submission = child
    try legacy.complete(at: path)
    try rejects { try malformed.save(at: path) }
    try check(try GatePendingLaunch.load(from: path) == nil, "Invalid marker was published")
    for mutation in ["wrong_app", "false_flag", "bad_pid"] {
        var invalid = request
        if mutation == "false_flag" { invalid.launchd = false }
        if mutation == "bad_pid" { invalid.submission = SurgeProcess(pid: 1, startedSeconds: 0, startedMicroseconds: -1) }
        if mutation == "wrong_app" { invalid = legacy; invalid.launchd = true }
        try AtomicFile.write(JSON.encode(invalid), to: path, mode: 0o600)
        try rejects { _ = try GatePendingLaunch.load(from: path) }
        try FileManager.default.removeItem(atPath: path)
    }
    try check(try JSON.decode(GatePendingLaunch.self, from: previous) == legacy, "Legacy pending marker stopped decoding")

    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/bin/sleep"); task.arguments = ["0.15"]
    task.standardInput = FileHandle.nullDevice; task.standardOutput = FileHandle.nullDevice; task.standardError = FileHandle.nullDevice
    try task.run()
    guard let identity = try SurgeProcess.read(pid: task.processIdentifier) else { throw GuardError("Missing observer fixture") }
    let observer = GateChildExitObserver(launchID: requestID)
    defer { withExtendedLifetime(observer) {} }
    var records: [[String: Any]] = []
    try observer.attachToLaunchdProcess(identity) { records.append($0) }
    observer.verifiedStartup(matching: identity)
    task.waitUntilExit()
    let deadline = SystemClock.seconds + 3
    while records.isEmpty && SystemClock.seconds < deadline { RunLoop.current.run(until: Date().addingTimeInterval(0.01)) }
    try check(records.count == 1 && records[0]["termination_reason"] as? String == "unavailable_non_child" &&
              records[0]["termination_status"] == nil && records[0]["signal"] == nil && records[0]["startup_verified"] as? Bool == true,
              "Non-child observation invented an exit status or lost its startup binding")
    let line = String(decoding: try JSONSerialization.data(withJSONObject: ["event": "surge_job_process_exited", "details": records[0]]), as: UTF8.self)
    try check(LogReader.format(line).contains("无法取得退出码") && LogReader.format(line, json: true).contains("unavailable_non_child"),
              "Non-child human/JSON logs overstated exit evidence")
    var replacements: [Process] = []
    var latest: SurgeProcess?
    for _ in 0..<2 {
        let replacement = Process()
        replacement.executableURL = URL(fileURLWithPath: "/bin/sleep"); replacement.arguments = ["0.1"]
        replacement.standardInput = FileHandle.nullDevice; replacement.standardOutput = FileHandle.nullDevice; replacement.standardError = FileHandle.nullDevice
        try replacement.run()
        guard let native = try SurgeProcess.read(pid: replacement.processIdentifier) else { throw GuardError("Missing replacement fixture") }
        try observer.attachToLaunchdProcess(native) { records.append($0) }
        let exitedBy = SystemClock.seconds + 3
        // Hold main callbacks until after replacement, using native exit as the barrier.
        while try SurgeProcess.read(pid: native.pid) == native && SystemClock.seconds < exitedBy { usleep(1_000) }
        try check(try SurgeProcess.read(pid: native.pid) != native, "Replacement fixture did not exit")
        replacements.append(replacement); latest = native
    }
    for replacement in replacements { replacement.waitUntilExit() }
    let deliveredBy = SystemClock.seconds + 3
    while records.count < 2 && SystemClock.seconds < deliveredBy { RunLoop.current.run(until: Date().addingTimeInterval(0.01)) }
    try check(records.count == 2 && records.last?["child_pid"] as? Int32 == latest?.pid &&
              records.last?["startup_verified"] as? Bool == false,
              "Obsolete exit callback or startup verification was attributed to a replacement watch")
    print("PASS: one-shot launch jobs retain pause fences, native identity, legacy markers and honest exit evidence")
}

// Explicit opt-in: disposable user-domain jobs only, never Surge or PF.
func gateLaunchdCheck() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("gate-launchd-check-" + UUID().uuidString)
    try UserPaths.prepare(directory.path)
    defer { try? FileManager.default.removeItem(at: directory) }
    var request = GatePendingLaunch(app: "com.nssurge.surge-mac", observer: UUID())
    request.launchd = true
    let id = request.id, service = GateLaunchJob.service(id)
    var plist = GateLaunchJob.plist(id)
    plist["ProgramArguments"] = ["/bin/sleep", "2"]
    let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
    let path = directory.appendingPathComponent("job.plist").path
    try AtomicFile.write(String(decoding: data, as: UTF8.self), to: path, mode: 0o600)
    defer { _ = try? Command.run("/bin/launchctl", ["bootout", service]) }
    try Command.checked("/bin/launchctl", ["bootstrap", "gui/\(getuid())", path])
    var child: SurgeProcess?
    let deadline = SystemClock.seconds + 5
    while child == nil && SystemClock.seconds < deadline {
        if case .running(let pid) = try GateLaunchJob.state(id) { child = try SurgeProcess.read(pid: pid) }
        if child == nil { RunLoop.current.run(until: Date().addingTimeInterval(0.01)) }
    }
    guard let child else { throw GuardError("Disposable launchd job did not start") }
    let pendingPath = directory.appendingPathComponent("pending.json").path
    try request.save(at: pendingPath)
    try rejects { try GatePendingLaunch.recover(id: id, observer: UUID(), at: pendingPath) }
    try check(try GatePendingLaunch.load(from: pendingPath) == request, "Explicit recovery cleared a still-loaded job")
    var query: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, child.pid]
    var info = kinfo_proc(), size = MemoryLayout<kinfo_proc>.size
    try check(sysctl(&query, u_int(query.count), &info, &size, nil, 0) == 0 && size == MemoryLayout<kinfo_proc>.size &&
              info.kp_proc.p_pid == child.pid && info.kp_eproc.e_ppid == 1 && getpgid(child.pid) == child.pid,
              "Job did not retain launchd parentage and an independent process group")
    let observer = GateChildExitObserver(launchID: id)
    defer { withExtendedLifetime(observer) {} }
    var records: [[String: Any]] = []
    try observer.attachToLaunchdProcess(child) { records.append($0) }
    while SystemClock.seconds < deadline {
        if try GateLaunchJob.state(id) == .absent, records.count == 1 { break }
        RunLoop.current.run(until: Date().addingTimeInterval(0.02))
    }
    try check(try GateLaunchJob.state(id) == .absent && records.count == 1 && SurgeProcess.read(pid: child.pid) != child,
              "One-shot job persisted, respawned or lost its non-child exit notification")
    print("PASS: disposable GUI job has PPID 1, independent process group, native exit notification and automatic removal")
}
