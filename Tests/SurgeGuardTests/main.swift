import Foundation
import SurgeGuardCore
import Darwin
import SystemConfiguration

if Array(CommandLine.arguments.dropFirst()) == ["--diagnostic-save-check"] {
    do { try diagnosticSaveCheck(); exit(0) }
    catch { fputs("FAIL: \(error)\n", stderr); exit(1) }
}

if CommandLine.arguments.count == 3, CommandLine.arguments[1] == "--diagnostic-lock-check" {
    do { try diagnosticLockCheck(CommandLine.arguments[2]); exit(0) }
    catch { fputs("FAIL: \(error)\n", stderr); exit(1) }
}

if Array(CommandLine.arguments.dropFirst()) == ["--gate-launchd-check"] {
    do { try gateLaunchdCheck(); exit(0) }
    catch { fputs("FAIL: \(error)\n", stderr); exit(1) }
}

if CommandLine.arguments.count == 4, CommandLine.arguments[1] == "--gate-exit-fixture",
   let status = Int32(CommandLine.arguments[3]) {
    switch CommandLine.arguments[2] {
    case "held":
        _ = try FileHandle.standardInput.read(upToCount: 1)
        exit(status)
    case "exit": exit(status)
    case "signal" where [SIGTERM, SIGKILL].contains(status):
        kill(getpid(), status)
        exit(99)
    default: exit(98)
    }
}

if Array(CommandLine.arguments.dropFirst()) == ["--audit-noisy-child"] {
    let line = Data("capture diagnostic\n".utf8)
    while true { try FileHandle.standardError.write(contentsOf: line) }
}

if Array(CommandLine.arguments.dropFirst()) == ["--audit-main-queue-check"] {
    let task = Process(), pipe = Pipe()
    task.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
    task.arguments = ["--audit-noisy-child"]
    task.standardInput = FileHandle.nullDevice; task.standardOutput = FileHandle.nullDevice; task.standardError = pipe
    try task.run()
    try pipe.fileHandleForWriting.close()
    let child = task.processIdentifier
    DispatchQueue.global().asyncAfter(deadline: .now() + 5) { kill(child, SIGKILL); exit(2) }
    var consumed = 0, stopped = false
    DispatchQueue.global().async {
        do {
            try PacketAudit.readDiagnostics(pipe.fileHandleForReading) { _ in
                try DispatchQueue.main.sync {
                    consumed += 1
                    if consumed == 20 {
                        // Exercise a bounded synchronous command on main while the pipe is backpressured.
                        _ = try Command.checked("/bin/sleep", ["0.02"])
                        if task.isRunning { kill(child, SIGTERM) }
                        stopped = true
                    }
                }
            }
            try pipe.fileHandleForReading.close()
            task.waitUntilExit()
            DispatchQueue.main.async { exit(stopped && consumed >= 20 && !task.isRunning ? 0 : 1) }
        } catch { kill(child, SIGKILL); exit(1) }
    }
    dispatchMain()
}

if CommandLine.arguments.count == 3, CommandLine.arguments[1] == "--gate-lock-check" {
    let home = FileManager.default.temporaryDirectory.appendingPathComponent("gate-lock-check-" + UUID().uuidString)
    do {
        defer { try? FileManager.default.removeItem(at: home) }
        let state = home.appendingPathComponent("Library/Application Support/SurgeGuard")
        try UserPaths.prepare(state.path)
        let fd = try UserPaths.lock(at: state.appendingPathComponent("gate.lock").path)
        defer { close(fd) }
        let status = state.appendingPathComponent("gate-status.json")
        let sentinel = "status belongs to the service holding gate.lock"
        try AtomicFile.write(sentinel, to: status.path, mode: 0o600)
        let result = try Command.run("/usr/bin/env", ["CFFIXED_USER_HOME=" + home.path, CommandLine.arguments[2], "run"], timeout: 5)
        try check(result.status != 0 && result.combined.contains("release the firewall lock") &&
                  String(contentsOf: status) == sentinel, "A failed Gate contender overwrote its owner's status")
        print("PASS: duplicate Gate run cannot publish over the lock owner's status")
        for flag in ["--help", "-h", "--unexpected"] {
            let invocation = try Command.run("/usr/bin/env", ["CFFIXED_USER_HOME=" + home.path, CommandLine.arguments[2], "run", flag], timeout: 5)
            try check(flag == "--unexpected" ? invocation.status != 0 && invocation.combined.contains("Unexpected arguments") :
                        invocation.status == 0 && invocation.output.contains("SurgeGate —"), "Gate help/invalid arguments reached the run loop")
            try check(try String(contentsOf: status) == sentinel, "Gate help/invalid arguments overwrote service status")
        }
        print("PASS: release Gate help and argument rejection precede service locking")
        exit(0)
    } catch { fputs("FAIL: \(error)\n", stderr); exit(1) }
}

if Array(CommandLine.arguments.dropFirst()) == ["--packet-audit-group-check"] {
    try PacketAudit.joinParentProcessGroup()
    print(getpgrp())
    exit(0)
}

if CommandLine.arguments.count == 3, CommandLine.arguments[1] == "--event-fifo-check" {
    let path = CommandLine.arguments[2]
    do { try EventFile.append(Data("fixture".utf8), to: path, owner: getuid(), lockPath: path + ".lock") }
    catch { print("rejected"); exit(0) }
    exit(1)
}

// Standalone checks also work with Command Line Tools, where XCTest may not
// be installed. Throw on failure so checks still work in optimized builds.
func check(_ value: @autoclosure () throws -> Bool, _ message: String) throws {
    if try !value() { throw GuardError(message) }
}

func rejects(_ operation: () throws -> Void) throws {
    do { try operation() } catch { return }
    throw GuardError("Expected rejection")
}

do {
    try systemUpdateTests()
    try gateLaunchTests()
    try diagnosticTests()
    try usbTCPTests()
    try protectionTests()
    let gateActions = ["install", "setup", "run", "start", "stop", "restart", "uninstall", "edit-config", "update-pause", "update-resume"]
    for action in gateActions {
        try check(try GateCommand.action([action]) == action, "Valid Gate action rejected")
        try rejects { _ = try GateCommand.action([action, "--unexpected"]) }
        for help in ["--help", "-h"] { try check(try GateCommand.action([action, help]) == nil, "Gate help would execute a management action") }
    }
    let validGateArguments = [["status"], ["status", "--json"], ["logs"], ["logs", "--json", "--follow"],
                              ["shutdown", "--action", "restart"], ["shutdown", "--action", "shutdown"],
                              ["recover-launch", UUID().uuidString, "--confirm-settled"]]
    for args in validGateArguments { try check(try GateCommand.action(args) == args[0], "Valid Gate options rejected") }
    for args in [[], ["help"], ["--help"], ["-h"], ["shutdown", "--help"], ["recover-launch", "-h"]] {
        try check(try GateCommand.action(args) == nil, "Help selected a Gate action")
    }
    for args in [["unknown"], ["status", "--unknown"], ["status", "--json", "--json"], ["logs", "--follow", "--follow"],
                 ["logs", "--unknown"], ["shutdown"], ["shutdown", "--action"], ["shutdown", "--action", "halt"],
                 ["recover-launch"], ["recover-launch", "invalid", "--confirm-settled"], ["recover-launch", UUID().uuidString]] {
        try rejects { _ = try GateCommand.action(args) }
    }
    print("PASS: Gate command parsing rejects unknown/extra arguments and keeps help non-mutating")

    do {
        let watchdog = DispatchWorkItem { fputs("FAIL: Gate exit observer check timed out\n", stderr); _exit(1) }
        DispatchQueue.global().asyncAfter(deadline: .now() + 20, execute: watchdog)
        defer { watchdog.cancel() }
        var records: [[String: Any]] = []
        let started = SystemClock.seconds
        for (mode, status) in [("held", Int32(0)), ("held_wrong_birth", 0), ("exit", 0), ("exit", 9), ("signal", SIGTERM), ("signal", SIGKILL)] {
            let task = Process(), input = Pipe()
            defer {
                try? input.fileHandleForReading.close()
                try? input.fileHandleForWriting.close()
            }
            task.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
            task.arguments = ["--gate-exit-fixture", mode.hasPrefix("held") ? "held" : mode, String(status)]
            task.standardInput = input
            task.standardOutput = FileHandle.nullDevice; task.standardError = FileHandle.nullDevice
            let launchID = UUID(), previousCount = records.count
            let observer = GateChildExitObserver(launchID: launchID)
            observer.attach(to: task) { details in
                dispatchPrecondition(condition: .onQueue(.main))
                records.append(details)
            }
            try task.run()
            try input.fileHandleForReading.close()
            if mode.hasPrefix("held") {
                guard let identity = try SurgeProcess.read(pid: task.processIdentifier) else { throw GuardError("Missing held fixture identity") }
                observer.recordIdentity(identity)
                let verification = mode == "held" ? identity : SurgeProcess(pid: identity.pid,
                    startedSeconds: identity.startedSeconds + 1, startedMicroseconds: identity.startedMicroseconds)
                observer.verifiedStartup(matching: verification)
                try input.fileHandleForWriting.write(contentsOf: Data([10]))
            }
            try input.fileHandleForWriting.close()
            // Main waits synchronously, like Gate's bounded commands: callbacks must never sync back to it.
            task.waitUntilExit()
            let deadline = SystemClock.seconds + 5
            while records.count == previousCount && SystemClock.seconds < deadline {
                RunLoop.current.run(until: Date().addingTimeInterval(0.01))
            }
            try check(records.count == previousCount + 1, "Missing or duplicate child exit event")
            let record = records.last!
            try check(record["child_pid"] as? Int32 == task.processIdentifier && record["launch_id"] as? String == launchID.uuidString,
                      "Delayed exit callback was attributed to a different launch")
            try check(record["termination_status"] as? Int32 == status && record["termination_sender"] as? String == "unknown",
                      "Exit status lost or termination sender invented")
            try check(record["startup_verified"] as? Bool == (mode == "held") && record["birth_time_available"] as? Bool == mode.hasPrefix("held"),
                      "Unobserved birth time or unverified startup was invented")
            try check((record["child_started_seconds"] != nil) == mode.hasPrefix("held"), "Missing child identity was not explicit")
            try check((record["exit_observed_uptime"] as? Double ?? 0) >= started, "Exit callback timestamp missing")
            if mode == "signal" {
                try check(record["termination_reason"] as? String == "uncaught_signal" && record["signal"] as? Int32 == status && record["exit_code"] == nil,
                          "Signal death was reported as a normal exit code")
            } else {
                try check(record["termination_reason"] as? String == "exit" && record["exit_code"] as? Int32 == status && record["signal"] == nil,
                          "Exit code 9 was confused with SIGKILL")
            }
            let line = String(decoding: try JSONSerialization.data(withJSONObject: ["component": "SurgeGate", "event": "surge_child_exited", "details": record]), as: UTF8.self)
            let decoded = try JSONSerialization.jsonObject(with: Data(LogReader.format(line, json: true).utf8)) as! [String: Any]
            let roundTrip = decoded["details"] as! [String: Any]
            try check(roundTrip["termination_status"] as? Int == Int(status) && roundTrip["launch_id"] as? String == launchID.uuidString,
                      "Machine log discarded exit evidence")
            let human = LogReader.format(line)
            try check(human.contains(mode == "signal" ? "未处理的信号" : "退出码") && human.contains("不能由本事件确认发起者或网络状态"),
                      "Human log omitted or overstated exit evidence")
        }
        let previousCount = records.count
        var launches: [(Process, UUID)] = []
        for code in [3, 4] {
            let task = Process(), launchID = UUID()
            task.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
            task.arguments = ["--gate-exit-fixture", "exit", String(code)]
            task.standardInput = FileHandle.nullDevice; task.standardOutput = FileHandle.nullDevice; task.standardError = FileHandle.nullDevice
            GateChildExitObserver(launchID: launchID).attach(to: task) { records.append($0) }
            try task.run()
            launches.append((task, launchID))
        }
        for (task, _) in launches { task.waitUntilExit() }
        let deadline = SystemClock.seconds + 5
        while records.count < previousCount + launches.count && SystemClock.seconds < deadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.01))
        }
        try check(records.count == previousCount + launches.count, "Overlapping launches lost or duplicated exit callbacks")
        for (task, launchID) in launches {
            try check(records.suffix(launches.count).contains { $0["launch_id"] as? String == launchID.uuidString &&
                $0["child_pid"] as? Int32 == task.processIdentifier && $0["exit_code"] as? Int32 == task.terminationStatus },
                      "An old exit callback was attributed to the replacement child")
        }
        let failed = Process()
        failed.executableURL = URL(fileURLWithPath: "/nonexistent-gate-exit-fixture")
        let beforeFailedSpawn = records.count
        GateChildExitObserver(launchID: UUID()).attach(to: failed) { records.append($0) }
        try rejects { try failed.run() }
        RunLoop.current.run(until: Date().addingTimeInterval(0.05))
        try check(records.count == beforeFailedSpawn, "Failed spawn invented a child exit")
    }
    print("PASS: Gate child exits retain identity, exit codes/signals and JSON without main-queue deadlock")

    for (cause, label) in [("identity_repair", "修复专用组启动身份"), ("ordered_restart", "有序重启电脑"), ("ordered_shutdown", "有序关闭电脑")] {
        for accepted in [true, false] {
            let record: [String: Any] = ["event": "surge_quit_result", "details": ["reason": cause, "accepted": accepted, "surge_pid": 42]]
            let line = String(decoding: try JSONSerialization.data(withJSONObject: record), as: UTF8.self)
            let human = LogReader.format(line)
            try check(human.contains(label) && human.contains("不能确认进程退出") && human.contains(accepted ? "请求已接受" : "请求未被接受"),
                      "Quit acknowledgement lost the cause or claimed process exit")
        }
    }
    let scopeLog = LogReader.format("{\"event\":\"surge_exit_observation_scope\"}")
    try check(scopeLog.contains("Gate 启动前已存在") && scopeLog.contains("Gate 停止后"), "Exit observation coverage gap omitted")
    print("PASS: Gate quit-request logs distinguish request acceptance from exit and expose coverage limits")

    try check(SystemClock.elapsedSeconds(since: 2.2, now: 4.9) == 2, "Elapsed seconds were rounded incorrectly")
    for start in [-1e300, 1e300, Double.nan, Double.infinity, -1, 20] {
        try check(SystemClock.elapsedSeconds(since: start, now: 10) == nil, "Invalid menu timestamp could overflow or masquerade as fresh")
    }
    try check(SystemClock.elapsedSeconds(since: 0, now: 1e300) == nil, "Elapsed seconds overflow accepted")
    try rejects { _ = try Probe.addresses(query: { _ in errno = ENOMEM; return -1 }) }
    _ = try Probe.addresses()
    print("PASS: bounded timestamp conversion and explicit interface inventory failures")

    let cleanup = Firewall(historyPath: nil)
    var cleared: [String] = []
    try cleanup.clearStates(addresses: { ["192.0.2.1", "2001:db8::1"] }) { cleared.append($0) }
    cleared = []
    try rejects {
        try cleanup.clearStates(addresses: { throw GuardError("injected interface enumeration failure") }) { cleared.append($0) }
    }
    try check(cleared == ["192.0.2.1", "2001:db8::1"], "Enumeration failure skipped known state cleanup")
    cleared = []
    try rejects { try cleanup.clearStates(addresses: { ["192.0.2.2"] }) { _ in throw GuardError("injected PF failure") } }
    try cleanup.clearStates(addresses: { ["192.0.2.3"] }) { cleared.append($0) }
    try check(cleared == ["192.0.2.1", "192.0.2.2", "192.0.2.3", "2001:db8::1"], "A failed cleanup forgot addresses needed for retry")
    cleared = []
    try cleanup.clearStates(addresses: { [] }) { cleared.append($0) }
    try check(cleared == ["192.0.2.3"], "Successful cleanup retained obsolete addresses")
    print("PASS: failed address inventory still clears known states and failed cleanup retains retry evidence")

    let auditMain = try Command.run(CommandLine.arguments[0], ["--audit-main-queue-check"], timeout: 8)
    try check(auditMain.status == 0, "Main-queue diagnostic backpressure deadlocked with child stop/reaping")
    print("PASS: live diagnostic flood, main-queue synchronous work, stop and background child reaping")

    let diagnosticURL = FileManager.default.temporaryDirectory.appendingPathComponent("audit-diagnostics-" + UUID().uuidString)
    do {
        defer { try? FileManager.default.removeItem(at: diagnosticURL) }
        func readDiagnostics(_ text: String, consume: (String) throws -> Void) throws {
            try AtomicFile.write(text, to: diagnosticURL.path, mode: 0o600)
            let handle = try FileHandle(forReadingFrom: diagnosticURL)
            defer { try? handle.close() }
            try PacketAudit.readDiagnostics(handle, consume: consume)
        }
        var rows: [String] = []
        try readDiagnostics(String(repeating: "line\n", count: 20_000) + String(repeating: "x", count: 65_536) + "\n尾行") { rows.append($0) }
        try check(rows.count == 20_002 && rows[20_000].count == 65_536 && rows.last == "尾行", "Diagnostic chunking dropped lines or final unterminated text")
        for suffix in ["", "\n"] {
            try rejects { try readDiagnostics(String(repeating: "x", count: 65_537) + suffix) { _ in } }
        }
        var consumed = 0
        try rejects { try readDiagnostics("one\ntwo\n") { _ in consumed += 1; throw GuardError("consumer failed") } }
        try check(consumed == 1, "Diagnostic producer ran past a failed synchronous consumer")
    }
    let diagnosticPipe = Pipe(), diagnosticLine = DispatchSemaphore(value: 0), diagnosticDone = DispatchGroup()
    final class DiagnosticResult: @unchecked Sendable { var error: Error? }
    let diagnosticResult = DiagnosticResult()
    diagnosticDone.enter()
    DispatchQueue.global().async {
        defer { try? diagnosticPipe.fileHandleForReading.close(); diagnosticDone.leave() }
        do { try PacketAudit.readDiagnostics(diagnosticPipe.fileHandleForReading) { if $0 == "ready" { diagnosticLine.signal() } } }
        catch { diagnosticResult.error = error }
    }
    try diagnosticPipe.fileHandleForWriting.write(contentsOf: Data("ready\n".utf8))
    let deliveredBeforeEOF = diagnosticLine.wait(timeout: .now() + 1) == .success
    try diagnosticPipe.fileHandleForWriting.close()
    let diagnosticCompleted = diagnosticDone.wait(timeout: .now() + 3) == .success
    try check(deliveredBeforeEOF && diagnosticCompleted && diagnosticResult.error == nil,
              "Capture diagnostics waited for EOF/full buffer instead of delivering live statistics")

    let orphanGroup = Process()
    orphanGroup.executableURL = URL(fileURLWithPath: "/bin/sh")
    orphanGroup.arguments = ["-c", "sleep 0.5 >/dev/null 2>&1 & exit 0"]
    orphanGroup.standardInput = FileHandle.nullDevice; orphanGroup.standardOutput = FileHandle.nullDevice; orphanGroup.standardError = FileHandle.nullDevice
    try orphanGroup.run()
    let orphanGroupID = orphanGroup.processIdentifier
    orphanGroup.waitUntilExit()
    let absentLeader = SurgeProcess(pid: orphanGroupID, startedSeconds: 1, startedMicroseconds: 0)
    try rejects { try PacketAudit.waitForProcessGroupExit(orphanGroupID, identities: [absentLeader], timeout: 0.05) }
    try PacketAudit.waitForProcessGroupExit(orphanGroupID, timeout: 3)
    try rejects { try PacketAudit.waitForProcessGroupExit(getpgrp(), timeout: 0) }
    print("PASS: bounded capture diagnostics, consumer failure and surviving child process-group drain")

    var groupSnapshot = PacketAuditSnapshot(capacityMegabytes: 256)
    let oldLeader = SurgeProcess(pid: 450, startedSeconds: 100, startedMicroseconds: 0)
    groupSnapshot.pid = 450; groupSnapshot.processGroup = 450; groupSnapshot.supervisorIdentity = oldLeader
    try check(try JSON.decode(PacketAuditSnapshot.self, from: Data(JSON.encode(groupSnapshot).utf8)).supervisorIdentity == oldLeader,
              "Capture snapshot lost supervisor birth evidence")
    groupSnapshot.supervisorIdentity = nil
    try check(try JSON.decode(PacketAuditSnapshot.self, from: Data(JSON.encode(groupSnapshot).utf8)).supervisorIdentity == nil,
              "Legacy capture snapshot could not be read")
    let groupLeader = Process()
    groupLeader.executableURL = URL(fileURLWithPath: "/bin/sleep"); groupLeader.arguments = ["5"]
    groupLeader.standardInput = FileHandle.nullDevice; groupLeader.standardOutput = FileHandle.nullDevice; groupLeader.standardError = FileHandle.nullDevice
    try groupLeader.run()
    do {
        defer { if groupLeader.isRunning { kill(groupLeader.processIdentifier, SIGKILL) }; groupLeader.waitUntilExit() }
        guard let identity = try SurgeProcess.read(pid: groupLeader.processIdentifier) else { throw GuardError("Missing group fixture leader") }
        let previousIdentity = SurgeProcess(pid: identity.pid, startedSeconds: identity.startedSeconds - 1,
                                            startedMicroseconds: identity.startedMicroseconds)
        try PacketAudit.waitForProcessGroupExit(identity.pid, identities: [previousIdentity], timeout: 0)
        try rejects { try PacketAudit.waitForProcessGroupExit(identity.pid, identities: [identity], timeout: 0.05) }
        try rejects { try PacketAudit.waitForProcessGroupExit(identity.pid, identities: [identity, previousIdentity], timeout: 0.05) }
        try rejects { try PacketAudit.waitForProcessGroupExit(identity.pid, timeout: 0.05) }
    }
    print("PASS: capture group cleanup retains orphans but excludes proven supervisor PID reuse")

    let legacyCapture = Process()
    legacyCapture.executableURL = URL(fileURLWithPath: "/bin/sleep"); legacyCapture.arguments = ["5"]
    legacyCapture.standardInput = FileHandle.nullDevice; legacyCapture.standardOutput = FileHandle.nullDevice; legacyCapture.standardError = FileHandle.nullDevice
    try legacyCapture.run()
    do {
        defer { if legacyCapture.isRunning { kill(legacyCapture.processIdentifier, SIGKILL) }; legacyCapture.waitUntilExit() }
        // The supervisor is gone, but an older capture child survives in a separate process group.
        let drainedGroups: [pid_t: [SurgeProcess]] = [groupLeader.processIdentifier: []]
        try rejects { try PacketAudit.waitForCaptureExit(groups: drainedGroups, legacyPIDs: [legacyCapture.processIdentifier], timeout: 0.05) }
        try rejects { try PacketAudit.waitForCaptureExit(groups: [:], legacyPIDs: [legacyCapture.processIdentifier], timeout: 0.05) }
        kill(legacyCapture.processIdentifier, SIGTERM)
        legacyCapture.waitUntilExit()
        try PacketAudit.waitForCaptureExit(groups: drainedGroups, legacyPIDs: [legacyCapture.processIdentifier], timeout: 0.05)
    }
    print("PASS: drained supervisor group does not conceal a surviving legacy capture child")

    let auditArguments = try PacketAudit.arguments(megabytes: 256)
    try check(auditArguments.contains("pktap,all") && auditArguments.contains("-W") && auditArguments.contains("8") &&
              auditArguments[auditArguments.firstIndex(of: "-C")! + 1] == "32" && !auditArguments.contains("-I"),
              "Recorder lost all-interface coverage, bounded retention or enabled disruptive Wi-Fi monitor mode")
    try check(auditArguments[auditArguments.firstIndex(of: "-B")! + 1] == "512", "Capture buffer request exceeded the standard macOS BPF maximum")
    for capacity in [0, 255, 257, -1, Int.max] { try rejects { _ = try PacketAudit.arguments(megabytes: capacity) } }
    var auditConfig = PacketAuditConfiguration(); try auditConfig.validate()
    auditConfig.timeZone = "not/a/zone"; try rejects { try auditConfig.validate() }
    var packetStats = PacketCaptureStatistics()
    try check(packetStats.consume("0 packets dropped by kernel") == nil && packetStats.consume("20 packets captured") == nil &&
              packetStats.consume("25 packets received by filter") == nil, "Partial/misordered statistics became a zero-loss report")
    let completedStats = packetStats.consume("3 packets dropped by kernel")
    try check(completedStats?.captured == 20 && completedStats?.receivedByFilter == 25 && completedStats?.droppedByKernel == 3,
              "Packet statistics lost capture drops")
    var resetStats = completedStats!; resetStats.receivedByFilter = 0
    try check(completedStats!.follows(completedStats!) && !resetStats.follows(completedStats!), "Counter reset or wrap was silently treated as continuous statistics")
    try check(packetStats.consume("4 packets dropped by kernel") == nil, "Statistics reused an old capture baseline")
    let liveStats = packetStats.consume("tcpdump: 349 packets captured, 366 packets received by filter, 0 packets dropped by kernel")
    try check(liveStats?.captured == 349 && liveStats?.receivedByFilter == 366 && liveStats?.droppedByKernel == 0,
              "macOS single-line live statistics were not recognized")
    try check(packetStats.consume("tcpdump: 20 packets captured, 25 packets received by filter, 3 packets dropped by kernel") == completedStats,
              "Single-line statistics lost capture drops")
    let singularStats = packetStats.consume("tcpdump: 1 packet captured, 1 packet received by filter, 1 packet dropped by kernel")
    try check(singularStats?.captured == 1 && singularStats?.receivedByFilter == 1 && singularStats?.droppedByKernel == 1,
              "Singular live statistics were rejected")
    for malformed in [
        "tcpdump: 20 packets captured, 25 packets received by filter",
        "tcpdump: 25 packets received by filter, 20 packets captured, 0 packets dropped by kernel",
        "tcpdump: 20 packets captured, invalid packets received by filter, 0 packets dropped by kernel",
        "tcpdump: 20 packets captured, 25 packets received by filter, 0 packets dropped by kernel,",
        "tcpdump: 20 packets captured,, 0 packets dropped by kernel"
    ] {
        _ = packetStats.consume("99 packets captured")
        _ = packetStats.consume("99 packets received by filter")
        try check(packetStats.consume(malformed) == nil && packetStats.consume("0 packets dropped by kernel") == nil,
                  "Malformed live statistics reused or left a partial baseline")
    }
    _ = packetStats.consume("20 packets captured")
    _ = packetStats.consume("25 packets received by filter")
    try check(packetStats.consume("3 packets dropped by kernel") == completedStats,
              "Live statistics parsing broke final multiline statistics")
    var auditState = PacketAuditSnapshot(capacityMegabytes: 256)
    auditState.bootId = "boot-a"; auditState.checkedUptime = 10
    try check(auditState.fresh(boot: "boot-a", now: 11) && !auditState.fresh(boot: "boot-b", now: 11) &&
              !auditState.fresh(boot: "boot-a", now: 18) && !auditState.fresh(boot: "boot-a", now: 9) && !auditState.noBypassVerified,
              "Audit freshness or packet-path confidence was overstated")
    auditState.state = "capturing"
    try check(!auditState.fresh(boot: "boot-a", now: 11), "Recorder claimed healthy capture without packet statistics")
    auditState.capturePid = 400; auditState.counters = completedStats; auditState.countersUptime = 10
    try check(auditState.fresh(boot: "boot-a", now: 11), "Fresh capture statistics were rejected")
    auditState.countersUptime = 0
    try check(!auditState.fresh(boot: "boot-a", now: 11), "Fresh status publication concealed stale capture statistics")
    let childGroup = try Command.checked(CommandLine.arguments[0], ["--packet-audit-group-check"]).trimmingCharacters(in: .whitespacesAndNewlines)
    try check(childGroup == String(getpgrp()), "Capture child did not rejoin supervisor group for launchd cleanup")
    print("PASS: packet recorder arguments, partial/drop statistics, boot freshness and child process-group cleanup")

    let captureDirectory = FileManager.default.temporaryDirectory.appendingPathComponent("packet-audit-test-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: captureDirectory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    do {
        defer { try? FileManager.default.removeItem(at: captureDirectory) }
        func le<T: FixedWidthInteger>(_ value: T, _ data: inout Data) {
            var value = value.littleEndian; withUnsafeBytes(of: &value) { data.append(contentsOf: $0) }
        }
        var pcap = Data()
        le(UInt32(0xa1b2c3d4), &pcap); le(UInt16(2), &pcap); le(UInt16(4), &pcap)
        for value: UInt32 in [0, 0, 262144, 1] { le(value, &pcap) }
        let frame = Data([UInt8](repeating: 0, count: 65_536))
        for time: UInt32 in 1...40 {
            le(time, &pcap); le(UInt32(123456), &pcap); le(UInt32(frame.count), &pcap); le(UInt32(frame.count), &pcap); pcap.append(frame)
        }
        let source = captureDirectory.appendingPathComponent("source.pcap").path
        try AtomicFile.write(String(), to: source, mode: 0o600)
        try pcap.write(to: URL(fileURLWithPath: source))
        let range = try PacketCaptureRange.read(source, owner: getuid(), maximumBytes: 4_000_000)
        try check(range.packets == 40 && abs(range.earliest!.timeIntervalSince1970 - 1.123456) < 0.00001 &&
                  abs(range.latest!.timeIntervalSince1970 - 40.123456) < 0.00001 && range.readError == nil, "Retained pcap time range was inferred from file modification times")
        let rangeFD = open(source, O_RDONLY | O_CLOEXEC)
        guard rangeFD >= 0 else { throw GuardError("Cannot open range identity fixture") }
        defer { close(rangeFD) }
        var rangeInitial = stat(); try check(fstat(rangeFD, &rangeInitial) == 0, "Cannot stat range fixture")
        try check(PacketCaptureRange.unchanged(source, descriptor: rangeFD, initial: rangeInitial), "Stable capture appeared replaced")
        let movedSource = source + ".previous"
        try FileManager.default.moveItem(atPath: source, toPath: movedSource)
        try pcap.write(to: URL(fileURLWithPath: source)); chmod(source, 0o600)
        try check(!PacketCaptureRange.unchanged(source, descriptor: rangeFD, initial: rangeInitial), "Rotated filename retained obsolete inode coverage")
        let output = captureDirectory.appendingPathComponent("ring").path
        _ = try Command.checked("/usr/sbin/tcpdump", ["-r", source, "-C", "1", "-W", "2", "-w", output], timeout: 5)
        let ringFiles = try FileManager.default.contentsOfDirectory(atPath: captureDirectory.path).filter { $0.hasPrefix("ring") }
        try check(Set(ringFiles) == ["ring0", "ring1"], "Native tcpdump rotation did not retain a fixed file count or expected filenames")
        for name in ringFiles {
            let size = (try FileManager.default.attributesOfItem(atPath: captureDirectory.appendingPathComponent(name).path)[.size] as! NSNumber).intValue
            try check(size <= 1_000_000 + 65_536 + 64, "Native rotation exceeded one-record overshoot")
        }
        let retained = captureDirectory.appendingPathComponent("retained-before-capacity-reduction.pcap").path
        var oldSegment = pcap
        for _ in 0..<12 { oldSegment.append(pcap.dropFirst(24)) }
        try AtomicFile.write("", to: retained, mode: 0o600)
        try oldSegment.write(to: URL(fileURLWithPath: retained))
        try check(oldSegment.count > 32_000_000 + 65_536, "Capacity-reduction fixture must exceed the new segment limit")
        let retainedRange = try PacketCaptureRange.read(retained, owner: getuid())
        try check(retainedRange.packets == 520 && retainedRange.readError == nil &&
                  retainedRange.earliest == range.earliest && retainedRange.latest == range.latest,
                  "Reducing ring capacity made valid retained history unreadable")
        let retainedFD = open(retained, O_WRONLY | O_CLOEXEC)
        guard retainedFD >= 0 else { throw GuardError("Cannot open oversized capture fixture") }
        defer { close(retainedFD) }
        try check(ftruncate(retainedFD, 512_000_000 + 65_536 + 1) == 0, "Cannot create oversized sparse capture")
        try rejects { _ = try PacketCaptureRange.read(retained, owner: getuid()) }
        var ng = Data()
        for value: UInt32 in [0x0a0d0d0a, 28, 0x1a2b3c4d] { le(value, &ng) }
        le(UInt16(1), &ng); le(UInt16(0), &ng); le(UInt64.max, &ng); le(UInt32(28), &ng)
        le(UInt32(1), &ng); le(UInt32(20), &ng); le(UInt16(1), &ng); le(UInt16(0), &ng); le(UInt32(256), &ng); le(UInt32(20), &ng)
        for time: UInt32 in [3_000_000, 5_000_000] {
            for value: UInt32 in [6, 36, 0, 0, time, 4, 4] { le(value, &ng) }
            ng.append(Data([0, 0, 0, 0])); le(UInt32(36), &ng)
        }
        let ngPath = captureDirectory.appendingPathComponent("fixture.pcapng").path
        try AtomicFile.write("", to: ngPath, mode: 0o600); try ng.write(to: URL(fileURLWithPath: ngPath))
        let ngRange = try PacketCaptureRange.read(ngPath, owner: getuid(), maximumBytes: 4096)
        try check(ngRange.packets == 2 && ngRange.earliest?.timeIntervalSince1970 == 3 && ngRange.latest?.timeIntervalSince1970 == 5,
                  "Native pcap-ng timestamp scan failed")
        ng.removeLast(2); try ng.write(to: URL(fileURLWithPath: ngPath))
        let partial = try PacketCaptureRange.read(ngPath, owner: getuid(), maximumBytes: 4096)
        try check(partial.readError != nil, "Truncated capture was reported as an intact time range")
        let alias = captureDirectory.appendingPathComponent("alias").path
        try FileManager.default.createSymbolicLink(atPath: alias, withDestinationPath: source)
        try rejects { _ = try PacketCaptureRange.read(alias, owner: getuid(), maximumBytes: 4_000_000) }
        try rejects { _ = try PacketCaptureRange.read(source, owner: getuid(), maximumBytes: 5) }
        chmod(source, 0o644)
        try rejects { _ = try PacketCaptureRange.read(source, owner: getuid(), maximumBytes: 4_000_000) }
        let fifo = captureDirectory.appendingPathComponent("fifo").path
        try check(mkfifo(fifo, 0o600) == 0, "Could not create unsafe-file fixture")
        try rejects { _ = try PacketCaptureRange.read(fifo, owner: getuid(), maximumBytes: 4096) }
    }
    print("PASS: actual pcap/pcap-ng ranges, retained history after capacity reduction, bounded rotation and unsafe files")

    let auditRow: [String: Any] = ["id": 7, "startDate": 100.0, "pid": 400, "remoteHost": "example.com:443",
                                  "policyName": "DIRECT", "outBytes": 10, "completed": false,
                                  "URL": "https://example.com/?secret=do-not-store", "headers": ["Authorization": "do-not-store"], "body": "do-not-store"]
    func requestBatch(_ row: [String: Any], pid: Int32 = 401) throws -> SurgeRequestAuditBatch {
        try SurgeRequestAuditBatch.parse(JSONSerialization.data(withJSONObject: ["active-requests": [row], "recent-requests": [row]]), surgePid: pid, started: 10, completed: 11)
    }
    let batch = try requestBatch(auditRow)
    try check(!JSON.encode(batch).contains("do-not-store") && batch.activeRequests[0].policyName == "DIRECT", "Request audit stored URL/header/body secrets or lost Surge DIRECT metadata")
    var requestHistory = SurgeRequestAuditHistory()
    try check(requestHistory.changes(batch).count == 1 && requestHistory.changes(batch).isEmpty, "Request audit lost first observation or flooded unchanged snapshots")
    var byteUpdate = auditRow; byteUpdate["outBytes"] = 30
    try check(requestHistory.changes(requestBatch(byteUpdate)).isEmpty, "Lifetime byte updates flooded request event history")
    byteUpdate["completed"] = true
    try check(requestHistory.changes(requestBatch(byteUpdate)).count == 1, "Request completion evidence was lost")
    byteUpdate["id"] = 8
    _ = requestHistory.changes(try requestBatch(byteUpdate))
    try check(requestHistory.recentWindowOverlap.hasPrefix("missing"), "Non-overlapping request history silently became complete")
    _ = requestHistory.changes(try requestBatch(byteUpdate, pid: 402))
    try check(requestHistory.recentWindowOverlap == "surge_process_changed", "Surge replacement lost request audit boundary")
    try rejects { _ = try SurgeRequestAuditBatch.parse(Data("{}".utf8), surgePid: 401, started: 10, completed: 11) }
    var invalidRequest = auditRow; invalidRequest["startDate"] = "bad"
    try rejects { _ = try requestBatch(invalidRequest) }
    print("PASS: Surge request metadata excludes secrets, distinguishes lifetime counts and exposes rolling/session history gaps")
    let dropEvent = "{\"event\":\"audit_capture_drops\",\"component\":\"PacketAudit\",\"time\":\"2026-01-01T00:00:00Z\",\"display_time_zone\":\"Asia/Singapore\",\"details\":{\"dropped_by_kernel\":3}}"
    let dropHuman = LogReader.format(dropEvent)
    try check(dropHuman.contains("2026-01-01 08:00:00.000 +08:00") && dropHuman.contains("内核抓包丢失：3 包") &&
              dropHuman.contains("没有记录到绕过不代表确认无绕过"), "Audit log lost configured time zone, capture loss or evidence boundary")
    let requestEvent: [String: Any] = ["event": "audit_surge_request", "details": ["request": try JSONSerialization.jsonObject(with: Data(JSON.encode(batch.recentRequests[0]).utf8))]]
    let requestLine = String(decoding: try JSONSerialization.data(withJSONObject: requestEvent), as: UTF8.self)
    try check(LogReader.format(requestLine).contains("DIRECT 也可能由 Surge 处理") && LogReader.format(requestLine).contains("不是本次增量"),
              "Surge request counts or DIRECT selection became a bypass claim")
    try check(LogReader.format(requestLine, json: true).contains("source_port") == false &&
              LogReader.format(requestLine, json: true).contains("policy_name"), "Audit JSON was rewritten or invented absent evidence")
    print("PASS: audit logs preserve configured display time zone, loss evidence and Surge request limitations")

    let egressHeader = ",interface,state,bytes_in,bytes_out,\n"
    let egressFirst = egressHeader + "Example.400,,,999,999,\ntcp4 192.168.1.2:5000<->1.1.1.1:443,en0,Established,999,999,\n"
    let egressDelta = egressHeader + "\"Example, Browser.400\",,,100,200,\n" +
        "tcp4 192.168.1.2:5000<->1.1.1.1:443,en0,Established,100,200,\n" +
        "tcp4 192.168.1.2:5001<->8.8.8.8:443,en0,Established,0,0,\n" +
        "tcp4 192.168.1.2:5002<->10.0.0.1:443,en0,Established,100,200,\n" +
        "tcp4 198.18.0.1:5003<->1.1.1.1:443,utun108,Established,100,200,\n" +
        "udp4 *:5004<->*:*,en0,,50,20,\n" +
        "tcp6 [2001:4860::1]:5005<->[2001:4860::8888]:443,en0,Established,30,40,\n" +
        "tcp6 2001:4860::1.5007<->2001:4860::8888.443,en0,Established,30,40,\n" +
        "udp4 *:*<->*:*,,,,,\n" +
        "tcp4 *:5008<->*:*,,Listen,,,\n" +
        "udp4 *:5009<->*:*,en0,,0,0,\n" +
        "udp4 *:5010<->*:*,en0,,1,0,\n" +
        "tcp4 192.168.1.2:5011<->1.1.1.1:443,,Established,1,2,\n" +
        "Surge.401,,,100,200,\ntcp4 192.168.1.2:5006<->1.0.0.1:443,en0,Established,100,200,\n"
    let observed = try EgressObservation.parse(egressFirst + egressDelta, surgeInterface: "utun108", surgePID: 401)
    try check(observed.flows.count == 6 && observed.flows.filter({ $0.destinationScope == "public" }).count == 3 &&
              observed.unresolvedActiveSockets == 2 && observed.unmeasuredSockets == 1 && observed.unattributedActiveSockets == 1,
              "Egress sample lost IPv4/IPv6/local/unknown activity or included Surge/idle sockets")
    try check(observed.flows[0].process == "Example, Browser" && observed.flows[0].sentBytes == 200,
              "Egress sample used lifetime totals or broke quoted process names")
    let transportNamedProcess = try EgressObservation.parse(egressFirst + egressDelta.replacingOccurrences(of: "Example, Browser.400", with: "tcp4 Client.400"),
                                                           surgeInterface: "utun108", surgePID: 401)
    try check(transportNamedProcess.flows.first?.process == "tcp4 Client", "Process name was mistaken for a socket row")
    let duplicateUDP = "udp4 *:5004<->*:*,en0,,50,20,\n"
    let reused = try EgressObservation.parse(egressFirst + egressDelta.replacingOccurrences(of: duplicateUDP, with: duplicateUDP + duplicateUDP),
                                            surgeInterface: "utun108", surgePID: 401)
    try check(reused.flows.first(where: { $0.localEndpoint == "*:5004" })?.sentBytes == 40,
              "Reused UDP tuple discarded activity or disabled the observer")
    let encodedEgress = try JSON.encode(observed)
    try check(try JSON.decode(EgressObservation.self, from: Data(encodedEgress.utf8)).flows == observed.flows, "Egress JSON did not round trip")
    for invalid in [egressFirst, egressHeader + egressHeader, egressFirst + egressDelta.replacingOccurrences(of: "100,200,\n", with: "bad,200,\n"),
                    egressFirst + egressDelta.replacingOccurrences(of: "Surge.401", with: "invalid-process"), egressFirst + "\"unterminated\n"] {
        try rejects { _ = try EgressObservation.parse(invalid, surgeInterface: "utun108", surgePID: 401) }
    }
    for address in ["10.0.0.1", "127.0.0.1", "169.254.1.1", "172.16.0.1", "192.168.1.1", "100.64.0.1", "198.18.1.1",
                    "192.0.2.1", "198.51.100.1", "203.0.113.1", "224.0.0.251", "::1", "fe80::1", "fd00::1", "ff02::1", "2001:db8::1", "not-an-ip"] {
        try check(!EgressObservation.isPublicAddress(address), "Non-public egress address was reported as public: \(address)")
    }
    for address in ["1.1.1.1", "8.8.8.8", "2001:4860::8888", "::ffff:1.1.1.1", "64:ff9b::101:101"] {
        try check(EgressObservation.isPublicAddress(address), "Public egress address was silently missed: \(address)")
    }
    var egressHistory = EgressHistory()
    try check(egressHistory.newActivity(observed.flows, now: 10).count == 6, "First egress evidence was suppressed")
    try check(egressHistory.newActivity(observed.flows, now: 11).isEmpty, "Unchanged egress flooded the event log")
    try check(egressHistory.newActivity(observed.flows, now: 310).count == 6, "Continued egress could never be recorded again")
    let churn = (1...25).map { index -> EgressFlow in var flow = observed.flows[0]; flow.pid = Int32(index); return flow }
    try check(egressHistory.newActivity(churn, now: 311).count == 20, "Egress batch did not bound connection churn")
    var egressDetails = try JSONSerialization.jsonObject(with: Data(encodedEgress.utf8)) as! [String: Any]
    egressDetails["flows"] = (egressDetails["flows"] as! [[String: Any]]).map { value in
        var value = value; value["process_kind"] = "system_extension"; return value
    }
    let egressRecord: [String: Any] = ["event": "egress_path_observed", "details": egressDetails]
    let egressLine = String(decoding: try JSONSerialization.data(withJSONObject: egressRecord), as: UTF8.self)
    try check(LogReader.format(egressLine).contains("系统扩展") && LogReader.format(egressLine).contains("200 字节") &&
              LogReader.format(egressLine).contains("en0"), "Readable egress log lost classification or evidence")
    let dnsFixture = Data("{\"dnsCache\":[{\"domain\":\"example.com\",\"data\":[\"1.1.1.1\",\"1.0.0.1\"]},{\"domain\":\"cdn.example.com\",\"data\":[\"1.1.1.1\"]}],\"local\":[{\"domain\":\"router.local\",\"data\":\"192.168.1.1\"}]}".utf8)
    let vipFixture = Data("{\"items\":[{\"domain\":\"vip.example.com\",\"IP\":\"198.18.0.10\"}]}".utf8)
    let domainMap = try EgressObservation.parseSurgeDomains(dnsFixture, source: "dns")
        .merging(EgressObservation.parseSurgeDomains(vipFixture, source: "virtual_ip")) { $0 + $1 }
    try check(domainMap["1.1.1.1"] == ["cdn.example.com", "example.com"] &&
              domainMap["192.168.1.1"] == ["router.local"] &&
              domainMap["198.18.0.10"] == ["vip.example.com"],
              "Surge DNS cache / virtual IP domain lookup failed")
    var domainFlow = (egressDetails["flows"] as! [[String: Any]])[0]
    domainFlow["candidate_domains"] = ["cdn.example.com", "example.com"]
    let domainEvent = String(decoding: try JSONSerialization.data(withJSONObject: ["event": "egress_path_observed", "details": ["flows": [domainFlow]]]), as: UTF8.self)
    try check(LogReader.format(domainEvent).contains("Surge DNS 缓存候选域名：cdn.example.com, example.com") &&
              LogReader.format(domainEvent).contains("不代表已确认该连接请求的域名"),
              "Readable egress log omitted or overstated Surge DNS candidate domains")
    try check(LogReader.format(egressLine, json: true).contains("remote_endpoint"), "Machine egress log lost endpoint evidence")
    let discoveryDelta = egressHeader + "Discovery Service.402,,,0,0,\n" +
        "udp6 *.5353<->*.*,awdl0,,45,0,\n" +
        "udp4 *:5353<->*:*,en0,,267,0,\n" +
        "Example Player.403,,,0,0,\n" +
        "udp6 *.5353<->*.*,awdl0,,0,45,\n" +
        "udp4 *:5353<->*:*,en0,,267,45,\n" +
        "udp4 *:60000<->*:*,en0,,297,125,\n" +
        "udp6 *.5353<->*.*,llw0,,45,45,\n"
    let discovery = try EgressObservation.parse(egressFirst + discoveryDelta, surgeInterface: "utun108", surgePID: 401)
    let discoveryDetails = try JSONSerialization.jsonObject(with: Data(JSON.encode(discovery).utf8))
    let discoveryRecord: [String: Any] = ["event": "egress_path_observed", "details": discoveryDetails]
    let discoveryLine = String(decoding: try JSONSerialization.data(withJSONObject: discoveryRecord, options: [.sortedKeys, .withoutEscapingSlashes]), as: UTF8.self)
    let discoveryHuman = LogReader.format(discoveryLine)
    try check(discovery.flows.count == 6 && discovery.flows.allSatisfy({ $0.destinationScope == "unresolved" }),
              "A local service port falsely established a known remote destination")
    try check(discoveryHuman.contains("仅有接收计数") && discoveryHuman.contains("有发送计数") &&
              discoveryHuman.contains("本地端点：*:60000") && discoveryHuman.contains("本地端点：*.5353") &&
              discoveryHuman.components(separatedBy: "mDNS 常用端口").count - 1 == 5 &&
              discoveryHuman.components(separatedBy: "无法区分局域网与公网").count - 1 == 6,
              "Unknown UDP evidence lost direction, local endpoint or qualified service-port hint")
    for human in [discoveryHuman, LogReader.format(egressLine)] {
        try check(human.contains("未验证数据包实际路径") && human.contains("nettop 报告接口") &&
                  !human.contains("公网直出") && !human.contains("已确认绕过"),
                  "Socket/interface counters were presented as proof of the actual packet path")
    }
    try check(LogReader.format(discoveryLine, json: true) == discoveryLine,
              "Human evidence correction rewrote the original machine record")
    let timingRecord: [String: Any] = ["event": "gate_changed", "time": "2026-01-01T00:00:00.123Z", "message": "signed Surge process missing",
                                     "details": ["exit_event_to_block_verified_ms": 22.5]]
    let timingLine = String(decoding: try JSONSerialization.data(withJSONObject: timingRecord), as: UTF8.self)
    try check(LogReader.format(timingLine).contains("00.123") && LogReader.format(timingLine).contains("22.5 毫秒"), "Exit-event timing or millisecond timestamp lost in readable logs")
    print("PASS: sampled egress uses new byte activity, separates Surge/local/unknown sockets and retains bounded deduplicated evidence")

    var sending = observed.flows.first(where: { $0.destinationScope == "public" })!
    var receiving = sending; receiving.sentBytes = 0
    var extensionFlow = sending; extensionFlow.processKind = "system_extension"
    try check(sending.category == "public_send_review" && receiving.category == "public_receive_only" &&
              extensionFlow.category == "system_extension" && discovery.flows.allSatisfy({ $0.category == "unresolved_peer" }),
              "Traffic evidence confused public sends, receive-only, independent extensions or unknown peers")
    var transitions = EgressHistory()
    try check(transitions.newActivity([receiving], now: 1, context: "allowed:1").count == 1, "Initial receiving evidence missing")
    try check(transitions.newActivity([sending], now: 2, context: "allowed:1").count == 1, "Receive-to-send escalation was deduplicated away")
    try check(transitions.newActivity([sending], now: 3, context: "allowed:1").isEmpty, "Identical evidence was repeated")
    try check(transitions.newActivity([sending], now: 4, context: "blocked:2").count == 1, "Firewall transition hid repeated socket activity")
    var unknownReceive = discovery.flows[0]; unknownReceive.sentBytes = 0
    var unknownSend = unknownReceive; unknownSend.sentBytes = 45
    try check(transitions.newActivity([unknownReceive], now: 5).count == 1 && transitions.newActivity([unknownSend], now: 6).count == 1,
              "Unknown-peer receive-to-send escalation was hidden by dedup")
    var bounded = EgressHistory()
    _ = bounded.newActivity(churn, now: 1)
    try check(bounded.limited == 5 && bounded.deduplicated == 0, "Evidence cap did not expose omitted new records")
    _ = bounded.newActivity(churn, now: 2)
    try check(bounded.limited == 0 && bounded.deduplicated == 20, "Capped evidence was marked as already recorded")
    let receiveChurn = churn.map { flow -> EgressFlow in var flow = flow; flow.sentBytes = 0; return flow }
    sending.pid = 900
    var priority = EgressHistory()
    try check(priority.newActivity(receiveChurn + [sending], now: 1).first?.pid == 900, "Receive-only activity crowded out public sending evidence")
    var changedDetails = egressDetails
    changedDetails["guard_state_at_start"] = "allowed"; changedDetails["guard_state_at_end"] = "blocked"
    changedDetails["guard_state_during_sample"] = "changed"; changedDetails["guard_state_at_log"] = "blocked"
    changedDetails["limited_flows"] = 3
    let changedLine = String(decoding: try JSONSerialization.data(withJSONObject: ["event": "egress_path_observed", "details": changedDetails]), as: UTF8.self)
    let changedHuman = LogReader.format(changedLine)
    try check(changedHuman.contains("采样关联窗口发生切换") && changedHuman.contains("不按结束状态归因整段流量") && changedHuman.contains("另有 3 条"),
              "Mixed-state or capped sample was presented as complete blocked traffic")
    try check(LogReader.format(egressLine).contains("未跟踪切换"), "Historical samples invented a verified firewall timeline")
    print("PASS: traffic evidence escalations survive dedup, priority/caps are explicit and mixed-state samples remain unassigned")

    let pfZero = try PFBlockCounters.parse("surge-guard-block 0 0 0 0 0 0 0\n")
    let pfCount = try PFBlockCounters.parse("other-label 0 0 0 0 0 0 0\nsurge-guard-block 10 3 300 1 100 2 200\n")
    try check(pfCount.packets == 3 && pfCount.bytes == 300 && pfCount.outPackets == 2 && pfCount.inPackets == 1 &&
              pfCount.delta(since: pfZero) == pfCount && pfCount.delta(since: pfCount) == pfZero,
              "Own PF label counters or directional deltas were misread")
    for invalid in ["", "other-label 1 3 300 1 100 2 200", "surge-guard-block 10 3 300 1 100 2 200\nsurge-guard-block 10 3 300 1 100 2 200",
                    "surge-guard-block 10 bad 300 1 100 2 200", "surge-guard-block 10 4 300 1 100 2 200",
                    "surge-guard-block 10 3 300 1 100 2 200 0", "surge-guard-block 10 0 0 18446744073709551615 0 1 0"] {
        try rejects { _ = try PFBlockCounters.parse(invalid) }
    }
    try rejects { _ = try pfZero.delta(since: pfCount) }
    let countDetails: [String: Any] = ["block_id": "example-period", "phase": "before_allow", "counter_continuity": false, "delta_has_baseline": false,
                                     "totals": try JSONSerialization.jsonObject(with: Data(JSON.encode(pfCount).utf8)),
                                     "delta": try JSONSerialization.jsonObject(with: Data(JSON.encode(pfCount).utf8))]
    let countLine = String(decoding: try JSONSerialization.data(withJSONObject: ["event": "pf_block_traffic", "details": countDetails]), as: UTF8.self)
    let countHuman = LogReader.format(countLine)
    try check(countHuman.contains("3 包 / 300 字节") && countHuman.contains("入站 1 包，出站 2 包") &&
              countHuman.contains("不能累加成完整历史") && countHuman.contains("未计入的命中") && countHuman.contains("零计数也不能证明没有绕过"),
              "PF counter log lost direction, reset/read boundaries or evidence limits")
    try check(countHuman.contains("基线未知，不能作为增量"), "Counter recovery invented an incremental baseline")
    try check(LogReader.format(countLine, json: true).contains("out_packets"), "Machine PF counter evidence was lost")
    let counterFailure = "{\"event\":\"pf_block_observation_failed\",\"message\":\"permission denied\",\"details\":{}}"
    try check(LogReader.format(counterFailure).contains("原有防火墙策略不变"), "Counter read failure was confused with firewall failure")
    print("PASS: PF counter evidence parses only the own label, preserves directions and rejects missing, reset, overflow or ambiguous data")

    let atomicDirectory = FileManager.default.temporaryDirectory.appendingPathComponent("surge-atomic-test-" + UUID().uuidString)
    do {
        try UserPaths.prepare(atomicDirectory.path)
        defer { try? FileManager.default.removeItem(at: atomicDirectory) }
        let path = atomicDirectory.appendingPathComponent("status.json").path
        let values = [String(repeating: "A", count: 4096), String(repeating: "B", count: 8192)]
        let originalMask = umask(0o077)
        defer { umask(originalMask) }
        try AtomicFile.write(values[0], to: path, mode: 0o644)
        final class WriteResult: @unchecked Sendable { var failure: String? }
        let result = WriteResult(), completed = DispatchGroup()
        completed.enter()
        DispatchQueue.global().async {
            defer { completed.leave() }
            do { for index in 0..<150 { try AtomicFile.write(values[index % 2], to: path, mode: 0o644) } }
            catch { result.failure = String(describing: error) }
        }
        var unreadable = false, incomplete = false, samples = 0
        while completed.wait(timeout: .now()) != .success {
            var info = stat()
            if lstat(path, &info) != 0 || info.st_mode & 0o777 != 0o644 { unreadable = true }
            if let value = try? String(contentsOfFile: path), values.contains(value) {} else { incomplete = true }
            samples += 1
        }
        try check(result.failure == nil && samples > 0 && !unreadable && !incomplete,
                  "Atomic publication exposed wrong permissions or incomplete content: \(result.failure ?? "reader failure")")
        try AtomicFile.write("private", to: path, mode: 0o600)
        var info = stat(); lstat(path, &info)
        try check(info.st_mode & 0o777 == 0o600, "Private state permissions were widened")
    }
    print("PASS: atomic state publication keeps final permissions and complete content under restrictive umask")
    let lockURL = FileManager.default.temporaryDirectory.appendingPathComponent("surge-guard-lock-test-" + UUID().uuidString)
    do {
        let first = open(lockURL.path, O_CREAT | O_RDWR, 0o600)
        let second = open(lockURL.path, O_RDWR)
        guard first >= 0, second >= 0 else { throw GuardError("Cannot create lock fixture") }
        defer { close(first); close(second); try? FileManager.default.removeItem(at: lockURL) }
        try RuntimeLock.acquire(first, timeout: 0)
        let beforeLocks = (try? FileManager.default.contentsOfDirectory(atPath: "/dev/fd").count) ?? 0
        for _ in 0..<100 {
            let blocked = open(lockURL.path, O_RDWR | O_CLOEXEC)
            try rejects { _ = try RuntimeLock(taking: blocked) }
            try check(fcntl(blocked, F_GETFD) == -1 && errno == EBADF, "Failed lock initializer retained its FD")
        }
        let afterLocks = (try? FileManager.default.contentsOfDirectory(atPath: "/dev/fd").count) ?? 0
        try check(afterLocks <= beforeLocks + 1, "Failed lock construction leaked descriptors")
        try rejects { try RuntimeLock.acquire(second, timeout: 0.06) }
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.1) { flock(first, LOCK_UN) }
        try RuntimeLock.acquire(second, timeout: 1)
        flock(second, LOCK_UN)
    }
    print("PASS: delayed daemon lock release waits successfully; occupied lock times out")
    let directoryFixture = FileManager.default.temporaryDirectory.appendingPathComponent("surge-gate-directory-test-" + UUID().uuidString)
    do {
        defer { try? FileManager.default.removeItem(at: directoryFixture) }
        try UserPaths.prepare(directoryFixture.path)
        try UserPaths.prepare(directoryFixture.path)
        let bin = directoryFixture.appendingPathComponent("bin").path
        try UserPaths.prepare(bin)
        try UserPaths.prepare(bin)
        let regularFile = directoryFixture.appendingPathComponent("regular").path
        try "".write(toFile: regularFile, atomically: true, encoding: .utf8)
        try rejects { try UserPaths.prepare(regularFile) }
        let link = directoryFixture.appendingPathComponent("link").path
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: bin)
        try rejects { try UserPaths.prepare(link) }
    }
    print("PASS: user installer accepts existing bin directories and rejects files/symlinks")
    let backup = try BackupManifest(kind: "update")
    try JSON.decode(BackupManifest.self, from: Data(JSON.encode(backup).utf8)).validate()
    let launcherBackup = try BackupManifest(kind: "update", includesLauncher: true)
    try JSON.decode(BackupManifest.self, from: Data(JSON.encode(launcherBackup).utf8)).validate()
    try check(launcherBackup.version == 2 && launcherBackup.files.last == "surge-guard-launch", "Dedicated launcher was omitted from update recovery")
    try rejects { _ = try BackupManifest(kind: "policy", includesLauncher: true) }
    var invalidBackup = try JSONSerialization.jsonObject(with: Data(JSON.encode(backup).utf8)) as! [String: Any]
    for (field, value) in [("id", "../outside" as Any), ("kind", "unknown" as Any), ("files", ["/etc/pf.conf"] as Any)] {
        var modified = invalidBackup; modified[field] = value
        try rejects { try JSON.decode(BackupManifest.self, from: JSONSerialization.data(withJSONObject: modified)).validate() }
    }
    invalidBackup["files"] = []
    try rejects { try JSON.decode(BackupManifest.self, from: JSONSerialization.data(withJSONObject: invalidBackup)).validate() }
    print("PASS: recovery manifests reject path traversal, arbitrary destinations and incomplete backups")

    let actionFixture = FileManager.default.temporaryDirectory.appendingPathComponent("surge-guard-menu-test-" + UUID().uuidString)
    do {
        try FileManager.default.createDirectory(at: actionFixture, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: actionFixture) }
        let directory = actionFixture.path
        let mock = directory + "/mock"
        // The real script runs only against these fake tools; no sudo/PF/service mutation.
        let mockScript = """
        #!/bin/sh
        kind=$1; shift
        printf '%s %s\\n' "$kind" "$*" >> '\(directory)/calls'
        case "$kind" in
          id) echo 501 ;;
          sudo) case "$1" in -v) if [ -f '\(directory)/auth-failed' ]; then exit 1; fi; exit 0 ;; -n) shift ;; esac; exec "$@" ;;
          guard) case "$1" in
            --help) if [ -f '\(directory)/maintenance-capable' ]; then echo 'restore-policy os-update-begin'; else echo legacy; fi ;;
            os-update-begin|os-update-end) if [ -f '\(directory)/maintenance-failed' ]; then exit 7; fi ;;
            check) exit 0 ;;
          esac ;;
          launchctl)
            if [ "$1" = print ] && [ -f '\(directory)/second-failed' ]; then
              if [ -f '\(directory)/queried' ]; then echo 'Service query failed'; exit 5; fi
              touch '\(directory)/queried'
            fi
            if [ "$1" = print ] && [ -f '\(directory)/waiting' ] && [ ! -f '\(directory)/stopped' ]; then echo 'state = waiting'; exit 0; fi
            if [ "$1" = print ] && [ -f '\(directory)/query-failed' ]; then echo 'Service query failed' >&2; exit 5; fi
            if [ "$1" = print ] && [ -f '\(directory)/malformed-state' ]; then echo 'pid = 1234'; exit 0; fi
            if [ "$1" = print ] && [ -f '\(directory)/oversized-pid' ]; then printf 'state = running\\npid = 2147483648\\n'; exit 0; fi
            if [ "$1" = print ] && [ -f '\(directory)/missing-pid' ]; then echo 'state = running'; exit 0; fi
            if [ "$1" = print ] && [ -f '\(directory)/absent' ]; then echo 'Could not find service' >&2; exit 113; fi
            case "$1" in
              print) if [ -f '\(directory)/stopped' ]; then echo 'Could not find service'; exit 113; fi; echo 'state = running'; if [ -f '\(directory)/restarted' ]; then echo 'pid = 5678'; else echo 'pid = 1234'; fi ;;
              bootout) touch '\(directory)/stopped' ;;
              kill) touch '\(directory)/restarted' ;;
            esac ;;
          kill)
            if [ -f '\(directory)/stuck' ]; then exit 0; fi
            if [ ! -f '\(directory)/exited' ]; then touch '\(directory)/exited'; exit 0; fi
            exit 1 ;;
          lockf)
            if [ -f '\(directory)/lock-busy' ]; then exit 75; fi
            shift 4; exec "$@" ;;
          logger|pfctl) exit 0 ;;
          tail)
            if [ -f '\(directory)/tail-failed' ]; then exit 5; fi
            printf '%s\\n' '{"event":"gate_state","message":"0 application(s) pending"}' ;;
          sleep) exit 0 ;;
        esac
        """
        try mockScript.write(toFile: mock, atomically: true, encoding: .utf8)
        chmod(mock, 0o700)
        let project = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        var script = try String(contentsOf: project.appendingPathComponent("integrations/swiftbar/surge-guard-action.sh"))
        script = script.replacingOccurrences(of: "guard_bin=/Library/PrivilegedHelperTools/surge-guard", with: "guard_bin='\(directory)/guard'")
        for tool in ["launchctl", "kill", "sleep", "pfctl", "tail", "lockf", "logger"] {
            let original = tool == "pfctl" ? "/sbin/pfctl" : ["tail", "lockf", "logger"].contains(tool) ? "/usr/bin/" + tool : "/bin/" + tool
            script = script.replacingOccurrences(of: original, with: "'\(directory)/\(tool)'")
        }
        script = script.replacingOccurrences(of: "sudo ", with: "'\(directory)/sudo' ")
        script = script.replacingOccurrences(of: "$(id -u)", with: "$('\(directory)/id' -u)")
        let rendererPath = directory + "/renderer"
        script = script.replacingOccurrences(of: "renderer=\"$HOME/Library/Application Support/SurgeGuard/bin/surge-guard-ui\"", with: "renderer='\(rendererPath)'")
        let gatePath = directory + "/gate"
        script = script.replacingOccurrences(of: "gate_bin=\"$HOME/Library/Application Support/SurgeGuard/bin/surge-gate\"", with: "gate_bin='\(gatePath)'")
        try "#!/bin/sh\nprintf 'gate %s\\n' \"$*\" >> '\(directory)/calls'\nif [ -f '\(directory)/gate-failed' ]; then exit 9; fi\n".write(toFile: gatePath, atomically: true, encoding: .utf8)
        chmod(gatePath, 0o700)
        let rendererScript = "#!/bin/sh\nprintf 'renderer %s\\n' \"$*\" >> '\(directory)/calls'\nprintf 'rendered: '\n/bin/cat\n"
        try rendererScript.write(toFile: rendererPath, atomically: true, encoding: .utf8); chmod(rendererPath, 0o700)
        for tool in ["guard", "sudo", "launchctl", "kill", "sleep", "pfctl", "tail", "id", "lockf", "logger"] {
            let wrapper = "#!/bin/sh\nexec '\(mock)' \(tool) \"$@\"\n"
            let path = directory + "/" + tool
            try wrapper.write(toFile: path, atomically: true, encoding: .utf8); chmod(path, 0o700)
        }
        let testScript = directory + "/action.sh"
        try script.write(toFile: testScript, atomically: true, encoding: .utf8)
        for action in ["diagnose", "diagnose-watch"] {
            try "".write(toFile: directory + "/calls", atomically: true, encoding: .utf8)
            let result = try Command.run("/bin/bash", [testScript, action], timeout: 5)
            let diagnosticCalls = try String(contentsOfFile: directory + "/calls")
            let expected = action == "diagnose" ? "renderer diagnose\n" : "renderer diagnose --watch-seconds 120\n"
            try check(result.status == 0 && diagnosticCalls.contains(expected) && !diagnosticCalls.contains("guard ") &&
                      !diagnosticCalls.contains("pfctl") && !diagnosticCalls.contains("sudo " + rendererPath),
                      "Diagnostic menu queried the guard, changed PF or ran the user collector as root")
        }
        try "".write(toFile: directory + "/auth-failed", atomically: true, encoding: .utf8)
        let partialDiagnostic = try Command.run("/bin/bash", [testScript, "diagnose"], timeout: 5)
        try check(partialDiagnostic.status == 0 && partialDiagnostic.output.contains("证据并标明缺口"),
                  "Cancelled private-log authentication prevented partial diagnostics")
        try FileManager.default.removeItem(atPath: directory + "/auth-failed")
        for action in ["gate-update-pause", "gate-update-resume"] {
            let completed = try Command.run("/bin/bash", [testScript, action], timeout: 5)
            try check(completed.status == 0 && completed.output.contains("Gate 已确认"), "Upgrade guidance did not wait for successful Gate acknowledgement")
            try "".write(toFile: directory + "/gate-failed", atomically: true, encoding: .utf8)
            let failed = try Command.run("/bin/bash", [testScript, action], timeout: 5)
            try check(failed.status != 0 && !failed.output.contains("Gate 已确认"), "Upgrade action claimed success after a Gate error")
            try FileManager.default.removeItem(atPath: directory + "/gate-failed")
        }
        try "".write(toFile: directory + "/calls", atomically: true, encoding: .utf8)
        let recovered = try Command.run("/bin/sh", [testScript, "unlock"], timeout: 10)
        try check(recovered.status == 0 && recovered.output.contains("Protection is OFF"), "Offline recovery failed against legacy fixture: \(recovered.combined)")
        let calls = try String(contentsOfFile: directory + "/calls")
        try check(calls.range(of: "kill -0")!.lowerBound < calls.range(of: "pfctl -a io.github.surge-guard -F rules")!.lowerBound, "Rules cleared before daemon exit check")
        try check(calls.contains("lockf -k -t 20 /private/var/db/surge-guard/management.lock") &&
                  calls.contains("lockf -k -t 20 /private/var/db/surge-guard/lock") && calls.contains("manual_unlock"),
                  "Independent recovery bypassed management/runtime locking or lost its system-log event")
        try "".write(toFile: directory + "/lock-busy", atomically: true, encoding: .utf8)
        try "".write(toFile: directory + "/calls", atomically: true, encoding: .utf8)
        let busyRecovery = try Command.run("/bin/bash", [testScript, "unlock"], timeout: 5)
        try check(busyRecovery.status != 0 && !String(contentsOfFile: directory + "/calls").contains("\npfctl -a"),
                  "Independent recovery cleared rules despite a concurrent management/daemon lock")
        try FileManager.default.removeItem(atPath: directory + "/lock-busy")
        try FileManager.default.removeItem(atPath: directory + "/stopped")
        let restarted = try Command.run("/bin/sh", [testScript, "restart"], timeout: 10)
        try check(restarted.status == 0 && restarted.output.contains("pid=5678"), "Legacy restart did not wait for new PID: \(restarted.combined)")
        let restartCalls = try String(contentsOfFile: directory + "/calls")
        try check(restartCalls.contains("kill SIGTERM") && !restartCalls.contains("kickstart"), "Legacy restart used a forced restart")
        try "".write(toFile: directory + "/stuck", atomically: true, encoding: .utf8)
        try "".write(toFile: directory + "/calls", atomically: true, encoding: .utf8)
        let refused = try Command.run("/bin/sh", [testScript, "unlock"], timeout: 10)
        try check(refused.status != 0 && !String(contentsOfFile: directory + "/calls").contains("-F rules"), "Recovery cleared rules while old daemon was alive")
        try FileManager.default.removeItem(atPath: directory + "/stuck")
        try FileManager.default.removeItem(atPath: directory + "/stopped")
        try "".write(toFile: directory + "/calls", atomically: true, encoding: .utf8)
        let independent = try Command.run("/bin/bash", [testScript, "unlock"], timeout: 10)
        let independentCalls = try String(contentsOfFile: directory + "/calls")
        let binaryIndependent = independent.status == 0 && !independentCalls.contains("guard --help")
        try "".write(toFile: directory + "/query-failed", atomically: true, encoding: .utf8)
        try "".write(toFile: directory + "/calls", atomically: true, encoding: .utf8)
        let failedQuery = try Command.run("/bin/bash", [testScript, "unlock"], timeout: 10)
        let failedQueryCalls = try String(contentsOfFile: directory + "/calls")
        let queryFailureSafe = failedQuery.status != 0 && !failedQueryCalls.contains("-F rules")
        try check(binaryIndependent && queryFailureSafe, "Recovery depends on guard help or flushes after an unknown query: binaryIndependent=\(binaryIndependent), queryFailureSafe=\(queryFailureSafe)")
        try FileManager.default.removeItem(atPath: directory + "/query-failed")
        for fixture in ["malformed-state", "oversized-pid"] {
            try "".write(toFile: directory + "/" + fixture, atomically: true, encoding: .utf8)
            try "".write(toFile: directory + "/calls", atomically: true, encoding: .utf8)
            let malformed = try Command.run("/bin/bash", [testScript, "unlock"], timeout: 10)
            try check(malformed.status != 0 && !String(contentsOfFile: directory + "/calls").contains("-F rules"), "Malformed service query allowed anchor clearing")
            try FileManager.default.removeItem(atPath: directory + "/" + fixture)
        }

        try "".write(toFile: directory + "/missing-pid", atomically: true, encoding: .utf8)
        try "".write(toFile: directory + "/calls", atomically: true, encoding: .utf8)
        let missingPID = try Command.run("/bin/bash", [testScript, "unlock"], timeout: 10)
        try check(missingPID.status != 0 && !String(contentsOfFile: directory + "/calls").contains("-F rules"), "Recovery flushed without a known running PID")
        try FileManager.default.removeItem(atPath: directory + "/missing-pid")
        try "".write(toFile: directory + "/absent", atomically: true, encoding: .utf8)
        let absent = try Command.run("/bin/bash", [testScript, "unlock"], timeout: 10)
        try check(absent.status == 0, "Known missing service blocked independent recovery")
        try "".write(toFile: directory + "/calls", atomically: true, encoding: .utf8)
        try FileManager.default.removeItem(atPath: directory + "/absent")
        try FileManager.default.removeItem(atPath: directory + "/stopped")
        for marker in ["waiting", "second-failed"] { try "".write(toFile: directory + "/" + marker, atomically: true, encoding: .utf8) }
        let secondFailure = try Command.run("/bin/bash", [testScript, "unlock"], timeout: 10)
        let secondCalls = try String(contentsOfFile: directory + "/calls")
        try check(secondFailure.status != 0 && secondCalls.contains("launchctl bootout") && !secondCalls.contains("-F rules"),
                  "Second service-query failure cleared rules after a waiting job")
        for marker in ["second-failed", "queried", "stopped"] { try FileManager.default.removeItem(atPath: directory + "/" + marker) }
        try "".write(toFile: directory + "/calls", atomically: true, encoding: .utf8)
        let waitingRecovery = try Command.run("/bin/bash", [testScript, "unlock"], timeout: 10)
        let waitingCalls = try String(contentsOfFile: directory + "/calls")
        try check(waitingRecovery.status == 0 && waitingCalls.contains("launchctl bootout"), "Loaded waiting job was not removed before clearing rules")
        try "".write(toFile: directory + "/calls", atomically: true, encoding: .utf8)
        let logBridge = try Command.run("/bin/bash", [testScript, "logs"], timeout: 10)
        let logCalls = try String(contentsOfFile: directory + "/calls")
        try check(logBridge.status == 0 && logBridge.output.contains("rendered: {") && logCalls.contains("renderer format-logs"), "System log reader bypassed the user formatter")
        try check(logCalls.contains("sudo \(directory)/tail -n 200 /private/var/db/surge-guard/events.log") && !logCalls.contains("sudo \(rendererPath)"), "User formatter was invoked with sudo")
        try check(!logCalls.contains("guard --help"), "Independent log access queried the potentially broken guard executable")
        for action in ["update-pause", "update-resume", "start", "stop"] {
            try "".write(toFile: directory + "/calls", atomically: true, encoding: .utf8)
            let updateBridge = try Command.run("/bin/bash", [testScript, "gate-" + action], timeout: 10)
            let updateCalls = try String(contentsOfFile: directory + "/calls")
            try check(updateBridge.status == 0 && updateCalls.contains("gate " + action) &&
                      !updateCalls.contains("sudo") && !updateCalls.contains("guard ") && !updateCalls.contains("pfctl"),
                      "Gate update action touched privileged firewall recovery")
        }
        for (action, file) in [("audit-logs", "events.log"), ("audit-requests", "requests.log")] {
            try "".write(toFile: directory + "/calls", atomically: true, encoding: .utf8)
            let auditBridge = try Command.run("/bin/bash", [testScript, action], timeout: 10)
            let auditCalls = try String(contentsOfFile: directory + "/calls")
            try check(auditBridge.status == 0 && auditCalls.contains("/private/var/db/surge-guard/packet-audit/" + file) &&
                      auditCalls.contains("renderer format-logs") && !auditCalls.contains("guard --help") && !auditCalls.contains("sudo \(rendererPath)"),
                      "Audit log bridge queried guard or ran the user formatter with privileges")
        }
        try "".write(toFile: directory + "/tail-failed", atomically: true, encoding: .utf8)
        try check(try Command.run("/bin/bash", [testScript, "logs"], timeout: 10).status != 0, "Log pipeline concealed a failed privileged reader")
        let plugin = try String(contentsOf: project.appendingPathComponent("integrations/swiftbar/surge-guard.5s.sh"))
        let pluginPath = directory + "/plugin.sh"
        try ("HOME='\(directory)'\n" + plugin).write(toFile: pluginPath, atomically: true, encoding: .utf8)
        let fallback = try Command.checked("/bin/sh", [pluginPath, "--section"])
        try check(fallback.contains("param1=unlock") && fallback.contains("param1=os-update-end") && !fallback.contains("---"),
                  "Missing independent recovery/maintenance fallback when renderer is absent")
        for action in ["os-update-begin", "os-update-end"] {
            try "".write(toFile: directory + "/calls", atomically: true, encoding: .utf8)
            let legacy = try Command.run("/bin/bash", [testScript, action])
            let legacyCalls = try String(contentsOfFile: directory + "/calls")
            try check(legacy.status != 0 && !legacyCalls.contains("sudo") && !legacyCalls.contains("pfctl"),
                      "Maintenance action attempted privileged changes with an unsupported guard")
            try "".write(toFile: directory + "/maintenance-capable", atomically: true, encoding: .utf8)
            try "".write(toFile: directory + "/calls", atomically: true, encoding: .utf8)
            let supported = try Command.run("/bin/bash", [testScript, action])
            let supportedCalls = try String(contentsOfFile: directory + "/calls")
            try check(supported.status == 0 && supportedCalls.contains("sudo \(directory)/guard " + action) &&
                      !supportedCalls.contains("pfctl"), "Maintenance action did not delegate only to the installed root helper")
            if action == "os-update-begin" {
                try check(supported.output.contains("ALL applications across reboots"), "Maintenance menu omitted the direct-access scope")
            }
            try "".write(toFile: directory + "/maintenance-failed", atomically: true, encoding: .utf8)
            try check(try Command.run("/bin/bash", [testScript, action]).status == 7, "Maintenance menu concealed helper failure")
            for marker in ["maintenance-failed", "maintenance-capable"] { try FileManager.default.removeItem(atPath: directory + "/" + marker) }
        }
    }
    print("PASS: offline legacy recovery waits for exit and refuses to flush while daemon remains alive")
    print("PASS: emergency recovery avoids the guard executable and refuses unknown queries or missing running PIDs")
    print("PASS: SwiftBar log bridge formats without sudo and propagates privileged-reader failure")
    print("PASS: maintenance menu checks installed capabilities, warns about all apps, retains fallback and propagates failure")

    for mask in 0..<64 {
        let state = Readiness(trustedProcess: mask & 1 != 0,
                              surgeService: mask & 2 != 0, connected: mask & 4 != 0,
                              vifUp: mask & 8 != 0, ownsDefaultRoute: mask & 16 != 0,
                              ipv6Safe: mask & 32 != 0)
        try check(state.ready == (mask == 63), "Incorrect readiness for mask \(mask)")
        try check(state.reasons.isEmpty == (mask == 63), "Missing failure reason")
    }
    print("PASS: all 64 readiness combinations")

    try check(Probe.connectionLossReason(.connected) == nil, "Connected tunnel was classified as a loss")
    for (status, expected) in [(SCNetworkConnectionStatus.disconnecting, "surge_tunnel_disconnecting"),
                               (.disconnected, "surge_tunnel_disconnected"), (.connecting, "surge_tunnel_connecting"),
                               (.invalid, "surge_tunnel_status_unknown")] {
        try check(Probe.connectionLossReason(status) == expected, "Non-connected tunnel could bypass loss blocking")
    }
    let lossRecord: [String: Any] = ["event": "readiness_loss_blocked", "message": "surge_tunnel_disconnecting",
                                    "details": ["pf": "blocked", "event_to_rules_loaded_ms": 12.3, "event_to_block_verified_ms": 45.6]]
    let lossLine = String(decoding: try JSONSerialization.data(withJSONObject: lossRecord), as: UTF8.self)
    let lossHuman = LogReader.format(lossLine)
    try check(lossHuman.contains("提前阻断") && lossHuman.contains("12.3 毫秒") && lossHuman.contains("45.6 毫秒") &&
              lossHuman.contains("旧连接状态清理已完成") && lossHuman.contains("未验证逐包零绕过"),
              "Loss log lost the blocking stages or overstated callback timing")
    try check(LogReader.format(lossLine, json: true).contains("event_to_rules_loaded_ms"), "Loss timing JSON was discarded")
    print("PASS: only connected tunnel status permits readiness; loss logs separate rule loading from state cleanup")

    let routeCheck = RouteCheck(url: "https://example.com", requiredGroup: "Residential", allowedFinalPolicies: ["Node A", "Node B"])
    let routeConfig = Configuration(version: 1, mode: "routes", routeChecks: [routeCheck])
    try routeConfig.validate()
    let roundTrip = try Configuration.decode(Data(JSON.encode(routeConfig).utf8))
    try check(roundTrip == routeConfig, "Configuration JSON round trip failed")
    try check(try roundTrip.fingerprint() == routeConfig.fingerprint(), "Identical policies have different query fingerprints")
    try check(try Configuration.enhanced.fingerprint() != routeConfig.fingerprint(), "Rule result cannot be bound to a different policy")
    for invalid in [Configuration(version: 1, mode: "routes", routeChecks: []),
                    Configuration(version: 1, mode: "enhanced", routeChecks: [routeCheck]),
                    Configuration(version: 2, mode: "enhanced", routeChecks: []),
                    Configuration(version: 1, mode: "routes", routeChecks: [routeCheck, routeCheck]),
                    Configuration(version: 1, mode: "routes", routeChecks: [RouteCheck(url: "https://user:secret@example.com", requiredGroup: "Residential", allowedFinalPolicies: ["Node A"])]),
                    Configuration(version: 1, mode: "routes", routeChecks: [RouteCheck(url: "https://example.com", requiredGroup: "Residential", allowedFinalPolicies: ["DIRECT"])])] {
        try rejects { try invalid.validate() }
    }
    try rejects { _ = try Configuration.decode(Data("{\"version\":1,\"mode\":\"enhanced\",\"route_checks\":[],\"typo\":true}".utf8)) }
    print("PASS: policy validation, credentials, duplicate checks and unknown fields")

    let persistent = Configuration(version: 1, mode: "routes", routeChecks: [routeCheck], persistentTCP: true)
    let persistentJSON = try JSON.encode(persistent)
    let persistentDecoded = try Configuration.decode(Data(persistentJSON.utf8))
    try check(persistentJSON.contains("\"persistent_tcp\":true") && persistentDecoded.usesPersistentTCP && persistentDecoded == persistent,
              "Persistent TCP flag was silently dropped by snake-case decoding")
    try check(!roundTrip.usesPersistentTCP && !JSON.encode(routeConfig).contains("persistent"), "Legacy policy changed behavior/encoding")
    try check(try persistent.fingerprint() != routeConfig.fingerprint(), "Enforcement change reused the old probe fingerprint")
    for value in ["null", "0", "1", "\"true\"", "[]", "{}"] {
        try rejects { _ = try Configuration.decode(Data("{\"version\":1,\"mode\":\"enhanced\",\"route_checks\":[],\"persistent_tcp\":\(value)}".utf8)) }
    }
    let tcpRules = try Policy.persistentTCP(group: 60000, interface: "utun42")
    try check(tcpRules.contains("from 198.18.0.1") && tcpRules.contains("group 60000") &&
              tcpRules.components(separatedBy: "keep state (if-bound)").count == 3 &&
              tcpRules.contains("block drop quick on ! lo0 proto tcp all") &&
              !tcpRules.contains("udp") &&
              !tcpRules.contains("user ") && !tcpRules.contains("utun*"),
              "Persistent policy changed TCP-only scope or widened identity/interface permissions")
    for interface in ["", "en0", "utun", "utun1\npass all", "utun１２", "utun0000000000000000"] {
        try rejects { _ = try Policy.persistentTCP(group: 60000, interface: interface) }
    }
    for group: UInt32 in [0, 20, 59999, 61000, UInt32.max] {
        try rejects { _ = try Policy.persistentTCP(group: group, interface: "utun42") }
    }
    var lanConfig = persistent
    lanConfig.allowLANTCP = true
    let lanJSON = try lanConfig.encoded()
    try check(lanJSON.contains("\"allow_lan_tcp\" : true") && Configuration.decode(Data(lanJSON.utf8)) == lanConfig,
              "LAN option failed validated serialization")
    try check(try lanConfig.fingerprint() != persistent.fingerprint(), "LAN policy reused a route generation")
    try check(!persistent.allowsLANTCP && !JSON.encode(persistent).contains("allow_lan_tcp"), "LAN opt-in changed existing defaults")
    for value in ["null", "0", "1", "\"true\"", "[]", "{}"] {
        try rejects { _ = try Configuration.decode(Data("{\"version\":1,\"mode\":\"enhanced\",\"route_checks\":[],\"persistent_tcp\":true,\"allow_lan_tcp\":\(value)}".utf8)) }
    }
    try rejects { try Configuration(version: 1, mode: "enhanced", routeChecks: [], allowLANTCP: true).validate() }
    try rejects { try Configuration(version: 1, mode: "enhanced", routeChecks: [], persistentTCP: false, allowLANTCP: true).validate() }
    try Configuration(version: 1, mode: "enhanced", routeChecks: [], allowLANTCP: false).validate()
    print("PASS: LAN TCP opt-in is strict, persistent-only and part of policy generations")

    for address in ["10.0.0.0", "10.255.255.255", "172.16.0.0", "172.31.255.255", "192.168.0.0", "192.168.255.255"] {
        try check(LANTCP.privateIPv4(address), "Private range boundary rejected: \(address)")
    }
    for address in ["9.255.255.255", "11.0.0.0", "172.15.255.255", "172.32.0.0", "192.167.255.255", "192.169.0.0",
                    "100.64.0.1", "169.254.1.2", "127.0.0.1", "224.0.0.1", "198.18.0.1", "203.0.113.1", "0.0.0.0",
                    "fc00::1", "::ffff:192.168.1.1", "192.168.1", "192.168.1.1/24", "192.168.1.1\npass all",
                    "192.168.1.1\0\npass all", "192.168.01.1", " 192.168.1.1"] {
        try check(!LANTCP.privateIPv4(address), "LAN exception accepted non-private or malformed address: \(address)")
    }
    let lanBindings = [LANTCPBinding(interface: "en0", address: "192.168.50.2"), LANTCPBinding(interface: "en7", address: "10.2.0.3")]
    let lanAddresses = lanBindings.map { InterfaceAddress(name: $0.interface, address: $0.address, up: true, loopback: false) }
    var ignoredLANAddresses = [InterfaceAddress(name: "en0", address: "203.0.113.2", up: true, loopback: false),
                              InterfaceAddress(name: "en0", address: "192.168.60.2", up: false, loopback: false),
                              InterfaceAddress(name: "en0", address: "192.168.60.3", up: true, loopback: true)]
    for name in ["utun9", "bridge0", "lo0", "awdl0", "en", "en１", "en0\npass all", "en0000000000000000"] {
        ignoredLANAddresses.append(InterfaceAddress(name: name, address: "192.168.50.3", up: true, loopback: false))
        try rejects { _ = try LANTCP.rules(bindings: [LANTCPBinding(interface: name, address: "192.168.50.3")]) }
    }
    try check(try LANTCP.bindings(addresses: Array(lanAddresses.reversed()) + lanAddresses + ignoredLANAddresses) == lanBindings,
              "LAN inventory did not deduplicate/sort or included a wrong interface/address")
    try rejects { _ = try LANTCP.rules(bindings: lanBindings + lanBindings) }
    try rejects { _ = try LANTCP.rules(bindings: [LANTCPBinding(interface: "en0", address: "192.168.1.1\0\npass all")]) }
    let manyLANAddresses = (1...65).map { InterfaceAddress(name: "en0", address: "10.0.0.\($0)", up: true, loopback: false) }
    try rejects { _ = try LANTCP.bindings(addresses: manyLANAddresses) }
    try rejects { _ = try LANTCP.rules(bindings: manyLANAddresses.map { LANTCPBinding(interface: $0.name, address: $0.address) }) }
    print("PASS: LAN scope accepts only bounded private IPv4 on up en interfaces and rejects injection")

    let lanRules = try LANTCP.rules(bindings: lanBindings)
    let lanBlockedRules = try Policy.blockedRules(lanTCPBindings: lanBindings)
    let lanAllowedRules = try Policy.persistentTCP(group: 60000, interface: "utun42", lanTCPBindings: lanBindings)
    try check(lanBlockedRules == lanRules + Policy.blocked && lanAllowedRules == lanRules + tcpRules,
              "LAN rules displaced public blocking or Surge identity restrictions")
    try check(try Policy.blockedRules() == Policy.blocked && LANTCP.rules(bindings: []).isEmpty, "Disabled LAN policy changed defaults")
    let lanLines = lanRules.split(separator: "\n")
    try check(lanLines.count == 12 && lanLines.allSatisfy { $0.contains("inet proto tcp") && $0.contains("keep state (if-bound)") && !$0.contains("any") },
              "LAN rule widened protocol, family, peer or interface state scope")
    for binding in lanBindings {
        for network in LANTCP.networks {
            try check(lanRules.contains("pass in quick on \(binding.interface) inet proto tcp from \(network) to \(binding.address) flags S/SA") &&
                      lanRules.contains("pass out quick on \(binding.interface) inet proto tcp from \(binding.address) to \(network) flags S/SA"),
                      "LAN rules failed to constrain both the peer and actual local interface/address")
        }
    }
    let lanFirewall = Firewall(historyPath: nil)
    try check(try lanFirewall.setLANTCP(lanBindings) && !lanFirewall.setLANTCP(lanBindings), "Stable LAN inventory caused reloads")
    try rejects { _ = try lanFirewall.setLANTCP(lanBindings + lanBindings) }
    try check(lanFirewall.lanTCPBindings == lanBindings, "Rejected LAN inventory changed pending rules")
    // This must fail before invoking PF; no group means the caller would clear its anchor.
    try rejects { try lanFirewall.allow() }
    try check(try lanFirewall.setLANTCP([lanBindings[1]]) && lanFirewall.lanTCPBindings == [lanBindings[1]] &&
              lanFirewall.setLANTCP([]) && lanFirewall.lanTCPBindings.isEmpty && !lanFirewall.setLANTCP([]),
              "Interface withdrawal/disabled policy failed to remove the prior LAN scope")
    print("PASS: LAN rules preserve public blocking in both states and revoke withdrawn interfaces")

    var processInfo = kinfo_proc()
    processInfo.kp_eproc.e_ucred.cr_uid = 501
    processInfo.kp_eproc.e_pcred.p_ruid = 501
    processInfo.kp_eproc.e_ucred.cr_groups.0 = 60000
    processInfo.kp_eproc.e_pcred.p_rgid = 60000
    let infoSize = MemoryLayout<kinfo_proc>.size
    try check(DedicatedEgress.identityMatches(processInfo, returnedSize: infoSize, uid: 501, group: 60000), "Correct native identity rejected")
    for size in [0, infoSize - 1, infoSize + 1] {
        try check(!DedicatedEgress.identityMatches(processInfo, returnedSize: size, uid: 501, group: 60000), "Absent/truncated native identity accepted")
    }
    for field in 0..<4 {
        var wrong = processInfo
        switch field {
        case 0: wrong.kp_eproc.e_ucred.cr_uid = 502
        case 1: wrong.kp_eproc.e_pcred.p_ruid = 502
        case 2: wrong.kp_eproc.e_ucred.cr_groups.0 = 20
        default: wrong.kp_eproc.e_pcred.p_rgid = 20
        }
        try check(!DedicatedEgress.identityMatches(wrong, returnedSize: infoSize, uid: 501, group: 60000), "Native identity field mismatch accepted")
    }
    try check(!DedicatedEgress.identityMatches(processInfo, returnedSize: infoSize, uid: 501, group: 20), "Ordinary group accepted")
    try check(!DedicatedEgress.identityMatches(processInfo, returnedSize: infoSize, uid: 0, group: 60000), "Root identity accepted")
    try check(!(try DedicatedEgress.identityMatches(pid: getpid(), uid: max(501, getuid()), group: 60000)), "Ordinary test process matched dedicated egress group")
    try check((try? DedicatedEgress.identityMatches(pid: Int32.max, uid: 501, group: 60000)) != true, "Missing process was trusted")
    print("PASS: persistent TCP opt-in, legacy encoding, interface-bound rules and strict egress identity")

    try check(try DedicatedEgress.availableGroup(record: nil, occupied: { $0 == 60_000 }) == 60_001,
              "Fresh dedicated group selection reused an occupied ID")
    try check(try DedicatedEgress.availableGroup(record: ["gid": 60_004], occupied: { _ in false }) == 60_004,
              "Interrupted group creation did not retain its reserved identity")
    for record: [String: UInt32] in [["gid": 20], [:], ["gid": 60_000, "other": 1]] {
        try rejects { _ = try DedicatedEgress.availableGroup(record: record, occupied: { _ in false }) }
    }
    try rejects { _ = try DedicatedEgress.availableGroup(record: ["gid": 60_004], occupied: { _ in true }) }
    try rejects { _ = try DedicatedEgress.availableGroup(record: nil, occupied: { _ in true }) }
    print("PASS: dedicated group installation retries preserve recorded identity and reject collisions")

    let processA = SurgeProcess(pid: 100, startedSeconds: 1, startedMicroseconds: 1)
    let processB = SurgeProcess(pid: 101, startedSeconds: 2, startedMicroseconds: 2)
    var processTrust = SurgeProcessTrust()
    var signatureQueries = 0
    func signature(_ pid: pid_t) -> Bool { signatureQueries += 1; return pid == 100 }
    try check(try processTrust.trustedPID(candidates: [processA], validate: signature) == 100, "Single valid process rejected")
    try check(try processTrust.trustedPID(candidates: [processA], validate: signature) == 100 && signatureQueries == 1, "Unchanged process signature was not cached")
    try check(processTrust.matches(candidates: [processA]), "Current trusted identity was lost")
    for changed in [[], [processB], [processA, processB], [SurgeProcess(pid: 100, startedSeconds: 3, startedMicroseconds: 1)]] {
        try check(!processTrust.matches(candidates: changed), "Process replacement could retain allowed state before signature validation")
    }
    try check(signatureQueries == 1, "Identity-change check invoked signature validation before blocking")
    try check(try processTrust.trustedPID(candidates: [processA, processB], validate: signature) == nil, "Second process did not invalidate cached trust")
    try check(try processTrust.trustedPID(candidates: [processA], validate: signature) == 100 && signatureQueries == 2, "Returning to a single process reused invalidated trust")
    let reusedPID = SurgeProcess(pid: 100, startedSeconds: 3, startedMicroseconds: 1)
    try check(try processTrust.trustedPID(candidates: [reusedPID], validate: { _ in false }) == nil, "PID reuse bypassed signature validation")
    try check(try processTrust.trustedPID(candidates: [processB], validate: signature) == nil, "Invalid signature trusted")
    try check(try processTrust.trustedPID(candidates: [], validate: signature) == nil, "Empty process inventory trusted")
    try rejects { _ = try processTrust.trustedPID(candidates: [processA], validate: { _ in throw GuardError("fixture") }) }
    try check(try processTrust.trustedPID(candidates: [processA], validate: signature) == 100, "Failed signature query poisoned recovery")
    let beforeAmbiguity = processTrust.revision
    try check(!processTrust.observe(candidates: [processA, processB]) && processTrust.revision != beforeAmbiguity,
              "Early ambiguity path retained cached signature or route revision")
    let queriesBeforeRecovery = signatureQueries
    try check(try processTrust.trustedPID(candidates: [processA], validate: signature) == 100 && signatureQueries == queriesBeforeRecovery + 1,
              "Early blocking skipped signature cache invalidation")
    processTrust = SurgeProcessTrust()
    try check(try processTrust.trustedPID(candidates: [processA], validate: signature, recheck: { [processA, processB] }) == nil,
              "Candidate appearing during signature validation was trusted")
    let changedRevision = processTrust.revision
    try check(try processTrust.trustedPID(candidates: [processA], validate: signature, recheck: { [processA] }) == 100 &&
              processTrust.revision != changedRevision, "Return from ambiguous inventory did not invalidate prior route generation")
    _ = try Probe.surgeCandidates()
    print("PASS: native process inventory and trust invalidation on second instance, disappearance and PID reuse")

    let explanation: [String: Any] = ["rule-policy": "Residential", "final": "Node A", "final-type": "Shadowsocks",
                                      "steps": [["group": "Residential", "selected": "Nested"], ["group": "Nested", "selected": "Node A"]]]
    func route(_ object: [String: Any]) throws -> RouteResult {
        try RouteResult.evaluate(JSONSerialization.data(withJSONObject: object), check: routeCheck)
    }
    let matching = try route(explanation)
    try check(matching.ready, "Nested allowed proxy rejected")
    var different = explanation
    different["final"] = "Node C"
    different["steps"] = [["group": "Residential", "selected": "Nested"], ["group": "Nested", "selected": "Node C"]]
    try check(!(try route(different)).ready, "Unlisted node accepted")
    different = explanation; different["rule-policy"] = "Other"
    try check(!(try route(different)).ready, "Wrong rule group accepted")
    different = explanation; different["steps"] = []
    try check(!(try route(different)).ready, "Unresolved group accepted")
    different = explanation; different["final-type"] = "DIRECT"
    try check(!(try route(different)).ready, "Built-in direct type accepted")
    different = explanation; different.removeValue(forKey: "final-type")
    try rejects { _ = try route(different) }
    try rejects { _ = try RouteResult.evaluate(Data("not-json".utf8), check: routeCheck) }
    print("PASS: nested routing, unlisted/direct targets and malformed CLI responses")

    let groupOnly = RouteCheck(url: "https://example.com", requiredGroup: "Residential")
    let groupConfiguration = Configuration(version: 1, mode: "routes", routeChecks: [groupOnly])
    let groupJSON = try JSON.encode(groupConfiguration)
    try check(!groupJSON.contains("allowed_final_policies"), "Group-only policy serialized a misleading null allowlist")
    try check(try Configuration.decode(Data(groupJSON.utf8)) == groupConfiguration, "Omitted allowlist did not round trip")
    try check(try groupConfiguration.fingerprint() != routeConfig.fingerprint(), "Group-only policy shared a fingerprint with a restricted policy")
    for badValue in ["null", "[]", "\"Node A\"", "[1]", "[\"Node A\",\"Node A\"]", "[\"DIRECT\"]"] {
        let invalid = groupJSON.replacingOccurrences(of: "\"required_group\":\"Residential\"", with: "\"allowed_final_policies\":\(badValue),\"required_group\":\"Residential\"")
        try rejects { _ = try Configuration.decode(Data(invalid.utf8)) }
    }
    for final in ["Node A", "Node C"] {
        var value = explanation; value["final"] = final
        value["steps"] = [["group": "Residential", "selected": "Nested"], ["group": "Nested", "selected": final]]
        try check(try RouteResult.evaluate(JSONSerialization.data(withJSONObject: value), check: groupOnly).ready, "Group-only matching rejected a changed proxy node")
    }
    for (key, value) in [("rule-policy", "Other"), ("final", "DIRECT"), ("final", "REJECT"), ("final-type", "DIRECT"), ("final-type", "REJECT")] {
        var invalid = explanation; invalid[key] = value
        try check(!(try RouteResult.evaluate(JSONSerialization.data(withJSONObject: invalid), check: groupOnly)).ready, "Group-only matching accepted a wrong group or direct/reject result")
    }
    var unresolved = explanation; unresolved["steps"] = []
    try check(!(try RouteResult.evaluate(JSONSerialization.data(withJSONObject: unresolved), check: groupOnly)).ready, "Group-only matching accepted an unresolved group")
    try check(!groupOnly.allowsFinalPolicy(nil) && !groupOnly.allowsFinalPolicy(""), "Daemon result binding accepted a missing final policy")
    for finalType in ["select", "url-test", "smart", "fallback", "load-balance", "unknown", "future-proxy"] {
        var value = explanation; value["final-type"] = finalType
        try check(!(try RouteResult.evaluate(JSONSerialization.data(withJSONObject: value), check: groupOnly)).ready,
                  "Unknown or unresolved final type passed: \(finalType)")
    }
    for steps in [ [["group": "Residential"]],
                   [["group": "Residential", "selected": "Residential"]],
                   [["group": "Residential", "selected": "Nested"], ["group": "Other", "selected": "Node A"]],
                   [["group": "Residential", "selected": "Nested"], ["group": "Nested", "selected": "Residential"]] ] {
        var value = explanation; value["steps"] = steps
        try check(!(try RouteResult.evaluate(JSONSerialization.data(withJSONObject: value), check: groupOnly)).ready,
                  "Broken/cyclic selection chain passed")
    }
    print("PASS: optional final-policy allowlist accepts group proxy changes; null/empty/malformed lists and direct/reject results fail closed")

    var snapshot = GuardSnapshot(runId: "test", firewallVerifiedUptime: 100, allowed: true,
                                 configurationMode: "routes", readiness: nil, session: nil, reasons: [])
    snapshot.bootId = "boot-a"; snapshot.checkedUptime = 100
    try check(snapshot.fresh(boot: "boot-a", now: 101), "Fresh status rejected")
    try check(!snapshot.fresh(boot: "boot-b", now: 101), "Previous boot status accepted")
    try check(!snapshot.fresh(boot: "boot-a", now: 110), "Expired status accepted")
    try check(!snapshot.fresh(boot: "boot-a", now: 99), "Future status accepted")
    snapshot.firewallVerifiedUptime = 90
    try check(!snapshot.fresh(boot: "boot-a", now: 101), "Expired PF audit accepted")
    let statusData = try JSON.encode(snapshot)
    let decoded = try JSON.decode(GuardSnapshot.self, from: Data(statusData.utf8))
    try check(decoded.bootId == snapshot.bootId, "Status schema did not round trip")
    print("PASS: boot-bound monotonic status/PF freshness")
    try check(decoded.lanTcpEnabled == nil && decoded.lanTcpBindings == nil, "Old snapshots acquired an implicit LAN exception")
    snapshot.lanTcpEnabled = true; snapshot.lanTcpBindings = lanBindings
    let lanSnapshotJSON = try JSON.encode(snapshot)
    let lanSnapshot = try JSON.decode(GuardSnapshot.self, from: Data(lanSnapshotJSON.utf8))
    try check(lanSnapshot.lanTcpEnabled == true && lanSnapshot.lanTcpBindings == lanBindings &&
              lanSnapshotJSON.contains("\"lan_tcp_enabled\":true") && lanSnapshotJSON.contains("\"lan_tcp_bindings\":"),
              "Effective LAN scope disappeared from snake-case status JSON")
    let lanLog = "{\"event\":\"gate_changed\",\"message\":\"waiting\",\"details\":{\"allow_lan_tcp\":true}}"
    try check(LogReader.format(lanLog).contains("例外：已配置的私网 TCP") && LogReader.format(lanLog, json: true).contains("allow_lan_tcp"),
              "Blocked-state logs hid the configured LAN exception")
    print("PASS: LAN status supports old readers and exposes effective scope without losing JSON evidence")
    let freshSnapshot = GuardSnapshot(runId: "display-test", firewallVerifiedUptime: SystemClock.seconds,
                                     allowed: true, configurationMode: "enhanced", readiness: nil, session: nil, reasons: [])
    let snapshotObject = try JSONSerialization.jsonObject(with: Data(JSON.encode(freshSnapshot).utf8))
    for (running, state, included, expected) in [(true, "allowed", true, true), (false, "allowed", true, false),
                                               (true, "unknown", true, false), (true, "allowed", false, false)] {
        var object: [String: Any] = ["daemon_running": running, "state": state, "reason": ""]
        if included { object["snapshot"] = snapshotObject }
        let report = try JSON.decode(StatusReport.self, from: JSONSerialization.data(withJSONObject: object))
        try check(report.firewallVerified == expected, "Menu accepted PID/condition-only or unknown status as verified PF")
    }
    print("PASS: menu requires running daemon and current verified PF; conditions alone cannot be green")
    for (running, fresh, state, pending, allowed, green) in [
        (true, true, "ready", [String](), true, true),
        (false, true, "ready", [], true, false), (true, false, "ready", [], true, false),
        (true, true, "ready", [], false, false), (true, true, "ready", ["com.example.A"], true, false),
        (true, true, "waiting", [], true, false), (true, true, "waiting_network", [], true, false), (true, true, "restoring", [], true, false),
        (true, true, "error", [], true, false), (true, true, "unknown", [], true, false), (true, true, "shutting_down", [], true, false),
        (true, true, "update_paused", [], true, false), (true, true, "waiting_identity", [], true, false),
        (true, true, "os_update_paused", [], true, false), (true, true, "os_update_waiting", [], true, false),
        (true, true, "recovery_failed", [], true, false), (true, true, "launch_recovery_required", [], true, false)
    ] {
        let object: [String: Any] = ["running": running, "fresh": fresh, "status": ["state": state, "pending": pending]]
        let report = try JSON.decode(GateStatusReport.self, from: JSONSerialization.data(withJSONObject: object))
        try check(report.menuTitle(guardAllowed: allowed).contains("🟢") == green, "SurgeGate menu displayed false green")
    }
    print("PASS: companion green requires fresh running ready state, no pending apps and verified network permission")
    let pauseRequested = LogReader.format("{\"component\":\"SurgeGate\",\"event\":\"update_pause_requested\",\"message\":\"Waiting for launch\"}")
    try check(pauseRequested.contains("须等待 Gate 确认") && !pauseRequested.contains("已暂停"), "Pause request log claimed completed acknowledgement")

    let pause = GateUpdate(paused: true), resume = GateUpdate(paused: false)
    let pauseData = Data(try JSON.encode(pause).utf8)
    for date in [-1e300, 1e300, -1] {
        var malformedUpdate = try JSONSerialization.jsonObject(with: pauseData) as! [String: Any]
        malformedUpdate["changed_at"] = date
        try rejects { _ = try GateUpdate.decode(JSONSerialization.data(withJSONObject: malformedUpdate)) }
    }
    for state in ["stopped", "future_state", ""] {
        try check(!resume.acknowledged(by: resume, state: state, fresh: true), "Unknown state acknowledged automatic recovery")
    }
    try check(try GateUpdate.decode(pauseData) == pause, "Update mode lost its durable identity")
    try check(pause.acknowledged(by: pause, state: "update_paused", fresh: true), "Fresh matching pause was not acknowledged")
    try check(!pause.acknowledged(by: pause, state: "ready", fresh: true) &&
              !pause.acknowledged(by: pause, state: "update_paused", fresh: false) &&
              !pause.acknowledged(by: GateUpdate(paused: true), state: "update_paused", fresh: true) &&
              !resume.acknowledged(by: pause, state: "update_paused", fresh: true) &&
              !resume.acknowledged(by: resume, state: "recovery_failed", fresh: true),
              "Stale, different or unfinished update request acknowledged")
    try check(resume.acknowledged(by: resume, state: "waiting", fresh: true) &&
              resume.acknowledged(by: resume, state: "waiting_network", fresh: true) &&
              resume.acknowledged(by: resume, state: "unknown", fresh: true), "Resume incorrectly required verified network permission")
    try check(!pause.acknowledged(by: pause, state: "waiting_network", fresh: true), "Network waiting acknowledged an update pause")
    for bad in ["{}", "{\"paused\":true}", String(repeating: " ", count: 4097),
                String(decoding: pauseData, as: UTF8.self).replacingOccurrences(of: "\"version\":1", with: "\"version\":2")] {
        try rejects { _ = try GateUpdate.decode(Data(bad.utf8)) }
    }
    let updateDirectory = FileManager.default.temporaryDirectory.appendingPathComponent("surge-update-test-" + UUID().uuidString)
    do {
        try UserPaths.prepare(updateDirectory.path)
        defer { try? FileManager.default.removeItem(at: updateDirectory) }
        let path = updateDirectory.appendingPathComponent("update.json").path
        try check(try GateUpdate.load(from: path) == nil, "Absent update file invented a pause")
        try AtomicFile.write(try JSON.encode(pause), to: path, mode: 0o600)
        try check(try GateUpdate.load(from: path) == pause && GateUpdate.load(from: path) == pause, "Pause was consumed or changed across readers/restarts")
        chmod(path, 0o644)
        try rejects { _ = try GateUpdate.load(from: path) }
        try FileManager.default.removeItem(atPath: path)
        try FileManager.default.createSymbolicLink(atPath: path, withDestinationPath: "/dev/null")
        try rejects { _ = try GateUpdate.load(from: path) }
    }
    var retry = GateRetry()
    retry.succeeded(at: 1, launched: false)
    try check(retry.canAttempt(at: 2) && retry.failure == nil, "Readiness waiting incurred a failure cooldown")
    retry.succeeded(at: 10, launched: true)
    retry.succeeded(at: 11, launched: false)
    try check(!retry.canAttempt(at: 19.99) && retry.canAttempt(at: 20), "Subsequent tick erased the 10s post-launch grace window")
    retry.failed("launch failed", at: 2)
    try check(!retry.canAttempt(at: 31.99) && retry.canAttempt(at: 32) && retry.failure == "launch failed", "Actual failure did not retain bounded 30s backoff")
    retry.succeeded(at: 5, launched: false)
    try check(retry.failure == nil && retry.canAttempt(at: 5), "Manual recovery did not clear failure backoff")
    print("PASS: persistent update pause, bounded private reads, fresh request acknowledgement and recovery retry backoff")

    let startupAddress = InterfaceAddress(name: "en7", address: "192.0.2.2", up: true, loopback: false)
    var startupRetry = GateRetry()
    for tick in 0..<45 {
        try check(!Probe.startupNetworkReady(primaryInterface: nil, addresses: [startupAddress]),
                  "DHCP address started Surge before macOS published the primary network")
        startupRetry.succeeded(at: Double(tick), launched: false)
    }
    try check(Probe.startupNetworkReady(primaryInterface: "en7", addresses: [startupAddress]) && startupRetry.canAttempt(at: 45),
              "Published primary network did not permit immediate startup after captive evaluation")
    for primary in [nil, "", "en0"] as [String?] {
        try check(!Probe.startupNetworkReady(primaryInterface: primary, addresses: [startupAddress]), "Missing/wrong primary interface permitted startup")
    }
    for addresses in [[InterfaceAddress](),
                      [InterfaceAddress(name: "en7", address: "192.0.2.2", up: false, loopback: false)],
                      [InterfaceAddress(name: "en7", address: "127.0.0.1", up: true, loopback: true)],
                      [InterfaceAddress(name: "en7", address: "2001:db8::1", up: true, loopback: false)],
                      [InterfaceAddress(name: "en7", address: "invalid", up: true, loopback: false)]] {
        try check(!Probe.startupNetworkReady(primaryInterface: "en7", addresses: addresses), "Unusable primary interface permitted startup")
    }
    let startupWaitLog = "{\"component\":\"SurgeGate\",\"event\":\"gate_waiting_network\",\"message\":\"Waiting for primary network\",\"details\":{\"pending_count\":0}}"
    try check(LogReader.format(startupWaitLog).contains("暂不启动 Surge") && !LogReader.format(startupWaitLog).contains("应用恢复完成") &&
              LogReader.format(startupWaitLog, json: true).contains("Waiting for primary network"), "Startup wait log hid its cause or claimed recovery completed")
    let startupMenu = try JSON.decode(GateStatusReport.self, from: Data("{\"running\":true,\"fresh\":true,\"status\":{\"state\":\"waiting_network\",\"pending\":[]}}".utf8))
    try check(startupMenu.menuTitle(guardAllowed: true).contains("等待 macOS 主网络"), "Startup wait menu hid the native network dependency")
    print("PASS: startup waits for the native primary IPv4 network, survives captive delay without cooldown, and exposes honest wait status")

    var auditMenu = PacketAuditSnapshot(capacityMegabytes: 256)
    auditMenu.surgeHistoryHasGaps = true
    try check(auditMenu.historyDescriptions == ["抓包历史：未记录到缺口", "Surge 请求历史：有缺口"], "Request gap misrepresented as packet capture gap")
    auditMenu.captureHistoryHasGaps = true; auditMenu.surgeHistoryHasGaps = false
    try check(auditMenu.historyDescriptions == ["抓包历史：有缺口", "Surge 请求历史：未记录到缺口"], "Capture gap misrepresented as request gap")
    print("PASS: independent packet capture and Surge request history gap presentation")

    var gate = GateConfiguration.standard
    gate.startupApps = ["com.example.B", "com.example.A"]
    gate.priorityOrder = ["com.example.C", "com.example.A"]
    gate.excludedApps = ["com.example.D"]
    try gate.validate()
    try check(gate.targets(saved: ["com.example.C", "com.example.B", "com.example.D", "com.apple.finder", "com.nssurge.surge-mac"]) == ["com.example.C", "com.example.A", "com.example.B"], "Gate order, deduplication or exclusions failed")
    gate.restoreSession = false
    try check(gate.targets(saved: ["com.example.C"]) == ["com.example.A", "com.example.B"], "Disabled session restoration ignored")
    gate.startupApps = ["Terminal"]
    try rejects { try gate.validate() }
    print("PASS: portable app IDs, launch order, exclusions and session opt-out")
    let checkpoint = GateSession(apps: ["com.example.A"], pending: ["com.example.Missing"])
    let restored = try GateSession.decode(Data(JSON.encode(checkpoint).utf8))
    try check(restored.apps == checkpoint.apps && restored.pending == checkpoint.pending, "Pending recovery lost in checkpoint")
    try rejects { _ = try GateSession.decode(Data("{}".utf8)) }
    try rejects { _ = try GateSession.decode(Data("{\"apps\":[\"Terminal\"],\"pending\":[],\"saved_at\":0}".utf8)) }
    print("PASS: session round trip preserves pending apps; corrupt session is rejected")

    let longIDs = (0..<1024).map { "com.example." + String(repeating: "a", count: 238) + String(format: "%04d", $0) }
    var fullGate = GateConfiguration.standard
    fullGate.startupApps = Array(longIDs.prefix(256))
    fullGate.priorityOrder = Array(longIDs[256..<512])
    fullGate.excludedApps = Array(longIDs[768..<1024])
    try fullGate.validate()
    try check(try GateConfiguration.decode(Data(JSON.encode(fullGate, pretty: true).utf8)) == fullGate,
              "Valid maximum-length Gate lists could not be read back")
    let merged = fullGate.targets(saved: Array(longIDs[256..<768]))
    let largeSession = GateSession(apps: Array(longIDs[256..<512]), pending: merged)
    let largeData = Data(try largeSession.encoded().utf8)
    try check(merged.count == 768 && largeData.count > 65_536 && GateSession.decode(largeData).pending == merged,
              "Merged valid lists poisoned the next Gate startup")
    let sessionFile = FileManager.default.temporaryDirectory.appendingPathComponent("gate-session-limit-" + UUID().uuidString)
    do {
        defer { try? FileManager.default.removeItem(at: sessionFile) }
        try AtomicFile.write(try checkpoint.encoded(), to: sessionFile.path, mode: 0o600)
        try rejects { try AtomicFile.write(try GateSession(apps: [], pending: longIDs + ["com.example.overflow"]).encoded(), to: sessionFile.path, mode: 0o600) }
        try check(try GateSession.decode(Data(contentsOf: sessionFile)).pending == checkpoint.pending,
                  "Rejected session overwrote the previous checkpoint")
    }
    let largePolicy = Configuration(version: 1, mode: "routes", routeChecks: [
        RouteCheck(url: "https://example.com", requiredGroup: "Proxy", allowedFinalPolicies: (0..<128).map {
            String(repeating: "x", count: 502) + String(format: "%03d", $0)
        })
    ])
    try check(try JSON.encode(largePolicy).utf8.count <= 65_536 && JSON.encode(largePolicy, pretty: true).utf8.count > 65_536,
              "Policy size regression fixture missed the formatting boundary")
    try check(try Configuration.decode(Data(largePolicy.encoded().utf8)) == largePolicy,
              "Policy publication grew beyond its own reader's limit")
    var oversizedPolicy = largePolicy
    oversizedPolicy.routeChecks[0].allowedFinalPolicies = (0..<128).map { String(repeating: "x", count: 509) + String(format: "%03d", $0) }
    try rejects { _ = try oversizedPolicy.encoded() }
    print("PASS: bounded policy/config/session publication round trips and oversized checkpoints retain prior data")
    let logRecord: [String: Any] = ["time": "2026-01-01T00:00:00Z", "level": "warning", "event": "gate_changed", "pid": 123,
                                    "message": "route_policy_mismatch", "details": ["pf": "blocked", "routes": [["url": "https://example.com", "ready": false, "expected_group": "Residential", "actual_group": "Other", "final_policy": "Node C"]]]]
    let logLine = String(decoding: try JSONSerialization.data(withJSONObject: logRecord), as: UTF8.self)
    let readable = LogReader.format(logLine)
    try check(readable.contains("BLOCKED") && readable.contains("Residential") && readable.contains("Other") && readable.contains("Node C"), "Readable log omitted decision context")
    let machine = try JSONSerialization.jsonObject(with: Data(LogReader.format(logLine, json: true).utf8)) as? [String: Any]
    try check(machine?["event"] as? String == "gate_changed", "Machine log lost event fields")
    try check(LogReader.format("legacy event") == "legacy event", "Legacy logs became unreadable")
    let legacyPermission: [String: Any] = ["event": "gate_state", "level": "info", "app": "", "pid": 123,
                                         "message": "unknown: status_unavailable: Error Domain=NSCocoaErrorDomain Code=257 Permission denied UserInfo={raw-details}"]
    let permissionLine = String(decoding: try JSONSerialization.data(withJSONObject: legacyPermission), as: UTF8.self)
    let friendlyPermission = LogReader.format(permissionLine)
    try check(friendlyPermission.contains("WARNING") && friendlyPermission.contains("SurgeGate") && friendlyPermission.contains("EACCES/13") && friendlyPermission.contains("暂停"), "Status failure lacks cause/impact/severity")
    try check(!friendlyPermission.contains("UserInfo") && !friendlyPermission.contains("event=") && !friendlyPermission.contains("pid="), "Default human log leaked raw diagnostic noise")
    try check(LogReader.format(permissionLine, json: true).contains("raw-details"), "Raw diagnostics were lost")
    let terminalInjection = String(decoding: try JSONSerialization.data(withJSONObject: ["event": "\u{1b}[31munknown", "time": "\u{1b}[31mclock", "level": "\u{1b}[31merror"]), as: UTF8.self)
    try check(!LogReader.format(terminalInjection).contains("\u{1b}"), "Log header preserved terminal control characters")
    let progress = String(decoding: try JSONSerialization.data(withJSONObject: ["event": "gate_state", "app": "", "message": "1 application(s) pending"]), as: UTF8.self)
    try check(LogReader.format(progress).contains("剩余 1 个应用"), "Legacy progress was not explained")
    let recovered = String(decoding: try JSONSerialization.data(withJSONObject: ["event": "gate_status_recovered", "component": "SurgeGate", "details": ["pending_count": 0, "guard_state": "allowed"]]), as: UTF8.self)
    try check(LogReader.format(recovered).contains("已恢复") && LogReader.format(recovered).contains("剩余 0 个应用"), "Recovery state is not clear")
    let nestedFailure = "rule_probe_failed: /bin/launchctl asuser 501 helper failed: raw-helper-error\nsurge-guard: surge-cli --raw status failed: Surge isn't running on the local machine. Use --remote to specify a remote target."
    let waitingRecord: [String: Any] = ["component": "SurgeGate", "event": "gate_waiting", "message": "blocked: " + nestedFailure,
                                       "details": ["guard_state": "blocked", "reason": nestedFailure, "pending_count": 0]]
    let waitingLine = String(decoding: try JSONSerialization.data(withJSONObject: waitingRecord), as: UTF8.self)
    let waitingLog = LogReader.format(waitingLine)
    try check(waitingLog.contains("系统门禁已阻断") && waitingLog.contains("恢复暂停") && waitingLog.contains("Surge CLI 暂时无法连接"), "Waiting log omitted actual CLI cause and paused state")
    try check(!waitingLog.contains("asuser") && !waitingLog.contains("raw-helper-error") && LogReader.format(waitingLine, json: true).contains("raw-helper-error"), "Nested helper diagnostics polluted the human log or vanished from JSON")
    let failedProbe = String(decoding: try JSONSerialization.data(withJSONObject: ["event": "rule_probe_failed", "message": nestedFailure]), as: UTF8.self)
    try check(LogReader.format(failedProbe).contains("Surge CLI 暂时无法连接") && !LogReader.format(failedProbe).contains("raw-helper-error"), "Root probe failure retained nested command noise")
    try check(readable.contains("SurgeGuard") && readable.contains("普通联网已阻断") && readable.contains("最终策略"), "System log lacks component/state/route context")
    print("PASS: both components explain state, cause, impact, progress and recovery; JSON retains raw diagnostics")
    _ = try JSONSerialization.jsonObject(with: Data(LogReader.format("legacy event", json: true).utf8))
    let logURL = FileManager.default.temporaryDirectory.appendingPathComponent("surge-guard-log-test-" + UUID().uuidString)
    do {
        try (logLine + "\nlegacy record without trailing newline").write(to: logURL, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: logURL) }
        try LogReader.show(path: logURL.path, follow: false, json: false)
    }
    print("PASS: readable decision logs, machine JSON and legacy records")
    let eventDirectory = FileManager.default.temporaryDirectory.appendingPathComponent("surge-events-test-" + UUID().uuidString)
    do {
        try UserPaths.prepare(eventDirectory.path)
        defer { try? FileManager.default.removeItem(at: eventDirectory) }
        let path = eventDirectory.appendingPathComponent("events.jsonl").path
        let lockPath = path + ".lock"
        for index in 1...5 {
            let record = Data(("record-\(index):" + String(repeating: "x", count: EventFile.maximumBytes / 2)).utf8)
            try EventFile.append(record, to: path, owner: getuid(), lockPath: lockPath)
        }
        for (suffix, index) in [("", 5), (".1", 4)] {
            let value = try Data(contentsOf: URL(fileURLWithPath: path + suffix))
            var info = stat(); lstat(path + suffix, &info)
            try check(value.count <= EventFile.maximumBytes && String(decoding: value.prefix(9), as: UTF8.self).hasPrefix("record-\(index):"), "Log rotation lost the newest/previous record or exceeded its bound")
            try check(info.st_mode & 0o777 == 0o600, "Log permissions were widened")
        }
        try check(try FileManager.default.contentsOfDirectory(atPath: eventDirectory.path).count == 3, "Log rotation accumulated extra files")
        try rejects { try EventFile.append(Data(repeating: 65, count: EventFile.maximumBytes), to: path, owner: getuid(), lockPath: lockPath) }
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: path)
        try rejects { try EventFile.append(Data("unsafe".utf8), to: path, owner: getuid(), lockPath: lockPath) }
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
        try rejects { try EventFile.append(Data("wrong owner".utf8), to: path, owner: getuid() + 1, lockPath: lockPath) }
        try FileManager.default.removeItem(atPath: path + ".1")
        try FileManager.default.createSymbolicLink(atPath: path + ".1", withDestinationPath: path)
        try rejects { try EventFile.append(Data(repeating: 65, count: EventFile.maximumBytes / 2), to: path, owner: getuid(), lockPath: lockPath) }
        let fifo = eventDirectory.appendingPathComponent("fifo").path
        try check(mkfifo(fifo, 0o600) == 0, "Cannot create FIFO fixture")
        let rejected = try Command.run(CommandLine.arguments[0], ["--event-fifo-check", fifo], timeout: 2)
        try check(rejected.status == 0 && rejected.output.contains("rejected"), "Event FIFO blocked before file validation")
        try rejects { _ = try UserPaths.readPrivate(fifo) }
        try rejects { let fd = try UserPaths.lock(at: fifo); close(fd) }
    }
    print("PASS: bounded private event logs retain only current/previous files and reject oversized or unsafe writes")

    let config = """
    # Existing configuration
    set skip on lo0
    scrub-anchor "com.apple/*"
    nat-anchor "com.apple/*"
    anchor "com.apple/*"
    load anchor "com.apple" from "/etc/pf.anchors/com.apple"
    # User comment must survive

    """
    let installed = try Policy.attaching(to: config)
    let reinstalled = try Policy.attaching(to: installed)
    let removed = try Policy.removingAttachment(from: installed)
    try check(installed == reinstalled, "Installation must be idempotent")
    try check(removed == config, "Removal must preserve original configuration")
    try check(installed.range(of: Policy.attachment)!.lowerBound <
              installed.range(of: "\nanchor \"com.apple/*\"")!.lowerBound, "Wrong anchor order")
    print("PASS: PF configuration installation/removal round trip")

    let installationPreview = try Policy.installationPreview(installed)
    try check(!installationPreview.contains(Policy.anchorPath) && installationPreview.contains(Policy.blocked) &&
              installationPreview.contains("load anchor \"com.apple\" from \"/etc/pf.anchors/com.apple\"") &&
              installationPreview.contains("# User comment must survive"),
              "Fresh installation preview depends on its absent file or lost existing anchors/comments")
    try rejects { _ = try Policy.installationPreview(config) }
    try rejects { _ = try Policy.installationPreview(installed + Policy.configBlock) }
    try rejects { _ = try Policy.installationPreview(installed.replacingOccurrences(of: Policy.end, with: "pass all\n" + Policy.end)) }
    _ = try Command.checked("/sbin/pfctl", ["-n", "-f", "-"], input: installationPreview)
    try rejects { _ = try Command.checked("/sbin/pfctl", ["-n", "-f", "-"], input: installationPreview + "invalid-pf-syntax\n") }
    print("PASS: fresh-install native PF preflight parses the new anchor inline without requiring its file")

    let appleDefault = """
    # Apple default configuration, retained after an OS update
    scrub-anchor "com.apple/*"
    nat-anchor "com.apple/*"
    rdr-anchor "com.apple/*"
    dummynet-anchor "com.apple/*"
    anchor "com.apple/*"
    load anchor "com.apple" from "/etc/pf.anchors/com.apple"
    # Keep this comment

    """
    let appleLive = "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n"
    for live in ["", "anchor \"com.apple/*\" all\n", appleLive,
                 Policy.attachment + " all\nanchor \"com.apple/*\" all\n",
                 "scrub-anchor \"com.apple/*\" all fragment reassemble\n" + Policy.attachment + " all\nanchor \"com.apple/*\" all\n"] {
        let restored = try Policy.restoringDefaultAttachment(appleDefault, liveRules: live)
        try check(try Policy.removingAttachment(from: restored) == appleDefault,
                  "OS-update attachment recovery changed Apple's rules or comments")
        try check(try Policy.restoringDefaultAttachment(restored, liveRules: live) == restored,
                  "Interrupted attachment recovery is not idempotent")
    }
    for invalid in ["", config, appleDefault + "pass quick all\n", appleDefault + "set skip on en0\n",
                    appleDefault + "nat on en0 from any to any -> (en0)\n",
                    appleDefault + "anchor \"other.service\"\n", appleDefault + Policy.begin,
                    appleDefault + Policy.end, appleDefault + "# " + Policy.anchor,
                    appleDefault.replacingOccurrences(of: "/etc/pf.anchors/com.apple", with: "/tmp/other-anchor"),
                    appleDefault.replacingOccurrences(of: "rdr-anchor \"com.apple/*\"", with: ""),
                    appleDefault + String(repeating: "# comment\n", count: 8000)] {
        try rejects { _ = try Policy.restoringDefaultAttachment(invalid, liveRules: appleLive) }
    }
    for invalid in ["pass quick all\n" + appleLive, appleLive + "anchor \"other.service\" all\n",
                    appleLive + Policy.attachment + " all\n", appleLive + "anchor \"com.apple/*\" all\n",
                    "scrub-anchor \"other/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n",
                    "scrub-anchor \"com.apple/*\" all fragment reassemble\n", "Permission denied\n"] {
        try rejects { _ = try Policy.restoringDefaultAttachment(appleDefault, liveRules: invalid) }
    }
    let recoveryRules = try Command.checked("/sbin/pfctl", ["-n", "-v", "-R", "-o", "none", "-f", "-"], input: Policy.restoredDefaultFilters)
    // pfctl -n prints wildcard anchor paths as /* before resolving them against the kernel.
    try check(recoveryRules.contains("surge-guard-block") && recoveryRules.contains("scrub-anchor") &&
              recoveryRules.trimmingCharacters(in: .whitespacesAndNewlines).hasSuffix("anchor \"/*\" all"),
              "Filter-only attachment recovery lost blocking rules or default wildcard attachments")
    try check(!Policy.restoredDefaultFilters.contains("load anchor") && !Policy.restoredDefaultFilters.contains("nat-anchor"),
              "Attachment recovery would reload unrelated anchor contents or NAT")
    print("PASS: OS-update attachment recovery accepts only default layouts, retries interrupted attachment, and rejects custom rules")
    print("PASS: native filter-only recovery includes blocking rules and retains the Apple attachment without reloading its contents")

    var attachmentSteps: [String] = []
    try Firewall.preparingAttachment({ attachmentSteps.append("prepared") }, blockOnFailure: {
        throw GuardError("Unexpected block after successful preparation")
    })
    try check(attachmentSteps == ["prepared"], "Successful preparation entered the failure path")
    for failure in ["unreadable PF file", "custom live layout", "backup write failed", "disk publish failed after live attachment"] {
        attachmentSteps = []
        do {
            try Firewall.preparingAttachment({
                attachmentSteps.append("prepare")
                throw GuardError(failure)
            }, blockOnFailure: { attachmentSteps.append("blocked") })
            throw GuardError("Attachment failure was swallowed")
        } catch {
            try check(attachmentSteps == ["prepare", "blocked"] && String(describing: error).contains(failure) &&
                      String(describing: error).contains("blocking verified, repair is still required"),
                      "Failed preparation retained an old allow state or lost the original error")
        }
    }
    do {
        try Firewall.preparingAttachment({ throw GuardError("disk read failed") },
                                         blockOnFailure: { throw GuardError("PF enable failed") })
        throw GuardError("Unverified block was accepted")
    } catch {
        let message = String(describing: error)
        try check(message.contains("disk read failed") && message.contains("PF enable failed") &&
                  message.contains("blocking could not be verified") && !message.contains("blocking verified"),
                  "Attachment/block failure lost evidence or claimed verified protection")
    }
    print("PASS: attachment preparation failures block before reporting errors and preserve failed-block uncertainty")

    let missingStatus = try JSON.decode(StatusReport.self, from: Data("""
    {"state":"unknown","daemon_running":false,"reason":"status_unavailable: original read error"}
    """.utf8))
    let diagnosed = missingStatus.diagnosingConfiguration(appleDefault)
    try check(diagnosed.state == "unknown" && !diagnosed.firewallVerified &&
              diagnosed.reason.hasPrefix("pf_attachment_missing:") && diagnosed.reason.contains(missingStatus.reason),
              "Missing disk attachment hid the raw error or invented verified protection")
    try check(missingStatus.diagnosingConfiguration(appleDefault + Policy.begin).reason.hasPrefix("pf_attachment_invalid:"),
              "Partial PF attachment was mistaken for an ordinary missing file")
    try check(missingStatus.diagnosingConfiguration(try Policy.attaching(to: appleDefault)).reason == missingStatus.reason,
              "An intact attachment masked an unrelated status error")
    for state in ["allowed", "blocked", "unlocked"] {
        var report = missingStatus; report.state = state
        try check(report.diagnosingConfiguration(appleDefault).reason == report.reason,
                  "On-disk diagnostic overrode current PF status or manual unlock")
    }
    print("PASS: PF attachment diagnostics preserve unknown protection, raw status errors and explicit unlock state")

    for invalid in ["", Policy.begin, Policy.end,
                    "anchor \"com.apple/*\"\nanchor \"com.apple/*\"\n",
                    "# io.github.surge-guard\nanchor \"com.apple/*\"\n"] {
        try rejects { _ = try Policy.attaching(to: invalid) }
    }
    let modified = Policy.configBlock.replacingOccurrences(of: Policy.end, with: "pass quick all\n" + Policy.end)
    try rejects { _ = try Policy.removingAttachment(from: modified) }
    try rejects { _ = try Policy.removingAttachment(from: Policy.configBlock + Policy.configBlock) }
    print("PASS: malformed/edited PF configuration is rejected")

    try check(Policy.attachedFirst(Policy.attachment + " all\nanchor \"com.apple/*\" all\n"), "Valid attachment rejected")
    let liveMacRules = "scrub-anchor \"com.apple/*\" all fragment reassemble\n" + Policy.attachment + " all\nanchor \"com.apple/*\" all\n"
    try check(Policy.attachedFirst(liveMacRules), "macOS normalization rule mistaken for a filter")
    try check(!Policy.attachedFirst("scrub-anchor \"com.apple/*\" all\npass quick all\n" + Policy.attachment + " all\n"), "Filter before guard accepted after normalization")
    for invalid in ["pass quick all\n" + Policy.attachment + " all\n",
                    "anchor \"com.apple/*\" all\n" + Policy.attachment + " all\n",
                    "anchor \"io.github.surge-guard-impostor\" all\n", ""] {
        try check(!Policy.attachedFirst(invalid), "Unsafe filter ordering accepted")
    }
    print("PASS: live PF attachment order")

    try check(Policy.defaultInterface("route to: default\n  interface: utun108\n") == "utun108", "Dynamic utun parsing failed")
    try check(Policy.defaultInterface("   interface: en0\n") == "en0", "Physical interface parsing failed")
    try check(Policy.defaultInterface("route: not in table") == nil, "Missing route accepted")
    try check(Policy.defaultInterface("interface: utun9 extra") == nil, "Malformed route accepted")
    print("PASS: route parser")

    try check(Policy.ipv6Safe(primaryInterface: nil, surgeInterface: "utun9"), "Missing global IPv6 route must be safe")
    try check(Policy.ipv6Safe(primaryInterface: "utun9", surgeInterface: "utun9"), "Surge IPv6 route rejected")
    try check(!Policy.ipv6Safe(primaryInterface: "en0", surgeInterface: "utun9"), "Physical IPv6 route accepted")
    try check(!Policy.ipv6Safe(primaryInterface: "", surgeInterface: "utun9"), "Malformed IPv6 state accepted")
    print("PASS: IPv6 safety gate")

    // -n is parse-only; never enable PF or touch live rules/state in tests.
    let parser = try Command.run("/sbin/pfctl", ["-n", "-a", Policy.anchor, "-f", "-"], input: Policy.blocked)
    try check(parser.status == 0, "PF parser rejected policy: \(parser.combined)")
    print("PASS: native macOS PF parser")
    _ = try Command.checked("/sbin/pfctl", ["-n", "-a", Policy.anchor, "-f", "-"], input: tcpRules)
    print("PASS: native persistent TCP rule syntax (no live firewall mutation)")
    for policy in [lanAllowedRules, lanBlockedRules] {
        let parsed = try Command.checked("/sbin/pfctl", ["-n", "-v", "-a", Policy.anchor, "-f", "-"], input: policy)
        for line in lanLines { try check(parsed.contains(line), "PF canonical output changed LAN verification: \(line)") }
    }
    print("PASS: native LAN TCP syntax and canonical verification in ready/blocked policies (parse-only)")

    var started = Date()
    do {
        _ = try Command.run("/bin/sleep", ["5"], timeout: 0.05)
        throw GuardError("Expected timeout")
    } catch {
        try check(String(describing: error).contains("/bin/sleep 5 timed out"), "Timeout omitted command context")
    }
    try check(Date().timeIntervalSince(started) < 2, "Timeout did not terminate child")
    started = Date()
    try rejects { _ = try Command.run("/usr/bin/yes", [], timeout: 0.1) }
    try check(Date().timeIntervalSince(started) < 2, "Full pipe defeated timeout")
    print("PASS: timeout and output backpressure")

    try rejects { _ = try Command.checked("/usr/bin/false", []) }
    let literal = try Command.run("/usr/bin/printf", ["%s", "literal $(not-a-command)"])
    try check(literal.output == "literal $(not-a-command)", "Unexpected shell evaluation")
    try rejects { _ = try Command.run("/usr/bin/true\u{0}/unexpected", []) }
    try rejects { _ = try Command.run("/usr/bin/printf", ["%s", "https://example.com/\u{0}other"]) }
    let binaryInput = "prefix\u{0}suffix"
    try check(try Command.checked("/bin/cat", [], input: binaryInput) == binaryInput, "NUL in pipe data must remain supported")
    for control in ["\u{0}", "\t", "\n", "\r", "\u{7f}"] {
        let malformed = Configuration(version: 1, mode: "routes", routeChecks: [
            RouteCheck(url: "https://example.com/" + control + "other", requiredGroup: "Proxy")
        ])
        try rejects { _ = try Configuration.decode(Data(JSON.encode(malformed).utf8)) }
    }
    try Configuration(version: 1, mode: "routes", routeChecks: [
        RouteCheck(url: "https://example.com/%00other", requiredGroup: "Proxy")
    ]).validate()
    // Constant test command only: exercise real stderr/stdout separation.
    let streams = try Command.run("/bin/sh", ["-c", "printf 'rules'; printf 'ALTQ warning' >&2"])
    try check(streams.output == "rules" && streams.diagnostics == "ALTQ warning", "Diagnostics contaminated structured output")
    print("PASS: command errors and literal arguments")
    func descriptorCount() -> Int {
        (0..<4096).filter { fcntl(Int32($0), F_GETFD) != -1 }.count
    }
    let descriptorsBefore = descriptorCount()
    for _ in 0..<40 { _ = try Command.run("/usr/bin/true", []) }
    try check(descriptorCount() <= descriptorsBefore + 2, "Repeated commands leaked descriptors: before=\(descriptorsBefore), after=\(descriptorCount())")
    print("PASS: repeated command execution closes pipe descriptors")
    let failedDescriptors = descriptorCount()
    for _ in 0..<10 {
        try rejects { _ = try Command.run("/nonexistent/surge-guard-test", []) }
        try rejects { _ = try Command.run("/bin/sleep", ["1"], timeout: 0.01) }
        _ = try Command.run("/bin/cat", [], input: "test")
    }
    try check(descriptorCount() <= failedDescriptors + 2, "Command failure/input/timeout leaked pipe descriptors")
    let emptyLog = FileManager.default.temporaryDirectory.appendingPathComponent("surge-empty-log-" + UUID().uuidString)
    try Data().write(to: emptyLog)
    defer { try? FileManager.default.removeItem(at: emptyLog) }
    let logDescriptors = descriptorCount()
    for _ in 0..<20 { try LogReader.show(path: emptyLog.path, follow: false, json: true) }
    try check(descriptorCount() <= logDescriptors + 2, "Repeated log reads leaked pipe descriptors")
    let mockService = try Command.run("/usr/bin/printf", ["state = running\n pid = 123\n"])
    try check(try StatusReport.serviceRunning(mockService, pid: 123), "Running daemon rejected")
    try check(!(try StatusReport.serviceRunning(mockService, pid: 456)), "Mismatched PID accepted")
    try rejects { _ = try StatusReport.serviceRunning(Command.run("/usr/bin/false", [])) }
    let absentService = try Command.run("/bin/launchctl", ["print", "system/io.github.surge-guard.nonexistent-test"])
    try check(!(try StatusReport.serviceRunning(absentService)), "Absent service was treated as running")
    print("PASS: command failures release descriptors; query errors remain unknown, distinct from absent service")
    // Read-only regression for the group-writable /var/run found on macOS.
    try check(!Paths.runtime.hasPrefix("/var/run/"), "Runtime state must not depend on a non-writable /var/run")
    try RootFiles.verify(URL(fileURLWithPath: Paths.runtime).deletingLastPathComponent().path, directory: true)
    print("PASS: protected runtime parent")
    let reviewDirectory = FileManager.default.temporaryDirectory.appendingPathComponent("surge-review-tests-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: reviewDirectory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: reviewDirectory) }
    let missingPolicy = reviewDirectory.appendingPathComponent("policy.json").path
    try check(try Configuration.forInstallation(path: missingPolicy) == .enhanced,
              "Fresh installation failed after its state directory was prepared")
    try FileManager.default.createSymbolicLink(atPath: missingPolicy, withDestinationPath: missingPolicy + ".missing")
    try rejects { _ = try Configuration.forInstallation(path: missingPolicy) }
    print("PASS: install preflight handles a newly created state directory but rejects dangling policies")

    let descendantFile = reviewDirectory.appendingPathComponent("descendant.pid").path
    let beforeDescendants = descriptorCount()
    for exitsEarly in [false, true, false] {
        let script = "sleep 20 & child=$!; printf '%s' \"$child\" > \"$1\"; " + (exitsEarly ? "exit 0" : "wait")
        let began = SystemClock.seconds
        try rejects { _ = try Command.run("/bin/sh", ["-c", script, "fixture", descendantFile], timeout: exitsEarly ? 2 : 0.1) }
        try check(SystemClock.seconds - began < 3, "Inherited output pipes defeated command bounds")
        let child = Int32(try String(contentsOfFile: descendantFile))!
        let deadline = SystemClock.seconds + 2
        while kill(child, 0) == 0 && SystemClock.seconds < deadline { usleep(10_000) }
        let gone = kill(child, 0) != 0 && errno == ESRCH
        if !gone { kill(child, SIGKILL) }
        try check(gone, "Timed-out command left its test descendant alive")
    }
    try rejects { _ = try Command.run("/bin/sleep", ["20"], input: String(repeating: "x", count: 16_000), timeout: 0.05) }
    try check(descriptorCount() <= beforeDescendants + 2, "Inherited stdout/stderr or blocked stdin leaked descriptors")
    print("PASS: timeouts and early parent exit reap command groups and close inherited/blocked pipes")

    let waitingJob = try Command.run("/usr/bin/printf", ["state = waiting\n"])
    try check(try StatusReport.serviceLoaded(waitingJob) && !StatusReport.serviceRunning(waitingJob), "Loaded idle job confused with absence")
    try check(!(try StatusReport.serviceLoaded(absentService)), "Absent job treated as loaded")
    try rejects { _ = try StatusReport.serviceLoaded(Command.run("/bin/sh", ["-c", "exit 5"])) }
    try rejects { _ = try StatusReport.serviceRunning(Command.run("/usr/bin/printf", ["state = running\n"])) }
    try rejects { _ = try StatusReport.serviceRunning(Command.run("/usr/bin/printf", ["state = running\npid = 0\n"])) }
    for pids in ["pid = 1", "pid = 123\npid = malformed", "pid = 123\npid = 456"] {
        try rejects { _ = try StatusReport.servicePID(Command.run("/usr/bin/printf", ["state = running\n" + pids + "\n"])) }
    }
    for malformed in ["", "pid = 123\n", "state = running\nstate = waiting\npid = 123\n", "state = \n"] {
        try rejects { _ = try StatusReport.serviceLoaded(Command.run("/usr/bin/printf", [malformed])) }
    }
    try check(try StatusReport.servicePID(mockService) == 123 && StatusReport.servicePID(waitingJob) == nil,
              "Restart identity was not read from the actual service")
    var mismatchedSnapshot = GuardSnapshot(runId: "fixture", firewallVerifiedUptime: SystemClock.seconds,
                                          allowed: true, configurationMode: "enhanced", readiness: nil, session: nil, reasons: [])
    mismatchedSnapshot.pid = 456
    let mismatch = try StatusReport.evaluate(service: mockService, snapshot: mismatchedSnapshot)
    try check(mismatch.state == "unknown" && mismatch.daemonRunning && !mismatch.firewallVerified && mismatch.reason == "status_process_mismatch",
              "Old process snapshot described a running replacement daemon as stopped/allowed")
    mismatchedSnapshot.pid = 123
    try check(try StatusReport.evaluate(service: mockService, snapshot: mismatchedSnapshot).state == "allowed", "Current fresh daemon rejected")
    let retainedStatus = try StatusReport.evaluate(service: mockService, snapshot: mismatchedSnapshot)
    for expireAudit in [false, true] {
        var expired = retainedStatus
        if expireAudit { expired.snapshot!.firewallVerifiedUptime = SystemClock.seconds - 9 }
        else { expired.snapshot!.checkedUptime = SystemClock.seconds - 9 }
        try check(expired.state == "allowed" && !expired.firewallVerified,
                  "A retained allowed state hid expiration during an application identity/launch operation")
        try check(try StatusReport.evaluate(service: mockService, snapshot: expired.snapshot!).state == "unknown",
                  "Expired launch authorization was not rejected on revalidation")
    }
    try check(retainedStatus.firewallVerified, "Expiry checks changed a separate fresh status value")
    print("PASS: retained allowed reports recheck both status and PF-audit freshness at use")
    try check(try StatusReport.evaluate(service: absentService, snapshot: mismatchedSnapshot).state == "stopped", "Absent daemon reported as running")
    try check(PacketAuditMenu(service: mockService, snapshot: nil).canStop &&
              PacketAuditMenu(service: nil, snapshot: nil).canStop &&
              !PacketAuditMenu(service: absentService, snapshot: nil).canStop,
              "Unknown audit state concealed the stop action")
    var incompleteAudit = PacketAuditSnapshot(capacityMegabytes: 256)
    incompleteAudit.pid = 123; incompleteAudit.state = "incomplete"
    let incompleteMenu = PacketAuditMenu(service: mockService, snapshot: incompleteAudit)
    try check(incompleteMenu.canStop && incompleteMenu.title.contains("不完整"), "Incomplete collector was described as stopped")
    incompleteAudit.state = "capturing"; incompleteAudit.checkedUptime = 0
    try check(PacketAuditMenu(service: mockService, snapshot: incompleteAudit).title.contains("待验证"), "Stale capture described as active")
    let stoppedReport = try JSON.decode(StatusReport.self, from: Data("{\"state\":\"stopped\",\"daemon_running\":false,\"reason\":\"test\"}".utf8))
    try check(stoppedReport.stoppedExplanation.contains("未经核验") && !stoppedReport.stoppedExplanation.contains("直接放行"),
              "Stopped guard claimed an empty firewall")
    print("PASS: service queries fail closed; stopped and incomplete menus retain uncertainty and recovery")

    let pendingLaunch = GatePendingLaunch(app: "com.example.fixture")
    let pendingPath = reviewDirectory.appendingPathComponent("launch.json").path
    try AtomicFile.write(JSON.encode(pendingLaunch), to: pendingPath, mode: 0o600)
    try check(try GatePendingLaunch.load(from: pendingPath) == pendingLaunch, "Pending launch did not survive reload")
    try check(!pause.acknowledged(by: pause, state: "update_pausing", fresh: true) &&
              !resume.acknowledged(by: resume, state: "launch_pending", fresh: true), "Outstanding launch acknowledged an update")
    let laterLaunch = GatePendingLaunch(app: "com.example.later")
    try AtomicFile.write(JSON.encode(laterLaunch), to: pendingPath, mode: 0o600)
    try pendingLaunch.complete(at: pendingPath)
    try check(try GatePendingLaunch.load(from: pendingPath) == laterLaunch, "Obsolete launch completion cleared a newer request")
    try laterLaunch.complete(at: pendingPath)
    try check(try GatePendingLaunch.load(from: pendingPath) == nil, "Completed launch kept its pause fence")
    let oldObserver = UUID(), newObserver = UUID()
    let orphan = GatePendingLaunch(app: "com.example.failed", observer: oldObserver)
    try orphan.save(at: pendingPath)
    let reloaded = try GatePendingLaunch.load(from: pendingPath)!
    try check(reloaded.disposition(observer: newObserver, callbackPending: false, appRunning: false, childIdentity: nil) == .orphaned,
              "Lost observer with absent app remained an eternal in-flight launch")
    try check(reloaded.disposition(observer: oldObserver, callbackPending: true, appRunning: true, childIdentity: nil) == .inFlight,
              "An active callback was bypassed by app appearance")
    try check(reloaded.disposition(observer: newObserver, callbackPending: false, appRunning: true, childIdentity: nil) == .settled,
              "Observed startup could not settle an orphan")
    try check(reloaded.disposition(observer: oldObserver, callbackPending: false, appRunning: false, childIdentity: nil) == .failed,
              "A finished local observer remained stuck after completion cleanup failed")
    try check(pendingLaunch.disposition(observer: newObserver, callbackPending: false, appRunning: false, childIdentity: nil) == .orphaned,
              "Legacy marker without observer was not recoverable")
    try rejects { try laterLaunch.save(at: pendingPath) }
    try rejects { try GatePendingLaunch.recover(id: orphan.id, observer: oldObserver, at: pendingPath) }
    try rejects { try GatePendingLaunch.recover(id: UUID(), observer: newObserver, at: pendingPath) }
    try rejects { try GateShutdownRequest.validate(paused: false, pendingLaunch: reloaded, phase: .idle) }
    try check(!pause.acknowledged(by: pause, state: "launch_recovery_required", fresh: true) &&
              !resume.acknowledged(by: resume, state: "launch_recovery_required", fresh: true), "Orphaned launch acknowledged an update")
    try check(try GatePendingLaunch.observationIsCurrent(reloaded, at: pendingPath), "Current launch observation rejected")
    try GatePendingLaunch.recover(id: orphan.id, observer: newObserver, at: pendingPath)
    try check(!(try GatePendingLaunch.observationIsCurrent(reloaded, at: pendingPath)) &&
              GatePendingLaunch.observationIsCurrent(nil, at: pendingPath), "Recovered marker allowed stale request consumption")
    try GateShutdownRequest.validate(paused: false, pendingLaunch: GatePendingLaunch.load(from: pendingPath), phase: .idle)
    try laterLaunch.save(at: pendingPath)
    try orphan.complete(at: pendingPath)
    try check(try GatePendingLaunch.load(from: pendingPath)?.id == laterLaunch.id, "Late completion cleared post-recovery launch")
    try laterLaunch.complete(at: pendingPath)

    let launchChild = Process()
    launchChild.executableURL = URL(fileURLWithPath: "/bin/sleep"); launchChild.arguments = ["0.5"]
    try launchChild.run()
    var tracked = GatePendingLaunch(app: "com.nssurge.surge-mac", observer: oldObserver)
    tracked.child = try SurgeProcess.read(pid: launchChild.processIdentifier)
    try check(tracked.child != nil, "Native launcher fixture missing")
    try tracked.save(at: pendingPath)
    let afterRestart = try GatePendingLaunch.load(from: pendingPath)!
    try check(afterRestart.disposition(observer: newObserver, callbackPending: false, appRunning: false,
                                       childIdentity: SurgeProcess.read(pid: launchChild.processIdentifier)) == .inFlight,
              "Living launcher was forgotten after observer restart")
    try rejects { try GatePendingLaunch.recover(id: tracked.id, observer: newObserver, at: pendingPath) }
    launchChild.waitUntilExit()
    try check(afterRestart.disposition(observer: newObserver, callbackPending: false, appRunning: false,
                                       childIdentity: SurgeProcess.read(pid: launchChild.processIdentifier)) == .failed,
              "Exited launcher with no app blocked recovery after Gate restart")
    let reusedChild = SurgeProcess(pid: tracked.child!.pid, startedSeconds: tracked.child!.startedSeconds + 1, startedMicroseconds: 0)
    try check(afterRestart.disposition(observer: newObserver, callbackPending: false, appRunning: false, childIdentity: reusedChild) == .failed,
              "PID reuse retained a dead launch request")
    try tracked.complete(at: pendingPath)
    print("PASS: restart launch recovery distinguishes living/exited/reused children, legacy/orphaned callbacks and exact-nonce confirmation")
    let request = try GateShutdownRequest(action: "restart")
    let requestPath = reviewDirectory.appendingPathComponent("shutdown.json").path
    try AtomicFile.write(JSON.encode(request), to: requestPath, mode: 0o600)
    try check(try GateShutdownRequest.load(from: requestPath)?.id == request.id, "Shutdown nonce was not preserved")
    let newerShutdown = try GateShutdownRequest(action: "shutdown")
    try check(!(try newerShutdown.withdraw(at: requestPath)), "Withdrawal removed another shutdown request")
    try check(try request.withdraw(at: requestPath) && GateShutdownRequest.load(from: requestPath) == nil,
              "Failed bootstrap left a shutdown request queued for later execution")
    try check(!(try request.withdraw(at: requestPath)), "Consumed shutdown was reported as withdrawn")
    try AtomicFile.write(JSON.encode(request), to: requestPath, mode: 0o600)
    try GateShutdownRequest.cancel(at: requestPath)
    try check(try GateShutdownRequest.load(from: requestPath) == nil, "Stopped/uninstalled Gate could replay a queued shutdown on reinstall")
    try GateShutdownRequest.cancel(at: requestPath)
    try AtomicFile.write("malformed request", to: requestPath, mode: 0o600)
    try GateShutdownRequest.cancel(at: requestPath)
    try laterLaunch.save(at: pendingPath)
    try FileManager.default.createSymbolicLink(atPath: requestPath, withDestinationPath: pendingPath)
    try GateShutdownRequest.cancel(at: requestPath)
    try check(try GatePendingLaunch.load(from: pendingPath) == laterLaunch, "Shutdown cancellation followed a symlink and cleared the launch fence")
    try laterLaunch.complete(at: pendingPath)
    let cancelDirectory = reviewDirectory.appendingPathComponent("cancel-denied")
    try UserPaths.prepare(cancelDirectory.path)
    let deniedRequest = cancelDirectory.appendingPathComponent("request.json").path
    try AtomicFile.write(JSON.encode(request), to: deniedRequest, mode: 0o600)
    do {
        defer { chmod(cancelDirectory.path, 0o700) }
        try check(chmod(cancelDirectory.path, 0o500) == 0, "Cannot prepare denied-cancellation fixture")
        try rejects { try GateShutdownRequest.cancel(at: deniedRequest) }
        try check(try GateShutdownRequest.load(from: deniedRequest)?.id == request.id, "Failed cancellation lost its queued request")
    }
    try GateShutdownRequest.cancel(at: deniedRequest)
    print("PASS: stopped/uninstalled Gate cancels queued shutdowns and reports cancellation failure without clearing launch fences")
    try rejects { try GateShutdownRequest.validate(paused: true, pendingLaunch: nil, phase: .idle) }
    try rejects { try GateShutdownRequest.validate(paused: false, pendingLaunch: nil, phase: .quitting) }
    for phase in [GateShutdownPhase.idle, .submitted, .aborted] {
        try GateShutdownRequest.validate(paused: false, pendingLaunch: nil, phase: phase)
    }
    var oldRequest = try JSONSerialization.jsonObject(with: Data(JSON.encode(request).utf8)) as! [String: Any]
    oldRequest["boot_id"] = "previous-boot"
    try AtomicFile.write(String(decoding: JSONSerialization.data(withJSONObject: oldRequest), as: UTF8.self), to: requestPath, mode: 0o600)
    try check(try GateShutdownRequest.load(from: requestPath) == nil, "Previous boot shutdown was replayed")
    try rejects { _ = try GateShutdownRequest(action: "invalid") }
    try check(GateShutdownPhase.submitted.canRetry && GateShutdownPhase.aborted.canRetry &&
              GateShutdownPhase.submitted.preservesSession && GateShutdownPhase.aborted.preservesSession &&
              !GateShutdownPhase.quitting.canRetry && !GateShutdownPhase.idle.preservesSession,
              "Cancelled or aborted power request lost retry/session semantics")
    print("PASS: persisted launch fence, pause acknowledgement, shutdown nonce/boot binding and cancellation retry")

    let canonicalDNS = Data("{\"dnsCache\":[{\"domain\":\"Example.COM.\",\"data\":[\"2001:4860:4860:0000:0000:0000:0000:8888\",\"::ffff:1.1.1.1\"]}],\"local\":[]}".utf8)
    let canonicalMap = try EgressObservation.parseSurgeDomains(canonicalDNS, source: "dns")
    try check(canonicalMap["2001:4860:4860::8888"] == ["example.com"] && canonicalMap["1.1.1.1"] == ["example.com"],
              "Equivalent IPv6/mapped IPv4 or domain spelling did not normalize")
    let forwardingDNS = Data("{\"dnsCache\":[],\"local\":[{\"domain\":\"forward.example\",\"data\":null,\"server\":\"system\"},{\"domain\":\"mapped.example\",\"data\":\"1.1.1.1\"}]}".utf8)
    try check(try EgressObservation.parseSurgeDomains(forwardingDNS, source: "dns")["1.1.1.1"] == ["mapped.example"],
              "A local DNS forwarding rule discarded valid address mappings")
    try rejects { _ = try EgressObservation.parseSurgeDomains(Data("{\"dnsCache\":[],\"local\":[{\"domain\":\"bad.example\"}]}".utf8), source: "dns") }
    let rawVIP = Data("{\"items\":[{\"d\":\"vip.example.com\",\"i\":3323068426,\"l\":0,\"c\":0}]}".utf8)
    try check(try EgressObservation.parseSurgeDomains(rawVIP, source: "virtual_ip")["198.18.0.10"] == ["vip.example.com"], "Raw integer virtual IP was lost")
    for source in ["dns", "virtual_ip"] {
        try rejects { _ = try EgressObservation.parseSurgeDomains(Data("{}".utf8), source: source) }
    }
    var enriched = observed
    enriched.flows[0].remoteEndpoint = "[2001:4860:4860:0:0:0:0:8888]:443"
    enriched.enrichDomains { source in
        if source == "dns" { return canonicalDNS }
        throw GuardError("fixture query failed")
    }
    let domainRoundTrip = try JSON.decode(EgressObservation.self, from: Data(JSON.encode(enriched).utf8))
    try check(domainRoundTrip.flows[0].candidateDomains == ["example.com"] && domainRoundTrip.domainQueries?["dns"]?.status == "ok" &&
              domainRoundTrip.domainQueries?["virtual_ip"]?.status == "failed", "JSON lost candidates or partial-query failures")
    enriched.enrichDomains { Data(($0 == "dns" ? "{\"dnsCache\":[],\"local\":[]}" : "{\"items\":[]}").utf8) }
    try check(enriched.domainQueries?.values.allSatisfy { $0.status == "empty" } == true && enriched.flows[0].candidateDomains == [],
              "Successful empty lookup confused with failure or retained old names")
    let manyDomains = (0..<8).map { ["domain": "node\($0).example", "data": ["1.1.1.1"]] as [String: Any] }
    let boundedDomains = try EgressObservation.parseSurgeDomains(JSONSerialization.data(withJSONObject: ["dnsCache": manyDomains + manyDomains, "local": []]), source: "dns")
    try check(boundedDomains["1.1.1.1"]?.count == 5, "Candidate domain deduplication/limit failed")
    print("PASS: structured candidate domains, canonical IP matching, raw VIP schema and explicit query outcomes")
    let menuProject = reviewDirectory.appendingPathComponent("menu-project")
    let menuHome = reviewDirectory.appendingPathComponent("menu-home")
    for path in ["scripts", ".build/release", "integrations/swiftbar"] {
        try FileManager.default.createDirectory(at: menuProject.appendingPathComponent(path), withIntermediateDirectories: true)
    }
    let menuUser = menuHome.appendingPathComponent("Library/Application Support/SurgeGuard")
    try FileManager.default.createDirectory(at: menuUser.appendingPathComponent("bin"), withIntermediateDirectories: true)
    let sentinel = "existing Gate must remain unchanged"
    let installedGate = menuUser.appendingPathComponent("bin/surge-gate")
    try sentinel.write(to: installedGate, atomically: true, encoding: .utf8)
    let fixtureExecutable = "#!/bin/sh\necho unexpected-service-query >> '\(menuProject.path)/mutations'\nexit 1\n"
    for path in [".build/release/surge-guard", ".build/release/surge-gate", "integrations/swiftbar/surge-guard-action.sh", "integrations/swiftbar/surge-guard.5s.sh"] {
        let target = menuProject.appendingPathComponent(path)
        try fixtureExecutable.write(to: target, atomically: true, encoding: .utf8)
        chmod(target.path, 0o700)
    }
    let sourceRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    var installer = try String(contentsOf: sourceRoot.appendingPathComponent("scripts/install-user.sh"))
    installer = installer.replacingOccurrences(of: "guard_bin=/Library/PrivilegedHelperTools/surge-guard", with: "guard_bin='\(menuProject.path)/.build/release/surge-guard'")
    installer = installer.replacingOccurrences(of: "set -eu", with: "set -eu\nHOME='\(menuHome.path)'\nexport HOME")
    let installerPath = menuProject.appendingPathComponent("scripts/install-user.sh")
    try installer.write(to: installerPath, atomically: true, encoding: .utf8)
    let menuInstall = try Command.run("/bin/sh", [installerPath.path, "--menu-only"], timeout: 10)
    try check(menuInstall.status == 0 && !FileManager.default.fileExists(atPath: menuProject.appendingPathComponent("mutations").path) &&
              String(contentsOf: installedGate) == sentinel && FileManager.default.isExecutableFile(atPath: menuUser.appendingPathComponent("bin/surge-guard-ui").path),
              "Menu-only installer queried or modified a service")
    print("PASS: menu-only installation updates the renderer without querying/restarting Gate or Guard")
    print("All checks passed. Live packet blocking has NOT been tested by this program.")
} catch {
    fputs("FAIL: \(error)\n", stderr)
    exit(1)
}
