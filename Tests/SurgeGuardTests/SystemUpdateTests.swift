import Foundation
import Darwin
import SurgeGuardCore

func systemUpdateTests() throws {
    var record = SystemUpdate(userID: 501, backupID: UUID().uuidString)
    for phase in [SystemUpdate.Phase.preparing, .active, .restoring] {
        record.phase = phase
        let data = Data(try JSON.encode(record).utf8)
        try check(try SystemUpdate.decode(data) == record, "Maintenance checkpoint did not round trip")
    }
    let valid = try JSONSerialization.jsonObject(with: Data(JSON.encode(record).utf8)) as! [String: Any]
    for (key, value) in [("version", 2 as Any), ("phase", "expired"), ("user_id", 0),
                         ("backup_id", "../backup"), ("started_at", -1), ("extra", true), ("id", NSNull())] {
        var changed = valid; changed[key] = value
        try rejects { _ = try SystemUpdate.decode(JSONSerialization.data(withJSONObject: changed)) }
    }
    for key in valid.keys {
        var changed = valid; changed.removeValue(forKey: key)
        try rejects { _ = try SystemUpdate.decode(JSONSerialization.data(withJSONObject: changed)) }
    }
    try rejects { _ = try SystemUpdate.decode(Data(repeating: 32, count: 4097)) }
    print("PASS: system update phases, cross-boot checkpoints and strict maintenance schema")

    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("system-update-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: directory) }
    let file = directory.appendingPathComponent("record.json").path
    try check(try SystemUpdate.load(from: file, owner: getuid()) == nil, "Absent maintenance record was not normal")
    try AtomicFile.write(try JSON.encode(record), to: file, mode: 0o644)
    try check(try SystemUpdate.load(from: file, owner: getuid()) == record, "Valid maintenance read failed")
    try rejects { _ = try SystemUpdate.load(from: file, owner: getuid() + 1) }
    let linkPath = directory.appendingPathComponent("symbolic").path
    try FileManager.default.createSymbolicLink(atPath: linkPath, withDestinationPath: file)
    try rejects { _ = try SystemUpdate.load(from: linkPath, owner: getuid()) }
    let hardLink = directory.appendingPathComponent("hard").path
    try FileManager.default.linkItem(atPath: file, toPath: hardLink)
    try rejects { _ = try SystemUpdate.load(from: file, owner: getuid()) }
    try FileManager.default.removeItem(atPath: hardLink)
    try check(chmod(file, 0o666) == 0, "Cannot prepare writable maintenance fixture")
    try rejects { _ = try SystemUpdate.load(from: file, owner: getuid()) }
    try check(chmod(file, 0o644) == 0, "Cannot restore maintenance fixture permissions")
    let fifo = directory.appendingPathComponent("fifo").path
    try check(mkfifo(fifo, 0o600) == 0, "Cannot create maintenance FIFO fixture")
    let start = SystemClock.seconds
    try rejects { _ = try SystemUpdate.load(from: fifo, owner: getuid()) }
    try check(SystemClock.seconds - start < 1, "Maintenance reader blocked on a FIFO")
    let descriptors = { (0..<4096).filter { fcntl(Int32($0), F_GETFD) != -1 }.count }
    let before = descriptors()
    for _ in 0..<100 {
        _ = try SystemUpdate.load(from: file, owner: getuid())
        try rejects { _ = try SystemUpdate.load(from: fifo, owner: getuid()) }
    }
    try check(descriptors() <= before + 1, "Maintenance reader leaked descriptors")
    try AtomicFile.write(String(repeating: "x", count: 4097), to: file, mode: 0o644)
    try rejects { _ = try SystemUpdate.load(from: file, owner: getuid()) }
    print("PASS: maintenance ownership, links, permissions, size, nonblocking reads and descriptor cleanup")

    let service = try Command.run("/usr/bin/printf", ["state = running\npid = 123\n"])
    var ack: [String: Any] = ["state": "os_update_paused", "system_update_id": record.id.uuidString,
                              "pid": 123, "boot_id": "boot", "checked_uptime": 99.0]
    func acknowledged(_ value: [String: Any]) throws -> Bool {
        try SystemUpdate.gateAcknowledged(JSONSerialization.data(withJSONObject: value), service: service,
                                          id: record.id, boot: "boot", now: 100)
    }
    try check(try acknowledged(ack), "Fresh Gate acknowledgement rejected")
    for (key, value) in [("state", "os_update_waiting" as Any), ("system_update_id", UUID().uuidString),
                         ("pid", 456), ("boot_id", "old-boot"), ("checked_uptime", 85), ("checked_uptime", 101)] {
        var changed = ack; changed[key] = value
        try check(try !acknowledged(changed), "Unsafe Gate acknowledgement accepted: \(key)")
    }
    ack.removeValue(forKey: "system_update_id")
    try check(try !acknowledged(ack), "Old Gate without maintenance acknowledgement accepted")
    print("PASS: Gate maintenance acknowledgement requires exact nonce, native PID, boot and freshness")

    record.phase = .active
    var snapshot = GuardSnapshot(runId: "fixture", firewallVerifiedUptime: SystemClock.seconds,
                                 allowed: false, configurationMode: "maintenance", readiness: nil, session: nil,
                                 reasons: [], enforcement: "os_update_maintenance", systemUpdateId: record.id)
    snapshot.pid = 123
    func report(_ snapshot: GuardSnapshot, _ value: SystemUpdate?) throws -> StatusReport {
        try StatusReport.evaluate(service: service, snapshot: snapshot).withSystemUpdate(value)
    }
    let released = try report(snapshot, record)
    try check(snapshot.version == 2, "Legacy snapshot readers could mistake maintenance for protected blocking")
    try check(released.maintenanceVerified && !released.firewallVerified && record.verified(by: released), "Maintenance was misreported as ordinary protection")
    try check(try !StatusReport.evaluate(service: service, snapshot: snapshot).firewallVerified,
              "A maintenance snapshot claimed protected PF without loading the checkpoint")
    var oldCheckpoint = try JSONSerialization.jsonObject(with: Data(JSON.encode(record).utf8)) as! [String: Any]
    oldCheckpoint["started_at"] = 1
    let persistent = try SystemUpdate.decode(JSONSerialization.data(withJSONObject: oldCheckpoint))
    try check(try persistent.verified(by: report(snapshot, persistent)), "Maintenance expired due to wall-clock age")
    let failedQuery = try JSON.decode(StatusReport.self, from: Data("""
    {"state":"unknown","daemon_running":false,"reason":"service_query_failed: fixture"}
    """.utf8)).withSystemUpdate(record)
    try check(failedQuery.systemUpdate == record && failedQuery.state == "unknown" &&
              !failedQuery.maintenanceVerified && failedQuery.reason.contains("service_query_failed"),
              "Query failure lost maintenance recovery metadata or claimed verification")
    var wrong = snapshot; wrong.systemUpdateId = UUID()
    try check(try report(wrong, record).state == "unknown", "Different maintenance generation accepted")
    wrong = snapshot; wrong.pid = 456
    try check(try !record.verified(by: report(wrong, record)), "Other daemon PID verified maintenance")
    wrong = snapshot; wrong.checkedUptime -= 9
    try check(try report(wrong, record).state == "unknown", "Expired maintenance status accepted")
    wrong = snapshot; wrong.bootId = "previous"
    try check(try !record.verified(by: report(wrong, record)), "Previous boot verified maintenance")
    wrong = snapshot; wrong.version = 1
    try check(try !record.verified(by: report(wrong, record)), "Maintenance used the legacy protected-PF snapshot version")
    try check(try report(snapshot, nil).state == "unknown", "Suspended snapshot without authorization appeared protected")
    record.phase = .restoring
    try check(try !record.verified(by: report(snapshot, record)), "Restoring accepted old released rules")
    snapshot.enforcement = "persistent_tcp_egress"
    try check(try !record.verified(by: report(snapshot, record)), "Maintenance snapshot version verified normal restoration")
    snapshot.version = 1
    for allowed in [false, true] {
        snapshot.allowed = allowed
        try check(try record.verified(by: report(snapshot, record)), "Verified restored PF was rejected")
    }
    record.phase = .preparing
    try check(try !record.verified(by: report(snapshot, record)), "Preparation falsely completed maintenance")
    record.phase = .active
    try check(try !record.verified(by: report(snapshot, record)), "Normal pre-maintenance PF snapshot verified rule release")
    print("PASS: maintenance and restored PF status distinguish intent, suspension, stale evidence and blocked protection")

    for failure in ["write", "clear", "verify", "none"] {
        var steps: [String] = []
        let operation = {
            try SystemUpdate.suspend(writeAnchor: {
                steps.append("write"); if failure == "write" { throw GuardError("fixture") }
            }, clearRules: {
                steps.append("clear"); if failure == "clear" { throw GuardError("fixture") }
            }, verify: { steps.append("verify"); return failure != "verify" })
        }
        if failure == "none" { try operation() } else { try rejects(operation) }
        try check(steps == (failure == "write" ? ["write"] : failure == "clear" ? ["write", "clear"] : ["write", "clear", "verify"]),
                  "Maintenance skipped durable ordering or continued after failure")
    }
    print("PASS: maintenance writes boot rules before live release and never accepts failed verification")
    try systemUpdateRestorationTests()
}

func systemUpdateRestorationTests() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("maintenance-restore-" + UUID().uuidString)
    try UserPaths.prepare(directory.path)
    defer { try? FileManager.default.removeItem(at: directory) }
    let path = directory.appendingPathComponent("runtime.lock").path
    func acquire() throws -> RuntimeLock {
        try RuntimeLock(taking: open(path, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600), timeout: 0.25)
    }
    func requireHeld() throws {
        let contender = open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC)
        guard contender >= 0 else { throw GuardError("Cannot open restoration lock fixture") }
        defer { close(contender) }
        try check(flock(contender, LOCK_EX | LOCK_NB) != 0 && (errno == EWOULDBLOCK || errno == EAGAIN),
                  "Restoration checkpoint/PF work ran without the runtime lock")
    }
    var record = SystemUpdate(userID: 501, backupID: UUID().uuidString); record.phase = .active
    let original = record
    var steps: [String] = []
    do {
        let child = Process(), input = Pipe(), output = Pipe()
        child.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
        child.arguments = ["--hold-runtime-lock", path]
        child.standardInput = input; child.standardOutput = output; child.standardError = FileHandle.nullDevice
        defer {
            for handle in [input.fileHandleForReading, input.fileHandleForWriting, output.fileHandleForReading, output.fileHandleForWriting] { try? handle.close() }
        }
        try child.run()
        let watchdog = DispatchWorkItem { fputs("FAIL: maintenance restoration lock test timed out\n", stderr); _exit(1) }
        DispatchQueue.global().asyncAfter(deadline: .now() + 5, execute: watchdog)
        defer {
            try? input.fileHandleForWriting.close()
            child.waitUntilExit(); watchdog.cancel()
        }
        try input.fileHandleForReading.close(); try output.fileHandleForWriting.close()
        let ready = try output.fileHandleForReading.read(upToCount: 6)
        try check(ready == Data("READY\n".utf8), "Restoration fixture child did not acquire its lifetime lock")
        let restored = try SystemUpdate.prepareRestoration(read: { steps.append("read"); return record }, stop: {
            steps.append("stop")
            try input.fileHandleForWriting.write(contentsOf: Data([10])); try input.fileHandleForWriting.close()
            child.waitUntilExit()
            try check(child.terminationStatus == 0, "Restoration did not stop its lock-owning fixture normally")
        }, lock: { steps.append("lock"); return try acquire() }, save: {
            try requireHeld(); steps.append("save"); record = $0
        }, protect: { try requireHeld(); steps.append("protect") })
        try check(steps == ["read", "stop", "lock", "read", "save", "protect"] && restored == record &&
                  record.phase == .restoring && record.id == original.id && record.backupID == original.backupID,
                  "Restoration acquired the lock before stopping or changed its checkpoint identity")
    }
    do { let released = try acquire(); withExtendedLifetime(released) {} }
    print("PASS: maintenance restoration stops a lifetime-lock child before acquiring the same runtime lock")

    let absent = try SystemUpdate.prepareRestoration(read: { nil }, stop: { throw GuardError("Unexpected stop") },
        lock: { throw GuardError("Unexpected lock") }, save: { _ in throw GuardError("Unexpected save") },
        protect: { throw GuardError("Unexpected PF operation") })
    try check(absent == nil, "Absent maintenance unexpectedly changed the running service")
    for failure in ["read", "reread", "stop", "lock", "save", "protect", "changed", "removed"] {
        var reads = 0, protected = false, saved = false
        do {
            _ = try SystemUpdate.prepareRestoration(read: {
                reads += 1
                if failure == "read" || (reads == 2 && failure == "reread") { throw GuardError("injected \(failure)") }
                if reads == 2 && failure == "removed" { return nil }
                if reads == 2 && failure == "changed" { return SystemUpdate(userID: 501, backupID: UUID().uuidString) }
                return original
            }, stop: {
                if failure == "stop" { throw GuardError("injected stop") }
            }, lock: {
                if failure == "lock" { throw GuardError("injected lock") }
                return try acquire()
            }, save: { checkpoint in
                try requireHeld()
                if failure == "save" { throw GuardError("injected save") }
                saved = true
                try check(checkpoint.phase == .restoring && checkpoint.id == original.id, "Restoration published the wrong checkpoint")
            }, protect: {
                try requireHeld(); protected = true
                if failure == "protect" { throw GuardError("injected protect") }
            })
            throw GuardError("Expected restoration failure was swallowed: \(failure)")
        } catch {
            let message = String(describing: error)
            try check(!message.contains("swallowed") && protected == !["stop", "lock"].contains(failure) &&
                      saved == (failure == "protect"), "Restoration skipped failure protection or continued past a failed step: \(failure)")
            if ["read", "reread", "save", "protect"].contains(failure) {
                try check(message.contains("injected \(failure)"), "Restoration lost the original failure: \(failure)")
            }
        }
    }
    print("PASS: restoration rechecks checkpoints under lock, protects failed reads/saves and stops on service/lock errors")
}
