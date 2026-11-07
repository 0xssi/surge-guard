import Foundation
import Darwin
import SurgeGuardCore

func diagnosticLockCheck(_ binary: String) throws {
    let home = FileManager.default.temporaryDirectory.appendingPathComponent("diagnostic-lock-" + UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: home) }
    let state = home.appendingPathComponent("Library/Application Support/SurgeGuard")
    try UserPaths.prepare(state.path)
    let lock = try UserPaths.lock(at: state.appendingPathComponent("diagnostic.lock").path)
    defer { close(lock) }
    let path = state.appendingPathComponent("diagnostic-report.json").path
    try AtomicFile.write("current writer's evidence", to: path, mode: 0o600)
    let result = try Command.run("/usr/bin/env", ["CFFIXED_USER_HOME=" + home.path, binary, "diagnose", "--json"], timeout: 5)
    let object = try JSONSerialization.jsonObject(with: Data(result.output.utf8)) as? [String: Any]
    try check(result.status != 0 && (object?["error"] as? String)?.contains("diagnostic writer lock") == true &&
              String(contentsOfFile: path) == "current writer's evidence", "Duplicate diagnostics overwrote evidence or returned invalid JSON")
    print("PASS: duplicate diagnostics preserve the active writer's private report and machine-readable failure")
}

func diagnosticSaveCheck() throws {
    var first = DiagnosticReport(minutes: 20)
    first.snapshots["fixture"] = ["generation": 1]
    try first.save()
    var second = DiagnosticReport(minutes: 20)
    second.snapshots["fixture"] = ["generation": 2]
    try second.save()
    second.snapshots["fixture"] = ["generation": 3]
    try second.save(rotatePrevious: false)
    for (suffix, generation) in [("", 3), (".1", 1)] {
        let path = DiagnosticReport.path + suffix
        var info = stat()
        try check(lstat(path, &info) == 0 && info.st_uid == getuid() && info.st_mode & 0o777 == 0o600,
                  "Diagnostic report exposed private evidence")
        let object = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: path))) as! [String: Any]
        let snapshot = (object["snapshots"] as! [String: Any])["fixture"] as! [String: Any]
        try check(snapshot["generation"] as? Int == generation, "Checkpoint overwrote the previous diagnostic session")
    }
}

func diagnosticTests() throws {
    let defaults = try DiagnosticOptions([])
    try check(defaults.minutes == 20 && defaults.watchSeconds == 0 && !defaults.json, "Diagnostic defaults changed")
    let selected = try DiagnosticOptions(["--json", "--watch-seconds", "300", "--minutes", "120"])
    try check(selected.minutes == 120 && selected.watchSeconds == 300 && selected.json, "Valid diagnostic limits rejected")
    for args in [["--minutes"], ["--minutes", "0"], ["--minutes", "121"], ["--minutes", "1.5"],
                 ["--watch-seconds", "0"], ["--watch-seconds", "301"], ["--watch-seconds", "-1"],
                 ["--json", "--json"], ["--unknown"], ["--minutes", "1", "--minutes", "2"]] {
        try rejects { _ = try DiagnosticOptions(args) }
    }
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    var report = DiagnosticReport(minutes: 20, now: now)
    let original: [String: Any] = ["time": now.timeIntervalSince1970 - 2, "event": "command_failed", "pid": 123,
                                   "details": ["raw_error": "Surge isn't running on the local machine", "signal": 9]]
    let line = String(decoding: try JSONSerialization.data(withJSONObject: original, options: [.sortedKeys]), as: UTF8.self)
    report.ingest(line + "\n{truncated<…>\n{\"time\":true}\n{\"time\":1}\n", source: "guard", jsonLines: true, now: now)
    report.ingest(line, source: "guard.1", jsonLines: true, now: now)
    try check(report.entries.count == 1 && report.sources[0]["malformed_or_undated_lines"] as? Int == 2,
              "Diagnostic time filtering, malformed evidence or rotation deduplication failed")
    let retained = report.entries[0]["record"] as! [String: Any]
    try check(retained["pid"] as? Int == 123 && (retained["details"] as? [String: Any])?["signal"] as? Int == 9,
              "Diagnostic report lost raw process/error evidence")
    report.unavailable("private_logs", error: "authentication_required")
    try check(report.render().contains("证据缺口") && !report.render().contains("根因已确定"), "Missing evidence appeared successful")
    let parsed = try JSONSerialization.jsonObject(with: Data(report.encoded().utf8)) as! [String: Any]
    try check(parsed["root_cause"] as? String == "not_determined" && parsed["no_bypass_verified"] as? Bool == false &&
              parsed["collection_finished"] as? Bool == false && report.render().contains("中间检查点"),
              "Diagnostic evidence claimed a root cause or no bypass")
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX"); formatter.timeZone = .current
    formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSSSSS"
    let dnsLine = formatter.string(from: now.addingTimeInterval(-1)) + " <WARNING> [SGDNSOverQUICSession-2] QUIC connection timeout"
    let ignored = formatter.string(from: now.addingTimeInterval(-1)) + " <VERBOSE> [SGHTTPConnection] body must not be collected"
    let memory = String(decoding: try JSONSerialization.data(withJSONObject: ["log": dnsLine + "\n" + ignored]), as: UTF8.self)
    try report.ingestMemory(memory, now: now)
    try report.ingestMemory(memory, now: now)
    try check(report.entries.count == 2 && report.entries.last?["raw"] as? String == dnsLine,
              "Memory capture duplicated records or collected unrelated HTTP data")
    try rejects { try report.ingestMemory("{\"log\":42}", now: now) }
    let later = formatter.string(from: now.addingTimeInterval(3)) + " <VERBOSE> [SGDNSClient] later observation"
    try report.ingestMemory(String(decoding: try JSONSerialization.data(withJSONObject: ["log": later]), as: UTF8.self), now: now.addingTimeInterval(4))
    try check(report.sources.contains { $0["source"] as? String == "surge_memory_gap" }, "Non-overlapping memory windows concealed a coverage gap")
    report.finish(at: now.addingTimeInterval(10))
    try check(report.endedAt == now.addingTimeInterval(10) && report.collectionFinished,
              "Failed memory polls shortened the observation window or completed reports stayed unfinished")

    var bounded = DiagnosticReport(minutes: 120, now: now)
    for index in 0..<(DiagnosticReport.maximumEntries + 3) {
        bounded.ingest("{\"time\":\(now.timeIntervalSince1970 - 10 + Double(index) / 1000),\"event\":\"fixture_\(index)\"}", source: "fixture", jsonLines: true, now: now)
    }
    try check(bounded.entries.count == DiagnosticReport.maximumEntries && bounded.omittedRecords == 3 &&
              !(bounded.entries.contains { ($0["raw"] as! String).contains("\"fixture_0\"") }), "Diagnostic entry bound did not preserve newest evidence")
    bounded.ingest(String(repeating: "x", count: DiagnosticReport.maximumInputBytes + 1), source: "oversized", jsonLines: false, now: now)
    try check(bounded.sources.last?["status"] as? String == "unavailable", "Oversized diagnostic input was accepted")
    var byteBounded = DiagnosticReport(minutes: 20, now: now)
    for index in 0..<80 {
        let payload = String(repeating: "x", count: 32_000)
        byteBounded.ingest("{\"time\":\(now.timeIntervalSince1970 - 1 + Double(index) / 1000),\"message\":\"\(payload)\"}", source: "fixture", jsonLines: true, now: now)
    }
    try check(byteBounded.omittedRecords > 0 && byteBounded.encoded().utf8.count <= 6_291_456, "Diagnostic byte budget or serialization limit failed")

    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("diagnostic-tests-" + UUID().uuidString)
    try UserPaths.prepare(directory.path)
    defer { try? FileManager.default.removeItem(at: directory) }
    let path = directory.appendingPathComponent("log").path
    try AtomicFile.write("old\nnew\nlast\n", to: path, mode: 0o600)
    let (tail, partial) = try DiagnosticReport.readTail(path, maximumBytes: 8)
    try check(partial && tail == "last\n", "Tail collection retained a partial first line")
    let link = directory.appendingPathComponent("link").path
    try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: path)
    try rejects { _ = try DiagnosticReport.readTail(link) }
    try check(chmod(path, 0o666) == 0, "Cannot prepare unsafe diagnostic fixture")
    try rejects { _ = try DiagnosticReport.readTail(path) }
    let fifo = directory.appendingPathComponent("fifo").path
    try check(mkfifo(fifo, 0o600) == 0, "Cannot prepare diagnostic FIFO")
    try rejects { _ = try DiagnosticReport.readTail(fifo) }
    let saved = try Command.run("/usr/bin/env", ["CFFIXED_USER_HOME=" + directory.path, CommandLine.arguments[0], "--diagnostic-save-check"], timeout: 5)
    try check(saved.status == 0, "Private diagnostic checkpoint failed: \(saved.combined)")
    print("PASS: diagnostic limits, raw evidence, coverage gaps, deduplication and private session checkpoints")
    try diagnosticBoundaryTests()
}

func diagnosticBoundaryTests() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("diagnostic-boundaries-" + UUID().uuidString)
    try UserPaths.prepare(directory.path)
    defer { try? FileManager.default.removeItem(at: directory) }
    let path = directory.appendingPathComponent("log").path
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX"); formatter.timeZone = .current
    formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSSSSS"
    let first = formatter.string(from: now.addingTimeInterval(-1200)) + " [SGDNS] first\n"
    let second = formatter.string(from: now.addingTimeInterval(-1190)) + " [SGDNS] second\n"
    try AtomicFile.write("old\n" + first + second, to: path, mode: 0o600)
    let (aligned, partial) = try DiagnosticReport.readTail(path, maximumBytes: (first + second).utf8.count)
    try check(partial && aligned == first + second, "Tail reading discarded a complete record at a line boundary")
    var alignedReport = DiagnosticReport(minutes: 20, now: now)
    alignedReport.ingest(aligned, source: "fixture", jsonLines: false, now: now, tailOnly: partial)
    try check(alignedReport.entries.count == 2 && alignedReport.sources[0]["history_start_unverified"] as? Bool == false,
              "Aligned tail reading lost evidence at the diagnostic window boundary")
    let (fragment, fragmentPartial) = try DiagnosticReport.readTail(path, maximumBytes: second.utf8.count + 2)
    try check(fragmentPartial && fragment == second, "Tail reading retained a partial first line")
    let (whole, wholePartial) = try DiagnosticReport.readTail(path, maximumBytes: try String(contentsOfFile: path).utf8.count)
    try check(!wholePartial && whole.hasPrefix("old\n"), "Whole-file boundary was marked truncated")
    print("PASS: diagnostic tails preserve complete boundary records and discard only known partial lines")

    let json = "{\"time\":\(now.timeIntervalSince1970 - 1),\"event\":\"fixture\"}"
    let line = json + String(repeating: " ", count: 127 - json.utf8.count) + "\n"
    let full = String(repeating: line, count: DiagnosticReport.maximumInputBytes / 128)
    for prefix in ["", "\n", "x"] {
        try AtomicFile.write(prefix + full, to: path, mode: 0o600)
        let result = try Command.run("/usr/bin/tail", ["-c", "1048577", path])
        let (text, truncated) = try DiagnosticReport.boundedTail(result.outputData)
        var report = DiagnosticReport(minutes: 20, now: now)
        report.ingest(text, source: "guard_events", jsonLines: true, now: now, tailOnly: truncated)
        try check(result.status == 0 && truncated == !prefix.isEmpty && report.entries.count == 1 &&
                  report.sources[0]["malformed_or_undated_lines"] as? Int == 0 &&
                  report.sources[0]["records_in_window"] as? Int == full.utf8.count / 128 - (prefix == "x" ? 1 : 0),
                  "Exact 1 MiB root-log collection invented truncation, lost a complete first record or counted a known fragment as malformed")
    }
    let raw = try Command.run("/usr/bin/printf", ["\\270\\255\\n" + json + "\n"])
    try check(raw.outputData.prefix(3) == Data([0xb8, 0xad, 10]), "Command output re-encoded a partial UTF-8 character")
    let (decoded, _) = try DiagnosticReport.boundedTail(raw.outputData, maximumBytes: raw.outputData.count - 1)
    try check(decoded == json + "\n", "Byte-tail trimming corrupted the first complete UTF-8 JSON record")
    try rejects { _ = try DiagnosticReport.boundedTail(Data(), maximumBytes: 0) }
    try rejects { _ = try DiagnosticReport.boundedTail(Data(repeating: 0, count: 10), maximumBytes: 8) }
    print("PASS: byte-accurate privileged tail bounds distinguish exact 1 MiB files, line boundaries and UTF-8 fragments")

    var watch = DiagnosticReport(minutes: 20, now: now)
    let memoryLine = formatter.string(from: now.addingTimeInterval(-1)) + " [SGDNS] repeated observation"
    let memory = String(decoding: try JSONSerialization.data(withJSONObject: ["log": memoryLine]), as: UTF8.self)
    for _ in 0..<60 { try watch.ingestMemory(memory, now: now) }
    let source = watch.sources.first { $0["source"] as? String == "surge_memory" }
    try check(watch.sources.count == 1 && source?["observations"] as? Int == 60 && watch.entries.count == 1 &&
              watch.render().components(separatedBy: "证据缺口：").count - 1 == 1,
              "Repeated watch polls flooded the report with duplicate logical sources or lost their observation count")
    let overlap = String(decoding: try JSONSerialization.data(withJSONObject: ["log": first + memoryLine]), as: UTF8.self)
    try watch.ingestMemory(overlap, now: now)
    try check(watch.sources[0]["first_observed_at"] as? Double == watch.startedAt.timeIntervalSince1970 &&
              watch.sources[0]["history_start_unverified"] as? Bool == false, "Memory-source aggregation forgot its earliest observed record")
    let later = formatter.string(from: now.addingTimeInterval(3)) + " [SGDNS] later"
    try watch.ingestMemory(String(decoding: JSONSerialization.data(withJSONObject: ["log": later]), as: UTF8.self), now: now.addingTimeInterval(4))
    try check(watch.sources.contains { $0["source"] as? String == "surge_memory_gap" && $0["status"] as? String == "unavailable" } &&
              watch.render().contains("memory_windows_do_not_overlap") && (watch.object["no_bypass_verified"] as? Bool) == false,
              "Watch aggregation concealed a real continuity gap or claimed no bypass")
    print("PASS: watch reports aggregate repeated memory sources while preserving real continuity gaps")
}
