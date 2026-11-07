import Foundation
import Darwin
import CoreFoundation

public struct DiagnosticOptions {
    public var minutes = 20
    public var watchSeconds = 0
    public var json = false

    public init(_ arguments: [String]) throws {
        var index = 0, seen = Set<String>()
        while index < arguments.count {
            let flag = arguments[index]
            guard seen.insert(flag).inserted else { throw GuardError("Duplicate diagnostic option: \(flag)") }
            if flag == "--json" { json = true; index += 1; continue }
            guard ["--minutes", "--watch-seconds"].contains(flag), arguments.indices.contains(index + 1),
                  !arguments[index + 1].isEmpty, arguments[index + 1].allSatisfy({ $0.isASCII && $0.isNumber }),
                  let value = Int(arguments[index + 1]), (1...(flag == "--minutes" ? 120 : 300)).contains(value) else {
                throw GuardError("Usage: diagnose [--minutes 1...120] [--watch-seconds 1...300] [--json]")
            }
            if flag == "--minutes" { minutes = value } else { watchSeconds = value }
            index += 2
        }
    }
}

/// Private diagnostic evidence only; never consumed by the permission decision.
public struct DiagnosticReport {
    public static let maximumInputBytes = 1_048_576
    public static let maximumEntries = 1_500
    public static let maximumEvidenceBytes = 2_097_152
    public static var path: String { UserPaths.directory + "/diagnostic-report.json" }
    public let startedAt: Date
    public private(set) var endedAt: Date
    public private(set) var collectionFinished = false
    public private(set) var sources: [[String: Any]] = []
    public private(set) var entries: [[String: Any]] = []
    public var snapshots: [String: Any] = [:]
    public private(set) var omittedRecords = 0
    private var evidenceBytes = 0
    private var seen = Set<String>()
    private var memoryEnd: Date?
    private let iso = ISO8601DateFormatter()
    private let local = DateFormatter()

    public init(minutes: Int, now: Date = Date()) {
        startedAt = now.addingTimeInterval(-Double(minutes) * 60)
        endedAt = now
        iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        local.locale = Locale(identifier: "en_US_POSIX")
        local.timeZone = .current
        local.dateFormat = "yyyy-MM-dd HH:mm:ss.SSSSSS"
    }

    public func timestamp(_ value: Any?) -> Date? {
        if let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID(),
           number.doubleValue.isFinite, (0...253_402_300_799).contains(number.doubleValue) {
            return Date(timeIntervalSince1970: number.doubleValue)
        }
        guard let text = value as? String else { return nil }
        if let date = iso.date(from: text) { return date }
        let plain = ISO8601DateFormatter()
        if let date = plain.date(from: text) { return date }
        return local.date(from: String(text.prefix(26)))
    }

    public mutating func unavailable(_ source: String, error: String) {
        sources.append(["source": source, "status": "unavailable", "error": String(error.prefix(2_048))])
    }

    public mutating func finish(at now: Date = Date()) {
        endedAt = max(endedAt, now)
        collectionFinished = true
    }

    public mutating func ingest(_ text: String, source: String, jsonLines: Bool, now: Date = Date(), tailOnly: Bool = false) {
        endedAt = max(endedAt, now)
        guard text.utf8.count <= Self.maximumInputBytes else {
            unavailable(source, error: "input_exceeded_1_mib"); return
        }
        var malformed = 0, matched = 0
        var first: Date?, last: Date?
        for raw in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = String(raw)
            let record = jsonLines ? (try? JSONSerialization.jsonObject(with: Data(line.utf8))) as? [String: Any] : nil
            guard let date = timestamp(jsonLines ? record?["time"] : line) else { malformed += 1; continue }
            first = min(first ?? date, date); last = max(last ?? date, date)
            guard date >= startedAt, date <= endedAt else { continue }
            matched += 1
            guard line.utf8.count <= 65_536 else { omittedRecords += 1; continue }
            guard !seen.contains(line) else { continue }
            var entry: [String: Any] = ["time": date.timeIntervalSince1970, "source": source, "raw": line]
            if let record { entry["record"] = record }
            // Account for both the raw line and the parsed record retained in JSON.
            let bytes = line.utf8.count * 2 + 256
            while !entries.isEmpty && (entries.count >= Self.maximumEntries || evidenceBytes + bytes > Self.maximumEvidenceBytes) {
                let oldest = entries.indices.min { (entries[$0]["time"] as! Double) < (entries[$1]["time"] as! Double) }!
                if date.timeIntervalSince1970 <= (entries[oldest]["time"] as! Double) { break }
                let removed = entries.remove(at: oldest)["raw"] as! String
                seen.remove(removed); evidenceBytes -= removed.utf8.count * 2 + 256
                omittedRecords += 1
            }
            guard entries.count < Self.maximumEntries, evidenceBytes + bytes <= Self.maximumEvidenceBytes else {
                omittedRecords += 1; continue
            }
            entries.append(entry); seen.insert(line); evidenceBytes += bytes
        }
        var result: [String: Any] = ["source": source, "status": "read", "coverage": "retained_records_only",
                                     "tail_only": tailOnly, "malformed_or_undated_lines": malformed, "records_in_window": matched,
                                     "history_start_unverified": first.map { $0 > startedAt } ?? true, "observations": 1]
        if let first { result["first_observed_at"] = first.timeIntervalSince1970 }
        if let last { result["last_observed_at"] = last.timeIntervalSince1970 }
        if source == "surge_memory", let index = sources.firstIndex(where: { $0["source"] as? String == source && $0["status"] as? String == "read" }) {
            let previous = sources[index]
            result["tail_only"] = tailOnly || previous["tail_only"] as? Bool == true
            for key in ["observations", "records_in_window", "malformed_or_undated_lines"] {
                result[key] = (previous[key] as? Int ?? 0) + (result[key] as? Int ?? 0)
            }
            if let first = previous["first_observed_at"] as? Double {
                result["first_observed_at"] = min(first, result["first_observed_at"] as? Double ?? first)
            }
            if let last = previous["last_observed_at"] as? Double {
                result["last_observed_at"] = max(last, result["last_observed_at"] as? Double ?? last)
            }
            result["history_start_unverified"] = (result["first_observed_at"] as? Double).map { $0 > startedAt.timeIntervalSince1970 } ?? true
            sources[index] = result
            return
        }
        sources.append(result)
    }

    public mutating func ingestMemory(_ output: String, now: Date = Date()) throws {
        guard output.utf8.count <= Self.maximumInputBytes,
              let object = try JSONSerialization.jsonObject(with: Data(output.utf8)) as? [String: Any],
              let log = object["log"] as? String else { throw GuardError("Invalid or oversized Surge memory log response") }
        let lines = log.split(separator: "\n").map(String.init)
        let dates = lines.compactMap { timestamp($0) }
        if let previous = memoryEnd, let first = dates.min(), first > previous.addingTimeInterval(0.5) {
            unavailable("surge_memory_gap", error: "memory_windows_do_not_overlap; continuity_unverified")
        }
        if let last = dates.max() { memoryEnd = last }
        let selected = lines.filter { line in
            ["[SGDNS", "[SGEncryptedDNS", "[SGQUICClientSession", "[SGQUICSession", "[SGAsyncSendUDPSocket"].contains { line.contains($0) }
        }
        ingest(selected.joined(separator: "\n"), source: "surge_memory", jsonLines: false, now: now)
        if dates.isEmpty { unavailable("surge_memory_gap", error: "no_dated_memory_records") }
    }

    public var object: [String: Any] {
        ["version": 1, "scope": "diagnostic_evidence_only", "root_cause": "not_determined", "no_bypass_verified": false,
         "collection_finished": collectionFinished,
         "started_at": startedAt.timeIntervalSince1970, "ended_at": endedAt.timeIntervalSince1970,
         "local_timezone": TimeZone.current.identifier, "snapshots": snapshots, "sources": sources,
         "omitted_records": omittedRecords, "entries": entries.sorted { ($0["time"] as! Double) < ($1["time"] as! Double) }]
    }

    public func encoded() throws -> String {
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
        guard data.count <= 6_291_456 else { throw GuardError("Diagnostic serialization exceeded its 6 MiB limit") }
        return String(decoding: data, as: UTF8.self)
    }

    public func render() -> String {
        let formatter = DateFormatter(); formatter.dateFormat = "yyyy-MM-dd HH:mm:ss Z"
        var lines = ["诊断窗口：\(formatter.string(from: startedAt)) → \(formatter.string(from: endedAt))",
                     "只读证据；根因尚未确定；不证明全程经过 Surge 或零逃逸。"]
        if !collectionFinished { lines.append("采集尚未完成：当前内容是中间检查点。") }
        for stage in ["start", "end"] {
            guard let values = snapshots[stage] as? [String: Any] else { continue }
            let guardState = values["guard"] as? [String: Any]
            let gate = (values["gate"] as? [String: Any])?["status"] as? [String: Any]
            let surge = values["surge"] as? [String: Any]
            let features = surge?["features"] as? [String: Any]
            let process = surge?["observed_process"] as? [String: Any]
            lines.append("\(stage == "start" ? "开始" : "结束")快照：Guard=\(guardState?["state"] ?? "未知")；Gate=\(gate?["state"] ?? "未知")；Surge=\(surge?["version"] ?? "未知") PID=\(process?["pid"] ?? "未知")；增强模式=\(features?["enhanced-mode"] ?? "未知")")
        }
        for source in sources where source["status"] as? String != "read" || source["tail_only"] as? Bool == true ||
            source["history_start_unverified"] as? Bool == true || (source["malformed_or_undated_lines"] as? Int ?? 0) > 0 {
            lines.append("证据缺口：\(source)")
        }
        lines.append("保留 \(entries.count) 条；因容量限制省略 \(omittedRecords) 条。以下显示最近 80 条，完整记录见私有 JSON。")
        for entry in entries.sorted(by: { ($0["time"] as! Double) < ($1["time"] as! Double) }).suffix(80) {
            let raw = entry["raw"] as! String
            let rendered = entry["record"] != nil ? LogReader.format(raw) : raw
            lines.append("[\(entry["source"] as! String)] " + rendered)
        }
        return lines.joined(separator: "\n").unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) || $0 == "\n" }.map(String.init).joined()
    }

    public static func boundedTail(_ data: Data, maximumBytes: Int = maximumInputBytes) throws -> (String, Bool) {
        guard maximumBytes > 0, maximumBytes <= maximumInputBytes, data.count <= maximumBytes + 1 else {
            throw GuardError("Invalid diagnostic tail bound")
        }
        let partial = data.count > maximumBytes
        var bytes = data
        if partial {
            let preceding = bytes.removeFirst()
            if preceding != 10 {
                if let newline = bytes.firstIndex(of: 10) { bytes.removeSubrange(bytes.startIndex...newline) }
                else { bytes.removeAll() }
            }
        }
        return (String(decoding: bytes, as: UTF8.self), partial)
    }

    public static func readTail(_ path: String, maximumBytes: Int = 524_288) throws -> (String, Bool) {
        guard maximumBytes > 0, maximumBytes <= maximumInputBytes else { throw GuardError("Invalid diagnostic input bound") }
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw GuardError("Cannot open diagnostic log: errno \(errno)") }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { try? handle.close() }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == getuid(), info.st_mode & S_IFMT == S_IFREG,
              info.st_mode & 0o022 == 0, info.st_size >= 0 else { throw GuardError("Unsafe diagnostic log") }
        let count = min(Int64(info.st_size), Int64(maximumBytes) + 1)
        try handle.seek(toOffset: UInt64(info.st_size) - UInt64(count))
        let data = try handle.read(upToCount: Int(count)) ?? Data()
        guard data.count == Int(count) else { throw GuardError("Diagnostic log changed while reading; retry collection") }
        return try boundedTail(data, maximumBytes: maximumBytes)
    }

    public func save(rotatePrevious: Bool = true) throws {
        let text = try encoded()
        if rotatePrevious, let previous = try UserPaths.readPrivate(Self.path, maximumBytes: 6_291_456) {
            try UserPaths.write(String(decoding: previous, as: UTF8.self), to: Self.path + ".1")
        }
        try UserPaths.write(text, to: Self.path)
    }
}
