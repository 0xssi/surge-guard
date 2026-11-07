import Foundation
import Darwin

public enum UserPaths {
    public static var directory: String { FileManager.default.homeDirectoryForCurrentUser.path + "/Library/Application Support/SurgeGuard" }
    public static var binary: String { directory + "/bin/surge-gate" }
    public static var config: String { directory + "/gate.json" }
    public static var session: String { directory + "/session.json" }
    public static var status: String { directory + "/gate-status.json" }
    public static var log: String { directory + "/gate-events.jsonl" }
    public static let label = "io.github.surge-guard.gate"
    public static var plist: String { FileManager.default.homeDirectoryForCurrentUser.path + "/Library/LaunchAgents/" + label + ".plist" }

    public static func prepare(_ path: String = directory) throws {
        guard geteuid() != 0 else { throw GuardError("SurgeGate must run as a normal user") }
        try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true,
                                               attributes: [.posixPermissions: 0o700])
        var info = stat()
        guard lstat(path, &info) == 0, info.st_uid == getuid(), info.st_mode & S_IFMT == S_IFDIR,
              info.st_mode & 0o022 == 0 else { throw GuardError("Unsafe user state directory") }
    }

    public static func readPrivate(_ path: String, maximumBytes: Int64 = 4096) throws -> Data? {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        if fd < 0, errno == ENOENT { return nil }
        guard fd >= 0 else { throw GuardError("Cannot read private Gate state: errno \(errno)") }
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { try? file.close() }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == getuid(), info.st_mode & S_IFMT == S_IFREG,
              info.st_mode & 0o077 == 0, info.st_size >= 0, info.st_size <= maximumBytes else {
            throw GuardError("Unsafe or oversized private Gate state")
        }
        let data = try file.read(upToCount: Int(maximumBytes) + 1) ?? Data()
        guard data.count <= maximumBytes else { throw GuardError("Gate state grew beyond its size limit") }
        return data
    }

    public static func lock(at path: String, timeout: TimeInterval = 0) throws -> Int32 {
        try prepare(URL(fileURLWithPath: path).deletingLastPathComponent().path)
        let fd = open(path, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0o600)
        guard fd >= 0 else { throw GuardError("Cannot open Gate lock") }
        do {
            var info = stat()
            guard fstat(fd, &info) == 0, info.st_uid == getuid(), info.st_mode & S_IFMT == S_IFREG,
                  info.st_mode & 0o077 == 0 else { throw GuardError("Unsafe Gate lock") }
            try RuntimeLock.acquire(fd, timeout: timeout)
        } catch { close(fd); throw error }
        return fd
    }

    public static func write(_ text: String, to path: String) throws {
        try prepare()
        guard URL(fileURLWithPath: path).deletingLastPathComponent().path == directory else {
            throw GuardError("User state must be written inside its managed directory")
        }
        var info = stat()
        if lstat(path, &info) == 0 {
            guard info.st_uid == getuid(), info.st_mode & S_IFMT == S_IFREG else { throw GuardError("Unsafe user state file") }
        }
        try AtomicFile.write(text, to: path, mode: 0o600)
    }
}

public struct GateConfiguration: Codable, Equatable {
    private static let bundleCharacters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
    public var version: Int
    public var startupApps: [String]
    public var priorityOrder: [String]
    public var excludedApps: [String]
    public var restoreSession: Bool
    public var delayBetweenAppsSeconds: Double
    public var quitTimeoutSeconds: Double

    public static let standard = GateConfiguration(version: 1, startupApps: [], priorityOrder: [], excludedApps: [],
                                                   restoreSession: true, delayBetweenAppsSeconds: 1, quitTimeoutSeconds: 30)

    public static func validBundleID(_ value: String) -> Bool {
        value.count <= 255 && value.contains(".") && !value.hasPrefix(".") && !value.hasSuffix(".") &&
            value.unicodeScalars.allSatisfy { bundleCharacters.contains($0) }
    }

    public func validate() throws {
        guard version == 1, delayBetweenAppsSeconds.isFinite, (0...30).contains(delayBetweenAppsSeconds),
              quitTimeoutSeconds.isFinite, (5...300).contains(quitTimeoutSeconds) else {
            throw GuardError("Invalid gate version, launch delay or quit timeout")
        }
        for list in [startupApps, priorityOrder, excludedApps] {
            guard list.count <= 256, Set(list).count == list.count, list.allSatisfy(Self.validBundleID) else {
                throw GuardError("Application lists require unique bundle IDs")
            }
        }
        guard !startupApps.contains("com.nssurge.surge-mac"), Set(startupApps).isDisjoint(with: excludedApps) else {
            throw GuardError("Startup apps must not contain Surge or an excluded app")
        }
    }

    public static func load() throws -> GateConfiguration {
        guard let data = try UserPaths.readPrivate(UserPaths.config, maximumBytes: 262_144) else {
            throw GuardError("Missing SurgeGate configuration")
        }
        return try decode(data)
    }

    public static func decode(_ data: Data) throws -> GateConfiguration {
        guard data.count <= 262_144, let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == ["version", "startup_apps", "priority_order", "excluded_apps", "restore_session", "delay_between_apps_seconds", "quit_timeout_seconds"] else {
            throw GuardError("Invalid or unknown SurgeGate configuration fields")
        }
        let config = try JSON.decode(GateConfiguration.self, from: data)
        try config.validate()
        return config
    }

    public func targets(saved: [String]) -> [String] {
        let excluded = Set(excludedApps + ["com.apple.finder", "com.nssurge.surge-mac"])
        var seen = Set<String>()
        let targets = (startupApps + (restoreSession ? saved : [])).filter { Self.validBundleID($0) && !excluded.contains($0) && seen.insert($0).inserted }
        let ranked = priorityOrder.filter { targets.contains($0) }
        return ranked + targets.filter { !ranked.contains($0) }
    }
}

public struct GateSession: Codable {
    public static let maximumBytes: Int64 = 1_048_576
    public var apps: [String]
    public var pending: [String]
    public var savedAt: Date

    public init(apps: [String], pending: [String]) { self.apps = apps; self.pending = pending; savedAt = Date() }

    public static func load() throws -> GateSession {
        guard let data = try UserPaths.readPrivate(UserPaths.session, maximumBytes: maximumBytes) else { return GateSession(apps: [], pending: []) }
        return try decode(data)
    }

    public func encoded() throws -> String {
        let text = try JSON.encode(self)
        _ = try Self.decode(Data(text.utf8))
        return text
    }

    public static func decode(_ data: Data) throws -> GateSession {
        guard data.count <= maximumBytes else { throw GuardError("Session is too large; previous checkpoint retained") }
        let result = try JSON.decode(GateSession.self, from: data)
        guard result.apps.count <= 1024, result.pending.count <= 1024,
              (result.apps + result.pending).allSatisfy(GateConfiguration.validBundleID) else {
            throw GuardError("Session requires at most 1024 valid IDs per list; previous checkpoint retained")
        }
        return result
    }
}

public struct GateStatusReport: Decodable {
    public let running: Bool
    public let fresh: Bool
    public let status: State
    public struct State: Decodable {
        public let state: String
        public let pending: [String]
        public let message: String?
        public let surge: GateSurgeIdentity?
        public let update: GateUpdate?
        public let capabilities: [String]?
    }

    public func menuTitle(guardAllowed: Bool) -> String {
        if !running { return status.state == "stopped" ? "⚪️ 已停止（不影响当前联网）" : "🟠 未运行" }
        guard fresh else { return "🟠 状态待验证" }
        switch status.state {
        case "ready":
            guard guardAllowed else { return "🟠 等待网络门禁" }
            return status.pending.isEmpty ? "🟢 已就绪" : "🟠 恢复应用中（\(status.pending.count) 个待恢复）"
        case "restoring": return "🟠 恢复应用中（\(status.pending.count) 个待恢复）"
        case "waiting": return "🟠 等待网络门禁"
        case "waiting_network": return "🟠 等待 macOS 主网络就绪"
        case "waiting_identity": return "🟠 等待阻断以修复身份"
        case "update_pausing": return "🟠 暂停确认中 · 等待启动请求结束"
        case "launch_pending": return "🟠 启动请求尚未结束"
        case "launch_recovery_required": return "🔴 启动结果未知 · 需确认恢复"
        case "shutdown_requested": return "🟠 已提交电源请求 · 系统取消后可重试"
        case "update_paused": return "🟠 已暂停自动重开 Surge"
        case "os_update_paused": return "🟠 系统更新维护中 · 自动操作暂停"
        case "os_update_waiting": return "🟠 系统更新维护尚未确认"
        case "recovery_failed": return "🔴 Surge 恢复失败 · 等待重试"
        case "unknown": return "🟠 门禁状态读取异常"
        case "error": return "🔴 服务异常，请查看日志"
        case "shutting_down": return "🟠 正在有序关机 / 重启"
        default: return "🟠 状态待验证"
        }
    }
}
