import Foundation
import Darwin

public struct GateUpdate: Codable, Equatable {
    public let version: Int
    public let id: UUID
    public let paused: Bool
    public let changedAt: Date
    public let reason: String
    public static var path: String { UserPaths.directory + "/update-mode.json" }

    public init(paused: Bool) {
        version = 1
        id = UUID()
        self.paused = paused
        changedAt = Date(timeIntervalSince1970: floor(Date().timeIntervalSince1970))
        reason = paused ? "User requested Surge update; automatic startup, identity repair and app restoration paused" :
            "User finished or cancelled Surge update; automatic recovery enabled"
    }

    public static func decode(_ data: Data) throws -> GateUpdate {
        guard data.count <= 4096, let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == ["version", "id", "paused", "changed_at", "reason"] else {
            throw GuardError("Invalid update mode; automatic recovery remains paused")
        }
        let value = try JSON.decode(GateUpdate.self, from: data)
        guard value.version == 1, (0...253_402_300_799).contains(value.changedAt.timeIntervalSince1970),
              !value.reason.isEmpty, value.reason.utf8.count <= 512,
              !value.reason.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else {
            throw GuardError("Invalid update mode; automatic recovery remains paused")
        }
        return value
    }

    public static func load(from path: String = path) throws -> GateUpdate? {
        try UserPaths.readPrivate(path).map(decode)
    }

    public func acknowledged(by update: GateUpdate?, state: String, fresh: Bool) -> Bool {
        fresh && update == self && (paused ? state == "update_paused" :
            ["ready", "restoring", "waiting", "waiting_network", "waiting_identity", "unknown"].contains(state))
    }
}

public struct GateRetry {
    public private(set) var nextAttempt: Double = 0
    public private(set) var failure: String?
    public init() {}
    public func canAttempt(at now: Double) -> Bool { now >= nextAttempt }
    public mutating func failed(_ message: String, at now: Double) { failure = message; nextAttempt = now + 30 }
    public mutating func succeeded(at now: Double, launched: Bool) {
        let hadFailure = failure != nil
        failure = nil
        nextAttempt = launched ? now + 10 : (hadFailure ? now : max(nextAttempt, now))
    }
}

public struct GateSurgeIdentity: Codable {
    public var pid: Int32?
    public var expectedGroup: UInt32?
    public var verified = false
    public var reason = "unverified"
    public var checkedAt = Date()
    public var checkedUptime = SystemClock.seconds
    public var satisfiesPolicy: Bool { pid != nil && (verified || reason == "dedicated_group_not_required") }
    public init() {}
}

// A timeout does not cancel an NSWorkspace request or a dedicated launcher.
public struct GatePendingLaunch: Codable, Equatable {
    public let id: UUID
    public let app: String
    public let bootId: String
    public let observer: UUID?
    public var child: SurgeProcess?
    public var launchd: Bool?
    public var submission: SurgeProcess?
    public static var path: String { UserPaths.directory + "/pending-launch.json" }
    public init(app: String, observer: UUID? = nil) {
        id = UUID(); self.app = app; bootId = SystemClock.bootID; self.observer = observer
    }

    public enum Disposition { case settled, inFlight, failed, orphaned }

    public static func observationIsCurrent(_ observed: GatePendingLaunch?, at path: String = path) throws -> Bool {
        try load(from: path) == observed
    }

    public func disposition(observer: UUID, callbackPending: Bool, appRunning: Bool, childIdentity: SurgeProcess?) -> Disposition {
        if callbackPending { return .inFlight }
        if appRunning { return .settled }
        if let child { return child == childIdentity ? .inFlight : .failed }
        return self.observer == observer ? .failed : .orphaned
    }

    public func launchdDisposition(job: GateLaunchJob.State, submissionRunning: Bool?,
                                   verifiedApp: SurgeProcess?, childIdentity: SurgeProcess?) -> Disposition {
        // The launchctl client finishing does not mean its job has finished launching.
        if submissionRunning == true { return .inFlight }
        if let child, child == childIdentity, child == verifiedApp { return .settled }
        if job != .absent || (child != nil && child == childIdentity) { return .inFlight }
        if submissionRunning == false || child != nil { return .failed }
        return .orphaned
    }

    public func save(at path: String = path, requireExisting: Bool = false) throws {
        let fd = try UserPaths.lock(at: path + ".lock", timeout: 2)
        defer { close(fd) }
        guard try Self.load(from: path).map({ $0.id == id }) ?? !requireExisting else {
            throw GuardError("An earlier application launch has not settled")
        }
        let encoded = try JSON.encode(self)
        _ = try Self.decode(Data(encoded.utf8))
        try AtomicFile.write(encoded, to: path, mode: 0o600)
    }

    public func complete(at path: String = path) throws {
        let fd = try UserPaths.lock(at: path + ".lock", timeout: 2)
        defer { close(fd) }
        if try Self.load(from: path)?.id == id { try FileManager.default.removeItem(atPath: path) }
    }

    public static func recover(id: UUID, observer: UUID, at path: String = path) throws {
        let fd = try UserPaths.lock(at: path + ".lock", timeout: 2)
        defer { close(fd) }
        guard let request = try load(from: path), request.id == id, request.observer != observer, request.child == nil else {
            throw GuardError("Launch recovery requires the exact orphaned request; inspect fresh Gate status")
        }
        if request.launchd == true {
            guard try GateLaunchJob.state(request.id) == .absent,
                  request.submission == nil else {
                throw GuardError("Launch recovery cannot clear a queued job or recorded launchctl submission")
            }
        }
        try FileManager.default.removeItem(atPath: path)
    }
    public static func load(from path: String = path) throws -> GatePendingLaunch? {
        guard let data = try UserPaths.readPrivate(path) else { return nil }
        let value = try decode(data)
        return value.bootId == SystemClock.bootID ? value : nil
    }

    private static func decode(_ data: Data) throws -> GatePendingLaunch {
        guard data.count <= 4096 else { throw GuardError("Oversized pending launch") }
        let value = try JSON.decode(Self.self, from: data)
        guard GateConfiguration.validBundleID(value.app), !value.bootId.isEmpty,
              [value.child, value.submission].allSatisfy({ identity in
                  identity.map { $0.pid > 1 && $0.startedSeconds > 0 && (0..<1_000_000).contains($0.startedMicroseconds) } ?? true
              }),
              value.launchd == nil || (value.launchd == true && value.app == "com.nssurge.surge-mac"),
              value.submission == nil || value.launchd == true else {
            throw GuardError("Invalid pending launch")
        }
        return value
    }
}

public struct GateShutdownRequest: Codable {
    public let id: UUID
    public let action: String
    public let bootId: String
    public static var path: String { UserPaths.directory + "/shutdown-request.json" }
    public init(action: String) throws {
        guard ["restart", "shutdown"].contains(action) else { throw GuardError("Invalid shutdown action") }
        id = UUID(); self.action = action; bootId = SystemClock.bootID
    }
    public static func validate(paused: Bool, pendingLaunch: GatePendingLaunch?, phase: GateShutdownPhase) throws {
        guard !paused else { throw GuardError("Finish or cancel the Surge update and resume Gate before ordered shutdown") }
        guard pendingLaunch == nil else { throw GuardError("Application launch is unresolved; inspect Gate status and settle/recover it before ordered shutdown") }
        guard phase == .idle || phase.canRetry else { throw GuardError("Ordered shutdown is still in progress") }
    }
    // The caller holds request.lock during submission, consumption and withdrawal.
    @discardableResult public func withdraw(at path: String = path) throws -> Bool {
        guard try Self.load(from: path)?.id == id else { return false }
        try FileManager.default.removeItem(atPath: path)
        return true
    }
    // Return a decline reason only after withdrawal; filesystem failures remain errors.
    public func consume(maintenance: Bool, at path: String = path, validate: () throws -> Void) throws -> String? {
        guard try withdraw(at: path) else { throw GuardError("Queued shutdown request changed before consumption") }
        do {
            guard !maintenance else { throw GuardError("System update maintenance prevents ordered shutdown") }
            try validate()
        }
        catch { return String(describing: error) }
        return nil
    }
    // Stop/uninstall hold command.lock and the stopped service's gate.lock, excluding all request writers.
    public static func cancel(at path: String = path) throws {
        guard unlink(path) == 0 || errno == ENOENT else {
            throw GuardError("Cannot cancel queued shutdown request: errno \(errno)")
        }
    }
    public static func load(from path: String = path) throws -> GateShutdownRequest? {
        guard let data = try UserPaths.readPrivate(path) else { return nil }
        let value = try JSON.decode(Self.self, from: data)
        guard ["restart", "shutdown"].contains(value.action), !value.bootId.isEmpty else { throw GuardError("Invalid shutdown request") }
        return value.bootId == SystemClock.bootID ? value : nil
    }
}

public enum GateShutdownPhase {
    case idle, quitting, submitted, aborted
    public var preservesSession: Bool { self != .idle }
    public var canRetry: Bool { self == .submitted || self == .aborted }
}
