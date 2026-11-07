import Foundation
import Darwin

/// Explicit administrator intent, independent of the user's Surge update pause.
public struct SystemUpdate: Codable, Equatable {
    public enum Phase: String, Codable { case preparing, active, restoring }
    public let version: Int
    public let id: UUID
    public var phase: Phase
    public let startedAt: Date
    public let userID: UInt32
    public let backupID: String
    enum CodingKeys: String, CodingKey {
        case version, id, phase, startedAt
        case userID = "userId", backupID = "backupId"
    }
    public static let path = Paths.publicState + "/system-update.json"
    public static let suspendedAnchor = "# surge-guard: explicit macOS update maintenance; protection suspended\n"

    public init(userID: UInt32, backupID: String) {
        version = 1; id = UUID(); phase = .preparing
        startedAt = Date(timeIntervalSince1970: floor(Date().timeIntervalSince1970))
        self.userID = userID; self.backupID = backupID
    }

    public static func decode(_ data: Data) throws -> SystemUpdate {
        guard data.count <= 4096,
              let fields = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(fields.keys) == ["version", "id", "phase", "started_at", "user_id", "backup_id"] else {
            throw GuardError("Invalid system update maintenance record")
        }
        let record = try JSON.decode(Self.self, from: data)
        guard record.version == 1, record.userID >= 501, UUID(uuidString: record.backupID) != nil,
              record.startedAt.timeIntervalSince1970.isFinite,
              (0...253_402_300_799).contains(record.startedAt.timeIntervalSince1970) else {
            throw GuardError("Invalid system update maintenance values")
        }
        return record
    }

    public static func load(from path: String = path, owner: uid_t = 0) throws -> SystemUpdate? {
        if path == Self.path {
            var parent = stat()
            if lstat(Paths.publicState, &parent) != 0, errno == ENOENT { return nil }
            try RootFiles.verify(Paths.publicState, directory: true)
        }
        // Open first: a replaced/symlinked/FIFO record must never authorize network release.
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        if fd < 0, errno == ENOENT { return nil }
        guard fd >= 0 else { throw GuardError("Cannot read system update maintenance: errno \(errno)") }
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { try? file.close() }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == owner, info.st_mode & 0o022 == 0,
              info.st_mode & S_IFMT == S_IFREG, info.st_nlink == 1, info.st_size >= 0, info.st_size <= 4096 else {
            throw GuardError("Unsafe system update maintenance record")
        }
        return try decode(file.read(upToCount: 4097) ?? Data())
    }

    public func save() throws {
        let encoded = try JSON.encode(self)
        _ = try Self.decode(Data(encoded.utf8))
        try RootFiles.write(encoded, to: Self.path, mode: 0o644)
    }

    public static func requireNormalOperation() throws {
        guard try load() == nil else {
            throw GuardError("System update maintenance is pending/active. Use os-update-end to restore protection before this operation.")
        }
    }

    public static func loadProtectingOnFailure(read: () throws -> SystemUpdate? = { try load() },
                                                protect: () throws -> Void) throws -> SystemUpdate? {
        do { return try read() }
        catch {
            let original = String(describing: error)
            do { try protect() }
            catch { throw GuardError("Invalid maintenance checkpoint: \(original); blocking could not be verified: \(error)") }
            throw GuardError("Invalid maintenance checkpoint: \(original); blocking verified; repair the checkpoint before retrying maintenance")
        }
    }

    public static func prepareRestoration(read: () throws -> SystemUpdate? = { try load() },
                                          stop: () throws -> Void,
                                          lock: () throws -> RuntimeLock = { try RuntimeLock(timeout: 20) },
                                          save: (SystemUpdate) throws -> Void = { try $0.save() },
                                          protect: () throws -> Void) throws -> SystemUpdate? {
        let observed = Result { try read() }
        if case .success(nil) = observed { return nil }
        // A running daemon owns the runtime lock until stop has completed.
        try stop()
        let runtime = try lock()
        defer { withExtendedLifetime(runtime) {} }
        let prepared = try loadProtectingOnFailure(read: {
            guard var record = try read() else {
                throw GuardError("Maintenance request disappeared before restoration; inspect status")
            }
            if case .success(let initial) = observed, record != initial {
                throw GuardError("Maintenance request changed before restoration; retry after inspection")
            }
            record.phase = .restoring
            try save(record)
            return record
        }, protect: protect)
        guard let record = prepared else { throw GuardError("Missing restoration checkpoint") }
        try protect()
        return record
    }

    public func verified(by report: StatusReport) -> Bool {
        guard report.snapshot?.systemUpdateId == id, report.systemUpdate == self else { return false }
        switch phase {
        case .preparing: return false
        case .active: return report.maintenanceVerified
        case .restoring: return report.firewallVerified && report.snapshot?.enforcement != "os_update_maintenance"
        }
    }

    public static func gateAcknowledged(_ data: Data, service: CommandResult, id: UUID,
                                       boot: String = SystemClock.bootID, now: Double = SystemClock.seconds) throws -> Bool {
        struct Acknowledgement: Decodable {
            let state: String; let systemUpdateId: UUID?; let pid: Int32
            let bootId: String; let checkedUptime: Double
        }
        let status = try JSON.decode(Acknowledgement.self, from: data)
        return try StatusReport.servicePID(service) == status.pid && status.state == "os_update_paused" &&
            status.systemUpdateId == id && !boot.isEmpty && status.bootId == boot &&
            status.checkedUptime.isFinite && status.checkedUptime >= 0 && now >= status.checkedUptime && now - status.checkedUptime < 15
    }

    // Keep the durable boot rules empty before removing live rules; retries repeat both steps.
    public static func suspend(writeAnchor: () throws -> Void, clearRules: () throws -> Void,
                               verify: () throws -> Bool) throws {
        try writeAnchor()
        try clearRules()
        guard try verify() else { throw GuardError("System update maintenance: own PF rules are not verified empty") }
    }
}
