import Foundation
import Darwin

/// One user-domain launch per request, never a login item or a restart policy.
public enum GateLaunchJob {
    public static func label(_ id: UUID) -> String { "io.github.surge-guard.surge.\(id.uuidString.lowercased())" }
    public static func service(_ id: UUID) -> String { "gui/\(getuid())/\(label(id))" }
    public static var plistPath: String { UserPaths.directory + "/surge-launch.plist" }

    public static func plist(_ id: UUID) -> [String: Any] {
        ["Label": label(id), "ProgramArguments": [DedicatedEgress.launcher],
         "RunAtLoad": true, "KeepAlive": false, "LaunchOnlyOnce": true, "ProcessType": "Interactive",
         "StandardInPath": "/dev/null", "StandardOutPath": "/dev/null", "StandardErrorPath": "/dev/null",
         "EnvironmentVariables": ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]]
    }

    public enum State: Equatable { case absent, pending, running(pid_t) }

    public static func state(_ result: CommandResult) throws -> State {
        let pid = try StatusReport.servicePID(result)
        if let pid { return .running(pid) }
        return result.status == 0 ? .pending : .absent
    }

    public static func state(_ id: UUID) throws -> State {
        try state(Command.run("/bin/launchctl", ["print", service(id)]))
    }
}
