import Foundation

/// Configure on the main queue; exit records are delivered there without waiting on it.
public final class GateChildExitObserver {
    private let launchID: UUID
    private var child: SurgeProcess?
    private var startupVerified = false
    private var source: DispatchSourceProcess?
    private var watchGeneration: UInt64 = 0

    public init(launchID: UUID) { self.launchID = launchID }
    deinit { source?.cancel() }

    public func recordIdentity(_ identity: SurgeProcess?) {
        dispatchPrecondition(condition: .onQueue(.main))
        child = identity
    }

    public func verifiedStartup(matching identity: SurgeProcess) {
        dispatchPrecondition(condition: .onQueue(.main))
        if child == identity { startupVerified = true }
    }

    public func attachToLaunchdProcess(_ identity: SurgeProcess, onExit: @escaping ([String: Any]) -> Void) throws {
        dispatchPrecondition(condition: .onQueue(.main))
        source?.cancel()
        watchGeneration &+= 1
        let generation = watchGeneration
        child = identity
        startupVerified = false
        let watch = DispatchSource.makeProcessSource(identifier: identity.pid, eventMask: .exit, queue: .main)
        source = watch
        watch.setEventHandler { [weak self] in self?.launchdExited(identity, generation: generation, onExit: onExit) }
        watch.resume()
        do {
            // Cover exit/PID reuse between the caller's native query and watch registration.
            if try SurgeProcess.read(pid: identity.pid) != identity { launchdExited(identity, generation: generation, onExit: onExit) }
        } catch { source?.cancel(); source = nil; throw error }
    }

    private func launchdExited(_ identity: SurgeProcess, generation: UInt64, onExit: ([String: Any]) -> Void) {
        guard source != nil, child == identity, watchGeneration == generation else { return }
        source?.cancel(); source = nil
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        onExit(["launch_id": launchID.uuidString, "child_pid": identity.pid,
                "child_started_seconds": identity.startedSeconds, "child_started_microseconds": identity.startedMicroseconds,
                "birth_time_available": true, "startup_verified": startupVerified,
                "process_relationship": "launchd_child", "termination_reason": "unavailable_non_child",
                "termination_sender": "unknown", "exit_observed_at": formatter.string(from: Date()),
                "exit_observed_uptime": SystemClock.seconds])
    }

    public func attach(to process: Process, onExit: @escaping ([String: Any]) -> Void) {
        dispatchPrecondition(condition: .onQueue(.main))
        // Attach before run(), including children that fail before identity can be read.
        process.terminationHandler = { [self] task in
            let pid = task.processIdentifier
            let status = task.terminationStatus
            let reason = task.terminationReason
            let observedAt = Date(), observedUptime = SystemClock.seconds
            DispatchQueue.main.async { [self] in
                let formatter = ISO8601DateFormatter()
                formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
                var details: [String: Any] = [
                    "launch_id": launchID.uuidString, "child_pid": pid,
                    "startup_verified": startupVerified, "termination_status": status,
                    "exit_observed_at": formatter.string(from: observedAt),
                    "exit_observed_uptime": observedUptime,
                    "termination_sender": "unknown", "birth_time_available": false
                ]
                if let child, child.pid == pid {
                    details["birth_time_available"] = true
                    details["child_started_seconds"] = child.startedSeconds
                    details["child_started_microseconds"] = child.startedMicroseconds
                }
                switch reason {
                case .exit:
                    details["termination_reason"] = "exit"
                    details["exit_code"] = status
                case .uncaughtSignal:
                    details["termination_reason"] = "uncaught_signal"
                    details["signal"] = status
                @unknown default:
                    details["termination_reason"] = "unknown"
                }
                onExit(details)
            }
        }
    }
}
