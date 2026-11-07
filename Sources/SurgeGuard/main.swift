import Foundation
import Darwin
import SystemConfiguration
import SurgeGuardCore

final class Daemon {
    let firewall = Firewall()
    let lock: RuntimeLock
    var allowed = false
    var allowedInterface: String?
    var lastReason = ""
    var store: SCDynamicStore?
    var source: CFRunLoopSource?
    var timer: Timer?
    var signals: [DispatchSourceSignal] = []
    var trustedSurgePID: pid_t?
    var surgeExitSource: DispatchSourceProcess?
    var surgeExitDetectedAt: Double?
    var surgeConnection: SCNetworkConnection?
    var surgeConnectionService: String?
    var surgeTrust = SurgeProcessTrust()
    var surgeWatchGeneration = 0
    var nextFirewallAudit: Double = 0
    let runID = UUID().uuidString
    var firewallVerified: Double = 0
    var configuration: Configuration?
    var session: SessionObservation?
    var sessionChecked: Double = 0
    var nextSessionProbe: Double = 0
    var sessionFailure = "rule_probe_pending"
    var probing = false
    var generation = 0
    var nextPublish: Double = 0
    var lastProbeError = ""
    var lastRoutes = ""
    var egressSampling = false
    var nextEgressSample: Double = 0
    var nextEgressSummary: Double = 0
    var egressHistory = EgressHistory()
    var egressFailure = ""
    var systemUpdate: SystemUpdate?
    var lastLocalTCPFailure = ""

    init() throws {
        lock = try RuntimeLock()
        try RootFiles.preparePublicState()
        try RootFiles.verify(Policy.anchorPath)
        systemUpdate = try SystemUpdate.loadProtectingOnFailure { try firewall.prepareBlocking() }
        if systemUpdate?.phase == .active {
            try firewall.suspendForSystemUpdate()
            firewallVerified = SystemClock.seconds
            return
        }
        try firewall.prepareBlocking()
        firewallVerified = SystemClock.seconds
        EventLog.write("daemon_started", message: "Blocked before checking Surge", details: ["run_id": runID])
    }

    func surgeProcessTrusted() throws -> Bool {
        let candidates = try Probe.surgeCandidates()
        let revision = surgeTrust.revision
        let retained = surgeTrust.observe(candidates: candidates)
        if surgeTrust.revision != revision { invalidateSession() }
        // Invalidate even on the early block path and when PF was already blocked.
        if allowed, !retained { return false }
        let observedRevision = surgeTrust.revision
        defer { if surgeTrust.revision != observedRevision { invalidateSession() } }
        let candidate = try surgeTrust.trustedPID(candidates: candidates, validate: Probe.surgeSignatureValid,
                                                 recheck: Probe.surgeCandidates)
        let sameCandidates = surgeTrust.revision == revision
        if let pid = candidate, sameCandidates, trustedSurgePID == pid, kill(pid, 0) == 0 { return true }
        trustedSurgePID = nil
        surgeExitSource?.cancel()
        surgeExitSource = nil
        surgeWatchGeneration += 1
        let watchGeneration = surgeWatchGeneration
        guard let pid = candidate else { return false }

        let exitSource = DispatchSource.makeProcessSource(identifier: pid, eventMask: .exit, queue: .main)
        exitSource.setEventHandler { [weak self] in
            guard let self, self.trustedSurgePID == pid, self.surgeWatchGeneration == watchGeneration else { return }
            self.surgeExitDetectedAt = SystemClock.seconds
            self.trustedSurgePID = nil
            self.surgeExitSource?.cancel()
            self.surgeExitSource = nil
            self.surgeTrust = SurgeProcessTrust()
            self.reconcile(forceFirewallAudit: true, lossReason: "surge_process_exited", detectedAt: self.surgeExitDetectedAt)
        }
        trustedSurgePID = pid
        surgeExitSource = exitSource
        exitSource.resume()
        guard kill(pid, 0) == 0 else {
            trustedSurgePID = nil
            surgeExitSource?.cancel()
            surgeExitSource = nil
            return false
        }
        return true
    }

    func invalidateSession() {
        generation += 1
        session = nil
        sessionChecked = 0
        nextSessionProbe = 0
        sessionFailure = "rule_probe_pending"
    }

    func updateSession(_ config: Configuration, force: Bool) {
        let now = SystemClock.seconds
        // Refresh immediately without discarding a still-fresh result; real losses invalidate separately.
        if force { generation += 1; nextSessionProbe = 0 }
        guard !probing, now >= nextSessionProbe else { return }
        probing = true
        nextSessionProbe = now + 1
        let requestedGeneration = generation
        let started = now
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let result = Result { try Probe.privilegedSession(configuration: config) }
            DispatchQueue.main.async {
                guard let self else { return }
                self.probing = false
                guard self.generation == requestedGeneration else { return }
                self.sessionChecked = started
                switch result {
                case .success(let observation):
                    let bound = observation.routes.count == config.routeChecks.count && zip(observation.routes, config.routeChecks).allSatisfy {
                        $0.url == $1.url && $0.expectedGroup == $1.requiredGroup &&
                            (!$0.ready || ($0.actualGroup == $1.requiredGroup && $1.allowsFinalPolicy($0.finalPolicy)))
                    }
                    self.session = bound ? observation : nil
                    self.sessionFailure = bound ? "" : "rule_probe_configuration_changed"
                case .failure(let error):
                    self.session = nil
                    self.sessionFailure = "rule_probe_failed: \(error)"
                }
                if self.session == nil && self.sessionFailure != self.lastProbeError {
                    EventLog.write("rule_probe_failed", level: "warning", message: self.sessionFailure,
                                   details: ["duration_ms": String(Int((SystemClock.seconds - started) * 1000)), "run_id": self.runID])
                }
                self.lastProbeError = self.session == nil ? self.sessionFailure : ""
                if let session = self.session, let routes = try? JSON.encode(session.routes), routes != self.lastRoutes {
                    EventLog.write("route_decision_changed", message: "Surge rule decision updated",
                                   details: ["routes": (try? JSONSerialization.jsonObject(with: Data(routes.utf8))) ?? [],
                                             "outbound_mode": session.mode, "run_id": self.runID])
                    self.lastRoutes = routes
                }
                self.reconcile()
            }
        }
    }

    func watchSurgeConnection() throws -> String? {
        guard let store else { throw GuardError("Network state subscription is unavailable") }
        let primary = SCDynamicStoreCopyValue(store, "State:/Network/Global/IPv4" as CFString) as? [String: Any] ?? [:]
        guard let service = primary["PrimaryService"] as? String, Probe.isSurgeService(service, store: store) else {
            return "primary network service is not Surge"
        }
        if surgeConnectionService != service {
            var context = SCNetworkConnectionContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(),
                                                     retain: nil, release: nil, copyDescription: nil)
            guard let connection = SCNetworkConnectionCreateWithServiceID(nil, service as CFString, { connection, status, info in
                guard let info else { return }
                let daemon = Unmanaged<Daemon>.fromOpaque(info).takeUnretainedValue()
                guard let current = daemon.surgeConnection, CFEqual(current, connection) else { return }
                let received = SystemClock.seconds
                daemon.reconcile(forceFirewallAudit: true, lossReason: Probe.connectionLossReason(status), detectedAt: received)
            }, &context), SCNetworkConnectionSetDispatchQueue(connection, .main) else {
                throw GuardError("Cannot subscribe to Surge tunnel state changes")
            }
            if let previous = surgeConnection, !SCNetworkConnectionSetDispatchQueue(previous, nil) {
                throw GuardError("Cannot replace the previous Surge tunnel subscription")
            }
            surgeConnection = connection
            surgeConnectionService = service
        }
        guard let connection = surgeConnection else { throw GuardError("Surge tunnel subscription is unavailable") }
        return Probe.connectionLossReason(SCNetworkConnectionGetStatus(connection))
    }

    func reconcile(forceFirewallAudit: Bool = false, lossReason: String? = nil, detectedAt: Double? = nil) {
        defer { surgeExitDetectedAt = nil }
        do {
            systemUpdate = try SystemUpdate.load()
            if let maintenance = systemUpdate, maintenance.phase == .active {
                allowed = false
                if forceFirewallAudit || SystemClock.seconds >= nextFirewallAudit {
                    nextFirewallAudit = SystemClock.seconds + 5
                    if try !firewall.systemUpdateSuspended() { try firewall.suspendForSystemUpdate() }
                    firewallVerified = SystemClock.seconds
                }
                if SystemClock.seconds >= nextPublish {
                    let snapshot = GuardSnapshot(runId: runID, firewallVerifiedUptime: firewallVerified, allowed: false,
                                                 configurationMode: "maintenance", readiness: nil, session: nil,
                                                 reasons: ["System update maintenance; all applications may connect directly"],
                                                 enforcement: "os_update_maintenance", systemUpdateId: maintenance.id)
                    try RootFiles.write(try JSON.encode(snapshot), to: Paths.snapshot, mode: 0o644)
                    nextPublish = SystemClock.seconds + 1
                }
                return
            }
            let received = detectedAt ?? SystemClock.seconds
            var loss = try lossReason ?? watchSurgeConnection()
            if loss == nil, try !surgeProcessTrusted() { loss = "surge_process_untrusted_or_ambiguous" }
            // Close before route/signature/configuration probes and PF integrity queries.
            if allowed, let loss {
                let timing = try firewall.block()
                allowed = false
                firewallVerified = timing.statesClearedUptime
                invalidateSession()
                let snapshot = GuardSnapshot(runId: runID, firewallVerifiedUptime: firewallVerified, allowed: false,
                                             configurationMode: configuration?.mode ?? "invalid", readiness: nil,
                                             session: nil, reasons: [loss], enforcement: configuration?.enforcement ?? "surge_readiness_gate",
                                             lanTcpEnabled: configuration?.allowsLANTCP, lanTcpBindings: firewall.lanTCPBindings,
                                             systemUpdateId: systemUpdate?.id, usbTcpBindings: firewall.usbTCPBindings)
                try RootFiles.write(try JSON.encode(snapshot), to: Paths.snapshot, mode: 0o644)
                EventLog.write("readiness_loss_blocked", level: "warning", message: loss,
                               details: ["run_id": runID, "detected_uptime": received, "pf": "blocked",
                                         "allow_lan_tcp": configuration?.allowsLANTCP ?? false,
                                         "block_rules_loaded_uptime": timing.rulesLoadedUptime,
                                         "block_verified_uptime": timing.statesClearedUptime,
                                         "event_to_rules_loaded_ms": max(0, (timing.rulesLoadedUptime - received) * 1000),
                                         "event_to_block_verified_ms": max(0, (timing.statesClearedUptime - received) * 1000)])
            }
            try firewall.rememberAddresses()
            let now = SystemClock.seconds
            if forceFirewallAudit || now >= nextFirewallAudit {
                nextFirewallAudit = now + 5
                if try !firewall.unchanged() {
                    allowed = false
                    try firewall.block()
                    EventLog.write("pf_reconciled", level: "warning", message: "Blocking before rechecking Surge", details: ["run_id": runID])
                }
                firewallVerified = SystemClock.seconds
            }
            var observation: Readiness?
            var probeFailure: String?
            do { observation = try Probe.readiness(trustedProcess: surgeProcessTrusted()) }
            catch { observation = nil; probeFailure = String(describing: error) }
            var reasons = observation?.reasons ?? ["readiness_probe_failed: \(probeFailure ?? "unknown error")"]
            if let loss, !reasons.contains(loss) { reasons.append(loss) }
            var config: Configuration?
            var localBindingsChanged = false
            var localTCPFailures: [String] = []
            do {
                config = try Configuration.load()
                let inventory = config!.allowsLANTCP ? LocalTCPInventory() : nil
                let bindings = inventory?.lan ?? []
                let usbBindings = inventory?.usb ?? []
                localTCPFailures = inventory?.errors ?? []
                let lanChanged = try firewall.setLANTCP(bindings)
                let usbChanged = try firewall.setUSBTCP(usbBindings)
                localBindingsChanged = lanChanged || usbChanged
                if configuration != config || lanChanged || usbChanged {
                    if configuration != config {
                        if allowed || localBindingsChanged { try firewall.block(); allowed = false; firewallVerified = SystemClock.seconds }
                        invalidateSession()
                    } else if !allowed {
                        // Revoke only removed local states; an inventory error must not reset the public Surge tunnel.
                        try firewall.block(clearExistingStates: false)
                        firewallVerified = SystemClock.seconds
                    }
                    configuration = config
                    EventLog.write("configuration_loaded", message: "Validated policy configuration and local TCP interfaces",
                                   details: ["mode": config!.mode, "run_id": runID, "allow_lan_tcp": config!.allowsLANTCP,
                                             "lan_tcp_bindings": try JSONSerialization.jsonObject(with: Data(JSON.encode(bindings).utf8)),
                                             "usb_tcp_bindings": try JSONSerialization.jsonObject(with: Data(JSON.encode(usbBindings).utf8))])
                }
            } catch {
                let lanRevoked = try firewall.setLANTCP([])
                let usbRevoked = try firewall.setUSBTCP([])
                if lanRevoked || usbRevoked {
                    try firewall.block()
                    allowed = false
                    firewallVerified = SystemClock.seconds
                }
                reasons.append("configuration_invalid: \(error)")
                config = nil
                configuration = nil
                generation += 1
                session = nil
            }
            let localFailure = localTCPFailures.joined(separator: "; ")
            if localFailure != lastLocalTCPFailure {
                EventLog.write(localFailure.isEmpty ? "local_tcp_inventory_recovered" : "local_tcp_inventory_failed",
                               level: localFailure.isEmpty ? "info" : "warning",
                               message: localFailure.isEmpty ? "Local TCP interface inventory recovered" : localFailure,
                               details: ["run_id": runID, "impact": "affected_local_tcp_exceptions_revoked; public_readiness_policy_unchanged"])
                lastLocalTCPFailure = localFailure
            }
            var egressGroup: UInt32?
            var surgeInterface: String?
            if config?.usesPersistentTCP == true {
                do {
                    egressGroup = try DedicatedEgress.group()
                    guard let pid = trustedSurgePID,
                          try DedicatedEgress.identityMatches(pid: pid, uid: Probe.consoleUID(), group: egressGroup!) else {
                        throw GuardError("surge_egress_identity_mismatch")
                    }
                    surgeInterface = try Probe.surgeInterface()
                    if allowed, allowedInterface != surgeInterface {
                        try firewall.block()
                        allowed = false
                        firewallVerified = SystemClock.seconds
                    }
                } catch { reasons.append("persistent_tcp_not_ready: \(error)") }
            }
            if config?.mode == "routes" {
                if observation?.ready == true, let config { updateSession(config, force: forceFirewallAudit) }
                else { generation += 1; session = nil; sessionChecked = 0 }
                if SystemClock.seconds - sessionChecked >= 3 || session == nil {
                    reasons.append(sessionFailure.isEmpty ? "rule_probe_expired" : sessionFailure)
                } else if let session {
                    if session.mode != "rule" { reasons.append("outbound_mode_is_\(session.mode)") }
                    if !session.enhancedMode { reasons.append("enhanced_mode_disabled") }
                    for route in session.routes where !route.ready { reasons.append("\(route.reason): \(route.url)") }
                    if session.routes.count != config?.routeChecks.count { reasons.append("incomplete_route_results") }
                }
            }
            if !allowed, reasons.isEmpty, observation?.ready == true, config != nil {
                firewall.recordBlockedTraffic(phase: "before_allow")
                // Optional evidence collection must not reopen using stale readiness or route results.
                do {
                    observation = try Probe.readiness(trustedProcess: surgeProcessTrusted())
                    reasons.append(contentsOf: observation?.reasons ?? [])
                    if let loss = try watchSurgeConnection(), !reasons.contains(loss) { reasons.append(loss) }
                } catch { reasons.append("readiness_probe_failed: \(error)") }
                if config?.mode == "routes", session == nil || SystemClock.seconds - sessionChecked >= 3 { reasons.append("rule_probe_expired") }
                if config?.usesPersistentTCP == true {
                    do {
                        guard let group = egressGroup, let pid = trustedSurgePID,
                              try DedicatedEgress.group() == group,
                              try DedicatedEgress.identityMatches(pid: pid, uid: Probe.consoleUID(), group: group),
                              try Probe.surgeInterface() == surgeInterface else {
                            throw GuardError("Surge identity/interface changed before allowing TCP")
                        }
                    } catch { reasons.append("persistent_tcp_not_ready: \(error)") }
                }
            }
            let ready = reasons.isEmpty && observation?.ready == true && config != nil
            if ready != allowed || (ready && localBindingsChanged) {
                if ready {
                    try firewall.allow(group: egressGroup, interface: surgeInterface)
                    allowedInterface = surgeInterface
                }
                else { try firewall.block() }
                allowed = ready
                firewallVerified = SystemClock.seconds
            }
            let reason = ready ? "allowed" : reasons.joined(separator: "; ")
            if reason != lastReason || SystemClock.seconds >= nextPublish {
                let snapshot = GuardSnapshot(runId: runID, firewallVerifiedUptime: firewallVerified, allowed: allowed,
                                             configurationMode: config?.mode ?? "invalid", readiness: observation, session: session, reasons: reasons,
                                             enforcement: config?.enforcement ?? "surge_readiness_gate",
                                             lanTcpEnabled: config?.allowsLANTCP, lanTcpBindings: firewall.lanTCPBindings,
                                             systemUpdateId: systemUpdate?.id, usbTcpBindings: firewall.usbTCPBindings,
                                             localTcpErrors: localTCPFailures.isEmpty ? nil : localTCPFailures)
                try RootFiles.write(try JSON.encode(snapshot), to: Paths.snapshot, mode: 0o644)
                nextPublish = SystemClock.seconds + 1
            }
            if reason != lastReason {
                var details: [String: Any] = ["run_id": runID, "mode": config?.mode ?? "invalid", "pf": ready ? "allowed" : "blocked",
                                              "allow_lan_tcp": config?.allowsLANTCP ?? false]
                if !ready, let detected = surgeExitDetectedAt {
                    details["surge_exit_event_uptime"] = detected
                    details["block_verified_uptime"] = firewallVerified
                    details["exit_event_to_block_verified_ms"] = max(0, (firewallVerified - detected) * 1000)
                }
                if let session, let encoded = try? JSON.encode(session.routes) {
                    details["routes"] = try? JSONSerialization.jsonObject(with: Data(encoded.utf8))
                }
                EventLog.write("gate_changed", level: ready ? "info" : "warning", message: reason, details: details)
                lastReason = reason
            }
            if !allowed { firewall.recordBlockedTraffic() }
        } catch {
            if (try? SystemUpdate.load())?.phase == .active {
                EventLog.write("system_update_unverified", level: "error", message: "Maintenance remains requested; release not verified: \(error)")
                try? FileManager.default.removeItem(atPath: Paths.snapshot)
                exit(1)
            }
            EventLog.write("reconciliation_failed", level: "error", message: "\(error). Blocking before launchd restart", details: ["run_id": runID])
            do {
                try firewall.setLANTCP([])
                try firewall.setUSBTCP([])
                try firewall.block()
                EventLog.write("fail_closed", message: "Block rules verified before restart")
            }
            catch { EventLog.write("pf_unverified", level: "critical", message: "Cannot verify blocking: \(error)") }
            try? FileManager.default.removeItem(atPath: Paths.snapshot)
            exit(1)
        }
    }

    func observeEgress() {
        guard systemUpdate?.phase != .active else { return }
        let now = SystemClock.seconds
        guard !egressSampling, now >= nextEgressSample else { return }
        egressSampling = true
        nextEgressSample = now + 30
        let stateAtStart = allowed ? "allowed" : "blocked"
        let trackingStarted = now
        let revisionAtStart = firewall.revision
        let blockIDAtStart = firewall.blockID
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let result = Result { try EgressObservation.collect() }
            DispatchQueue.main.async {
                guard let self else { return }
                self.egressSampling = false
                guard self.systemUpdate?.phase != .active else { return }
                switch result {
                case .failure(let error):
                    let reason = String(describing: error)
                    if reason != self.egressFailure {
                        EventLog.write("egress_observation_failed", level: "warning", message: reason,
                                       details: ["run_id": self.runID, "impact": "egress_observation_unavailable; firewall_policy_unchanged"])
                    }
                    self.egressFailure = reason
                case .success(var sample):
                    let now = SystemClock.seconds
                    if !self.egressFailure.isEmpty {
                        EventLog.write("egress_observation_recovered", message: "Passive egress sampling recovered", details: ["run_id": self.runID])
                    }
                    self.egressFailure = ""
                    sample.guardStateAtStart = stateAtStart
                    sample.guardStateAtEnd = self.allowed ? "allowed" : "blocked"
                    sample.guardStateDuringSample = revisionAtStart == self.firewall.revision ? stateAtStart : "changed"
                    sample.guardTrackingStartedUptime = trackingStarted
                    sample.guardTrackingCompletedUptime = now
                    let context = "\(self.firewall.revision)|\(sample.guardStateDuringSample!)"
                    let flows = self.egressHistory.newActivity(sample.flows, now: now, context: context)
                    for category in EgressFlow.categories {
                        let selected = flows.filter { $0.category == category }
                        guard !selected.isEmpty else { continue }
                        var evidence = sample; evidence.flows = selected
                        if var details = (try? JSON.encode(evidence)).flatMap({ try? JSONSerialization.jsonObject(with: Data($0.utf8)) }) as? [String: Any] {
                            details["run_id"] = self.runID
                            details["guard_state_at_log"] = self.allowed ? "allowed" : "blocked"
                            details["firewall_revision_start"] = revisionAtStart
                            details["firewall_revision_end"] = self.firewall.revision
                            details["pf_block_id_start"] = blockIDAtStart
                            details["pf_block_id_end"] = self.firewall.blockID
                            details["total_observed_flows"] = sample.flows.count
                            details["deduplicated_flows"] = self.egressHistory.deduplicated
                            details["limited_flows"] = self.egressHistory.limited
                            details["category"] = category
                            EventLog.write("egress_path_observed", level: category == "public_send_review" ? "warning" : "info",
                                           message: "Socket activity on an interface other than Surge VIF; inspect destination and network role", details: details)
                        }
                    }
                    if now >= self.nextEgressSummary {
                        self.nextEgressSummary = now + 300
                        EventLog.write("egress_observation_summary", message: "Sampling is active; absence of findings is not proof of no bypass",
                                       details: ["run_id": self.runID, "sample_interval_seconds": 30, "sample_seconds": sample.sampleSeconds,
                                                 "observed_flows": sample.flows.count, "unresolved_active_sockets": sample.unresolvedActiveSockets,
                                                 "unattributed_active_sockets": sample.unattributedActiveSockets, "unmeasured_sockets": sample.unmeasuredSockets,
                                                 "category_counts": Dictionary(uniqueKeysWithValues: EgressFlow.categories.map { category in
                                                     (category, sample.flows.filter { $0.category == category }.count)
                                                 }), "deduplicated_flows": self.egressHistory.deduplicated, "limited_flows": self.egressHistory.limited,
                                                 "scope": sample.scope])
                    }
                }
            }
        }
    }

    func run() throws {
        var context = SCDynamicStoreContext(version: 0,
            info: Unmanaged.passUnretained(self).toOpaque(), retain: nil, release: nil, copyDescription: nil)
        store = SCDynamicStoreCreate(nil, "surge-guard.events" as CFString, { _, _, info in
            guard let info else { return }
            Unmanaged<Daemon>.fromOpaque(info).takeUnretainedValue().reconcile(forceFirewallAudit: true)
        }, &context)
        guard let store,
              SCDynamicStoreSetNotificationKeys(store,
                ["State:/Network/Global/IPv4", "State:/Network/Global/IPv6"] as CFArray,
                ["State:/Network/Service/.*/IPv[46]", "State:/Network/Service/.*/VPN"] as CFArray),
              let source = SCDynamicStoreCreateRunLoopSource(nil, store, 0) else {
            throw GuardError("Cannot subscribe to network state changes")
        }
        self.source = source
        CFRunLoopAddSource(CFRunLoopGetMain(), source, .defaultMode)
        // Network/process events are primary; a 0.5 s fallback covers
        // missed readiness events, while PF integrity is audited every 5 s.
        timer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
            self?.reconcile()
            self?.observeEgress()
        }
        for number in [SIGTERM, SIGINT, SIGHUP] {
            signal(number, SIG_IGN)
            let handler = DispatchSource.makeSignalSource(signal: number, queue: .main)
            handler.setEventHandler { [weak self] in
                do {
                    let maintenance = (try? SystemUpdate.load())?.phase == .active
                    if !maintenance { try self?.firewall.block() }
                    try? FileManager.default.removeItem(atPath: Paths.snapshot)
                    EventLog.write(maintenance ? "system_update_daemon_stopped" : "daemon_stopped",
                                   message: maintenance ? "Maintenance remains active across restart; no blocking rules loaded" : "Leaving blocked rules installed")
                }
                catch { EventLog.write("pf_unverified", level: "critical", message: "Block on shutdown failed: \(error)"); exit(1) }
                exit(0)
            }
            handler.resume()
            signals.append(handler)
        }
        reconcile(forceFirewallAudit: true)
        CFRunLoopRun()
    }
}

do {
    try CLI.run(Array(CommandLine.arguments.dropFirst()))
} catch {
    EventLog.write("command_failed", level: "error", message: String(describing: error))
    if CommandLine.arguments.contains("--json") {
        struct Failure: Encodable { let ready = false; let error: String }
        print((try? JSON.encode(Failure(error: String(describing: error)))) ?? "{}")
    } else { fputs("surge-guard: \(error)\n", stderr) }
    exit(1)
}
