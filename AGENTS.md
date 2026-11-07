# Working in this repository

Read README.md first. It is the operational contract for all three components.

## Source map

- `Sources/SurgeGuardCore`: configuration validation, native readiness probes,
  bounded system commands, PF rules, status freshness and event logging.
- `Sources/CPcap`: SDK bridge to macOS system libpcap; no downloaded dependency.
- `Sources/SurgeGuard`: privileged daemon, CLI and SwiftBar menu renderer.
- `Sources/SurgeGate`: unprivileged application startup/session/shutdown service.
- `Sources/SurgeLaunch`: fixed set-group (`2755`, `root:_surge_guard`) C launcher
  for the official signed Surge application under `persistent_tcp`.
- `integrations/swiftbar`: thin plugin invoking the installed renderer.
- `scripts/install-user.sh`: user service/plugin installation; never run with sudo.
- `Tests/SurgeGuardTests`: standalone checks; no live firewall mutation or app quits.

## Contracts

- Keep public examples generic. Never commit a real profile, node credentials,
  private configuration, machine-specific paths, logs or diagnostic bundles.
- PF updates stay inside `io.github.surge-guard`. Do not globally disable PF,
  flush all state or replace unrelated configuration to simplify recovery.
- Preserve the existing signature, extension, VIF, route and IPv6 checks.
  Only explicit dynamic-store NoKey means absent IPv6; read/type/schema errors
  must never become an absent route or permit readiness.
- Configured route checks fail closed. Never convert a malformed/missing policy,
  failed CLI query or expired result into enhanced-only success.
- Omitted allowed_final_policies means exact group matching without a node
  allowlist; a supplied list remains nonempty and restrictive. Null/empty lists
  are errors. DIRECT/REJECT and unresolved groups remain blocked in both forms.
  Upgrade older binaries with their existing policy before applying group-only
  JSON; older readers reject the omitted field and would block networking.
- Run user-owned Surge CLI code only after dropping privileges. Do not execute
  user scripts or configured shell commands as root.
- A condition check is not a claim that PF is active. A cached status must be
  bound to the current boot, process and monotonic freshness limits.
- Set state-file permissions on the staged inode before publishing with rename.
  Foundation atomic rewrite followed by chmod can briefly publish 0600 under a
  daemon umask of 077. Use AtomicFile through the owner-validating wrappers;
  retain the concurrent permission/content regression test.
- Keep human logs clear about component, state, cause, impact and recovery.
  Status-read failure does not establish a network outage. Preserve raw error,
  event and process fields in JSON. SwiftBar's user-owned formatter must stay
  unprivileged; only the fixed log-reading command receives sudo.
- Command must explicitly close every pipe end, including unused stdin pipes,
  on success, failed launch and timeout. Keep repeated-call descriptor checks.
  A failed service query is unknown, never evidence the daemon stopped.
  Failed lock initialization must close its FD exactly once; do not assign the
  owning stored property before throwing acquisition has finished.
- Both event logs use EventFile: current plus one previous file, each at most
  1 MiB, with private ownership/permissions and a writer lock. Do not add
  unbounded service stdout/stderr files or log every unchanged polling tick.
- SurgeGate must consume verified daemon status, not proxy-port/utun guesses.
  Do not reintroduce force-kill, `pkill -f`, or success messages after app errors.
- Install/verify the independent SwiftBar recovery menu before privileged changes.
  `launchctl bootout` may return before daemon cleanup releases its lock. Wait
  for actual lock/PID release, back up before replacement, verify fresh PF status
  after startup and attempt rollback on update failure. Never fix this with sleeps
  of a guessed duration or repeated forced restarts. Recovery must work offline.
  Interface enumeration failure is an error, never an empty state-cleanup list;
  load blocking rules before that query and do not claim verified cleanup on failure.
  Still clear remembered addresses when enumeration fails, and retain them on any
  cleanup failure so retries do not forget old states.
  Persist the bounded boot-bound address history before allowing traffic; a new
  daemon must consume it before cleanup. Invalid history remains unverified while
  current-address cleanup is still attempted.
- Independent emergency/log actions must not query the guard executable, even
  for help/capabilities. A service-query error is not service absence: refuse
  anchor clearing on unexpected errors or a running job without a valid PID.
- Document the reactive/early-boot limitations accurately. Do not market this
  external gate as guaranteed packet-by-packet enforcement.
- A known tunnel/process loss while allowed must block before remaining probes
  and integrity queries. Watch the verified native service, reject obsolete
  callbacks and distinguish rule loading from old-state cleanup in timing logs.
  Never treat callback latency as actual failure-to-packet-block latency.
- Egress observations are passive evidence, never inputs to PF permission.
  Use the second nettop delta frame, expose missing counters/interfaces/UDP peers,
  and separate system-extension/local activity from public application warnings.
  Reported socket interfaces do not verify packet paths. Label receive-only
  records; wildcard UDP peers stay unknown even on a known service port. Never
  describe these counters as confirmed public direct traffic or proof of bypass.
  No observations is not a no-bypass claim; keep the sampler asynchronous and
  bounded, and retain JSON evidence/deduplication and failure/recovery events.
- The optional packet recorder is independent of PF permission. Keep its fixed
  all-interface capture, private bounded ring, persistent gap flags and fresh
  job/boot-bound status. `audit-stop` persistently disables launchd automatic
  startup; `audit-start` explicitly re-enables it. Root must drop privileges
  before Surge request queries.
  Rejoin the supervisor process group before exec so launchd reaps the capture
  child after crashes. Publish its process group before spawning; stop waits for
  the group even if the child PID was never published. Bind new group records to
  native supervisor birth time so PID reuse is not an
  unrelated group's stop dependency. Missing leaders do not prove group exit.
  Bound diagnostic input and queued work, and keep the live-pipe-before-EOF
  regression. Never equate a running collector, zero reported drops,
  request-window overlap or absent request match with verified no-bypass coverage.
  Raw packet prefixes may contain payload; keep captures/request metadata private.
- Optional `persistent_tcp` restricts ready-state non-loopback TCP to the verified
  Surge VIF (`198.18.0.1`, `keep state (if-bound)`) and Surge's dedicated effective
  group (`_surge_guard`, `60000...60999`, `keep state (if-bound)`). UDP is outside
  this mode's enforcement scope. Verify all four native `sysctl` process credential
  fields (`cr_uid`, `p_ruid`, `cr_groups.0`, `p_rgid`) with exact `kinfo_proc` size
  and no `ps` fallback. Cache Surge code-signature trust only by `(pid, birthTime)`
  and invalidate immediately if a second `Surge` candidate process appears.
  Candidate changes also invalidate route generations while blocked; recheck
  candidates after signature validation before caching the result.
- Optional `allow_lan_tcp` requires `persistent_tcp`; default stays off. Allow
  only IPv4 TCP between actual private local addresses on up `enN` interfaces
  and RFC1918 peers, in both ready and blocked states, with interface-bound state.
  The same opt-in allows link-local IPv6 TCP on up Apple USB NCM interfaces,
  identified by native driver/vendor inventory, bound to actual local addresses
  and fe80::/10 peers with interface-bound state. CoreDevice tunnels identified
  by bounded system inventory allow only their actual ULA address and ULA /64.
  Adding device bindings preserves carrier states; removing bindings or changing
  policy still clears old states. Keep public/unrelated-VPN/other IPv6 restrictions;
  network events audit PF and expedite route refresh without discarding a
  still-fresh result. Keep the three-second expiry and invalidate on actual
  readiness loss, policy changes and trusted process changes.
  invalid configuration or enumeration failure revokes the exception. Report its
  effective scope in status/menu/logs. Upgrade running Guard and Gate before
  writing this field; old readers reject it. Do not promise LAN survival through
  startup, upgrades or state cleanup, or add blocked-state UDP/DNS permissions.
  Optional LAN/USB inventory errors revoke only the affected exception and clear
  its old local-address/peer states; required readiness failures still block.
  Network events reject old in-flight query generations without extending the
  original three-second freshness of completed results.
- `SurgeGate` supports persistent `update-pause` / `update-resume` (`update-mode.json`)
  acknowledged by nonce + fresh status, plus `start` / `stop` / `restart`. Keep
  30s retry backoff on real launch/quit failures without penalizing post-launch
  grace windows or waiting-for-block states. Recover-launch takes request.lock
  before the pending-launch lock; consumption rechecks its launch observation
  under request.lock before withdrawing a queued shutdown. A timed-out launch is not cancelled:
  retain its private boot-bound pending marker until completion, and never
  acknowledge update pause while a launch remains unsettled. Publish shutdown
  requests before bootstrap, serialize submission/consumption, and preserve the
  session on retries after both quit failure and macOS cancellation.
- Bind pending launches to the observing Gate instance and recorded native child
  PID/birth time. A dead/reused child permits failure recovery; a lost observer
  without child evidence requires explicit nonce-bound `recover-launch` attestation
  or observed startup/new boot, never timeout-based cancellation. Keep shutdown
  requests responsive: decline and remove requests blocked by unresolved launches,
  and withdraw an unconsumed request if bootstrap fails. Do not acknowledge update
  pause while a launch is active or orphaned.
- Preserve the ordinary user's ownership of Surge.app for Sparkle. Launcher
  fstat/path consistency checks reduce replacement races but do not make signed
  validation and pathname exec atomic; document that remaining boundary.
- Validate serialized policy/session checkpoints with the reader's limits before
  publishing. Preserve prior sessions on overflow, and let only the Gate lock
  owner publish run failures; a failed duplicate run must not overwrite status.
- `install-user.sh --menu-only` and `--recovery-only` update independent menu
  files only; neither queries/restarts services nor replaces the Gate binary.
- Missing PF attachments may be restored only for a trusted existing installation
  with the recognized Apple default disk/live layout. Hold the runtime lock,
  back up and recheck before writing, and attach inline blocking rules with a
  filter-only load that preserves other anchors, NAT and options. Refuse custom
  layouts. Retrying a repair interrupted between live attachment and disk write
  must work. On preparation failure attempt blocking before throwing, preserving
  the original error and any unverified-block failure. Restoration is not verified
  PF enablement/state cleanup. Installing
  menu files does not enable SwiftBar login startup; verify that separately.
- Explicit root `os-update-begin` / `os-update-end` maintenance is cross-boot and
  never expires automatically. Require a fresh exact-nonce Gate acknowledgement
  before releasing protection; no pending launch or power request may be hidden
  by that acknowledgement. Preserve Gate's separate Surge update pause and saved
  session. Keep preparing/active/restoring checkpoints root-owned, bounded and
  strictly validated. Write the empty own boot anchor before clearing live rules;
  do not disable PF globally or clear other anchors. Active maintenance must not
  re-arm on daemon termination/startup. Invalid records fail closed. Ending must
  restore normal disk/live protection and verify fresh PID/boot/nonce-bound PF
  status before removing the checkpoint. Block incompatible management commands.
  Show orange maintenance and all-application direct-access scope, never green
  protection; intent alone is not verification. Retain offline emergency access.
  Use snapshot version 2 only for maintenance so version-1 readers cannot mistake
  empty rules for verified blocking; normal protection remains version 1.

## Validation and delivery

Run `scripts/check.sh` after changing logic. Add focused cases for new parsing,
failure handling or state transitions. Check CLI JSON remains machine-readable.
Use `docs/acceptance.md` for authorized live tests, and record performed versus
unperformed tests in `docs/verification.md`. Read-only checks can run normally;
perform deployment and disruptive tests within the user's authorized scope.
Do not infer a live protection pass from unit tests or a successful build.
