# Troubleshooting for people and agents

Start with these read-only commands. A successful condition probe is not proof
that the service/PF is active.

For a merged recent timeline, run the user renderer's `diagnose` command or use
the menu's **合并检查最近 20 分钟** action. `diagnose --watch-seconds 120` adds a
bounded passive DNS/QUIC memory-log observation; it neither enables recording nor
changes DNS/PF. See README for limits and private report paths. Prefer the full
private event files over truncated unified-log messages. Unavailable files,
non-overlapping memory windows and retained-time limits remain evidence gaps.
The diagnostic report deliberately leaves the final root cause undetermined.

```sh
/Library/PrivilegedHelperTools/surge-guard status --json
/Library/PrivilegedHelperTools/surge-guard doctor
sudo /Library/PrivilegedHelperTools/surge-guard doctor
sudo /Library/PrivilegedHelperTools/surge-guard logs
```

The last command renders retained events as readable records with local time,
severity, state/reason and expected/actual routing details. `logs --follow` uses
the same readable format for new events. `logs --json` emits JSON Lines for agents.
Human output names the component and explains cause, effect, remaining apps and
recovery. Raw OS errors, event codes and process/run IDs remain in JSON. The
SwiftBar bridge uses privileged fixed-file reads and unprivileged formatting,
including for historical events. Its formatter is `surge-guard format-logs`.
Nested helper errors are summarized in human output. A temporary inability to
connect to Surge CLI is shown as such, with restoration paused while blocked;
the original helper stderr remains in JSON. Do not hide that failure with green
status or treat it as evidence that the signed Surge process necessarily exited.
Old plain-text records stay readable and get a JSON wrapper in machine mode.
Following the log need not print anything new while conditions stay unchanged.
Each component keeps only its current log and one `.1` predecessor, each at most
1 MiB. The system predecessor is `events.log.1`; the companion predecessor is
`gate-events.jsonl.1`. Oversized records are rejected, and no unbounded companion
stdout/stderr file is configured. Existing `service.log` is retained without
further writes after the user service is updated.
Never make the private directory world-readable to simplify menu access.

| Symptom/reason | Check | Action |
| --- | --- | --- |
| `unknown`, `status_unavailable` | Is the new binary installed? Is the system job running? | An old daemon does not publish the new status schema. Install the independent recovery menu first, then update system and companion. Do not label PID-only detection as protected. |
| Permission denied reading status, followed shortly by recovery | Actual snapshot modes and `gate_status_unavailable` / `gate_status_recovered` | A verified writer bug briefly exposed 0600 during Foundation atomic rewrite. Update to the pre-permissioned POSIX publication fix. Do not make the entire private state directory readable or infer a network outage from a reader error. See the permission-window incident. |
| `status_or_pf_audit_expired` | Current PID, boot and recent `pf_unverified`/restart events | Run root doctor. A stale snapshot cannot prove either allowed or blocked PF; do not assume the menu color alone proves protection. |
| `stopped` | `launchctl print system/io.github.surge-guard` | Start the installed service; inspect startup errors if it exits. |
| `service_query_failed`, or old SurgeGate says `stopped` while the guard is verified allowed | Compare both CLI reports and inspect the companion's open descriptors | An unused-stdin pipe leak in the shared command runner caused persistent query failures. Update both binaries; query failures now stay unknown. See [the command-pipe incident](incidents/command-pipe-leak.md). |
| `unlocked` | `manual_unlock` event from this boot | This is intentional temporary removal. `start` or reboot re-arms; `uninstall` is permanent removal. |
| `configuration_invalid` | Validate the intended local policy | Correct the local draft and use `sudo ... configure FILE`. No enhanced-only fallback occurs on damaged installed settings. |
| `rule_probe_pending` | Is a console user logged in? | Wait for the user session and first bounded query. No external HTTP health request is required. |
| `rule_probe_failed` | Error and duration; `surge-cli status`, `surge-cli rule explain URL` as the user | Confirm CLI availability/version and user-session access. Do not run a user-owned CLI as root. Persistent identical errors are not logged every timer tick. |
| `rule_probe_expired` | Are queries slow/hung? | Results older than three seconds from query start cannot open the gate. Check CLI latency and reduce unnecessary checks. |
| `outbound_mode_is_direct/proxy` | `surge-cli mode` | Routes mode requires Rule mode. Change it deliberately in Surge, then recheck. |
| `route_policy_mismatch` | `route_decision_changed` event; expected/actual group and final node | Correct Surge's rule/group choice. When allowed_final_policies is supplied, the node must also be in that list. Omit the field to allow any proxy within the matching group; DIRECT/REJECT remain blocked. |
| Group-only JSON becomes `configuration_invalid` on an older installation | Installed binary version versus new build | Preserve the old policy while installing the new binary; verify status, then apply the group-only policy. Empty/null allowlists are invalid, not an alternative spelling for omission. |
| `pf_unverified` | Root doctor, first-anchor ordering, competing PF users | Resolve the reported PF error. Protection is unknown when PF cannot be programmed. Never flush all PF rules/state as a shortcut. |
| Enhanced mode unavailable | Signature/extension/VIF/default-route/IPv6 fields | Start Enhanced Mode, inspect competing VPNs/routes and rerun the condition probe. |
| `readiness_loss_blocked` | Cause, event/loss-observation uptime, rule-load uptime and final block/state-cleanup uptime | The allowed gate closed before remaining probes. Compare `event_to_rules_loaded_ms` and `event_to_block_verified_ms`; loading rules alone does not clear existing states. Neither field measures actual outage-to-event delay or proves zero bypass. |
| `egress_path_observed` | Process/PID, reported interface, local/remote endpoints, destination scope, process kind and new byte counts | A socket observation does not establish the actual packet path or confirm bypass. Distinguish sent bytes from receive-only activity. Wildcard UDP peers remain unknown, including local port 5353 (an mDNS hint). Public peers warrant review; network extensions are classified, not implicitly approved. |
| `egress_observation_failed` | Fixed `nettop` command timeout/output and parser error | Observation is unavailable; PF readiness continues unchanged. Do not interpret the missing evidence as no bypass. Check `observe-egress --json`, using sudo when full process visibility is needed. |
| Menu has two Surge sections | Existing combined plugin and standalone plugin | Use `install-user.sh --menu-only`, remove the standalone copy and call the renderer once from the combined menu. |
| Parent menu turns grey after a status change on SwiftBar 2.1.1 | Current isolated renderer and the installed user renderer version | Refresh the updated renderer. Parent entries carry primary light/dark colors to preserve SwiftBar's action during incremental submenu updates; changing PF or restarting the guard is unnecessary. |
| Emergency action reports it cannot inspect the guard service/PID | launchctl query error, authentication and expected job state | Restore query access and retry. It deliberately refuses to clear rules when absence/exit cannot be established. Only the specific missing-service result is absence; the action and log readers do not invoke the guard binary for help. |

## SurgeGate

```sh
"$HOME/Library/Application Support/SurgeGuard/bin/surge-gate" status --json
"$HOME/Library/Application Support/SurgeGuard/bin/surge-gate" logs
```

- `waiting`: the system guard has not recently verified `allowed`. Inspect its
  reasons first. A local proxy port being open is not a substitute.
- `unknown`: the guard report cannot be verified/read. Restoration pauses;
  this does not establish that the guard process or networking has stopped.
- `restoring`: some app launches remain pending. `application_restore_failed`
  identifies the bundle ID; absent apps remain pending rather than being lost.
- `ready`: initial restoration is complete. This is not a separate PF claim.
- `error`: inspect the event and configuration. A corrupt session/config is not
  silently discarded. The service retries configuration errors.
- `shutting_down`: a normal OS shutdown request is being processed; wait for
  app prompts. After shutdown is accepted, snapshots pause so an empty desktop
  cannot overwrite the saved session.
- `shutdown_aborted` (log event; status is `error`): no force-kill is performed.
  The saved session is retained and snapshots pause. Resolve the app/PF/permission
  error and retry ordered shutdown, or restart SurgeGate to resume restoration.
  After macOS cancels an accepted shutdown, the same retry/resume choices apply.
- `migration_app_unresolved`: inspect the retained legacy file and replace the
  display name with a valid Bundle ID in the new local config. Finder/Surge are
  always excluded from ordinary recovery.

Do not run ordered-shutdown tests on an unsaved working session. Unit tests do
not send app quit events or request OS shutdown.

## Diagnostics and public issues

Use SwiftBar's read-only egress sample or `surge-guard observe-egress --json`.
The daemon samples about one second every 30 seconds after the new system binary
is installed. Evidence uses only the second delta frame; old connection totals,
idle sockets, loopback and verified Surge-owned traffic are not reported as new
socket records with a non-VIF interface label. These labels are nettop's reported
interfaces, not verification of packet paths. A receive-only record is not
evidence of outbound transmission. A wildcard UDP peer (`*:*` or `*.*`) leaves
the destination unknown; even local port 5353 only suggests mDNS and cannot
establish a local or public peer. Unknown UDP peers are retained, and absent
counters/interfaces appear in summaries. A five-minute summary is an observer
heartbeat, not an all-clear. Twenty new flows per sample and five-minute dedup
bound evidence volume in addition to the existing current/previous log rotation.

These records cannot reconstruct activity before observation was installed or
all short-lived traffic between samples. Gate state logs answer when conditions
and PF checks changed, not which individual packets escaped. A Surge-exit timing
field measures callback receipt to PF verification; command/scheduling latency
and the 0.5-second fallback rule out a guaranteed tens-of-milliseconds deadline.
Keep endpoint/process evidence private when sharing reports.

New records split public sending candidates, public receive-only observations,
system extensions, local/reserved peers and unresolved peers. Only the first is
a warning; it remains unverified. A receive-to-send or PF-revision change bypasses
five-minute dedup. Summary counts describe that sample, not the whole five-minute
interval. `limited_flows` reports records omitted by the per-sample cap. Start/end
state and PF revision cover a conservative tracking window including task dispatch
and callback; a change anywhere in it prevents attribution to one guard state.
Manual/old samples do not invent a verified historical state.

`pf_block_traffic` is separate evidence: read-only `pfctl -a io.github.surge-guard
-s labels` counters for `surge-guard-block`, at most every five seconds while
blocked and when preparing to allow. Inspect `block_id`, `totals`, `delta`,
in/out counts, `counter_sampled_uptime` and `delta_baseline_uptime`. These are
matched block packets, without per-packet endpoints or processes. They cannot
be joined to a socket record to claim that specific flow was dropped. Zero
matches does not prove no bypass. The final read precedes actual clearing, so
the last small tail is not counted. Read/parse errors or counter decreases use
`pf_block_observation_failed`, never fabricated zeroes; baseline loss is explicit.
`pf_block_observation_gap` marks a reload without a final old-counter read:
blocking takes priority over logging. Neither failure changes firewall policy.

For full retained history, inspect both private files. macOS unified-log mirrors
can truncate long JSON records; a truncated mirror is not the full source:

```sh
sudo /bin/cat /private/var/db/surge-guard/events.log.1 /private/var/db/surge-guard/events.log \
  | "$HOME/Library/Application Support/SurgeGuard/bin/surge-guard-ui" format-logs
```

The predecessor may not exist before the first rotation. Do not publish raw output.

Share a small sanitized summary: component version, macOS/Surge versions,
configuration mode, state, reason/event codes and which acceptance scenario
failed. Remove personal URLs, group/node names, app lists, paths and raw logs.
The policy/status files are locally readable and must not contain credentials.

## Recovery

SwiftBar → **恢复与备份（离线可用）** is the first recovery path. It offers a
normal restart with bounded result checks, start/re-arm, trusted backup/rollback,
previous-policy restore and an independent emergency remove-block action.
Legacy guards support restart/start/emergency removal before upgrading; backup
commands are clearly marked as requiring the new system version.

If an update reports a lock conflict, do not repeatedly click forced restart.
An observed failure mode was `bootout` returning before the old daemon finished
TERM cleanup: the updater immediately failed on its lock, then the old daemon
left blocked rules with no loaded service. The fixed updater waits on the real
lock, saves a backup, verifies startup and attempts rollback on failure. See
[the incident contract](incidents/update-lock-race.md).

Emergency removal works without executing the installed guard binary. It waits
for the old PID to exit, clears only `io.github.surge-guard`, then verifies the
anchor is empty. Protection is explicitly OFF until Start or next boot. It
refuses to flush if the previous process is still alive. It never toggles Surge,
disables PF globally, or restores a whole old `pf.conf`.

In a local Terminal, `sudo /Library/PrivilegedHelperTools/surge-guard unlock`
stops the system service and removes only this gate. Keep the command available
offline before applying a new policy. The user service cannot unlock PF.

If the binary is absent, use README's independent recovery helper; do not clear
the anchor immediately after bootout without confirming process exit.
Retained policy/session data is separate from public source; do not restore an
old complete `pf.conf` over subsequent edits made by other services.
