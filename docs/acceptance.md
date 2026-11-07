# Local acceptance procedure

Run from a local Terminal with administrative access and an offline copy of the recovery commands. These steps intentionally disrupt connections. Do not infer a pass from `check`, PF rule text, a cached page, or DNS failure alone.

## Establish a usable baseline

Before enabling the guard, verify each target/protocol works on the network and record whether IPv6 is available. Use your own controlled endpoints where possible. A test with no working baseline is inconclusive, not a pass.

Example fresh HTTPS requests that bypass proxy environment variables and DNS:

```sh
curl --noproxy '*' -4 --connect-timeout 2 --max-time 4 \
  --resolve 'one.one.one.one:443:1.1.1.1' https://one.one.one.one/ -o /dev/null

curl --noproxy '*' -6 --connect-timeout 2 --max-time 4 \
  --resolve 'one.one.one.one:443:[2606:4700:4700::1111]' https://one.one.one.one/ -o /dev/null
```

These third-party endpoints are examples, not dependencies of the guard. Use a LAN HTTP server as an additional check if available. Also establish an ongoing TCP transfer and a UDP stream to a controlled external host: already-established sessions must be checked separately from new connections.

## Scenarios

For each transition, record the time, `surge-guard check`, root `status`, logs, fresh connection results and existing TCP/UDP behavior. Capture the actual physical interfaces, including both Ethernet and Wi-Fi when present. A packet capture contains private data; keep it outside the public repository.

| Scenario | Expected after reconciliation | What it tests |
| --- | --- | --- |
| Surge closed, guard running | Fresh and established ordinary traffic stops | Closed application |
| Surge open, Enhanced Mode off | Still blocked | No UI/process-only false positive |
| Enhanced Mode starting | Blocked until all readiness checks pass | Startup state |
| Enhanced Mode ready | Existing Surge routing policy works | Proxy + DIRECT compatibility |
| Routes mode, all configured URL/group/node checks pass | Allowed after a recent user-session query | Policy gate |
| Wrong group, unlisted node when a list is configured, DIRECT result, or Direct/Global mode | Blocked | No route-condition bypass |
| Group-only policy with a changed proxy in the same group, or another allowlisted proxy when a list is configured | Allowed; parsed route change appears in logs | Group-only matching and optional node restriction |
| CLI fails, hangs, user logs out, or rule result expires | Blocked; specific reason recorded | Query failure and freshness |
| Invalid/missing installed policy | Blocked; no readiness-only fallback | Configuration failure |
| Old boot/PID or stale status/PF audit | Menu reports unknown/stopped; Gate does not restore apps | No cached green status |
| Turn Enhanced Mode off | Blocked; measure actual latency | Toggle path |
| Graceful Surge update begins disconnecting | Native tunnel event triggers blocking before remaining probes | Early-disconnect subscription; record rule-load and old-state-cleanup times separately |
| Quit or force-quit Surge | Blocked; measure actual latency | Process/extension exit |
| Another VPN active, Surge off | Blocked | Wrong-tunnel rejection |
| Turn Surge Enhanced Mode back on | Fresh networking recovers | Recovery without DNS deadlock |
| Change Wi-Fi / attach Ethernet | Re-evaluate current interfaces | No fixed en0/utun assumption |
| Sleep and wake | Reconcile current state | Stale interface handling |
| Normal guard termination | Block left installed; launchd restarts | Shutdown cleanup |
| Manual `unlock` | Guard stops; its rules clear | Offline recovery |
| Reboot after `unlock` | Installed service re-arms after starting | Temporary unlock semantics |
| `uninstall`, then reboot | Guard does not return | Permanent removal |

## Companion and menu acceptance

For a primary tunnel absent from Setup/SCPreferences, also verify the
[kernel ownership backend](native-tunnel.md) with administrator read-only doctor.
Confirm the signed provider's native PID/birth identity and connected kernel
control socket resolve to the actual primary VIF. An unprivileged descriptor
query may be unavailable and must never borrow a cached success. In an authorized
disposable session, test provider exit, socket closure while the provider remains,
FD/PID reuse, ambiguous providers and primary/Setup changes. Confirm old callbacks
cannot reopen protection and route evidence is invalidated. Socket-close event
latency, the fallback poll and physical packet behavior are separate evidence.
Do not disconnect or kill a production tunnel merely to pass source acceptance.

Use a disposable/saved application session. Validate both light and dark menu
appearance, current reasons, diagnostics, retained-then-follow logs, policy draft
validation/application, normal restart and explicit temporary unlock. There must
be one Surge section, and no green protection label based only on a PID.

Before a system upgrade, confirm the independent recovery menu is installed and
works offline with the currently installed version. Back up files first. Run the
`check-recovery` preflight on the target OS before any service stop. It must use
the system native flock without assuming a `lockf` executable; missing interpreter,
core modules or fixed tools must fail without stopping Guard or replacing menu
files. In temporary fixtures, hold each Swift RuntimeLock and confirm recovery
cannot clear rules; confirm a concurrent Start is rejected by the locked final
service check. No preflight-only pass establishes that live unlock worked.
Test a normal restart: a new PID and fresh PF status must be observed, or a timeout and
reason shown. Do not use repeated `kickstart -k`. Exercise delayed old-process
cleanup and an update failure in a controlled environment; verify automatic
restoration and retain both failure/rollback logs. Confirm separate version and
policy backups, restore commands, legacy capability warnings, and that an old
whole `pf.conf` is never restored. On explicit emergency removal, the previous
PID must be gone before anchor clearing; verify protection-off display and
Start/re-arm. Never silently use emergency removal to pass an upgrade test.

For macOS-update recovery, use a disposable Mac/VM with a saved configuration
and an authorized maintenance window. Test a reset to the recognized Apple
default `pf.conf`, including empty live filters, existing Apple filters, and an
interrupted repair with Guard already attached but its disk block still missing.
Confirm the private pre-repair backup, original comments/Apple configuration,
default scrub attachment, nested Apple/third-party anchors, NAT and PF options
are retained. Verify the actual blocking rule after the filter-only load;
`pfctl` returning zero alone is insufficient. Reject custom disk/live rules,
partial markers, unexpected ownership, and concurrent edits without overwriting
them. Inject a failed load/write and retry; verified protection must not be
reported before enablement, old-state cleanup and a fresh status publication.
Also test `unlock`/disabled-service behavior so recovery cannot silently re-arm
an intentionally stopped job during the same boot. These tests do not establish
behavior in every macOS installer/recovery environment or early-boot coverage.

Enable SwiftBar's Launch at Login or register it in macOS Login Items, then log
in again and confirm the menu, refresh entry and both fresh service states.
Plugin installation alone does not configure or verify SwiftBar login startup.

For the Gate startup-network prerequisite, authorize a reboot/login with delayed
Wi-Fi/DHCP or captive-network evaluation. With Surge absent and Guard blocked,
confirm `waiting_network` while macOS has no primary IPv4 interface, even if an
interface already has a DHCP address. No Surge launch/pending marker should be
submitted during that wait. Confirm the menu/log explains the wait without
claiming an outage or PF permission, and that update pause/resume and ordered
shutdown remain responsive. Once macOS publishes the primary IPv4 network,
Gate should submit a normal launch on its next eligible loop without a fixed
delay or a new 30-second failure cooldown. Application restoration still waits
for fresh verified allowed Guard status. Retain an existing valid Surge, respect
manual Enhanced Mode preferences, and exercise both enhanced and persistent TCP
policies. Do not alter PF or captive-network settings to turn a failed case into
a pass; record any unresolved startup race separately.

For explicit `os-update-begin` / `os-update-end`, use a disposable Mac/VM and
authorize the all-application direct-access interval first. Upgrade Guard/Gate
and install the offline recovery menu. Check that old/stopped Gate, active or
orphaned launches and stale/wrong-nonce status prevent release. Gate must withdraw
queued power requests observed during maintenance and record their declined IDs
before acknowledging; an ongoing power operation still prevents acknowledgement.
Cancel preparation and confirm no old queued power request is replayed, and saved sessions and the original Surge
update pause survive. Enter maintenance and verify the own disk anchor and live
rules are empty, with other anchors/NAT/options retained; check orange status,
fresh process-bound `maintenance`, paused Gate, and no green protection claim.
Restart Guard, Gate and the machine, including multiple reboots: no automatic
re-arm or session loss. Ensure normal Guard mutations are refused. Fault each
phase (checkpoint/disk write, rule clear, startup, PF query, restoration and final
checkpoint removal), retry and verify no false completion. Test missing default
PF attachment recovery on End, and refusal of custom/unsafe layouts. Verify End
clears old states and accepts freshly verified blocked or allowed protection
before Gate resumes. End must preserve an existing Surge `update-pause`.
Run End while the active-maintenance daemon is still running: it must stop that
daemon before acquiring the runtime lock, without an emergency unlock first.
Changed/corrupt/unwritable checkpoint failures must retain the record and error
and attempt blocking under the lock, with no false completion.
Check the independent emergency and fallback-menu paths with a broken renderer;
an emergency rule removal must leave the maintenance checkpoint intact. Confirm
normal menu/Gate operation after End. Real macOS download/install/reboot and
first-login completion are separate live tests; unit tests do not establish them.

Verify the companion waits on recent system `allowed` status before each app
launch. Test bundle IDs, ordering, an absent app, failed launch retry and a changed
excluded-app setting. Confirm no lost pending apps. Verify periodic atomic
session checkpoints and recovery after a user-service restart. An app inventory
failure must retain the previous record rather than overwrite it with empty data.

On a saved/disposable session, test an app refusing normal quit or showing an
unsaved-document prompt. Ordered shutdown must abort without SIGKILL/pkill, keep
Surge until other apps finish, and retain the pre-shutdown session. Only request
OS shutdown after Surge exits and the firewall is verified blocked. Check cancelled
OS shutdown recovery and that snapshots cannot overwrite the retained session.

Test the legacy migration using copied local data, confirm original files remain,
and confirm only one companion LaunchAgent runs. Do not publish the legacy data.

Do not claim that `SIGKILL` of the guard while allowed remains closed: this is a documented limitation. If intentionally testing it, record the open interval and verify launchd recovery. Likewise, boot-time traffic before PF/service activation is not covered by the guarantee.

For early-disconnect acceptance, correlate the native tunnel status with the
`readiness_loss_blocked` event and a physical-interface capture. Test graceful
disconnect and abrupt loss separately; an early graceful callback does not prove
the crash path has no gap. Record actual packet behavior through rule loading
and state cleanup. A successful notification subscription, parser test or new
binary installation is not live no-bypass acceptance.

## Egress observation

For egress logging acceptance, use the read-only `observe-egress --json` command
first. With separately authorized traffic to a controlled endpoint, confirm a
non-Surge interface's byte increments are recorded with process/PID and scope;
normal Surge-owned egress and loopback are excluded. Check system-extension and
LAN/unknown-UDP classifications without treating them as implicitly approved.
Confirm receive-only records are labeled, local endpoints remain visible and
wildcard UDP peers stay unknown even on local port 5353. Neither interface labels
nor counters should be displayed as proof of an actual packet path or bypass.
Confirm repeated connections are deduplicated, a summary appears within five
minutes, and command failure/recovery does not change PF or gate policy. Do not
generate a bypass or bind a physical interface on an unsaved production session
merely to pass this test. Packet captures and process-exit timing acceptance
remain separate from parser/unit tests and a successful background sample.

For the updated logs, check that receive-to-send activity and a PF revision change
are not hidden by dedup. A start/end state match with an intervening revision
change must still be a mixed tracking window. Verify caps and coverage gaps remain
visible; manual samples must not claim continuous firewall-state tracking.

During a separately authorized block scenario, compare `pf_block_traffic` with
read-only `sudo pfctl -a io.github.surge-guard -s labels`. Match the own rule label,
in/out packet and byte totals and block ID. Confirm a final pre-allow read and
subsequent gate transition are distinct. Do not treat a counter as a per-process
packet trace. A missing label, malformed output or decreasing count must produce
an evidence gap/failure, not a zero-hit claim or an allow/block policy change.
Unit fixtures cannot establish live counter accuracy or complete packet coverage.

## Continuous recorder (separate opt-in)

Read [the recorder contract](packet-audit.md). Install it only after the independent
recovery menu is available. Confirm actual PKTAP packets contain expected physical
and VIF interface/direction metadata, known-process traffic and unknown ownership
without silently filtering the unknowns. Check that starting/stopping this job
does not restart the guard or mutate PF. Verify fresh job/PID/boot-bound status
and configured event/preview time zone.

During an authorized controlled Surge restart, preserve packet/request/event
time lines and verify recorder continuity separately from guard block latency.
Do not generate an intentional bypass on an unsaved production session merely
to pass this test. Confirm Surge CLI calls occur as the console user after UID
drop and that absent Surge/session/query errors record gaps rather than stopping
the PF gate or claiming an all-clear.

Exercise capture-buffer loss, child exit/supervisor crash, incomplete statistics,
disk write failure, stop/re-arm, update rollback and ring wrap. A recovered source
must retain earlier gap flags. After crash, launchd must reap the capture child;
the new session records a gap. Compare actual retained packet timestamps with
`audit-coverage`, including truncated/live files and overwritten history. Review
sleep, power loss, early boot and high-rate traffic separately. Offline fixtures
and zero reported drops do not establish full packet coverage or no bypass.

## Persistent TCP mode

Upgrade the guard, fixed launcher and SurgeGate with the old policy first.
Run the installed launcher `--check` as the console user; it must report the
normal UID and dedicated effective GID without opening Surge. Verify recovery
and keep a private copy of the previous policy before enabling `persistent_tcp`.
Existing route restrictions remain required until explicitly changed. For a
transit-only policy, apply `examples/persistent-tcp.json` after the binary upgrade;
this removes route-policy restrictions while retaining enhanced-mode and identity
checks. Unknown identities stay blocked.

With capture active, confirm the ready anchor is nonempty, contains the
dedicated group/VIF permissions and final TCP refusal, and uses interface-bound
states. Verify ordinary IPv4 TCP through the VIF, system-proxy requests, selected
proxy requests and Surge DIRECT. Compare own-label counters and socket group
attribution; group launch success alone is insufficient.

Continuously attempt fresh connections and maintain an established TCP stream
while normally quitting Surge and toggling Enhanced Mode. Correlate physical
packet observations, process metadata and peer responses; a captured outbound
packet without a response can be observed before filtering. Test abrupt loss
separately. During an explicitly authorized guard pause, repeat a normal Surge
quit to establish that blocking does not depend on the daemon reacting. Restore
the same daemon promptly, and verify fresh status and automatic SurgeGate recovery.

Test a manually launched ordinary-group Surge: networking must remain blocked
until Gate completes normal identity correction. Check policy changes, interface
replacement and migration of old states. IPv6 application TCP is default-blocked
in this implementation; do not claim IPv6 VIF functionality or UDP enforcement.
No Tailscale or other VPN exception exists. Update/reboot and early-boot ordering
remain separate acceptance scenarios.

## PF coexistence

Capture root `pfctl -sr`, relevant nested anchors and PF references before installation. Confirm the guard attaches first, normal updates change only its anchor, and unlock releases only its own reference. Verify Internet Sharing, VM networking and other PF users if they are part of your setup. The initial main-ruleset reload deserves separate review.

## Releasing results

Publish only sanitized results: OS/Surge versions, scenario pass/fail/inconclusive, measured latency range and remaining limitations. Exclude node IPs, profiles, usernames, device IDs, service UUIDs, logs and raw captures. A release should remain experimental until these tests have been completed.

## Ordinary-group startup and recovery

Keep the dedicated PF group fixed. With the native application bundle unchanged,
normally quit Surge and start it via LaunchServices as the console user. Hold
Gate recovery briefly to inspect the ordinary effective group. It must never
cause a PF exception for that group. Capture bounded public TCP probes and peer
responses while the wrong instance exists, then resume Gate and verify normal
termination, dedicated startup and fresh allowed status. A bounded guard pause
with an independent timed resume can isolate already-loaded PF enforcement from
a daemon-triggered full block. Record that interval separately; do not equate
post-resume full blocking with proof of the pre-resume interval. Real application
updates, power loss and early boot require separate tests.

## Update pause and recording lifecycle

With both services fresh, request `surge-gate update-pause` and require its
matching acknowledgement before starting the official updater. Restart only
SurgeGate and verify the same persisted pause is acknowledged by the new process,
with no automatic application launch or identity correction. Guard and its PF
rules must remain active. The menu must display pause duration, reason, current
Surge identity and the separate Guard state. Finish or cancel the official
updater before `update-resume`; verify fresh Gate status and the fixed group
before interpreting recovery as successful. A command timeout is not permission
to start updating. Malformed pause records must stop automatic recovery.

Separately test a normal Surge quit while paused: verify process absence, fresh
blocking, no automatic relaunch, and bounded TCP probes with physical packet
evidence. After resume, verify the dedicated identity and working positive
controls. Do not equate this simulation with an actual Sparkle upgrade, a hung
installer, a forced crash or a physical reboot.

Use full packet recording only for an authorized bounded investigation. Finish
offline review or preserve the relevant closed ring files before restarting
recording; an overlapping export and recorder restart can lose the test window.
`audit-stop` must remove the job, wait for the capture child to exit, and persist
the disabled launchd flag without changing Guard's PID or PF rules. Retained
files remain available. `audit-start` must explicitly re-enable the job and
produce fresh capture status. Record this intentional gap separately from a
Surge request-history gap. A stopped recorder is not disabled protection, and
neither a clean capture nor PF drop counters prove universal absence of bypass.


## Crash and race follow-up acceptance

Use a separate disposable session for these disruptive scenarios; the source
regressions do not establish their live outcomes.

- Before disruptive Surge tests, run `.build/debug/surge-guard-tests --gate-launchd-check`
  explicitly in a GUI session. This loads only a disposable `/bin/sleep` job;
  verify PPID 1, a separate process group, non-child exit notification and
  automatic job removal. The ordinary check script does not load launchd jobs.
- For a Surge started by the updated Gate, verify the GUI one-shot job's actual
  PID/native birth time matches trusted Surge and its dedicated credentials,
  PPID is 1 and the process group is independent of Gate. Compare a normal quit
  and an explicitly authorized signal termination with `surge_job_process_exited`.
  Verify launch ID/PID/native birth time and startup-verification flag; non-child
  records must not invent an exit code, signal or sender. Historical direct-child
  records retain their original exit code/signal distinction. Verify identity repair and ordered power operations
  record their quit request before calling the app, with acceptance separate
  from actual exit. Do not infer the external signal sender or PF state from
  these records. Restarting Gate around an existing Surge without a pending job
  must not claim coverage for that existing process. Verify no job restarts Surge
  while update pause is acknowledged, and no job remains after its process exits.
  Test Gate restart during submission, a queued job, startup, early launcher
  failure and a 10-second startup timeout: active submissions/jobs must fence
  update pause and ordered shutdown; query errors remain unknown. Perform any
  Wi-Fi/VPN reconnect compatibility replay only with separate authorization.
  Switch persistent TCP to enhanced while its launch is pending: the same
  trusted child must settle under the current policy, while unrelated/reused
  process identities must not. Application restoration still requires verified PF.
- Change the Surge candidate set while Guard is allowed and while already blocked.
  Verify signature and route results are invalidated, including a second candidate
  appearing during signature validation. Reopening requires new route evidence.
- Recover an orphaned Gate launch while a shutdown request is being submitted.
  A changed launch observation must be re-read before consuming the request;
  no stale request may run later, and an active launch still blocks shutdown.
- Crash the audit supervisor after spawning but before publishing the child PID.
  Stop/update must wait for its persisted process group, including a replacement
  supervisor, before replacing files. Also exercise sustained stderr and verify
  statistics arrive before EOF without an unbounded main-queue backlog.
- Interrupt dedicated-group installation before and after directory-service
  creation. Retry must retain the recorded reserved GID and refuse a collision;
  do not assign a new GID merely to bypass a failed prior installation.

## Optional private LAN TCP exception

After upgrading all policy readers, enable `allow_lan_tcp` while retaining the
existing persistent/route policy. Verify fresh `lan_tcp_enabled` and exact local
`lan_tcp_bindings`, and read back the anchor: both directions must constrain the
current private local address, `enN` interface, RFC1918 peer and if-bound state.
Check direct SSH to a controlled LAN device without an HTTP/SOCKS proxy; where
available, check an inbound private connection to a temporary local service too.
Public TCP binding must still fail while a Surge-proxied connection can succeed.

Within an authorized disruptive window, make Surge unready, change physical
network addresses, and disable the LAN option. Verify LAN-only recovery while
unready, withdrawal of old addresses/states, and restored default restrictions
when disabled. Malformed configuration and failed interface inventory must not
retain the exception. Test cold boot and service updates separately: startup and
state cleanup may still interrupt LAN connections. Do not infer these live
results from parser/unit tests. This option neither adds UDP DNS/mDNS recovery
nor proves that a permitted LAN peer cannot proxy onward.

## Apple USB development link

With no Apple USB NCM device attached, confirm `check --json` returns a structured
condition report with empty `usb_tcp_bindings`, rather than an enumeration error.
A successful empty native inventory must not invalidate the policy; genuine
enumeration failures must still revoke the local exceptions and fail closed.

With the existing `allow_lan_tcp` opt-in, attach an unlocked iPhone/iPad with
Developer Mode enabled. Check `check --json` / fresh `status --json` for
`usb_tcp_bindings`, and read back the own PF anchor: each USB rule must be IPv6
TCP only, bind an actual local link-local address and Apple NCM interface, use
`fe80::/10` peers and `keep state (if-bound)`. Compare native interface inventory
with the NCM device from `remotectl dumpstate`. CoreDevice's second-stage tunnel
must also appear, with TCP rules bound to its actual ULA address and ULA /64;
adding that tunnel must not destroy its established USB carrier connection.
Confirm CoreDevice connects and
the existing app installs/launches without turning off Surge Enhanced Mode.
Unplug/reconnect and verify old bindings disappear and any new names/addresses
replace them. Wi-Fi/unrelated-VPN/global IPv6, IPv4 and unrelated USB interfaces must not
receive a USB exception. Disable the local TCP option only in an authorized
window; both local exceptions must be revoked. An injected optional USB-inventory
failure must revoke only USB scope and retain verified LAN scope, and vice versa.
Failed common address/readiness enumeration still blocks. Inspect
`local_tcp_errors`, failure/recovery events and corresponding old-state cleanup;
an optional inventory error alone must not clear public Surge connections.
Record blocked-state, reboot and packet-level tests separately from normal
installation and unit tests. This exception does not exempt iCloud traffic.

## Merged diagnostics and short observation

Install the checked user renderer/menu through `install-user.sh --menu-only`.
Record Guard/Gate/Surge PID and native birth identity before and after; those
services must remain unchanged. Verify both diagnostic actions and the prominent
Surge prepare/finish-update actions appear. Diagnostic authentication may only
read the fixed private event files; user collection/formatting remains unprivileged.

- Run `diagnose --minutes 20 --json` with and without a usable sudo credential.
  Validate one JSON object, retained raw event/process/error fields, explicit
  unavailable sources and observed ranges. Neither truncated messages nor empty
  observations may become a clean-health/no-bypass conclusion.
- Run `diagnose --watch-seconds 5 --json`. Verify automatic completion, start/end
  snapshots, deduplicated bounded DNS/QUIC/socket context and private report
  permissions. Run another observation and interrupt it after a checkpoint;
  the previous session and latest checkpoint must remain readable. Do not claim
  that a retained timestamp range is complete packet coverage.
- Exercise rotated, malformed, undated, oversized, symlink, writable and FIFO
  inputs using isolated fixtures. Verify explicit omissions/gaps and bounded
  memory/output. A non-overlapping Surge memory window is unverified continuity,
  not proof that a particular event was lost.
- In a separately authorized update window, prepare a Surge update, wait for
  exact-request Gate acknowledgement, perform/cancel the official update, and
  finish/resume. A refused or timed-out acknowledgement must not print success.
  Resume acknowledgement alone must not claim networking or PF has recovered;
  fresh status must show the actual result. Keep identity verification and the
  30-second real-failure backoff. Do not quit/update Surge just to test labels.

Short observations do not enable the packet recorder or create any PF/DNS
permission. Packet capture remains an explicit separate audit operation with
the documented bounded ring, payload/privacy and coverage limits.
Use exact 1 MiB, aligned-line, mid-line and split-UTF-8 fixtures to verify tail
boundaries. Repeated identical watch samples must produce one memory-source
summary with an observation count, while actual non-overlapping windows remain
explicit gaps and no no-bypass conclusion is inferred.

## Review-fix fault cases

Run live cases only in an explicitly authorized maintenance window with offline
recovery available. Unit/fake-command cases do not replace these checks.

- Inject an IPv6 dynamic-store error while all other readiness checks pass.
  Verify no allow transition. Distinguish genuine NoKey from a read failure,
  wrong type or a present empty dictionary.
- With a safely backed-up installation, combine a corrupt maintenance record
  and a supported missing PF attachment. Startup/End must attempt blocking
  anchor restoration and attachment repair, retain the corrupt record and its
  original error, and never report verified protection after failed cleanup.
  Valid active maintenance must retain its empty anchor across restart.
- In isolated network/state fixtures, replace the daemon while an old local
  address is absent, then restore the address before its previous PF state
  expires. Verify the boot-bound address checkpoint participates in cleanup.
  Record packet evidence separately; a persisted list alone is not a no-bypass pass.
- Exercise DHCPv4 unicast renewal during blocking. Only local-source root-owned
  UDP 68 to server UDP 67 should receive the renewal exception; ordinary-user
  UDP, DNS and public application traffic remain blocked. Do not infer lease
  loss merely from a failed renewal before the broadcast rebind phase.
- Race independent emergency removal against Start. Management/runtime lock
  contention must prevent rule clearing while a daemon holds its runtime lock.
  Query/lock failure must abort, and a successful terminal message describes only
  the verified service/PF observation. The independent path records a system-log
  event and does not create the CLI's unlocked marker.
- Verify loaded-but-stopped Start requests a non-forced kickstart and waits for
  fresh status. Delay several URL queries and deliver a network change while
  they run: queries must remain bounded, preserve URL order and reject results
  from the previous generation. Three-second expiry is never extended.
