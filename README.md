# Surge Guard

A macOS network gate, application-startup companion and SwiftBar menu for Surge.

- **surge-guard** is a root LaunchDaemon. It blocks ordinary IP networking until
  Surge Enhanced Mode is ready, optionally requiring specific routing decisions.
- **surge-gate** is a normal-user LaunchAgent. It starts Surge, waits for recent
  verified firewall status, restores applications and checkpoints the session.
- **SwiftBar** reads the same status and provides diagnostics and management.

Public code and examples are generic. Domains, groups, proxy names and app lists
belong in each machine's local configuration. No proxy credentials are required.
[简体中文](README.zh-CN.md)

This is an independent, experimental utility. Enhanced Mode captures normal
application traffic through Surge; Surge may then select a proxy or DIRECT.
The default is **reactive readiness gating**. Optional `persistent_tcp` keeps a
TCP egress restriction installed while ready, using a dedicated Surge group.
Neither mode proves complete packet coverage or protection before PF starts.
Read the [limits](#limits) and [acceptance procedure](docs/acceptance.md).

## Agent entry point

Start here when inspecting or deploying on another Mac:

1. Read this file and `AGENTS.md`. Inspect existing services/configuration before
   changing them. Keep local settings, logs and diagnostics out of Git.
2. Run the read-only build and condition checks below. A successful `check` is
   not evidence that the firewall service is installed or protecting the Mac.
3. Choose an explicit policy mode; validate and probe that local configuration.
4. Install the offline recovery menu **before** any privileged changes. Verify
   its entries exist, then update the system component and verify `status`.
   Install the user companion last. Do not run the user installer with sudo.
5. Use `doctor` and retained logs for failures. Record live tests separately from
   syntax/unit checks. Do not silently unlock networking to make a test pass.

### Agent quick reference (architecture, paths & daily operations)

| Component | Binary / Launchd Label | State & Config Files | Emergency / Maintenance Commands |
| --- | --- | --- | --- |
| **surge-guard** (Root PF Daemon) | `/Library/PrivilegedHelperTools/surge-guard`<br>`system/io.github.surge-guard` | Policy: `/Library/Application Support/SurgeGuard/policy.json`<br>Status: `/Library/Application Support/SurgeGuard/status.json`<br>Logs: `/private/var/db/surge-guard/events.log` | **Emergency disable PF block**: `sudo /Library/PrivilegedHelperTools/surge-guard unlock`<br>**Re-enable PF guard**: `sudo /Library/PrivilegedHelperTools/surge-guard start`<br>**Read-only flow & DNS domain check**: `surge-guard observe-egress` |
| **surge-guard-launch** (Dedicated Group Launcher) | `/Library/PrivilegedHelperTools/surge-guard-launch` (`root:_surge_guard`, mode `2755`) | Group record: `/private/var/db/surge-guard/egress-group.json` (`gid` in `60000...60999`) | **Verify UID/GID & Surge signature**: `/Library/PrivilegedHelperTools/surge-guard-launch --check` |
| **surge-gate** (User Companion) | `~/Library/Application Support/SurgeGuard/bin/surge-gate`<br>`gui/$UID/io.github.surge-guard.gate` | Config: `~/Library/Application Support/SurgeGuard/gate.json`<br>Status: `~/Library/Application Support/SurgeGuard/gate-status.json`<br>Update mode: `~/Library/Application Support/SurgeGuard/update-mode.json` | **Pause before manual Surge quit/update**: `surge-gate update-pause`<br>**Resume after Surge update**: `surge-gate update-resume`<br>**Stop/Start companion without touching PF**: `surge-gate stop` / `surge-gate start`<br>**Ordered reboot/shutdown**: `surge-gate shutdown --action restart\|shutdown` |
| **surge-guard-audit** (Optional On-Demand Packet Audit) | `/Library/PrivilegedHelperTools/surge-guard-audit`<br>`system/io.github.surge-guard.audit` (disabled by default) | Dir: `/private/var/db/surge-guard/packet-audit/` | **Start on-demand capture**: `sudo /Library/PrivilegedHelperTools/surge-guard-audit audit-start`<br>**Stop & disable auto-start**: `sudo /Library/PrivilegedHelperTools/surge-guard-audit audit-stop` |

No Trellis setup, Python runtime or package manager is needed. Packet-file reads
use the system libpcap already shipped with macOS.

## Requirements and source map

macOS 13+, Swift 5.9+ / Xcode Command Line Tools, administrator access for PF, and
Surge Mac Network Extension Enhanced Mode. Routing checks require a Surge CLI
supporting `status --raw` and `rule explain` (Surge Mac 6.9+). Gateway VM alone
is not supported. SwiftBar is optional.

| Location | Responsibility |
| --- | --- |
| `Sources/SurgeGuardCore` | Configuration, signature/extension/VIF/route probes, bounded commands, PF, status and logs |
| `Sources/CPcap` | SDK bridge to system libpcap for offline packet timestamp reads |
| `Sources/SurgeGuard` | System daemon, management CLI and menu renderer |
| `Sources/SurgeGate` | Native user-session companion; no Python or app wrapper |
| `Sources/SurgeLaunch` | Fixed set-group launcher for the official Surge application |
| `integrations/swiftbar` | Thin portable plugin |
| `scripts/install-user.sh` | User companion and menu installer |
| `examples` | Generic policy and app configuration |
| `Tests/SurgeGuardTests` | Standalone non-mutating checks |

## Build and inspect — no network changes

```sh
scripts/check.sh
.build/release/surge-guard check --json
.build/release/surge-guard status --json
.build/release/surge-guard rules
```

The validation script builds the executables, runs tests and validates examples.
It never loads PF, quits apps or installs services. The command-line checks are
read-only. `status` can be `unknown` before the new daemon is installed.

## Choose the policy

The default preserves the original readiness-only behavior:

```json
{"version":1,"mode":"enhanced","route_checks":[]}
```

All six checks must pass: official signed Surge process, Surge's primary network
service, connected extension, expected active VIF, IPv4 default route through
that VIF, and no conflicting global IPv6 primary interface. Dynamic interface
numbers are supported. Surge's identity/address are checked, not a VPN name.
Only an explicit missing IPv6 store key means no global IPv6 route. Store errors,
non-dictionary values and a present dictionary without a valid primary interface
fail closed.

For additional routing conditions, copy and edit a local policy:

```sh
cp examples/routes.json policy.local.json
# Replace the example URL and exact group.
.build/release/surge-guard validate policy.local.json
.build/release/surge-guard check --config policy.local.json --json
```

```json
{
  "version": 1,
  "mode": "routes",
  "route_checks": [
    {
      "url": "https://example.com",
      "required_group": "Residential"
    }
  ]
}
```

In `routes` mode, Enhanced Mode must be ready, outbound mode must be `rule`, and
**every** route check must match the exact rule-selected group, resolve that
group and resolve to a proxy. Nested groups are supported. Omitting
`allowed_final_policies` allows proxy changes within that group without editing
this configuration. To additionally restrict final nodes, add, for example,
`"allowed_final_policies": ["Residential A", "Residential B"]` to a route check.
Existing allowlists retain their restrictions; explicit empty/null lists are
rejected. DIRECT/REJECT results, wrong groups, invalid JSON and failed/expired
queries fail closed in both forms. Node changes are logged. No group/node/domain
is hardcoded.

Surge CLI rule evaluation does not make an HTTP request to the target. It checks
the current rule decision, not real egress geography, residential-IP status or
server reachability. Process/URL/protocol-specific rules can affect actual apps;
this version evaluates the configured URL's default request context.
Status and URL queries run concurrently within a bounded three-second helper
budget. Results still expire three seconds after probe dispatch, including query
time. Network events discard in-flight results from the previous generation
while retaining an already completed result only until its original expiry.

The selected group chain must be contiguous, acyclic and end at a recognized
proxy type. Missing selections, unresolved group types and unknown final types
fail closed, including when no final-node allowlist is supplied.

At most eight URL checks are accepted. Unknown config fields, credentialed URLs
and URLs containing raw control characters are rejected. Keep secrets out of URLs, query strings and policy names:
policy/status files are locally readable so the menu can inspect them.

## Optional persistent TCP egress

After upgrading the system guard and user companion, add `"persistent_tcp": true`
to the existing policy and apply it with the installed `configure` command.
Keep existing `mode` and route checks. Omitted/false retains the reactive gate;
null, wrong types and unknown fields are errors. Older binaries reject this field,
so upgrade before applying it.

The ready-state anchor retains TCP rules: allow ordinary IPv4 TCP on the verified
Surge VIF from its expected address; allow TCP sockets with Surge's dedicated
effective group; reject all other non-loopback TCP, including IPv6. Both VIF and
dedicated-group allow rules bind connection state to the interface.
UDP is outside this opt-in's enforcement scope; it is not an all-protocol kill
switch. IPv6 application TCP has no VIF exception; Surge-owned IPv6 egress can
match the group. The local TCP opt-in below also covers Apple USB device links. There are no Tailscale,
other-VPN or ordinary-user identity exceptions. LAN TCP is blocked by default;
the explicit exception below is available. Failed readiness loads blocking rules
and clears this Mac's old states, retaining only configured LAN TCP exceptions.
Policy/interface changes also pass through that blocked transition.

If the requirement is only traversal through Surge, including Surge's own DIRECT
decisions, use `examples/persistent-tcp.json` (`enhanced` plus `persistent_tcp`).
User installation does not change an existing system policy or rule draft.
Apply this policy explicitly after upgrading the system binary. Existing routes
mode remains restrictive until explicitly replaced.

The installer creates an empty `_surge_guard` group using a free ID in
60000–60999 and installs `/Library/PrivilegedHelperTools/surge-guard-launch` as
root:that-group, mode 2755. This is a **set-group, not set-user/root** launcher.
It accepts no application path or arbitrary arguments, verifies the official
Surge signature, requires the console user's UID, supplies a fixed environment
and executes the fixed path `/Applications/Surge.app/Contents/MacOS/Surge`. `--check`
validates the launch prerequisites without starting or quitting an app.
The launcher opens the path components without following symlinks and compares
`fstat`/`lstat`-equivalent inode, ownership, mode, size and timestamps before and
after signature validation. A detected replacement or edit refuses the launch.
`Surge.app` remains owned by the normal user so Sparkle can update it in place;
no ownership or write-permission restriction is added to the app bundle.
These checks narrow the race but do not make signature validation plus pathname
`execve` atomic. The remaining check-to-exec window and a malicious process with
the same user's bundle-write access are outside this launcher's guarantees.

SurgeGate uses this launcher in persistent mode. If Surge has restarted under
the ordinary group, Gate waits for verified blocking, requests a normal quit,
waits for actual exit, and starts the dedicated instance. Refused/timed-out
quits remain errors; there is no forced termination or ordinary-identity
fallback. Manual Enhanced Mode preferences are still respected. Without Gate,
networking remains blocked until the dedicated launcher is used.

Each dedicated launch is a request-specific, one-shot job in the console user's
GUI launchd domain. The fixed launcher and Surge therefore have launchd as their
parent, rather than Gate. This avoids exposing Gate's child relationship to VPN
clients that classify DNS-port conflicts by parent PID; it cannot prevent an
administrator or another privileged program from terminating Surge. The job has
no restart policy and removes itself after exit. Its private staging plist stays
outside `~/Library/LaunchAgents`, so it is not an independent login startup item.
An already-running valid Surge is retained; deploying Gate does not retroactively
change that process's parentage. The new path applies to the next dedicated launch.

The fixed group remains the only Surge TCP egress identity across restarts and
application updates. It is never learned from the current process or widened to
an ordinary group. Surge can use its normal installer/updater; Guard does not
modify its bundle or require App Management permission. If Finder, Dock or an
updater starts Surge under an ordinary group, that instance has no dedicated
egress permission. Gate repairs it through the fixed launcher after verified
blocking. Recovery may briefly interrupt networking; it never grants an
ordinary-group fallback while waiting.

The launcher controls only launches that pass through it. This does not promise
that an independently started first instance already has the dedicated group.
The protection boundary is the persistent PF rules, not the speed of identity
repair. Surge's own executable retains its original ownership and permissions.

Normal operation must report `enforcement: "persistent_tcp_egress"` in fresh
`status --json`; an empty ready-state anchor is incorrect in this mode. PF rules
remain loaded if the guard becomes unresponsive, but status correctly becomes
stale. Read the performed/unperformed live tests in `docs/verification.md`;
syntax checks and group startup alone do not establish packet enforcement.

Update backups include the launcher when installed. Emergency unlock removes
this guard's rules as before. Uninstall removes the launcher but retains the
reserved group and its private installation record to avoid reassigning an
identity that a surviving Surge process or files may still use.

## Optional private LAN TCP access

To allow direct SSH, file sharing and other TCP services on common private LANs,
add `"allow_lan_tcp": true` to the existing policy **after updating both Guard and
Gate, including their running processes, and the menu renderer**. This requires
`persistent_tcp: true`; omitted/false preserves the original restriction. Older
binaries reject the new field. Preserve existing mode and route checks; apply
with the installed `configure` command and verify fresh status afterward.

The exception permits incoming and outgoing **IPv4 TCP only** between this Mac's
current private address on an up `enN` interface (Ethernet/Wi-Fi) and peers in
`10.0.0.0/8`, `172.16.0.0/12` or `192.168.0.0/16`. Rules bind the local address,
interface and connection state. They do not grant VPN/bridge interfaces, general
IPv6, CGNAT or public addresses an exception. Remote private subnets may
be reached through a LAN router; this is not limited to the directly attached
subnet. IP forwarding by this Mac is not authorized by these rules.

The same opt-in also permits **IPv6 link-local TCP on Apple USB NCM interfaces**
for wired iPhone/iPad development. Native IOKit inventory identifies Apple's USB
NCM driver and vendor; only up interfaces with actual `fe80::/10` local addresses
qualify. Rules bind that interface, local address and connection state, and allow
only `fe80::/10` peers. CoreDevice's second-stage `utunN` tunnel also permits TCP
between its actual ULA address and its own ULA /64. The bounded system
`remotectl dumpstate` inventory identifies CoreDevice interfaces; unrelated VPNs
do not qualify. There is no Wi-Fi or public IPv6 exception. Interface
names are discovered dynamically after reconnecting; enumeration failures revoke
the exception. Adding a device tunnel preserves its existing USB carrier states;
removal or other policy changes still block and clear old states. This does not
add a general iCloud or Apple-service bypass.

LAN TCP stays permitted when Surge or a configured route check is unready, so
local administration can recover a blocked machine. Address/interface changes
reload the rules and clear corresponding old local-address/peer states. Optional
USB inventory failure revokes USB exceptions while retaining verified LAN scope;
LAN inventory failure similarly revokes its scope. These warnings appear in
`local_tcp_errors` and the menu without invalidating a valid public-network
policy. Failure of a required readiness/address probe still blocks globally.
Invalid configuration removes both exceptions and fails closed. Startup, updates and state
cleanup can briefly interrupt even LAN connections; this is not an independent
out-of-band recovery path. The exception does not add blocked-state UDP DNS or
mDNS access, so recovery may require a literal IP address.

`status --json` exposes `snapshot.lan_tcp_enabled` and effective
`lan_tcp_bindings` and `usb_tcp_bindings`; the menu shows the same scope. A blocked status now describes
traffic outside the configured exception. A permitted LAN peer could itself
proxy traffic onward; do not treat this option as proof that every connection
or application goes through Surge. Public TCP restrictions and all existing
readiness/route checks remain in force. If Surge captures a LAN destination,
its own policy still decides that connection; adding a Surge DIRECT rule alone
cannot override a Guard block on a directly bound physical socket.

## Install or update the system guard

Do this locally: starting/updating briefly blocks and resets existing connections.
Prepare recovery first, as your normal user:

```sh
scripts/install-user.sh --recovery-only
```

For a combined menu, replace its Surge renderer with the `--section` invocation
below. For a standalone menu, copy `integrations/swiftbar/surge-guard.5s.sh` into
SwiftBar's configured plugin directory. Confirm **Recovery and backups / 恢复与备份**
is visible before continuing. This menu supports the legacy guard, requires no
network access and keeps an independent emergency action when a binary fails.
Keep an offline recovery command as well:

```sh
sudo /Library/PrivilegedHelperTools/surge-guard unlock
```

On a fresh installation, install the fixed helper and launcher first, then apply
the chosen policy **before starting the daemon**. Persistent TCP configuration
needs the installed launcher to prepare its dedicated group. Installation alone
does not start a new daemon; omit `configure` to use the enhanced-only default:

```sh
sudo .build/release/surge-guard install
sudo /Library/PrivilegedHelperTools/surge-guard configure policy.local.json
```

On updates, install the new binary with the existing policy first, verify status,
then apply any policy change using the installed binary. Older guards require
`allowed_final_policies`; giving them group-only JSON before upgrading would
block networking as an invalid configuration.

```sh
sudo .build/release/surge-guard install
/Library/PrivilegedHelperTools/surge-guard status --json
sudo /Library/PrivilegedHelperTools/surge-guard configure policy.local.json
```

On a **fresh install**, load the service:

```sh
sudo /Library/PrivilegedHelperTools/surge-guard start
/Library/PrivilegedHelperTools/surge-guard status --json
sudo /Library/PrivilegedHelperTools/surge-guard doctor
```

Updating a loaded service saves a root-owned backup, stops it normally, waits up
to 20 seconds for its firewall lock to be released, then replaces and restarts
it. `bootout` returning is not evidence that the old process has exited. The new
service must publish fresh verified PF status within 20 seconds; when readiness
passed before the update, it must return to `allowed`. A failure attempts to
restore and restart the previous version. Errors remain errors even if rollback
succeeds. Do not run `unlock` as an update step. If rollback also fails, use the
independent emergency menu action. An installed but unloaded service starts next boot.
For a routes-mode update, the staged new helper first verifies user-session CLI
access before stopping the old daemon. A failed preflight aborts the update;
keep Surge running during that upgrade. This preflight does not change PF.

The PF attachment must be first among filter rules. The installer retains the
original `/private/etc/pf.conf.surge-guard.backup` and refuses edited managed
blocks. Initial attachment may reload the main ruleset; review custom PF users.
Ordinary reconciliation updates only `io.github.surge-guard`.

If a macOS update removes the managed attachment, the installed daemon/start
command can restore it only when the disk file has the recognized Apple default
rule layout and live filter rules are empty or contain only the expected Apple
attachment (plus this guard when retrying an interrupted repair). A trusted
installation, original installation backup and unchanged default blocking anchor
are required. Custom rules, partial markers, conflicting order and unsafe files
are refused; inspect `doctor` and logs before repairing those manually.
The runtime lock serializes recovery. The last pre-repair configuration is saved
privately at `/private/var/db/surge-guard/pf.conf.before-attachment-repair`.
Recovery parses first, reloads only the filter attachments with inline blocking
rules, and then atomically restores the disk attachment after checking for
concurrent changes. It does not reload Apple's nested anchors, NAT or PF options.
No `allowed`/`blocked` status is published until PF enablement, state cleanup and
normal verification complete. If attachment preparation fails, Guard attempts
its normal block operation before reporting the error, including when the old
live anchor still permits traffic. A failed block is explicitly unverified.
A disk attachment diagnostic is not evidence that
live PF is blocking traffic. An unloaded/disabled guard is not restarted by a
separate watcher; outside system-update maintenance, explicit `unlock` retains
its start/next-boot semantics.

This attachment repair restores protection in the installed OS. It is separate
from the explicit system-update maintenance mode below and is not a promise of
compatibility with every installer environment. System updates can need networking
while Guard is running; Gate's `update-pause` alone does not exempt them from PF.
Old non-loopback addresses are retained in the private, boot-bound
`/private/var/db/surge-guard/addresses.json` checkpoint (at most 512 addresses and
64 KiB). A replacement daemon loads it before state cleanup. Failed enumeration
or cleanup retains retry evidence; invalid history prevents verified protection
and still attempts cleanup for currently enumerated addresses.

### macOS system-update maintenance

Upgrade **both Guard and Gate**, and install the independent recovery menu before
using this mode. In SwiftBar choose **准备更新 macOS**, or run:

```sh
sudo /Library/PrivilegedHelperTools/surge-guard os-update-begin
```

This is an explicit administrator-authorized suspension of **all SurgeGuard
network protection for all applications**, including across reboots. Applications
may connect directly to the Internet; this is not an Apple-only exception. It does
not quit Surge or guarantee network availability. Keep unrelated sensitive apps
closed during maintenance. The menu stays orange and shows elapsed time.

Preparation saves a private version/configuration backup, then waits for the
current console user's upgraded Gate to acknowledge the exact request with fresh
boot/process-bound status. Pending launches, unresolved launch recovery, queued
or ongoing power requests, and old/stopped Gate prevent acknowledgement: resolve
them and retry, or cancel using `os-update-end`. Protection is not released before
acknowledgement. Once verified, Gate pauses automatic Surge launches, identity
repairs, application restoration and periodic session checkpoints. Its separate
Surge `update-pause` setting and saved application session are retained.

Only this tool's disk anchor and live rules are cleared. Other PF anchors, NAT,
global PF enablement and policy configuration are retained. The daemon continues
to verify its own rules are empty, including after restart; `status --json`
reports `maintenance`, not `allowed`/`blocked`, and never claims active protection.
Maintenance snapshots use version 2 so old readers show unverified status instead
of falsely reporting blocking; normal protection snapshots remain version 1.
The root-owned `/Library/Application Support/SurgeGuard/system-update.json`
records `preparing`, `active` or `restoring`. A saved request alone does not prove
that PF release or restoration succeeded. Wait for **VERIFIED MAINTENANCE** before
starting the update through macOS's own controls. Do not use Gate's ordered power
actions for the system installer.

Maintenance **does not expire automatically**, regardless of elapsed time, daemon
restarts or reboots. After the OS update completes or is cancelled, choose
**结束维护并恢复保护**, or run:

```sh
sudo /Library/PrivilegedHelperTools/surge-guard os-update-end
/Library/PrivilegedHelperTools/surge-guard status --json
```

Ending also cancels an unfinished preparation. It restores the blocking boot
anchor, repairs a missing supported PF attachment if necessary, clears old states
and waits for fresh verified normal protection before removing the checkpoint
and allowing Gate to resume. `blocked` is a successful protection restoration,
not successful networking; Surge and all original policy checks must still pass.
An original Surge update pause remains paused and requires its own explicit
`update-resume`. Connections may reset while protection is restored.

On error, retain the checkpoint and retry the same command; never delete it to
force a success. During preparation/active maintenance retry `os-update-begin` or
end/cancel; once restoration starts, retry `os-update-end`. Ordinary Guard
start/restart/install/configuration/rollback actions are refused while the
checkpoint exists. Status, logs and the independent emergency rule-removal action
remain available offline. Emergency removal does not clear the maintenance
checkpoint: use `os-update-end` afterward, even after a reboot. A broken menu
renderer retains an End maintenance entry; a broken privileged binary still has
the independent emergency rule-removal path.
If the maintenance checkpoint is corrupt, startup and `os-update-end` attempt
normal boot-anchor restoration, supported attachment repair and blocking before
reporting the original error. The corrupt record is retained for administrator
repair; successful blocking does not mean maintenance ended. Explicit CLI
`unlock` remains available even with a pending or unreadable checkpoint.

After the update, verify fresh Guard/Gate status and SwiftBar login startup. Unit
checks do not prove update installation, firmware/personalization, recovery-OS
compatibility or early-boot coverage; see the authorized live acceptance cases.

The menu provides normal restart with result verification, Start/re-arm, Backup,
Restore previous version/config, Restore previous policy, and Emergency remove
block. Privileged actions open Terminal and explain the impact before requesting
sudo. Emergency recovery waits for the previous PID to exit and clears only this
guard's anchor; it never disables PF globally. It explicitly turns protection off
until Start or next boot outside system-update maintenance; during maintenance,
explicit End is required. A forced `kickstart -k` is not a normal restart path.

Update/manual backups live in `/private/var/db/surge-guard/backups/<id>` with root-only
access. Each `configure` separately saves the prior policy. Backups are retained;
restoration replaces only this tool's binary, LaunchDaemon, anchor file and/or
policy, never an entire old `pf.conf`. `rollback` can restore an older guard with
fewer checks, including a legacy enhanced-only version; review its capabilities.
The first installation has no previous version to restore. The user menu/config
backup is separate from these trusted root backups.

Root never executes the user-owned Surge CLI as root. A root-owned internal
helper enters the console user's bootstrap session, drops UID/GID/groups, then
queries Surge. The daemon keeps processing readiness while these bounded probes
run in the background. A session switch, network change or changed configuration
invalidates prior results. There is no inbound control socket or user-written
file that can command root PF operations.

## Install SurgeGate and SwiftBar

As your **normal user**, after the new system guard is installed:

```sh
scripts/install-user.sh
```

This installs the user binary and LaunchAgent, migrates the old `~/.surge_gate`
configuration if present, and installs a standalone plugin in SwiftBar's configured
plugin directory. Alternatively pass the plugin directory explicitly:

```sh
scripts/install-user.sh "$HOME/Documents/SwiftBar"
```

Installing a plugin does not enable SwiftBar at login. Enable SwiftBar's **Launch
at Login** or add the app to macOS **Login Items**, then verify it after logging
in again. Do not treat an already running menu as a login-startup acceptance.

For an existing combined control-center plugin, update only the independent
menu files (no Gate/Guard query, binary replacement or service restart):

```sh
scripts/install-user.sh --menu-only
```

`--menu-only` and `--recovery-only` both leave the companion untouched. To also
install/update Gate, run `.build/release/surge-gate install` explicitly; that
operation restarts the user service. Replace the combined plugin's old
Surge-specific rendering function with a call to:

```sh
"$HOME/Library/Application Support/SurgeGuard/bin/surge-guard-menu" --section
```

Do not keep both old and new Surge sections. No remote-service credentials or
other private projects are part of this plugin. Normal menu text follows the
system appearance; secondary/error colors have light and dark variants.
A stopped guard does not establish that its old PF rules are gone. Missing, stale
or incomplete recorder status is shown as uncertain, with a stop action when the
service may still be running; the menu does not infer zero memory use.
The companion is green only with fresh running/ready status, no pending apps
and a currently verified allowed network gate. Waiting/stale states are orange;
errors are red. The SwiftBar display names are `surge-guard` and `surge-gate`.

### Updating Surge

Use **Prepare Surge update / 准备升级 Surge（暂停自动恢复，保留 PF 保护）** and wait for acknowledgement before
starting the official updater. Gate then pauses automatic Surge startup, identity
repair and application restoration. It does not quit the current Surge, change
PF, stop Guard or grant the updater networking exceptions. Finish/cancel the
official update before choosing **Finish update and resume / 升级结束并恢复 Surge**.
These actions appear before the power controls. A failed pause/resume never
prints acknowledgement. Resuming automatic operations does not claim that
Enhanced Mode or PF verification has already recovered; inspect the menu status.
Download the complete installer while Surge works if the updater needs networking
after quitting it. A stalled updater is not automatically killed or treated as
finished; logs remain available and the pause has no automatic expiry.

The private `update-mode.json` survives Gate restarts and machine reboots.
Invalid/unreadable update state also suspends automatic actions. A matching
request ID and fresh service status are required for acknowledgement; a timeout
retains the request and reports failure, not permission to start updating.
An operation already in progress must settle before the pause is acknowledged.
A launch timeout does not cancel an NSWorkspace request or a launchd submission.
`pending-launch.json` records the observing Gate instance, the launchctl submission
PID/birth time separately from the actual launcher/Surge PID/birth time, and the
request-specific job identity. A queued job, living submission, living unverified
launcher or callback keeps the pause unacknowledged. After Gate restarts, only the
recorded job process's verified Surge startup settles a dedicated request; a
finished submission alone never does. When the job is absent and the recorded
submission/child is proven gone (including PID reuse), failure recovery waits
30 seconds. Old direct-child launch records remain readable. Do not downgrade
Gate while a launch request is unresolved.

If Gate crashes before recording the child identity, or loses an NSWorkspace
callback, an absent application alone cannot establish cancellation. Gate reports
`launch_recovery_required` with the application and request ID instead of waiting
silently forever. After independently confirming that the old launch finished,
failed or was cancelled, run as the normal user:

```sh
"$HOME/Library/Application Support/SurgeGuard/bin/surge-gate" status --json
"$HOME/Library/Application Support/SurgeGuard/bin/surge-gate" recover-launch REQUEST_UUID --confirm-settled
```

Use the exact `pending_launch.id` from fresh status. Recovery and shutdown
consumption share the request lock; Gate retries a changed launch observation
before consuming a queued request. This explicit attestation
clears only that orphaned request; it does not cancel LaunchServices work or clear
an existing update pause. If completion cannot be established, keep waiting or
reboot to invalidate the previous boot's request. A timeout or manual deletion
is not proof of cancellation. Ordered shutdown rejects unresolved launches with
an explicit error; already queued requests are consumed and declined without
quitting apps, so they cannot unexpectedly execute after later launch recovery.
Ordered shutdown is refused while update pause is active.
If service startup fails before a queued shutdown is consumed, its exact nonce is
withdrawn so it can be retried. A consumed request's outcome must be checked in
status/logs. Gate configuration/session/status reads are bounded, reject symlinks
and special files, and require files owned by the current user without group or
other access (normally mode `0600`).

The user CLI exposes `update-pause` and `update-resume`. Actual recovery failures
retry no earlier than 30 seconds; waiting for verified blocking does not consume
that cooldown. Each repair sends one normal quit request and never force-kills.
`surge-gate COMMAND --help` (or `-h`) only displays help. Unknown, duplicate or
extra options are rejected before management locks or service actions.
The LaunchAgent uses `ProcessType=Interactive`; Foundation's child process group
keeps Surge separate from Gate's group. Reinstall the user service to load the
plist change. A change in Surge candidates invalidates cached signature and routing results,
even while blocked; candidates are rechecked after signature validation. PID
reuse is distinguished by its native start time.

### Application configuration

Edit `~/Library/Application Support/SurgeGuard/gate.json`, using `examples/gate.json`.

| Field | Meaning |
| --- | --- |
| `startup_apps` | Bundle IDs always started after protection is ready |
| `priority_order` | Ordering among startup/restored apps |
| `excluded_apps` | Apps excluded from session recovery and ordered quits |
| `restore_session` | Restore the recorded previous-session apps |
| `delay_between_apps_seconds` | Delay between successful launches, 0–30 |
| `quit_timeout_seconds` | Normal-quit timeout, 5–300; timeout aborts shutdown |

Find an app's Bundle ID in its `Contents/Info.plist`. Display names such as
“Terminal” are not stable across languages. The companion skips Finder and Surge
in ordinary restoration. Failed launches remain pending and retry. Session files
are atomically checkpointed every 30 seconds, including pending apps; hard power
loss can lose changes since the last durable checkpoint. App documents/windows
are left to each app's own recovery mechanism.

Each configured app list allows 256 bundle IDs (at most 255 ASCII characters
each); `gate.json` is bounded to 256 KiB. Session lists allow 1024 IDs each so
startup and saved lists can merge without truncation. Session and Gate status
reads are bounded to 1 MiB. Every checkpoint is validated before replacement;
exceeding a session limit reports an error and retains the previous checkpoint.
Older Gate binaries with smaller limits cannot read these larger checkpoints.

SurgeGate waits for fresh `allowed` daemon status, including recent PF verification.
It never falls back to proxy-port or arbitrary-utun guesses. A normal-user service
cannot stop other login items from starting; the system firewall gate is what
blocks their traffic until conditions pass. SurgeGate starts Surge, but does not
silently change its Enhanced Mode preference or routing choices.

Before a new Surge launch, Gate waits for macOS to publish a primary IPv4 network
with an up, non-loopback IPv4 interface. A DHCP address alone is insufficient:
at login, captive-network evaluation can temporarily withhold the primary
network and cause NetworkExtension startup to fail with `No network available`.
`waiting_network` means startup is deferred; Gate rechecks on its normal loop,
without a fixed delay, an Internet probe or a launch-failure cooldown. Pause and
ordered shutdown remain responsive. A running valid Surge is retained, and Gate
does not force Enhanced Mode on or restart it merely because readiness is blocked.
This startup prerequisite does not authorize PF permission or app restoration;
all existing verified daemon checks still apply.

Legacy original files are retained. The old `com.user.surgegate` login task is
unloaded, and its plist is renamed to `.migrated-backup`. Unknown legacy app names
are logged for manual conversion. Keep the old files until migration is verified.

### Ordered shutdown

Use SwiftBar → **surge-gate** → the power section at the top (blue restart,
red shutdown), or:

```sh
"$HOME/Library/Application Support/SurgeGuard/bin/surge-gate" shutdown --action restart
# Or: --action shutdown
```

The request is published under a command lock before starting an absent service,
so startup cannot restore apps ahead of the queued shutdown. Concurrent requests
cannot overwrite one another. Service-query failures are errors, not absence.
The running user service handles the request independently of the calling terminal.
It saves the session, requests normal application quits, waits, quits Surge last,
verifies the system guard is blocked, then requests macOS shutdown. Apps can show
unsaved-document dialogs; a refusal/timeout aborts. It never sends SIGKILL or
`pkill -f`, and does not change macOS global restore settings. OS Automation
permission may be required for the final system request. This mechanism is not a
hook for every Apple-menu shutdown, power loss or kernel failure.
An accepted Apple event only means the request was submitted: macOS or another
app can still cancel it. Gate retains the saved session and pauses snapshots and
recovery after submission or an aborted quit. Explicitly repeat ordered shutdown
to retry (preserving already-quit apps), or restart Gate to resume recovery.
A request still in the quitting phase cannot be queued again.

## Status, diagnostics and commands

| Command | Privileges / meaning |
| --- | --- |
| `surge-guard check --json` | Normal user; fresh conditions; exit 0 ready, 1 not ready/error |
| `surge-guard status --json` | Normal user; recent daemon/PF snapshot; exit 0 if report produced |
| `surge-guard doctor` | Normal user summary; sudo adds live PF inspection |
| `surge-guard diagnose [--minutes 1...120] [--watch-seconds 1...300] [--json]` | Normal user; default 20-minute merged evidence, optional short DNS/QUIC observation and private report |
| `surge-guard observe-egress [--json]` | Read-only socket/interface activity sample; sudo can improve process visibility |
| `surge-guard validate FILE` | Normal user; syntax/semantic validation only |
| `sudo surge-guard configure FILE` | Validate then atomically install policy; daemon reloads automatically |
| `sudo surge-guard logs [--follow] [--json]` | Last 200 readable events; optional follow or machine JSON Lines |
| `surge-guard format-logs [--json]` | Format stdin without privileges; used by the SwiftBar log bridge |
| `sudo surge-guard restart` | TERM cleanup blocks before launchd restarts the daemon |
| `sudo surge-guard backup` | Save installed binary, service, anchor file and policy |
| `sudo surge-guard rollback` | Restore the last update/manual backup, restart and verify |
| `sudo surge-guard restore-policy` | Restore the policy saved before the last configure |
| `sudo surge-guard unlock` | Remove this gate temporarily; start/reboot re-arms it |
| `sudo /Library/PrivilegedHelperTools/surge-guard os-update-begin` | Suspend all-application protection across reboots after Gate acknowledgement |
| `sudo /Library/PrivilegedHelperTools/surge-guard os-update-end` | Finish/cancel system maintenance; verify normal PF before Gate resumes |
| `surge-gate status [--json]` | Normal user; companion state, pending apps and freshness |
| `surge-gate start` / `stop` / `restart` | Normal user; start, stop (without changing PF) or restart companion |
| `surge-gate update-pause` / `update-resume` | Normal user; pause/resume automatic Surge relaunch during manual quits or updates |
| `surge-gate logs` / `edit-config` | Normal user companion logs and bundle-ID config |

The user menu provides **合并检查最近 20 分钟** and **120 秒 DNS／QUIC 诊断**.
They use the installed user renderer, independently of the guard executable:

```sh
"$HOME/Library/Application Support/SurgeGuard/bin/surge-guard-ui" diagnose
"$HOME/Library/Application Support/SurgeGuard/bin/surge-guard-ui" diagnose --minutes 20 --watch-seconds 120 --json
```

Run these as the normal user. The menu requests sudo authentication only for
fixed private event-file reads; cancellation still produces a partial report.
Direct CLI use never prompts: an existing sudo credential may allow those reads,
otherwise the report records them as unavailable. User-owned collection and
formatting code never runs as root. No PF, DNS, app, service or recorder setting
is changed, and no remote connectivity test is performed.

Reports combine current Guard/Gate/Surge/recorder snapshots, both retained Guard
and Gate event files, and tails of up to four Surge logs. Each input is bounded
to 1 MiB (Surge file tails to 512 KiB). A short observation polls at most 2,000
Surge memory-log lines every two seconds, retaining only DNS/QUIC/socket context.
It stops after the requested monotonic duration, at most 300 seconds. The report
retains at most 1,500 newest entries with a 2 MiB evidence budget and a 6 MiB
serialized limit. Human output shows the last 80 retained entries.
Initial/final status collection takes additional bounded command time. A writer
lock refuses overlapping diagnostic runs before either can replace the report.

The report and one predecessor are private `0600` files at
`~/Library/Application Support/SurgeGuard/diagnostic-report.json` and `.json.1`.
During observation, ten-second checkpoints preserve the previous *session's*
report; interruption may lose the last interval. Reports may contain local
addresses, process paths and domains. Checkpoints have `collection_finished: false`;
normal completion sets it true without claiming complete historical coverage.
Do not publish or commit them. Permissions,
malformed/undated records, input tails, non-overlapping memory windows, observed
time ranges and capacity omissions are explicit. Retained timestamps do not
prove continuous coverage. JSON preserves the original structured event fields.
`root_cause` remains `not_determined` and `no_bypass_verified` remains false;
absent warnings or a successful status read do not establish network health.
For packet evidence, separately opt into the existing recorder described in
[packet-audit.md](docs/packet-audit.md); short diagnostics never enable it.

Only the user menu/renderer need updating for these diagnostic and presentation
changes: `scripts/install-user.sh --menu-only`. This does not replace or restart
Guard, Gate or Surge. Older menu renderers do not provide these commands.

JSON uses snake_case. `check` includes `version`, `ready`, `mode`, `readiness`,
`reasons` and optional `session`. `status` includes `state`, `daemon_running`,
`reason`, optional `snapshot` and optional `system_update`. Inspect `state`, not
the exit code alone. States are `allowed`, `blocked`, `unlocked`, `stopped`,
`unknown` and `maintenance`. Only the last state verifies explicit suspension,
not protection. Ordinary management commands in this table are refused while
system-update maintenance exists; use End or the independent emergency menu.

Snapshots are root-owned, tied to the current boot/PID, and expire after eight
seconds without both status and PF audit freshness. Routing results expire after
three seconds from probe start. These are stale-result cutoffs, not packet-block
latency guarantees. The daemon polls readiness every 0.5s, routing at roughly 1s,
and audits PF every 5s. Scheduling and command operations add latency.
The menu shows the snapshot's local publication time separately from the PF
audit age. A fresh snapshot can be less than a second old; opening the menu
does not turn those recorded ages into a live second-by-second clock.

On disk, events are JSON Lines with time, component, event, level, PID, message
and details. `logs` renders local time, component, severity, state, cause/impact,
recovery and routing decisions. PID/run/event identifiers and raw OS error
dictionaries stay in `--json`, keeping the default output readable.
`--follow` uses the same readable format; `--json` produces machine-readable JSON
Lines, including a JSON wrapper for old plain-text events. For example:

```text
2026-01-01 12:00:00 +00:00  [WARNING] SurgeGuard · BLOCKED / 已阻断
  状态：普通联网已阻断，条件通过后自动恢复
  原因：分流策略与配置不一致 [route_policy_mismatch]: https://example.com
  ✗ https://example.com
    预期分流组：Residential
    实际分流组：Other
    最终策略：Node C
  配置=routes  PF=blocked
```

SurgeGate distinguishes already-running applications from launch requests,
reports the remaining count, and records unavailable/recovered status separately.
A status-file read failure pauses application restoration; it does not by itself
establish an Internet outage. State files receive their final permissions before
atomic publication, preventing a transient private-file permission window.

Gate records `surge_job_submitted`, `surge_job_process_observed` and
`surge_job_process_exited` for one-shot dedicated launch jobs. Records retain the
launch ID, actual process PID/native birth time, startup verification and callback
wall/monotonic time. Gate is no longer the parent: it can observe exit but cannot
obtain that process's exit code, signal or sender. The launchctl submission's
completion is not a Surge exit. Historical `surge_child_started`/`surge_child_exited`
records from direct launches still render their original exit codes/signals.
An early launcher failure is not labeled a verified Surge exit. Gate events also
include a run ID and millisecond timestamps. `surge_quit_requested` records
Gate's identity-repair or ordered shutdown/restart intent before a normal quit;
`surge_quit_result` records request acceptance, not confirmed exit.

These records use the existing private rotating Gate log (`surge-gate logs --json`).
An exit code of zero does not establish a user-requested quit, and a signal does
not identify its sender. Callback time is not the exact exit time or a network
protection measurement. `surge_exit_observation_scope` records the coverage limit:
existing Surge processes without a pending job record, NSWorkspace launches and
exits after Gate stops are not covered by this observer. Updating source/menu
files alone does not change the running service; deploy the Gate binary and
verify the next dedicated startup in a maintenance window.

SwiftBar's recent/follow system-log actions use fixed privileged `tail` reads and
an unprivileged user renderer. This also formats historical logs without running
user-owned formatting code as root. Root log files stay private; the guard's own
`logs --json` remains the full source for agent diagnostics.

Use `gate_changed`, `route_decision_changed`, `rule_probe_failed`, `pf_unverified`,
`configuration_loaded` and `manual_unlock` to follow a decision. Each component
keeps only its current event file and one `.1` predecessor, each capped at 1 MiB
(at most 2 MiB per component). Rotation happens before appending; oversized
records and unsafe files are rejected. Unchanged polls do not produce events.
The companion's launchd stdout/stderr point to `/dev/null`; logging failures go
to the macOS-managed system log. Old `service.log` files are retained without
further writes. App names/URLs/policies are local diagnostic data; do not publish raw logs.
See [troubleshooting](docs/troubleshooting.md).

The updated daemon also samples socket activity for about one second every
30 seconds using the fixed system `nettop` command in a background task. It logs
`egress_path_observed` when socket counters change and the **reported interface**
differs from Surge VIF, excluding the verified Surge process and loopback.
Evidence includes PID/process, reported interface, local/remote endpoints and
**new bytes in the sample**, not lifetime counters. These are socket observations,
not captured packets: the interface field does not establish the actual packet
path or prove bypass. A public application record is flagged for review, not a
confirmed direct connection. Receive-only records are labeled separately from
records with sent bytes. A wildcard UDP peer is unknown, not a public destination.
Local UDP port 5353 suggests mDNS but cannot establish that record's destination
or path. System-extension identity does not approve an independent network.
Classification never changes PF; no product, interface number or user-specific
exception is hardcoded.

The same evidence is deduplicated for five minutes, with at most 20 new evidence
records per sample and a five-minute summary. A receive-to-send change or PF
revision change is recorded again. Public sending candidates take priority over
receive-only/local/unknown records; omitted and deduplicated counts are explicit.
Events include the sample command's wall/monotonic interval and the daemon's
state at both ends of a conservative tracking interval (including task dispatch
and callback time). A PF revision change marks it mixed, even if the
start and end states match. This association does not classify individual bytes
as passed or blocked. Manual/historical samples without this tracking say unknown.

While blocked, the daemon reads only its own PF label counters at most every
five seconds and once when preparing to allow. `pf_block_traffic` records new and
current cumulative matched packets/bytes, separated into inbound and outbound,
with a unique block ID and monotonic counter boundaries. These are rule matches,
not per-process/endpoint packet records. The last read precedes rule clearing;
hits after that read are not included. Reloads and read/parse failures produce
explicit gap/failure events instead of zero counts. Observation failure does not
change firewall decisions. No PF logging flags or packet capture are enabled.
The opening checks are refreshed after the optional counter read.

Existing private 1 MiB rotation
still applies. Missing counters/interfaces and unresolved UDP targets are exposed
as coverage gaps. Command/parsing failures generate an observation-unavailable
event and recovery is recorded; observation failure never changes network policy.
Short-lived connections between samples, packet-level enforcement and complete
historical reconstruction are **not covered**. No events is not proof of no bypass.
Normal-user `observe-egress`, including `--json`, adds structured
`flows[].candidate_domains` (at most five deduplicated names per socket) and
`domain_queries` for DNS and virtual-IP queries. Addresses are canonicalized,
including IPv6 spellings and IPv4-mapped IPv6. Both raw `d`/integer `i` and
exported `domain`/`IP` virtual-IP records are supported. Each query reports `ok`,
`empty`, `failed` with its error, or `unavailable`; background daemon observations
report `not_requested`. Root does not execute the user-owned Surge CLI for these
lookups. These are cache candidates, not verified request domains or packet paths.

SwiftBar provides **查看连接采样（只读）** and the existing log actions show this
evidence. Background logging starts only after the updated system guard is installed;
updating the user renderer alone adds the manual check, not background observation.

System events now retain millisecond wall time and monotonic uptime. A received
Surge process-exit callback adds its time and the subsequent verified-block time
to the blocking event. The elapsed time measures **callback receipt to PF
verification**, not actual process exit to the last escaping packet. The guard
remains resident; event handling, a 0.5-second fallback and bounded system commands
do not promise a fixed tens-of-milliseconds block deadline.

The guard also subscribes directly to the verified Surge service's native tunnel
status. Disconnecting, disconnected, connecting and unknown states cannot open
the gate. When an allowed gate receives a loss/exit event, or observes the
primary service/tunnel is no longer ready, it loads blocking rules and clears old
connection states **before** the remaining readiness/configuration probes and PF
integrity queries. Stale callbacks from a replaced subscription are ignored;
subscription failure fails closed. Reopening still requires all six checks and
fresh configured routing results.

`readiness_loss_blocked` records separate monotonic times for event receipt/loss
observation, rule-load completion and verified block/state-cleanup completion.
Rules alone do not terminate existing PF states, so the final completion matters.
These intervals do not measure actual tunnel failure to event delivery, or prove
zero escaped packets. Default allowed mode still clears this guard's anchor: **faster
notification handling is not a permanent packet-level kill switch**. Strict
no-fallback enforcement requires verified tunnel/system filtering support;
the documented Surge `include-all-networks` profile option is under
[iOS-only parameters](https://manual.nssurge.com/profile/general.html), not a
validated macOS solution. Do not set it on a Mac and claim this requirement passed.

## Optional continuous packet recorder

For short-lived traffic that a periodic socket sample cannot cover, an optional
independent recorder captures all PKTAP interfaces to a bounded private pcap-ng
ring and retains filtered Surge request metadata. It has separate start/stop,
health, history-gap, actual retained-time-range and SwiftBar actions. It does not
restart the guard or change PF. System `libpcap` handles offline timestamp reads.
Raw prefixes can contain payload; the default 256 MB ring overwrites old history.
Missing attribution and capture/request gaps stay unverified, and collector
health is never a no-bypass claim. It is off until explicitly installed.
Read the [packet-audit contract and commands](docs/packet-audit.md) before enabling.

## Managed files and removal

| Path | Owner / purpose |
| --- | --- |
| `/Library/PrivilegedHelperTools/surge-guard` | root / system binary |
| `/Library/PrivilegedHelperTools/surge-guard-launch` | root:dedicated group, 2755 / fixed unprivileged Surge launcher |
| `/Library/LaunchDaemons/io.github.surge-guard.plist` | root / boot service |
| `/Library/Application Support/SurgeGuard/policy.json` | root, 0644 / local policy |
| `/Library/Application Support/SurgeGuard/status.json` | root, 0644 / recent status |
| `/private/var/db/surge-guard/events.log` | root, 0600 / private events |
| `~/Library/Application Support/SurgeGuard/` | user / companion, app settings, session, logs, draft |
| `~/Library/LaunchAgents/io.github.surge-guard.gate.plist` | user / login service |
| SwiftBar plugin directory / `surge-guard.5s.sh` | user / optional menu entry |

```sh
"$HOME/Library/Application Support/SurgeGuard/bin/surge-gate" uninstall
sudo /Library/PrivilegedHelperTools/surge-guard uninstall
```

Remove the installed SwiftBar plugin, or the one invocation in your combined menu.
Configuration, sessions, logs and the original PF backup are retained for recovery.
Gate `stop` and `uninstall` cancel unconsumed ordered shutdown requests so a later
start/reinstall cannot replay them; cancellation failure is reported as an error.
This does not cancel a power request already submitted to macOS.
Only the managed PF block is removed; unrelated PF content is preserved.

If the binary is unavailable, run the independently installed recovery helper
as your normal user in a local Terminal:

```sh
"$HOME/Library/Application Support/SurgeGuard/bin/surge-guard-action" unlock
# If the installed helper is missing, use the reviewed repository copy:
# /bin/bash integrations/swiftbar/surge-guard-action.sh unlock
```

It authenticates only fixed system commands, validates the service state/PID,
waits for the old process to exit, confirms the job is absent, then clears only
this anchor under the management/runtime locks and verifies it is empty. It
records the result in the macOS system log without invoking the Guard executable.
Its independent path does not publish the CLI's unlocked marker; stopped/unknown
cached menu state is not live PF verification. `bootout` returning alone does not establish
process exit. Query failures abort recovery. Never globally disable PF or flush
another service's rules to recover this utility.

## Limits

- Blocked mode permits loopback and narrow DHCP/IPv6 link configuration; normal
  Internet/LAN traffic and DNS are blocked, except the explicit private LAN TCP
  option above. This is not zero packets on the link.
  DHCPv4 unicast renewal is limited to root-owned UDP sockets from a local
  address/port 68 to server port 67; it does not permit ordinary DNS or UDP.
- Default allowed mode clears this guard's anchor and preserves Surge policies, including
  DIRECT. It does not independently exclude physical-interface binding, alternate
  VPNs or Surge exclusions. Default-route readiness is not an unbypassable tunnel.
- RunAtLoad cannot guarantee PF is enabled before the first boot-time packet.
  In default mode, SIGKILL/hangs while allowed can leave it allowed until recovery.
  Persistent TCP mode retains its existing rules, subject to PF attachment,
  state/interface correctness and third-party/admin modifications.
- A CLI policy name is not proof of residential-IP ownership or reachability.
- macOS/Surge updates, other VPNs, Internet Sharing and custom PF require retesting.
- An administrator/root attacker can alter this guard. It is not malware isolation.

[Verification record](docs/verification.md) distinguishes completed tests from
unperformed live scenarios. MIT license. Not affiliated with Surge.

Primary references: [Enhanced Mode](https://manual.nssurge.com/features/enhanced-mode.html),
[Surge CLI](https://manual.nssurge.com/tools/cli.html),
[NetworkExtension](https://developer.apple.com/documentation/networkextension).
