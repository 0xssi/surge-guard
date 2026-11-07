#!/bin/bash
# This script runs as the user. Only fixed system/installed commands use sudo.
set -euo pipefail
guard_bin=/Library/PrivilegedHelperTools/surge-guard
label=io.github.surge-guard
action=${1:---help}
if [ "$#" -gt 1 ]; then printf '%s\n' 'Expected one action.' >&2; exit 2; fi
case "$action" in
    --help) printf '%s\n' 'Actions: restart, start, unlock, backup, rollback, restore-policy, os-update-begin, os-update-end, logs, follow-logs, audit-logs, audit-requests, diagnose, diagnose-watch, doctor, open-surge, gate-update-pause, gate-update-resume, gate-start, gate-stop'; exit 0 ;;
    restart|start|unlock|backup|rollback|restore-policy|os-update-begin|os-update-end|logs|follow-logs|audit-logs|audit-requests|diagnose|diagnose-watch|doctor|open-surge|gate-update-pause|gate-update-resume|gate-start|gate-stop) ;;
    *) printf '%s\n' 'Unknown recovery action.' >&2; exit 2 ;;
esac
if [ "$(id -u)" -eq 0 ]; then printf '%s\n' 'Run this menu action as your normal user.' >&2; exit 1; fi
if [ "$action" = open-surge ]; then exec /usr/bin/open -a Surge; fi
case "$action" in
    diagnose|diagnose-watch)
        renderer="$HOME/Library/Application Support/SurgeGuard/bin/surge-guard-ui"
        if [ ! -x "$renderer" ]; then printf '%s\n' 'Reinstall the user menu renderer for diagnostics.' >&2; exit 1; fi
        printf '%s\n' '只读诊断：认证仅用于读取私有系统日志；不修改 PF、DNS 或服务。报告含本机地址和域名，请勿公开。'
        if ! sudo -v; then printf '%s\n' '私有系统日志认证未完成，继续收集可读取的证据并标明缺口。'; fi
        if [ "$action" = diagnose-watch ]; then exec "$renderer" diagnose --watch-seconds 120; fi
        exec "$renderer" diagnose ;;
esac
case "$action" in
    gate-update-pause|gate-update-resume|gate-start|gate-stop)
        gate_bin="$HOME/Library/Application Support/SurgeGuard/bin/surge-gate"
        if [ ! -x "$gate_bin" ]; then printf '%s\n' 'SurgeGate is not installed.' >&2; exit 1; fi
        case "$action" in
            gate-update-pause) printf '%s\n' '准备升级 Surge：等待 Gate 确认暂停自动重开、身份修复与应用恢复。PF 保护继续保留。' ;;
            gate-update-resume) printf '%s\n' '请确认官方升级已完成或取消，再恢复自动操作；此操作不修复或终止更新器。' ;;
        esac
        "$gate_bin" "${action#gate-}"
        case "$action" in
            gate-update-pause) printf '%s\n' 'Gate 已确认暂停。现在可通过 Surge 官方入口升级；完成或取消后点击「升级结束并恢复 Surge」。' ;;
            gate-update-resume) printf '%s\n' 'Gate 已确认恢复自动操作。请查看菜单中的身份、增强模式及 PF 验证结果；确认恢复不等于已恢复联网。' ;;
        esac
        exit 0 ;;
esac

service_snapshot() {
    local service_text query_status pid service_state
    if service_text=$(sudo -n /bin/launchctl print "system/$label" 2>&1); then
        service_state=$(printf '%s\n' "$service_text" | /usr/bin/awk '/^[[:space:]]*state =/ {count++; sub(/^[[:space:]]*state = ?/, ""); state=$0} END {if (count != 1 || state == "") exit 1; print state}') || {
            printf '%s\n' 'Cannot confirm the guard service state; refusing recovery.' >&2
            return 1
        }
        pid=$(printf '%s\n' "$service_text" | /usr/bin/awk '/^[[:space:]]*pid =/ {print $3}')
        case "$pid" in
            '')
                if [ "$service_state" = running ]; then
                    printf '%s\n' 'Cannot confirm the running guard PID; refusing recovery.' >&2
                    return 1
                fi ;;
            *[!0-9]*|0|1) printf '%s\n' 'Invalid guard PID; refusing recovery.' >&2; return 1 ;;
        esac
        if [ -n "$pid" ] && ! /usr/bin/awk -v pid="$pid" 'BEGIN {exit !(pid > 1 && pid <= 2147483647)}'; then
            printf '%s\n' 'Guard PID is outside the native range; refusing recovery.' >&2
            return 1
        fi
        printf 'loaded %s\n' "$pid"
    else
        query_status=$?
        if [ "$query_status" -eq 113 ] && [[ "$service_text" = *'Could not find service'* ]]; then printf 'absent \n'; return 0; fi
        printf 'Cannot inspect guard service (status %s); refusing recovery: %s\n' "$query_status" "$service_text" >&2
        return 1
    fi
}
service_pid() {
    local snapshot
    snapshot=$(service_snapshot) || return 1
    printf '%s\n' "${snapshot#* }"
}
wait_exit() {
    old_pid=$1
    [ -n "$old_pid" ] || return 0
    attempts=0
    while sudo -n /bin/kill -0 "$old_pid" 2>/dev/null; do
        attempts=$((attempts + 1))
        if [ "$attempts" -ge 20 ]; then
            printf '%s\n' 'Previous guard did not exit within 20s. Refusing to clear rules while it can reapply them.' >&2
            return 1
        fi
        /bin/sleep 1
    done
}

modern=0
case "$action" in
    unlock|logs|follow-logs|audit-logs|audit-requests) ;; # Independent actions must never invoke a broken/hung guard binary.
    *)
        help_text=$("$guard_bin" --help 2>/dev/null || true)
        case "$help_text" in *restore-policy*) modern=1 ;; esac
        case "$action" in
            os-update-begin|os-update-end)
                case "$help_text" in *os-update-begin*) ;; *)
                    printf '%s\n' 'Upgrade Guard and Gate before using system update maintenance.' >&2; exit 1 ;;
                esac ;;
            backup|rollback|restore-policy)
                if [ "$modern" -ne 1 ]; then
                    printf '%s\n' 'The installed legacy guard has no trusted backup/rollback commands. Upgrade only after this recovery menu is present.' >&2
                    exit 1
                fi ;;
        esac ;;
esac
printf 'surge-guard · %s\n' "$action"
case "$action" in
    os-update-begin) printf '%s\n' 'WARNING: this suspends SurgeGuard protection for ALL applications across reboots. Other applications may connect directly. Finish/cancel macOS updating, then explicitly use End maintenance to restore protection.' ;;
    os-update-end) printf '%s\n' 'Use after macOS updating has completed or been cancelled. Restores the original protection; networking may block until Surge and policy checks pass.' ;;
    restart|start) printf '%s\n' 'Connections may briefly reset. Protection remains armed. Waiting for the actual result; do not click repeatedly.' ;;
    unlock) printf '%s\n' 'WARNING: this explicitly removes surge-guard protection until Start guard or next boot. An existing system-update maintenance request persists across reboot and needs End maintenance. Other PF anchors remain unchanged.' ;;
    rollback) printf '%s\n' 'Restores the previous binary, service and policy. An older version may have fewer protection checks. Connections may reset.' ;;
    restore-policy) printf '%s\n' 'Restores the policy saved before the last change. Its allowed routes may differ.' ;;
esac
sudo -v
if [ "$action" = logs ] || [ "$action" = follow-logs ] || [ "$action" = audit-logs ] || [ "$action" = audit-requests ]; then
    renderer="$HOME/Library/Application Support/SurgeGuard/bin/surge-guard-ui"
    if [ ! -x "$renderer" ]; then printf '%s\n' 'Reinstall the user menu renderer to format logs.' >&2; exit 1; fi
    tail_args=(-n 200)
    if [ "$action" = follow-logs ]; then tail_args+=(-F); fi
    log_path=/private/var/db/surge-guard/events.log
    if [ "$action" = audit-logs ]; then log_path=/private/var/db/surge-guard/packet-audit/events.log; fi
    if [ "$action" = audit-requests ]; then log_path=/private/var/db/surge-guard/packet-audit/requests.log; fi
    # Only the fixed tail command is privileged; the formatter stays unprivileged.
    sudo /usr/bin/tail "${tail_args[@]}" "$log_path" | "$renderer" format-logs
    exit 0
fi
if [ "$action" = unlock ]; then
    # Independent of the guard executable, policy, renderer and network.
    snapshot=$(service_snapshot)
    old_pid=${snapshot#* }
    if [[ "$snapshot" = 'loaded '* ]]; then
        sudo -n /bin/launchctl bootout "system/$label"
    fi
    wait_exit "$old_pid"
    snapshot=$(service_snapshot)
    if [[ "$snapshot" != 'absent ' ]]; then
        printf '%s\n' 'Guard service is still loaded; refusing to clear rules.' >&2
        exit 1
    fi
    # Serialize the mutation with CLI management and the daemon's final block, including a concurrent Start.
    sudo -n /usr/bin/lockf -k -t 20 /private/var/db/surge-guard/management.lock \
        /usr/bin/lockf -k -t 20 /private/var/db/surge-guard/lock \
        /sbin/pfctl -a "$label" -F rules
    rules=$(sudo -n /sbin/pfctl -a "$label" -sr)
    [ -z "$rules" ] || { printf '%s\n' 'ERROR: guard rules are still present.' >&2; exit 1; }
    /usr/bin/logger -t surge-guard 'SurgeGuard manual_unlock: independent recovery verified the service absent and own anchor empty; protection off at verification; Start/End maintenance restores protection. Cached status is not live PF verification.'
    printf '%s\n' 'Verified: guard service stopped and its anchor empty. Protection is OFF. Use End maintenance if a system-update request exists; otherwise use Start guard to re-arm.'
    exit 0
fi
if [ "$modern" -eq 1 ]; then exec sudo "$guard_bin" "$action"; fi

# Legacy support lets recovery be installed BEFORE upgrading the root daemon.
case "$action" in
    doctor) exec sudo "$guard_bin" status ;;
    start) sudo "$guard_bin" start ;;
    restart)
        old_pid=$(service_pid)
        if [ -n "$old_pid" ]; then
            sudo -n /bin/launchctl kill SIGTERM "system/$label"
        else
            sudo "$guard_bin" start
        fi ;;
esac
attempts=0
while [ "$attempts" -lt 20 ]; do
    new_pid=$(service_pid)
    if [ -n "$new_pid" ] && [ "$new_pid" != "${old_pid:-}" ]; then
        rules=$(sudo -n /sbin/pfctl -a "$label" -sr)
        if "$guard_bin" check >/dev/null 2>&1 && [ -z "$rules" ]; then
            printf 'Legacy service recovered: pid=%s, readiness passed, guard anchor empty. Routing checks are not supported by this version.\n' "$new_pid"
            sudo "$guard_bin" status
            exit 0
        fi
    fi
    attempts=$((attempts + 1))
    /bin/sleep 1
done
printf '%s\n' 'Recovery did not reach ALLOWED within 20s. Inspect logs/diagnostics; use Emergency remove block if connectivity is urgently needed.' >&2
exit 1
