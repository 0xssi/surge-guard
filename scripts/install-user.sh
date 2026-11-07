#!/bin/sh
set -eu

if [ "$(id -u)" -eq 0 ]; then
    printf '%s\n' 'Run this script as your normal user, without sudo.' >&2
    exit 1
fi
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
guard_bin=/Library/PrivilegedHelperTools/surge-guard
user_dir="$HOME/Library/Application Support/SurgeGuard"

if [ ! -x "$project_dir/.build/release/surge-guard" ]; then
    printf '%s\n' 'Build the release executables first. See README.' >&2
    exit 1
fi
if [ "$#" -gt 1 ]; then
    printf '%s\n' 'Usage: scripts/install-user.sh [--menu-only | --recovery-only | SWIFTBAR_PLUGIN_DIRECTORY]' >&2
    exit 1
fi
/bin/bash "$project_dir/integrations/swiftbar/surge-guard-action.sh" check-recovery

mkdir -p "$user_dir/bin"
chmod 700 "$user_dir" "$user_dir/bin"
user_backup="$user_dir/backups/user-$(date +%Y%m%d-%H%M%S)-$$"
mkdir -p "$user_backup"
chmod 700 "$user_dir/backups" "$user_backup"
for name in surge-guard-ui surge-guard-action surge-guard-menu surge-gate; do
    if [ -f "$user_dir/bin/$name" ]; then cp -p "$user_dir/bin/$name" "$user_backup/$name"; fi
done
gate_plist="$HOME/Library/LaunchAgents/io.github.surge-guard.gate.plist"
if [ -f "$gate_plist" ]; then cp -p "$gate_plist" "$user_backup/gate.plist"; fi
install -m 700 "$project_dir/.build/release/surge-guard" "$user_dir/bin/surge-guard-ui.new"
mv -f "$user_dir/bin/surge-guard-ui.new" "$user_dir/bin/surge-guard-ui"
install -m 700 "$project_dir/integrations/swiftbar/surge-guard-action.sh" "$user_dir/bin/surge-guard-action"
install -m 700 "$project_dir/integrations/swiftbar/surge-guard.5s.sh" "$user_dir/bin/surge-guard-menu"
printf '%s\n' 'SwiftBar login startup is separate: enable Launch at Login in SwiftBar or add it to macOS Login Items, then verify after logging in again. Installing menu files does not enable it.'
if [ "${1:-}" = --recovery-only ] || [ "${1:-}" = --menu-only ]; then
    printf '%s\n' 'Offline recovery menu installed without changing system/user services. Invoke surge-guard-menu --section in your combined plugin.'
    printf 'Previous user menu files: %s\n' "$user_backup"
    exit 0
fi
case "$("$guard_bin" --help 2>/dev/null || true)" in
    *swiftbar*) ;;
    *) printf '%s\n' 'Recovery menu installed. Upgrade the system guard before installing the user companion.' >&2; exit 1 ;;
esac
"$project_dir/.build/release/surge-gate" install
printf '%s\n' 'Existing system policy, rule draft and persistent update pause are retained. Apply policy changes explicitly with configure.'
plugin_dir=${1:-$(/usr/bin/defaults read com.ameba.SwiftBar PluginDirectory 2>/dev/null || true)}
if [ -z "$plugin_dir" ] || [ ! -d "$plugin_dir" ]; then
    printf '%s\n' 'No SwiftBar plugin directory found. The user service is installed; pass a plugin directory to install the menu.'
    exit 0
fi
plugin="$plugin_dir/surge-guard.5s.sh"
if [ -f "$plugin" ]; then
    mkdir -p "$user_dir/backups"
    cp -p "$plugin" "$user_dir/backups/surge-guard.$(date +%Y%m%d-%H%M%S).sh"
fi
install -m 700 "$project_dir/integrations/swiftbar/surge-guard.5s.sh" "$plugin"
printf 'SwiftBar plugin installed: %s\n' "$plugin"
printf '%s\n' 'Refresh SwiftBar. For one combined menu, use --menu-only instead and follow README.'
