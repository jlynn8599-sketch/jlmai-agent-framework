#!/usr/bin/env bash
# =====================================================================
# JLMAI Vault Lockdown — SAFE version (reviewed)
# Copyright (c) 2026 JLM AI Agent LLC. All rights reserved.
# Author: Jessica Lynn Moss <jlmaiagent@astermail.org>
#
# This is a SAFE replacement for the lockdown script shown in AI chat
# output. The original was never reviewed; this one is built to be
# cautious, reversible, and explicit.
#
# SAFETY RULES BUILT IN:
#  1. Operates ONLY on the vault directory you pass (default below).
#     It refuses any other path. It will never touch / , /etc, /var,
#     your home directory, or anything outside the vault.
#  2. DRY-RUN BY DEFAULT: with no flags it only PRINTS what it would do.
#     Nothing changes until you pass --apply.
#  3. NETWORK EGRESS IS NEVER BLOCKED BY THIS SCRIPT. Blocking all
#     non-loopback egress would cut the machine's internet and can lock
#     you out. That step is deliberately NOT in here. If you ever want
#     egress filtering, that is a separate, reviewed firewall change —
#     not a surprise inside a permissions script.
#  4. REVERSIBLE: --apply saves the current permissions to a backup file
#     first; --restore reapplies them.
#  5. NEVER RUNS ITSELF. You read it, then run it yourself.
#
# Usage:
#   ./jlmai-vault-lockdown-safe.sh                     # dry run (safe)
#   ./jlmai-vault-lockdown-safe.sh --apply             # lock down, with backup
#   ./jlmai-vault-lockdown-safe.sh --restore            # undo using the backup
#   ./jlmai-vault-lockdown-safe.sh --apply /other/vault # a different vault dir
# =====================================================================

set -euo pipefail

VAULT_DIR="${1:-/var/secure/jlmai-vault}"
MODE="dry-run"
if [[ "${2:-}" == "--apply" ]] || [[ "${1:-}" == "--apply" ]]; then MODE="apply"; fi
if [[ "${1:-}" == "--restore" ]] || [[ "${2:-}" == "--restore" ]]; then MODE="restore"; fi
# Allow flag-first or path-first ordering.
if [[ "${1:-}" == "--apply" || "${1:-}" == "--restore" ]]; then VAULT_DIR="${2:-/var/secure/jlmai-vault}"; fi

BACKUP_FILE="${VAULT_DIR}/.permissions-backup-$(date +%Y%m%d-%H%M%S).txt"
# For restore, use the NEWEST backup file in the vault.
latest_backup() { ls -t "${VAULT_DIR}"/.permissions-backup-*.txt 2>/dev/null | head -n 1; }

# --- Guards: never operate outside the intended vault ---
case "$VAULT_DIR" in
  /var/secure/jlmai-vault|/var/secure/jlmai-vault/*) ;;
  *) echo "ERROR: Refusing to operate on '$VAULT_DIR'. This script only touches the jlmai vault."; exit 1 ;;
esac
if [[ ! -d "$VAULT_DIR" ]]; then echo "ERROR: Vault directory '$VAULT_DIR' does not exist. Nothing to do."; exit 1; fi

if [[ "$MODE" == "restore" ]]; then
  BAK="$(latest_backup)"
  if [[ -z "$BAK" ]]; then echo "ERROR: No permissions backup found in '$VAULT_DIR'. Cannot restore."; exit 1; fi
  echo "Restoring permissions from: $BAK"
  while read -r perms path; do
    chmod "$perms" "$path"
    echo "  restored $perms $path"
  done < "$BAK"
  echo "Restore complete."
  exit 0
fi

echo "Vault: $VAULT_DIR"
echo "Mode:  $MODE"
echo ""

if [[ "$MODE" == "dry-run" ]]; then
  echo "DRY RUN — nothing will change. To actually apply, re-run with --apply."
  echo "Would set directories to 0700 and files to 0600 under:"
  echo "  $VAULT_DIR"
  echo ""
  echo "Current state (first 20 entries):"
  find "$VAULT_DIR" -maxdepth 2 -printf "%m %p\n" 2>/dev/null | head -n 20
  echo ""
  echo "Network egress: NOT touched by this script (by design)."
  exit 0
fi

# --- Apply mode ---
echo "Saving current permissions to: $BACKUP_FILE"
find "$VAULT_DIR" -printf "%m %p\n" > "$BACKUP_FILE"
echo "Backup saved. To undo later, run with --restore."
echo ""
echo "Locking down: directories -> 0700, files -> 0600 (vault only)."
find "$VAULT_DIR" -type d -exec chmod 0700 {} +
find "$VAULT_DIR" -type f -not -name ".permissions-backup-*.txt" -exec chmod 0600 {} +
# The backup file itself stays readable only by owner.
chmod 0600 "$BACKUP_FILE"
echo "Done. Network egress was NOT changed."
echo "To undo: ./jlmai-vault-lockdown-safe.sh --restore"
