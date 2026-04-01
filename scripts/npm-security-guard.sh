#!/usr/bin/env bash
# npm-supply-chain-guard — blocks known-malicious npm packages
# Runs as both preinstall and postinstall. Both phases run all checks (lock file + node_modules).
#
# Local protection (3 layers):
#   1. Root package.json preinstall+postinstall hooks (fires on every npm install)
#   2. Git pre-commit hook (auto-installed via npm prepare; see scripts/install-git-hooks.sh)
#   3. .npmrc enforces audit=true and audit-level=critical
# CI protection: .github/workflows/npm-security-audit.yml
#
# To add blocked packages: edit scripts/blocklist.conf (single source of truth).

set -euo pipefail

# ============================================================================
# BLOCKLIST — sourced from scripts/blocklist.conf (shared with git-pre-commit-security.sh)
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=blocklist.conf
source "${SCRIPT_DIR}/blocklist.conf"

# ============================================================================
# CHECKS
# ============================================================================

# --- Fully blocked packages ---
for pkg in "${BLOCKED_PACKAGES[@]}"; do
  # Check if blocked package appears in package-lock.json (blocks install; lock file must be fixed manually)
  if [ -f "package-lock.json" ] && grep -q "\"${pkg}\"" package-lock.json 2>/dev/null; then
    echo "SECURITY ALERT: Blocked package '${pkg}' detected in package-lock.json!"
    echo "This package is associated with a known supply chain attack."
    echo "Remove it from your dependencies and regenerate the lock file."
    exit 1
  fi

  # Check if blocked package is in node_modules (catches leftovers from prior installs; auto-removes)
  if [ -d "node_modules/${pkg}" ]; then
    echo "SECURITY ALERT: Blocked package '${pkg}' found in node_modules!"
    echo "This package is associated with a known supply chain attack."
    echo "Removing immediately..."
    rm -rf "node_modules/${pkg}"
    exit 1
  fi
done

# --- Blocked specific versions ---
for entry in "${BLOCKED_VERSIONS[@]}"; do
  pkg="${entry%%:*}"
  ver="${entry##*:}"

  # Check package-lock.json
  # -A3: "version" field appears within 3 lines of key in npm lockfile v2/v3 format.
  if [ -f "package-lock.json" ]; then
    if grep -q "\"node_modules/${pkg}\"" package-lock.json 2>/dev/null; then
      PKG_VERSION=$(grep -A3 "\"node_modules/${pkg}\"" package-lock.json | grep '"version"' | head -1 | sed 's/.*"version": "\(.*\)".*/\1/')
      if [ "$PKG_VERSION" = "$ver" ]; then
        echo "SECURITY ALERT: ${pkg}@${ver} is compromised! Blocking installation."
        echo "Remove or update this dependency to a safe version."
        exit 1
      fi
    fi
  fi

  # Check node_modules (catches pre-existing stale installs, especially on postinstall)
  if [ -f "node_modules/${pkg}/package.json" ]; then
    INSTALLED_VERSION=$(grep '"version"' "node_modules/${pkg}/package.json" 2>/dev/null | head -1 | sed 's/.*"version": "\(.*\)".*/\1/')
    if [ "$INSTALLED_VERSION" = "$ver" ]; then
      echo "SECURITY ALERT: ${pkg}@${ver} is compromised!"
      echo "Removing from node_modules..."
      rm -rf "node_modules/${pkg}"
      exit 1
    fi
  fi
done
