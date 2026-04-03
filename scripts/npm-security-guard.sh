#!/usr/bin/env bash
# npm/pnpm supply chain guard — blocks known-malicious packages
# Works with both npm and pnpm lockfile formats.
#
# Protection layers:
#   1. pnpm deny-by-default scripts + onlyBuiltDependenciesFile (pnpm-workspace.yaml)
#   2. pnpm minimumReleaseAge — rejects recently-published packages
#   3. This script — reactive blocklist check (lock files + node_modules)
#   4. Git pre-commit hook (scripts/git-pre-commit-security.sh)
#   5. CI workflow (.github/workflows/supply-chain-security-audit.yml)
#   6. Socket CLI — dynamic dependency analysis
#
# Blocklist defined in scripts/blocklist.conf (single source of truth).

set -euo pipefail

# Source shared blocklist
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=blocklist.conf
source "${SCRIPT_DIR}/blocklist.conf"

# --- Fully blocked packages ---
for pkg in "${BLOCKED_PACKAGES[@]}"; do
  # Check lock files (npm and pnpm formats)
  # JSON lockfile: anchor with double quotes to avoid partial-name false positives
  if [ -f "package-lock.json" ] && grep -Fq "\"${pkg}\"" package-lock.json 2>/dev/null; then
    echo "SECURITY ALERT: Blocked package '${pkg}' detected in package-lock.json!"
    echo "This package is associated with a known supply chain attack."
    echo "Remove it from your dependencies and regenerate the lock file."
    exit 1
  fi
  # YAML lockfile: anchor with whitespace prefix and @/: suffix to avoid partial-name matches
  if [ -f "pnpm-lock.yaml" ] && grep -Eq "(^|[[:space:]])${pkg}[@:]" pnpm-lock.yaml 2>/dev/null; then
    echo "SECURITY ALERT: Blocked package '${pkg}' detected in pnpm-lock.yaml!"
    echo "This package is associated with a known supply chain attack."
    echo "Remove it from your dependencies and regenerate the lock file."
    exit 1
  fi

  # Check node_modules (catches leftovers from prior installs; auto-removes)
  # pnpm uses node_modules/.pnpm/<pkg>@<ver> structure
  PNPM_MATCH=""
  if [ -d "node_modules/.pnpm" ]; then
    PNPM_MATCH=$(find node_modules/.pnpm -maxdepth 1 -name "${pkg}@*" -type d 2>/dev/null | head -1 || true)
  fi
  if [ -d "node_modules/${pkg}" ] || [ -n "$PNPM_MATCH" ]; then
    echo "SECURITY ALERT: Blocked package '${pkg}' found in node_modules!"
    echo "This package is associated with a known supply chain attack."
    echo "Removing immediately..."
    rm -rf "node_modules/${pkg}"
    if [ -d "node_modules/.pnpm" ]; then
      find node_modules/.pnpm -maxdepth 1 -name "${pkg}@*" -type d -exec rm -rf {} + 2>/dev/null || true
    fi
    exit 1
  fi
done

# --- Blocked specific versions ---
for entry in "${BLOCKED_VERSIONS[@]}"; do
  pkg="${entry%%:*}"
  ver="${entry##*:}"

  # Check npm package-lock.json format
  # -A3: "version" field appears within 3 lines of key in npm lockfile v2/v3 format.
  if [ -f "package-lock.json" ]; then
    if grep -Fq "\"node_modules/${pkg}\"" package-lock.json 2>/dev/null; then
      PKG_VERSION=$(grep -FA3 "\"node_modules/${pkg}\"" package-lock.json | grep -F '"version"' | head -1 | sed 's/.*"version": "\(.*\)".*/\1/')
      if [ "$PKG_VERSION" = "$ver" ]; then
        echo "SECURITY ALERT: ${pkg}@${ver} is compromised! Blocking installation."
        echo "Remove or update this dependency to a safe version."
        exit 1
      fi
    fi
  fi

  # Check pnpm-lock.yaml format (pkg@ver: in packages, pkg@ver(peer): in snapshots)
  if [ -f "pnpm-lock.yaml" ]; then
    if grep -Eq "(^|[[:space:]])${pkg}@${ver}[:(]" pnpm-lock.yaml 2>/dev/null; then
      echo "SECURITY ALERT: ${pkg}@${ver} is compromised! Found in pnpm-lock.yaml."
      echo "Remove or update this dependency to a safe version."
      exit 1
    fi
  fi

  # Check node_modules (catches pre-existing stale installs; auto-removes)
  if [ -f "node_modules/${pkg}/package.json" ]; then
    INSTALLED_VERSION=$(grep -F '"version"' "node_modules/${pkg}/package.json" 2>/dev/null | head -1 | sed 's/.*"version": "\(.*\)".*/\1/')
    if [ "$INSTALLED_VERSION" = "$ver" ]; then
      echo "SECURITY ALERT: ${pkg}@${ver} is compromised!"
      echo "Removing from node_modules..."
      rm -rf "node_modules/${pkg}"
      if [ -d "node_modules/.pnpm" ]; then
        find node_modules/.pnpm -maxdepth 1 \( -name "${pkg}@${ver}" -o -name "${pkg}@${ver}(*" \) -type d -exec rm -rf {} + 2>/dev/null || true
      fi
      exit 1
    fi
  fi
done
