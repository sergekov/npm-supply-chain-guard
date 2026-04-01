#!/usr/bin/env bash
# Git pre-commit hook: scan staged package files for blocked npm packages.
# Auto-installed via npm prepare (scripts/install-git-hooks.sh).
# Manual fallback: bash scripts/install-git-hooks.sh
#
# Reads staged content (not working tree) to prevent bypass via unstaged edits.
# To extend: edit scripts/blocklist.conf (single source of truth).

set -euo pipefail

# ============================================================================
# BLOCKLIST — sourced from scripts/blocklist.conf (shared with npm-security-guard.sh)
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=blocklist.conf
source "${SCRIPT_DIR}/blocklist.conf"

# ============================================================================
# SCAN STAGED FILES
# ============================================================================

# Get list of staged files matching package patterns
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '(package\.json|package-lock\.json)$' || true)

if [ -z "$STAGED_FILES" ]; then
  exit 0
fi

while IFS= read -r file; do
  # Read staged content (not working tree) to prevent bypass via unstaged edits
  STAGED_CONTENT=$(git show ":${file}" 2>/dev/null || true)
  if [ -z "$STAGED_CONTENT" ]; then
    continue
  fi

  # Check for fully blocked packages
  for pkg in "${BLOCKED_PACKAGES[@]}"; do
    if echo "$STAGED_CONTENT" | grep -q "\"${pkg}\""; then
      echo "SECURITY ALERT: Blocked package '${pkg}' found in staged file: ${file}"
      echo "This package is associated with a known supply chain attack."
      echo "Commit rejected. Remove the package and try again."
      exit 1
    fi
  done

  # Check for blocked versions
  for entry in "${BLOCKED_VERSIONS[@]}"; do
    pkg="${entry%%:*}"
    ver="${entry##*:}"
    # Check package-lock.json format (node_modules key)
    # -A3: "version" field appears within 3 lines of key in npm lockfile v2/v3 format.
    if echo "$STAGED_CONTENT" | grep -q "\"node_modules/${pkg}\""; then
      if echo "$STAGED_CONTENT" | grep -A3 "\"node_modules/${pkg}\"" | grep -q "\"version\": \"${ver}\""; then
        echo "SECURITY ALERT: Compromised ${pkg}@${ver} found in staged file: ${file}"
        echo "Commit rejected. Use a safe version or remove the dependency."
        exit 1
      fi
    fi
    # Check package.json format — catch any version spec containing the blocked version
    # Covers: exact, =, ^, ~, >=, > prefixes. Does not cover hyphen ranges or compound ranges with spaces.
    if echo "$STAGED_CONTENT" | grep -qE "\"${pkg}\"[[:space:]]*:[[:space:]]*\"[~^>=]*${ver}\""; then
      echo "SECURITY ALERT: Compromised ${pkg}@${ver} referenced in staged file: ${file}"
      echo "Commit rejected. Use a safe version or remove the dependency."
      exit 1
    fi
  done
done <<< "$STAGED_FILES"
