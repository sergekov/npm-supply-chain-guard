#!/usr/bin/env bash
# Automatically installs git hooks after npm install (via "prepare" lifecycle script).
# Appends security guard to existing pre-commit hooks or creates a new one.
# Hook resolves paths at runtime via git rev-parse, so it works across checkouts.

set -euo pipefail

HOOKS_DIR="$(git rev-parse --show-toplevel 2>/dev/null)/.git/hooks" || exit 0

# Skip if not in a git repo (e.g. installed as a dependency)
if [ ! -d "$HOOKS_DIR" ]; then
  exit 0
fi

# Skip if the hook already delegates to our script
if [ -f "$HOOKS_DIR/pre-commit" ] && grep -q "git-pre-commit-security.sh" "$HOOKS_DIR/pre-commit" 2>/dev/null; then
  exit 0
fi

# Single-quoted: $(git rev-parse ...) is evaluated at hook runtime, not install time
GUARD_LINE='bash "$(git rev-parse --show-toplevel)/scripts/git-pre-commit-security.sh"'

# If no pre-commit hook exists, create one
if [ ! -f "$HOOKS_DIR/pre-commit" ]; then
  cat > "$HOOKS_DIR/pre-commit" << 'HOOK'
#!/usr/bin/env bash
# Auto-installed by npm prepare script. See: scripts/install-git-hooks.sh
bash "$(git rev-parse --show-toplevel)/scripts/git-pre-commit-security.sh"
HOOK
  chmod +x "$HOOKS_DIR/pre-commit"
  echo "Installed git pre-commit security hook."
else
  # Append security guard to existing pre-commit hook
  printf '\n# npm security guard (auto-appended by scripts/install-git-hooks.sh)\n%s\n' "$GUARD_LINE" >> "$HOOKS_DIR/pre-commit"
  chmod +x "$HOOKS_DIR/pre-commit"
  echo "Appended security guard to existing .git/hooks/pre-commit."
fi
