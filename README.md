# npm-supply-chain-guard

Drop-in protection against npm supply chain attacks. Pre-configured for the **axios@1.14.1 compromise** (2026-03-30) and extensible for future threats.

## What Happened

On March 30, 2026, the axios npm maintainer's account was compromised. A malicious version `axios@1.14.1` was published containing a fake dependency `plain-crypto-js@4.2.1` that delivers a multi-platform **Remote Access Trojan (RAT)** targeting:

- `.ssh` directories (SSH keys)
- `.aws` directories (AWS credentials)
- Process monitoring and credential harvesting

**C2 Server:** `sfrclak.com` (142.11.206.73)

**Known safe versions:** `axios@1.14.0`, `axios@0.30.3`

**Recommended:** Use native `fetch()` instead of axios (available since Node.js 18)

## Protection Layers

This guard provides **4 layers of defense**:

| Layer | When It Fires | What It Catches |
|-------|---------------|-----------------|
| **npm preinstall** | Before `npm install` writes to disk | Blocked packages in `package-lock.json` |
| **npm postinstall** | After `npm install` completes | Malicious packages in `node_modules/` |
| **Git pre-commit** | Before `git commit` | Blocked packages in staged `package.json` / `package-lock.json` |
| **CI/CD workflow** | On every PR and push | Lock file scan + post-install scan + `npm audit` |

## Quick Start

### Option A: Copy into your project (recommended)

```bash
# Clone this repo
git clone https://github.com/sergekov/npm-supply-chain-guard.git

# Copy the guard files into your project
cp npm-supply-chain-guard/.npmrc your-project/
cp -r npm-supply-chain-guard/scripts/ your-project/scripts/
cp -r npm-supply-chain-guard/.github/ your-project/.github/

# Make scripts executable
chmod +x your-project/scripts/*.sh

# Merge the package.json scripts into your existing package.json
# Add these to your "scripts" section:
#   "preinstall": "bash scripts/npm-security-guard.sh",
#   "postinstall": "bash scripts/npm-security-guard.sh",
#   "prepare": "bash scripts/install-git-hooks.sh"
```

### Option B: Start a new project with protection built in

```bash
git clone https://github.com/sergekov/npm-supply-chain-guard.git my-project
cd my-project
npm install  # triggers preinstall guard + auto-installs git hooks
```

### Option C: Add to a monorepo

For monorepos with multiple package directories, update the CI workflow matrix:

```yaml
strategy:
  matrix:
    directory:
      - frontend
      - backend/node
      - packages/api
```

And wire the guard in each sub-package's `package.json`:

```json
{
  "scripts": {
    "preinstall": "bash ../../scripts/npm-security-guard.sh",
    "postinstall": "bash ../../scripts/npm-security-guard.sh"
  }
}
```

Adjust the relative path (`../` or `../../`) based on directory depth.

## Block the C2 Domain (Recommended)

Add the attacker's command-and-control server to your `/etc/hosts`:

```bash
# macOS / Linux
sudo bash -c 'printf "\n# Block axios supply chain attack C2 domain (2026-03-30)\n127.0.0.1 sfrclak.com\n127.0.0.1 www.sfrclak.com\n" >> /etc/hosts'

# Flush DNS cache (macOS)
sudo dscacheutil -flushcache && sudo killall -HUP mDNSResponder
```

## Check if You're Already Compromised

Run these checks on your machine:

```bash
# Check for RAT artifacts
ls -la /Library/Caches/com.apple.act.mond 2>&1    # macOS
ls -la /tmp/ld.py 2>&1                              # Linux
# Windows: check %PROGRAMDATA%\wt.exe

# Check for the malicious package in your projects
find ~/Projects -path "*/node_modules/plain-crypto-js" -type d 2>/dev/null
find ~/Projects -path "*/node_modules/axios/package.json" -exec grep -l '"version": "1.14.1"' {} \; 2>/dev/null

# Check for C2 connections
# Look for outbound connections to sfrclak.com or 142.11.206.73
```

If any of these return results, your machine may be compromised. Disconnect from the network, rotate all SSH keys and AWS credentials, and investigate further.

## Extending the Guard

All blocked packages are defined in a single file: `scripts/blocklist.conf`. Both the npm guard and the git pre-commit hook source this file — edit once, both are updated.

### Adding a New Blocked Package

Edit `scripts/blocklist.conf`:

```bash
BLOCKED_PACKAGES=(
  "plain-crypto-js"
  "new-malicious-package"    # Description of the threat
)
```

### Adding a New Blocked Version

```bash
BLOCKED_VERSIONS=(
  "axios:1.14.1"
  "other-package:2.0.0"      # Description of the compromise
)
```

### CI Workflow: Adding Package Directories

Update `.github/workflows/npm-security-audit.yml`:

```yaml
strategy:
  matrix:
    directory:
      - .
      - packages/frontend
      - packages/backend
```

## How It Works

### npm Lifecycle Hooks

The root `package.json` registers `preinstall` and `postinstall` scripts that run `scripts/npm-security-guard.sh` on every `npm install`. The preinstall phase catches malicious packages in `package-lock.json` before they're installed. The postinstall phase scans `node_modules/` for anything that slipped through.

### Git Pre-Commit Hook

`scripts/install-git-hooks.sh` runs automatically via the npm `prepare` lifecycle (after `npm install`). It installs a git pre-commit hook that scans **staged content** (not the working tree) of `package.json` and `package-lock.json` files for blocked packages. This prevents committing malicious dependencies even if the npm guard is bypassed.

### CI/CD Workflow

The GitHub Actions workflow runs on PRs and pushes affecting package files. It performs a lock file scan before installation, runs `npm ci`, then does a post-install `node_modules` scan, and finally runs `npm audit --audit-level=critical`.

## IOC Watchlist

Indicators of Compromise for the axios@1.14.1 attack:

| Indicator | Type | Description |
|-----------|------|-------------|
| `sfrclak.com` | C2 Domain | Command and control server |
| `142.11.206.73` | C2 IP | IP address of C2 server |
| `/Library/Caches/com.apple.act.mond` | File (macOS) | RAT persistence artifact |
| `/tmp/ld.py` | File (Linux) | RAT persistence artifact |
| `%PROGRAMDATA%\wt.exe` | File (Windows) | RAT persistence artifact |
| `plain-crypto-js` | npm Package | Malicious dependency containing the RAT |

## References

- [ITNews: Supply chain attack hits 300-million-download axios npm package](https://www.itnews.com.au/news/supply-chain-attack-hits-300-million-download-axios-npm-package-624699)

## License

Apache License 2.0 - See [LICENSE](LICENSE) file.
