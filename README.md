# npm-supply-chain-guard

Prevention-first protection against npm supply chain attacks. Uses **pnpm deny-by-default scripts**, **package age gating**, **exotic dependency blocking**, and an extensible reactive blocklist. Pre-configured for the **axios@1.14.1 compromise** (2026-03-30) and extensible for future threats.

## What Happened

On March 30, 2026, the axios npm maintainer's account was compromised. A malicious version `axios@1.14.1` was published containing a fake dependency `plain-crypto-js@4.2.1` that delivers a multi-platform **Remote Access Trojan (RAT)** targeting:

- `.ssh` directories (SSH keys)
- `.aws` directories (AWS credentials)
- Process monitoring and credential harvesting

**C2 Server:** `sfrclak.com` (142.11.206.73)

**Known safe versions:** `axios@1.14.0`, `axios@0.30.3`

**Recommended:** Use native `fetch()` instead of axios (available since Node.js 18)

## Why Prevention Matters

A reactive blocklist only catches **known** threats. By the time you add a package to the blocklist, every developer who ran `npm install` has already executed the malicious code on their machine. Their SSH keys, AWS credentials, and session tokens are already exfiltrated.

The axios@1.14.1 attack had an **18-hour window** between publication and detection. During that window, blocklists were useless.

Prevention-first means your machine is protected **before** the threat is identified:

- **Deny-by-default scripts** — malicious postinstall scripts never execute
- **Package age gating** — newly published packages (< 7 days) are rejected automatically
- **Exotic dependency blocking** — git repos and tarball URLs in transitive deps are blocked

The reactive blocklist remains as a secondary layer for known threats.

## Protection Layers

| # | Layer | Mechanism | Protects Machine? | Type |
|---|-------|-----------|-------------------|------|
| 1 | Script execution | pnpm deny-by-default + `onlyBuiltDependenciesFile` | **Yes** | Prevention |
| 2 | Package age gate | pnpm `minimumReleaseAge` (7 days) | **Yes** | Prevention |
| 3 | Exotic dep blocking | pnpm `blockExoticSubdeps: true` | **Yes** | Prevention |
| 4 | Dynamic analysis | Socket CLI (advisory in CI; preventive via `socket pnpm install` locally) | Optional | Advisory / Prevention |
| 5 | Network firewall | Little Snitch / LuLu (recommended, not bundled) | **Yes** | Exfiltration defense |
| 6 | C2 domain block | `/etc/hosts` (documented below) | **Yes** | Exfiltration defense |
| 7 | Reactive blocklist | `scripts/blocklist.conf` + guard + pre-commit + CI | Partially | Reactive |
| 8 | Audit | `pnpm audit --audit-level=critical` | Partially | Reactive |

## Quick Start

### Option A: Copy into your project (pnpm — recommended)

```bash
# Clone this repo
git clone https://github.com/sergekov/npm-supply-chain-guard.git

# Copy the guard files into your project
cp npm-supply-chain-guard/pnpm-workspace.yaml your-project/
cp npm-supply-chain-guard/.onlyBuiltDependencies.json your-project/
cp npm-supply-chain-guard/.npmrc your-project/
cp -r npm-supply-chain-guard/scripts/ your-project/scripts/
cp -r npm-supply-chain-guard/.github/ your-project/.github/

# Make scripts executable
chmod +x your-project/scripts/*.sh

# Merge the package.json scripts into your existing package.json:
#   "preinstall": "bash scripts/npm-security-guard.sh",
#   "postinstall": "bash scripts/npm-security-guard.sh",
#   "prepare": "bash scripts/install-git-hooks.sh",
#   "security:check": "bash scripts/npm-security-guard.sh",
#   "security:audit": "pnpm audit --audit-level=critical"

# Install with pnpm (deny-by-default is active immediately)
cd your-project && pnpm install
```

**Important:** `.onlyBuiltDependencies.json` ships with common examples (`esbuild`, `sharp`). Replace these with packages your project actually uses that need postinstall scripts (native addons, etc.). Only listed packages are allowed to run lifecycle scripts.

### Option B: Copy into your project (npm fallback)

If you cannot migrate to pnpm, the reactive blocklist and CI workflow still work with npm:

```bash
cp npm-supply-chain-guard/.npmrc your-project/
cp -r npm-supply-chain-guard/scripts/ your-project/scripts/
cp -r npm-supply-chain-guard/.github/ your-project/.github/
chmod +x your-project/scripts/*.sh

# Add lifecycle hooks to your package.json:
#   "preinstall": "bash scripts/npm-security-guard.sh",
#   "postinstall": "bash scripts/npm-security-guard.sh",
#   "prepare": "bash scripts/install-git-hooks.sh"
```

Note: With npm, you lose layers 1-3 (deny-by-default scripts, age gating, exotic dep blocking). The guard script and CI workflow still provide reactive protection.

### Option C: Monorepo setup

For monorepos with multiple package directories, update `pnpm-workspace.yaml`:

```yaml
packages:
  - 'packages/*'
  - 'apps/*'
```

And update the CI workflow matrix in `.github/workflows/supply-chain-security-audit.yml`:

```yaml
strategy:
  matrix:
    directory:
      - packages/frontend
      - packages/backend
      - apps/web
```

## Socket CLI

[Socket](https://socket.dev) provides dynamic analysis of npm packages before installation. It detects:

- Network access in install scripts
- Filesystem access outside `node_modules`
- Obfuscated code and encoded payloads
- Known malware signatures

### Usage

```bash
# Install Socket CLI
npm install -g @socketsecurity/cli

# Scan before installing (replaces pnpm install)
socket pnpm install

# Generate a report
npx @socketsecurity/cli report create --view
```

Socket CLI is included in the CI workflow with `continue-on-error: true` — it runs as an advisory check and does not block the pipeline by default.

## Network Protection

Supply chain attacks need to **exfiltrate** stolen credentials. An outbound firewall on your development machine adds a critical defense layer.

### macOS

- **[Little Snitch](https://www.obdev.at/products/littlesnitch/index.html)** ($49) — enterprise-grade, per-process outbound firewall with connection alerts
- **[LuLu](https://objective-see.org/products/lulu.html)** (free, open source) — lightweight outbound firewall by Objective-See

Both will alert you when `node` or any child process attempts to connect to an unknown domain — exactly what the axios RAT does when exfiltrating credentials to `sfrclak.com`.

### Linux

Use `iptables` or `nftables` rules to restrict outbound connections from Node.js processes to known-good destinations.

## Block the C2 Domain

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

### Adding Blocked Packages

Edit `scripts/blocklist.conf` (single source of truth — shared by the guard script, pre-commit hook, and CI workflow):

```bash
BLOCKED_PACKAGES=(
  "plain-crypto-js"
  "new-malicious-package"    # Description of the threat
)
```

### Adding Blocked Versions

```bash
BLOCKED_VERSIONS=(
  "axios:1.14.1"
  "other-package:2.0.0"      # Description of the compromise
)
```

### Allowing Build Scripts

If a package needs to run postinstall scripts (native addons like `esbuild`, `sharp`, `better-sqlite3`), add it to `.onlyBuiltDependencies.json`:

```json
[
  "esbuild",
  "sharp",
  "better-sqlite3"
]
```

Only packages in this file are allowed to execute lifecycle scripts. Everything else is blocked by pnpm's deny-by-default policy.

### CI Workflow: Adding Package Directories

Update `.github/workflows/supply-chain-security-audit.yml`:

```yaml
strategy:
  matrix:
    directory:
      - .
      - packages/frontend
      - packages/backend
```

## How It Works

### Prevention Layer (pnpm)

`pnpm-workspace.yaml` configures three native security features:

1. **`onlyBuiltDependenciesFile`** — points to `.onlyBuiltDependencies.json`, an allowlist of packages permitted to run lifecycle scripts. All other packages have install/postinstall scripts silently disabled. This is the single most effective defense — the axios RAT's postinstall script would never execute.

2. **`minimumReleaseAge: 10080`** — rejects any package version published less than 7 days ago. The axios@1.14.1 attack had an 18-hour staging window; this policy blocks it outright.

3. **`blockExoticSubdeps: true`** — prevents transitive dependencies from pulling in git repos or tarball URLs, closing a class of dependency confusion attacks.

### Reactive Layer (blocklist)

`scripts/npm-security-guard.sh` scans lock files (`package-lock.json` and `pnpm-lock.yaml`) and `node_modules/` for known-malicious packages. It supports both npm and pnpm lockfile formats. It runs automatically on every `pnpm install` via `preinstall` (lock file scan before packages are written) and `postinstall` (node_modules scan after packages are written) hooks, explicitly via `pnpm run security:check`, and through CI.

### Git Pre-Commit Hook

`scripts/install-git-hooks.sh` runs automatically via the `prepare` lifecycle (after `pnpm install`). It installs a git pre-commit hook that scans **staged content** (not the working tree) of `package.json`, `package-lock.json`, and `pnpm-lock.yaml` files for blocked packages. This prevents committing malicious dependencies even if other guards are bypassed.

### CI/CD Workflow

The GitHub Actions workflow runs on PRs and pushes affecting package files. It:
1. Scans lock files for blocked packages (both pnpm and npm formats)
2. Installs with `pnpm install --frozen-lockfile`
3. Runs the post-install security scan
4. Runs `pnpm audit --audit-level=critical`
5. Runs Socket CLI analysis (advisory)

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

## Why pnpm?

| Capability | npm | pnpm v10+ |
|-----------|-----|-----------|
| Lifecycle scripts | All enabled by default | **All disabled by default** |
| Per-package script allowlist | Not supported (binary on/off) | `onlyBuiltDependenciesFile` / `allowBuilds` |
| Package age gate | `min-release-age` (npm 11+ only) | `minimumReleaseAge` in `pnpm-workspace.yaml` |
| Provenance trust policy | Not supported | `trustPolicy: no-downgrade` |
| Git dependency bypass (PackageGate) | **Unfixed** ("works as expected") | **Patched in pnpm v10** |
| Exotic transitive dep blocking | Not supported | `blockExoticSubdeps: true` |
| Lockfile injection resistance | Requires separate `lockfile-lint` tool | Lockfile format inherently resistant |

For more on npm security risks, see Liran Tal's [npm security best practices](https://github.com/lirantal/npm-security-best-practices).

## References

- [pnpm Supply Chain Security](https://pnpm.io/supply-chain-security)
- [Socket.dev — Introducing Safe npm](https://socket.dev/blog/introducing-safe-npm)
- [Liran Tal — npm Security Best Practices](https://github.com/lirantal/npm-security-best-practices)
- [PackageGate — Zero-days in JS Package Managers](https://www.koi.ai/blog/packagegate-6-zero-days-in-js-package-managers-but-npm-wont-act)
- [CISA Alert — npm Ecosystem Supply Chain Compromise](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)
- [ITNews — Supply Chain Attack Hits axios npm Package](https://www.itnews.com.au/news/supply-chain-attack-hits-300-million-download-axios-npm-package-624699)

## License

Apache License 2.0 — See [LICENSE](LICENSE) file.
