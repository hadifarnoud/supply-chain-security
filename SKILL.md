---
name: supply-chain-security
description: Supply-chain and CI/CD security standards — npm/pnpm hygiene, the 14-item attack taxonomy (typosquatting, account takeover, cache poisoning, tag re-pointing, lockfile tampering, wormable malware), GitHub Actions hardening, Docker pinning, IOC quick-scan commands, and the per-project audit findings. Use for any npm/pnpm/lockfile work, any .github/workflows change, Dockerfile or image pinning, MCP/dev-tool config review, or a supply-chain audit.
---

# Supply-Chain Security Standards

Applies to all projects. Rules reviewed 2026-11-11 (post Shai-Hulud / Mini Shai-Hulud worm).

---

## Machine-level defaults (`~/.npmrc`)

```
minimum-release-age=1440        # pnpm only — MINUTES (1440 = 24h)
min-release-age=1               # npm 12+ only — DAYS  (1 = 24h)
```

**The two package managers use different key names AND different units.** Verified
2026-08-21 by reading each tool's source: pnpm computes
`Date.now() - minimumReleaseAge * 60 * 1e3` (minutes); npm's config definition for
`min-release-age` carries `hint: '<days>'`. Both lines are required — one does not
cover the other, and copying `1440` into the npm key would mean 1440 *days* and
block essentially every install.

npm prints `Unknown user config "minimum-release-age"` on install and warns it
will stop working in a future major. That is unavoidable while the key lives in
`~/.npmrc`: pnpm 11 removed global config writing (`pnpm config set --global`
now redirects to a per-project `pnpm-workspace.yaml`), so `~/.npmrc` is the only
place a *global* pnpm gate can live. Accept the warning; do not delete the key.

### Do not rely on these — verified inert

- `block-exotic-subdependencies` — appears in neither npm's nor pnpm's source.
  It has never done anything. Exotic dependencies must be caught by review, not
  by this key.
- `ignore-scripts=true` — this skill previously claimed it was set globally. It
  is **not** set, and `npm config get ignore-scripts` returns `false`, so
  lifecycle scripts **do** run on install.

  **Decided 2026-08-21: leave it off. Do not enable it.** Postinstall is the
  primary npm compromise vector, so this is a known, accepted gap — not an
  oversight to fix. Turning it on globally breaks native builds (esbuild, swc,
  sharp, node-gyp) across every project and the breakage surfaces far from the
  cause. The 24h release-age gate above carries this risk instead. If a specific
  project ever needs script isolation, scope it there — never globally.

Check claims like these against the tool rather than against this file — all
three entries here were wrong when audited.

---

## Supply-chain attack taxonomy (reference before auditing)

### 1. Typosquatting / Dependency Confusion
Package name nearly identical to a popular one, or a public package matching an internal scoped name. 454,648 malicious npm packages published in 2025 alone.
**Detect:** `npm info <pkg> | grep -E 'created|repository'` on unfamiliar packages. Cross-reference against internal registry names.

### 2. Maintainer Account Takeover
Attacker phishes a maintainer, publishes a new version with a post-install payload. Shai-Hulud Sept 2025 hit chalk, debug, ansi-styles (2.6B weekly downloads). Axios (100M+/week) hit March 2026 via DPRK social engineering.
**Detect:** `npm diff <pkg>@<last-known-good> <pkg>@latest -- package.json scripts` — check for new lifecycle scripts added in patch versions.

### 3. Repo Jacking / Namespace Squatting
Attacker registers an abandoned GitHub username or npm namespace, recreates the repo, serves malicious code.
**Detect:** Check `package.json` `repository` field; flag GitHub accounts created after the package's first npm publish date.

### 4. CI/CD Pipeline Injection (pull_request_target / cache poisoning)
Attacker opens a PR against a repo with `pull_request_target` that shares a cache with a privileged publish job. Poison the pnpm store; the next release workflow leaks the npm OIDC token. TanStack vector (Nov 2025, Mini Shai-Hulud May 2026, 300+ packages, 16M weekly downloads).
**Detect:**
```bash
grep -r "pull_request_target" .github/workflows/
grep -r "cache" .github/workflows/ | grep -i "pnpm\|npm\|store"
```
**Hard rule:** Never use `pull_request_target` if the workflow checks out PR code or shares a cache with a privileged job.

### 5. Docker Image Poisoning
Attacker compromises Docker Hub credentials and overwrites existing image tags (including `latest`) with malicious binaries. Trivy `aquasec/trivy` tags `0.69.4–0.69.6` and `latest` poisoned March 2026. KICS April 2026 — five tags overwritten; scans Terraform/K8s configs containing secrets.
**Detect:** `docker inspect <image> --format '{{.Id}}'` vs. a pinned digest in config.
**Hard rule:** Pin all images to `@sha256:` digest. Never use `latest` for security tooling images.

### 6. GitHub Actions Tag Re-pointing
Attacker compromises an action maintainer's token, moves an existing version tag to point to malicious code. tj-actions/changed-files CVE-2025-30066 (March 2025, 23,000+ repos) dumped all CI secrets to logs. May 2026: popular action tags redirected to imposter commits.
**Detect:**
```bash
grep -r "uses:.*@v[0-9]" .github/workflows/   # flags tag-pinned (bad)
grep -r "uses:.*@[a-f0-9]\{40\}" .github/workflows/  # SHA-pinned (correct)
```
**Hard rule:** Pin every third-party action to a full 40-char commit SHA, not a version tag. `actions/*` (first-party) may use major version tags.

### 7. Lockfile Tampering / Integrity Bypass (PackageGate-class)
Attacker modifies the lockfile to substitute a malicious package version or removes integrity hashes so the next install silently fetches a different tarball. Six zero-day lockfile vulnerabilities documented Jan 2026 (Koi Security).
**Detect:**
```bash
grep -E '"resolved".*git\+|tarball' package-lock.json pnpm-lock.yaml
grep -v "integrity" pnpm-lock.yaml | grep "resolved"
```
**Hard rule:** CI must use `pnpm install --frozen-lockfile` or `npm ci` — never bare `npm install`.

### 8. Subdependency Shadowing
Attacker targets a 3+ level deep transitive dependency. `@ctrl/tinycolor` was a Shai-Hulud propagation node.
**Detect:** `npm ls --all 2>/dev/null | grep -E "postinstall|preinstall"`. Use `socket scan` on PRs.

### 9. Social Engineering Maintainer Handoff
Attacker poses as a recruiter or business partner to get npm publish rights. UNC1069 (DPRK) targeted Axios maintainer March 2026, also attempted against Socket CEO, Lodash creator, Fastify lead.
**Detect:** `npm owner ls <pkg>` for critical deps; monitor for new collaborators before a suspicious release.

### 10. Protestware (Intentional Maintainer Sabotage)
Maintainer intentionally injects destructive code. `colors.js` v1.4.44–1.4.2 (Jan 2022, infinite loop), `node-ipc` v10.1.1–10.1.3 (March 2022, deleted files on Russian IPs). Three new malicious `node-ipc` versions May 2026.
**Detect:**
```bash
npm diff <pkg>@<prev> <pkg>@<new> -- lib/
grep -r "networkInterfaces\|geoip\|fs.rmdir\|fs.unlink" node_modules/<pkg>/
```
Pin `node-ipc`, `colors`, `faker` to exact known-good versions.

### 11. Wormable Self-Replicating Malware
Payload steals npm tokens/PATs and autonomously publishes malicious versions of other packages the victim maintains. First observed Shai-Hulud Sept 2025; Mini Shai-Hulud May 2026 (300+ packages, 16M weekly downloads, npm + PyPI simultaneously).
**Detect IOCs:**
```bash
find .github/workflows -name "*.js"            # bundle.js in workflows
grep -ri "shai-hulud" .                        # worm string
find node_modules -name "data.json" -newer package.json  # exfil staging
find node_modules -name "cloud.json"
```

### 12. Dormant / Environment-Conditional Payloads
Payload only activates when `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, or `CI=true` is present — evades sandbox scanners.
**Detect:**
```bash
grep -r "process.env.AWS_SECRET\|process.env.GITHUB_TOKEN\|process.env.NPM_TOKEN" node_modules/
```
Flag any package reading these vars that has no legitimate reason to do so.

### 13. Security Tool as Attack Vector
Attackers specifically target security scanning tools (Trivy, KICS, Semgrep) because they run with elevated access to secrets and infra config in CI. Trivy and KICS were both hit March–April 2026.
**Hard rule:** Pin all security tool Docker images to digest, not tag. Verify digests out-of-band against vendor release notes.

### 14. Non-Registry / CDN Dependencies
Packages resolved from git URLs, GitHub tarballs, or custom CDNs (e.g. `cdn.sheetjs.com`) bypass registry security gates and provenance, and are not covered by the release-age gate either — it only applies to registry versions. Some lack integrity hashes entirely. Nothing blocks these automatically; they have to be caught in review.
**Detect:**
```bash
grep -E '"resolved".*github\.com|cdn\.' package-lock.json pnpm-lock.yaml
grep -E '"version":\s*"(git\+|https?:)' package.json
```

---

## Per-project npm/pnpm hygiene

- Commit lockfiles. CI must use `pnpm install --frozen-lockfile` (or `npm ci`). Never bare `npm install` in CI.
- Pin `packageManager` in `package.json` to lock the pnpm/npm version.
- Pin packages in compromised namespaces to exact versions: `@tanstack/*`, `posthog-node`, `@mistralai/*`, `@langchain/mistralai`, `@ctrl/*`, `ngx-*`, `rxnt-*`, `@zapier/*`, `@postman/*`, `@uipath/*`, `agent-mcp`, `@semgrep/*`, `node-ipc`, `colors`, `faker`.
- No wildcard `"*"` versions in `package.json`.
- No `pkg.pr.new` URLs — these are ephemeral PR preview builds, not immutable artifacts.
- For npm/yarn projects, mirror the same npmrc gates in their local `.npmrc`.
- Prefer pnpm for new projects. Don't migrate working projects just for security.

---

## GitHub Actions hardening

### Hard rules

- **Never** use `pull_request_target` if the workflow checks out PR code, runs install/build/test from PR code, or shares a cache with a privileged workflow.
- `pull_request_target` is only acceptable for reading PR metadata (labels, comments, title) with no checkout.
- Don't share caches between PR-triggered jobs and publish/release jobs.
- **Never** use `curl | bash` or `wget | sh` against a mutable branch (`@main`, `@master`) in CI. Always pin installer scripts to a specific release and verify a checksum.

### `workflow_run` guards

When using `workflow_run` to chain a privileged job after a parent workflow, the `if:` MUST assert all of:

```yaml
if: >
  github.event_name == 'workflow_dispatch' ||
  (github.event.workflow_run.conclusion == 'success' &&
   github.event.workflow_run.head_branch == 'main' &&
   github.event.workflow_run.head_repository.full_name == github.repository &&
   github.event.workflow_run.event == 'push')
```

### Action pinning

- Pin every third-party action to a full 40-char commit SHA, not `@v1`/`@v6`.
- Add a comment with the human-readable tag for auditability: `docker/login-action@65d0a9e  # v3`
- First-party `actions/*` may use major version tags.
- Get current SHAs: `gh api repos/<owner>/<action>/git/ref/tags/<tag>`
- Automate with: `npx pin-github-action .github/workflows/*.yml`
- Minimize `permissions:` per job. Default to `contents: read`. Add `id-token: write` only on the publish step.

### npm publishing workflows

- Require 2FA on the npm account: `npm profile enable-2fa auth-and-writes`.
- Use **trusted publishing** (OIDC) instead of long-lived `NPM_TOKEN` secrets.
- Add `--provenance` (or `provenance: true`) so consumers can verify origin.
- Publish only from a `release.yml` triggered by tag push on `main`. Never from PR-triggered workflows.

---

## Docker / container hygiene

- Pin every `FROM` to a digest: `FROM node:22-slim@sha256:<hash>`
- Never use `latest` or no-tag images in production Dockerfiles or CI.
- Security tooling images (Trivy, KICS, Semgrep, Snyk, Grype, Hadolint) are highest-risk — pin these first.
- Get current digests: `docker buildx imagetools inspect node:22-slim --format '{{json .Manifest.Digest}}'`
- For private registry images: publish with immutable tags + digests.

---

## Developer tools & config files

- Never store API tokens or secrets in plaintext in `~/.cursor/mcp.json`, `~/.claude/settings.json`, or similar config files. Use environment variables or a keychain.
- Pin MCP server packages to exact versions (`mcp-remote@0.1.2`, not `mcp-remote@latest`).
- Check `~/.vscode/tasks.json` and `~/.cursor/` for unexpected auto-run hooks after any supply chain incident.

---

## Detection / monitoring

- Install [zizmor](https://github.com/zizmorcore/zizmor) or `snyk-labs/github-actions-scanner` in CI for any repo with workflows.
- Add socket.dev GitHub App on any repo that publishes packages (any publishable library).
- Subscribe to npm security advisories RSS and PyPI malware feeds.

### IOC quick-scan checklist

```bash
# Shai-Hulud / worm IOCs
grep -ri "shai-hulud" .
find .github/workflows -name "*.js"
find node_modules -name "cloud.json"
# Compromised workflow patterns
grep -r "pull_request_target" .github/workflows/
grep -r "curl.*|.*sh\|wget.*|.*sh\|base64.*eval" .github/workflows/
# Unpinned actions
grep -r "uses:.*@v[0-9]" .github/workflows/
# Lockfile exotic deps
grep -E '"resolved".*git\+|cdn\.' package-lock.json pnpm-lock.yaml
grep -v integrity pnpm-lock.yaml | grep resolved
# Docker
grep -r "FROM.*:latest\|FROM.*[^@]$" Dockerfile* docker-compose*.yml
```

---
