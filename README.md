# supply-chain-security

A Claude Code skill: supply-chain and CI/CD security standards.

Covers npm/pnpm hygiene (release-age gates, lockfiles), a 14-item attack taxonomy with detection commands, GitHub Actions hardening (SHA pinning, `pull_request_target`, `workflow_run` guards), Docker digest pinning, and an IOC quick-scan checklist.

## Install

```bash
npx skills add hadifarnoud/supply-chain-security -g -a claude-code -y
```

Update later with `npx skills update`.

Review the rules before adopting them. They reflect one team's decisions, for example leaving `ignore-scripts` off globally.
