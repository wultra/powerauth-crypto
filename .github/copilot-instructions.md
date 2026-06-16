# Copilot Instructions — powerauth-crypto

This file captures conventions used when working with GitHub Copilot in the `powerauth-crypto`
repository and the broader Wultra PowerAuth ecosystem.

---

## Changelog

`CHANGELOG.md` lives at the **repo root**. Update it as part of every PR — before creating the PR,
not after merge.

### Format

Follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/):

```markdown
# Changelog

## X.Y.Z (TBA)
### Added
- New feature description [(#N)](https://github.com/wultra/powerauth-crypto/issues/N)

### Changed
- Changed behaviour description [(#N)](...)

### Fixed
- Bug fix description [(#N)](...)

## 1.2.3 - 2025-03-01
### Added
- ...
```

**Change type subsections** (use only those that apply):
- `Added` — new features
- `Changed` — changes in existing functionality
- `Deprecated` — soon-to-be removed features
- `Removed` — removed features
- `Fixed` — bug fixes
- `Security` — security vulnerability fixes

**Rules:**
- Always add new entries under `## X.Y.Z (TBA)` (the unreleased section at the top).
- On release, rename `## X.Y.Z (TBA)` to `## x.y.z - YYYY-MM-DD` (ISO 8601 date).
- Each entry: `- <Description starting with verb> [(#N)](https://github.com/wultra/powerauth-crypto/issues/N)` — link to the issue, not the PR.
- Descriptions should be human-readable, not raw commit messages (e.g. "Fixed NPE when application list is empty" not "fix #811: add missing import").
- Skip the Changelog update only for changes with no user-visible impact (e.g. pure CI/tooling changes).
