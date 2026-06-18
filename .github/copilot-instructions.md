# Copilot Instructions — powerauth-crypto

This file captures conventions used when working with GitHub Copilot in the `powerauth-crypto`
repository and the broader Wultra PowerAuth ecosystem.

---

## Changelog

`CHANGELOG.md` lives at the **repo root**. Update it as part of every PR — before creating the PR,
not after merge.

### Format

Follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) **strictly**. The header must
mention both Keep a Changelog and Semantic Versioning, the file must contain a `## [Unreleased]`
section, and all version/section headings must be linkable via reference-style links at the bottom:

```markdown
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- New feature description [(#N)](https://github.com/wultra/powerauth-crypto/issues/N)

### Changed
- Changed behaviour description [(#N)](...)

### Fixed
- Bug fix description [(#N)](...)

## [1.2.3] - 2025-03-01
### Added
- ...

[unreleased]: https://github.com/wultra/powerauth-crypto/compare/1.2.3...HEAD
[1.2.3]: https://github.com/wultra/powerauth-crypto/compare/1.2.2...1.2.3
```

**Change type subsections** (use only those that apply):
- `Added` — new features
- `Changed` — changes in existing functionality
- `Deprecated` — soon-to-be removed features
- `Removed` — removed features
- `Fixed` — bug fixes
- `Security` — security vulnerability fixes

**Rules:**
- Header must mention both [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
- Always add new entries under the `## [Unreleased]` section at the top.
- On release: rename `## [Unreleased]` to `## [x.y.z] - YYYY-MM-DD` (ISO 8601 date), add a fresh empty `## [Unreleased]` section above it, update the `[unreleased]` reference link, and add the new version's compare link.
- Versions and sections must be linkable via reference-style links at the bottom of the file.
- Each entry: `- <Description starting with verb> [(#N)](https://github.com/wultra/powerauth-crypto/issues/N)` — link to the issue, not the PR.
- Descriptions should be human-readable, not raw commit messages (e.g. "Fixed NPE when application list is empty" not "fix #811: add missing import").
- Skip the Changelog update only for changes with no user-visible impact (e.g. pure CI/tooling changes).
