# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Entries are derived from Conventional Commits.

## [Unreleased]

### Added

- Add decodeJwt, verifyJwt, inspectJwt, formatInspection and JwtError for local, WebCrypto-only JWT inspection and verification with an explicit algorithm allowlist, key-family binding and a per-check report, plus a CLI runner in src/cli.ts and a threat model in docs/SECURITY.md.
- Initial project structure from the factory utility template.
