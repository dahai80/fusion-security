---
doc_id: fusion-security/changelog
product: fusion-security
class: app
entry: guided-ui
doc_type: changelog
title: { zh: "fusion-security 变更日志", en: "fusion-security changelog" }
audience: engineer
status: draft
version: 0.2.0rc14
updated: 2026-11-07
owner: "@dahai"
source_of_truth:
  - CHANGELOG.md
---

# Changelog

All notable changes to fusion-security are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Adopt the fusion docs-system v1.1 contract (app x guided-ui): add `docs/product-page.md`, `docs/get-started.md`, `docs/troubleshooting.md` with 12-key frontmatter, dashboard screenshots under `docs/img/`, `CHANGELOG.md`, hardened `ci/validate_docs.py`, and a docs validation GitHub workflow.

### Changed

- Add docs-contract frontmatter to `README.md`, `README_CN.md`, `AGENTS.md`, `CLAUDE.md`, `DEPRECATED.md`, `docs/api.md`, `docs/benchmark.md`, `docs/security-self-assessment.md`, and the Helm chart README.
- Fix docs redlines: replace non-allowlisted HTML tags (`h1`/`strong`/`em`/`sub`) in README headers with allowlisted equivalents, remove literal example password values, and reword the v0.2.0rc1 feature heading in `README_CN.md`.

## [0.2.0rc14] - 2026-11-03

### Changed

- Frontend: empty-state CTAs guide users to the first business action (#77).

## [0.2.0rc13] - 2026-11-02

### Fixed

- Frontend: dark theme left white canvas behind transparent layout (#75).

> Earlier release history is tracked in GitHub Releases for this repository.
