# Changelog

## v1.1.0 (2026-06-04)

### Features
- feat(registry): implement database caching and background pre-computation for candlesticks graph
- feat(registry): collect all code manifests and return empty placeholders for candlesticks
- feat(registry): support multi-manifest constraints in /candlesticks endpoint (#24)
- feat(registry): implement candlesticks endpoint and constraints helper
- feat(registry): update package parsing and counting to support nested lockfile layout
- feat(registry): implement nested multi-lockfile formatting, chain events (init/forget) and documentation

### Bug Fixes
- fix(registry): dynamically reconstruct package constraints and parallelize upstream checks in candlesticks API

### Refactoring
- refactor(registry): secure admin routes under /api/v1/internal and strip legacy Admin SPA

### Chores & Maintenance
- chore(release): integrate semantic-release and changelog automation
- test(registry): add edge-case integration tests for candlesticks API
- test(registry): add multi-lockfile integration test and update existing tests for new nested formatting


