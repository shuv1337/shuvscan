# Roadmap

## Phase 1: Trustworthy collector

- Capability inventory and distro/kernel detection
- One SSH session per host with multiplexed probe execution
- Probe timeouts, output budgets, and cancellation
- Fixture-backed evaluators across major distributions
- SARIF and OCSF exports

## Phase 2: Detection engine

- Signed declarative probe packs with schema validation
- Package ownership, process ancestry, sockets, namespaces, and container evidence
- Baselines, suppressions with expiry, and drift-aware scoring
- Cross-probe correlation with explainable confidence

## Phase 3: Fleet workbench

- SQLite evidence store with retention controls
- Resumable scheduler, bastions, host groups, and rate limits
- Keyboard-driven TUI and standalone HTML reports
- Case bundles with cryptographic manifests

## Phase 4: Ecosystem

- Community and commercial rule-pack boundaries
- Reproducible signed releases for cargo, Homebrew, Nix, and OCI
- Plugin SDK for data-only integrations, never arbitrary remote shell
- Fleet API with scoped credentials and immutable audit events
