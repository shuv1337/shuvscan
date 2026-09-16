# Agent guide

Shuvscan is an evidence-first Linux security scanner. Preserve these contracts:

- Probe scripts are static scanner assets. Never interpolate target or pack data into shell.
- Collection failures and partial evidence must remain visible; they are never clean passes.
- Probes are read-only and must not install, download, mutate, or weaken target security controls.
- Bound work and retained output at collection time, not only during serialization.
- Keep machine-readable stdout free of diagnostics; diagnostics belong on stderr.
- New findings need a stable ID, remediation, collector behavior tests, and evaluator fixtures.
- Signed packs may select compiled probes but never supply executable code.

Before committing, run:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked
cargo audit
```

Use Jujutsu (`jj`) for local version-control work.
