# Evaluator fixtures

These files contain synthetic, sanitized collector stdout representative of
major Linux distribution families. They test only the stable evaluator boundary:
whether already-collected evidence raises a finding. They do not execute probe
scripts or represent complete host snapshots. A distro fixture must account for
every detection probe. Evidence-only probes have no finding evaluator and are
covered by collector-specific tests instead. Detection probes that do not apply
to a distro's default stack go in `omitted` with a reason; all others need both
non-finding and finding evidence.

Each case supplies one non-finding and one finding sample. Add or update cases
when evaluator semantics change, and never place evidence copied from a live
host in this corpus.
