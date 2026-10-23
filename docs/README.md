# Docs

Index of the documents under `docs/`, grouped by directory. The PRD comes
first because the design is sized to it.

## Product

- [PRD: Touchstone](product/touchstone.md) — paste a vendor's URL, get an evidence-graded CVE report.

## Architecture

- [Design: Touchstone](architecture/touchstone.md) — one Go module, one binary (`touchstone`), one container: a modular monolith where each evidence source is a package behind an interface, and a pure pipeline core merges their output into a `ScanReport`.
