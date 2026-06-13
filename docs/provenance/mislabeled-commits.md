# Mislabeled commit provenance (MER-45)

Two historical mega-commits shipped multiple backlog tickets under subjects
that name zero or only one ticket. Git notes on each SHA record the full
mapping; this file is a human-readable mirror for reviewers who have not fetched
`refs/notes/commits`.

| SHA | Subject | Also implements |
|-----|---------|-----------------|
| `754e2ee` | `feat(datapath): implement MER-26 writer and translation layer` | MER-17 (verdict enforcement), MER-23 (policy compiler), MER-31 (flow aggregation); authored ADR-0005 |
| `96f9fdb` | `impkement phase2` (typo; content is Phase-0/1, not Phase-2) | MER-13 (LICENSE), MER-15 (wire equivalence tests), MER-36 (schema sentinel), MER-37 (netns reconciliation), MER-38 (lint pin), MER-39 (Consumer.Close), MER-40 (ADR-0006), MER-41 partial (ADR index); advances gate suites MER-18/21/29 |

Each row has a committed mirror at `docs/provenance/<sha>.note` (CI-verified) and a
matching `git notes` entry (push with `git push origin refs/notes/commits`).

## Backfill commands

```bash
git notes add -m "Also implements MER-17, MER-23, MER-31; authored ADR-0005" 754e2ee
git notes add -m "Mislabeled mega-commit (Phase-0/1, not Phase-2). Also implements MER-13, MER-15, MER-36, MER-37, MER-38, MER-39, MER-40, MER-41 (partial); advances gate suites MER-18/21/29" 96f9fdb
git push origin refs/notes/commits
```

Verify locally:

```bash
make check-provenance-notes
```
