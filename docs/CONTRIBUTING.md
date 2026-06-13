# Contributing to Meridian

## Commit → ticket traceability (MER-45)

Every implementation commit must be traceable to a backlog ticket. This
prevents ledger drift (e.g. commit `754e2ee` shipped MER-17, MER-23, MER-31,
and ADR-0005 under a single MER-26 subject).

### Subject format

Use [Conventional Commits](https://www.conventionalcommits.org/) with a
**MER-&lt;n&gt;** reference:

```text
feat(scope): implement MER-26 datapath writer
fix(bpf): close sentinel race MER-36
```

### Rules

1. **One primary ticket per commit.** The subject names the ticket that owns the
   change. If a single commit implements multiple tickets, list **every**
   ticket ID in the subject or body:

   ```text
   feat(datapath): MER-26 writer; also MER-17 verdict, MER-23 compiler, MER-31 aggregate
   ```

2. **Implementation prefixes require a ticket.** Commits whose subject starts
   with `feat:`, `fix:`, or `refactor:` must contain at least one `MER-<n>` in
   the subject or body. The CI gate `scripts/check-mer-ticket-refs.sh` enforces
   this on every pull request.

3. **Exempt prefixes** (no MER required): `docs:`, `chore:`, `ci:`, `test:`,
   `style:`, `perf:`, `build:`, `revert:`, merge commits.

4. **Provenance for historical mislabels.** When a past commit shipped work
   under the wrong ticket, backfill with `git notes` rather than rewriting
   history:

   ```bash
   git notes add -m "Also implements MER-17, MER-23, MER-31; authored ADR-0005" 754e2ee
   ```

### Local check

```bash
make check-commits          # origin/main..HEAD
scripts/check-mer-ticket-refs.sh abc..def   # explicit range
```

### Git notes

Annotated notes on specific SHAs are part of the traceability story. After
adding a note locally, push it when collaborating:

```bash
git push origin refs/notes/commits
```
