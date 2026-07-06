# Active Ticket

ID: MER-71

Title: A-2 — netlink veth lifecycle (4/N CLOSE-OUT: real-attach gate + production wiring + Lima evidence)

Objective:
Close MER-71. Tranches 1–3 (`2778bd9`, `896f851`, `e68c2ea`) landed the
orchestrator, watcher, supervisor wiring (ENOBUFS retry loop), the A-2 gate,
and armed the manifest row (11 armed gates). TPM review of `e68c2ea` found
three acceptance gaps that block closure:

  (a) **Gate measures a fake.** `TestVethAttachLifecycleGate_MER71` uses
      `linkwatchRecorder` — no real TC program is ever attached, so the
      "no leaked attachments/qdiscs" claim is unverifiable. Harden the gate:
      drive the real MER-57 TC attach manager (root + netns are already
      available in this suite) so the 100 ms budget covers actual
      `EnsureAttached` → qdisc/filter on the host-side veth, and the leak
      check inspects real kernel state (no `mh-*`/`r71*` qdiscs or filters
      left after teardown). Keep the recorder-based assertions if useful,
      but the armed gate row must exercise the real path.
  (b) **Feature is dead code in the shipped binary.** No caller constructs
      a `NetlinkWatcher`: wire it in `cmd/meridian-agent` (the process
      composition root) into `supervisor.StartupOptions.LinkWatcher`,
      flag-gated if appropriate (mirror the `--cgroup` opt-in pattern), with
      a sane default selector for pod veths.
  (c) **No Lima evidence.** Run the full battery on Lima 5.15 in an ISOLATED
      window and record it: update `docs/PHASE3_GATES.md` gate-status table —
      A-2 → armed=yes/green with the run evidence; while there, correct the
      stale A-3 row (MER-73 closed green, 1.92 ms; actual test name is
      TestRestToKernelGate_MER73) per the committed history.

Stay in scope: linkwatch gate test, `cmd/meridian-agent` wiring,
`docs/PHASE3_GATES.md`. Do NOT touch eBPF programs, the frozen schema, the
ADS path, or start PKI (MER-74/75). depguard: no `bpf/` outside `bpfobj`.

Dependencies:
- Tranches 1–3 ✅ (`e68c2ea` at HEAD). MER-57 attach managers ✅. No new deps.
- Lima 5.15, root, ISOLATED window (confirm no second gate runner — MER-68).

Acceptance Criteria:
1. The armed A-2 gate exercises the REAL attach path: TC qdisc/filter
   actually present on each host-side veth within 100 ms (reconcile + event
   paths), actually gone after deletion; kernel-state leak check (not map
   bookkeeping) passes after teardown. Never t.Skip under root on 5.15.
2. `cmd/meridian-agent` constructs and passes the NetlinkWatcher into the
   supervisor (flag-gated OK); the binary's veth auto-attach is reachable in
   production, not only from tests.
3. Lima 5.15 isolated run: `make test-integration` green;
   `make check-gate-skips` → 0 skips across all 11 armed gates. Evidence
   (kernel, date, result) recorded in `docs/PHASE3_GATES.md` A-2 row; stale
   A-3 row corrected in the same edit.
4. Host: `go build ./...` / `go vet ./...` / `go test -race ./internal/...`
   clean; `go mod tidy` no diff; depguard clean.
5. Commit(s) reference MER-71; `make check-commits` passes; `git status`
   clean; branch pushed.

Files Expected To Change:
- test/integration/linkwatch_test.go     (real-attach hardening + kernel leak check)
- cmd/meridian-agent/*.go                 (construct + wire NetlinkWatcher, flag)
- docs/PHASE3_GATES.md                    (A-2 evidence; A-3 row correction)
- internal/agent/supervisor/*.go          (only if wiring needs a small seam)

Required Tests:
- `limactl shell meridian -- make test-integration` (ISOLATED) → real TC attach <100 ms, kernel leak check clean
- `limactl shell meridian -- make check-gate-skips`             → 0 skips / 11 armed gates
- `go build ./...` / `go vet ./...` / `go test -race ./internal/...` → clean
- `make check-commits` → MER-71 linkage satisfied

Commit Message:
feat(agent): MER-71 (4/N) real-attach A-2 gate + meridian-agent linkwatch wiring + Lima evidence
