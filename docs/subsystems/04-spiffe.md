# Subsystem 4 — SPIFFE Identity & PKI

> CA hierarchy, CSR-based SVID issuance, rotation, Workload API socket, node bootstrap, trust bundle distribution, audit logging. PRD Phase 4 (bootstrap touches Phases 3 and 7).

## Responsibilities

**Owns:**

1. **CA hierarchy.** Offline self-signed **Root CA** (10y); online **Intermediate CA** (ECDSA **P-384**, 1y) held in-process by `meridian-control`. Root signs intermediate offline; intermediate signs SVIDs.
2. **SVID issuance over mTLS gRPC.** Validate agent CSRs (workload keys ECDSA **P-256**), sign with the intermediate, return the chain. 24h SVID TTL.
3. **Issuance authorization.** *May this node request an SVID for this workload identity?* Enforced server-side: a node may only request identities for workloads bound to it (cross-checked against the identity registry).
4. **Rotation.** Agents rotate at **2/3 lifetime** (16h of 24h); new cert active before old expires (zero-downtime NFR).
5. **SPIFFE Workload API Unix socket.** Agent serves the standard Workload API (`FetchX509SVID` streaming, `FetchX509Bundles`) at e.g. `/run/meridian/workload.sock` — consumable by the node proxy and any `go-spiffe`-compatible client.
6. **Node bootstrap identity.** One node credential authenticates both the ADS stream and SVID issuance (see bootstrap scheme below).
7. **Trust bundle distribution.** Root + active intermediates pushed to agents and re-served via the Workload API.
8. **Audit logging.** Every issued SVID logged (SPIFFE ID, serial, validity, requesting node, CSR hash); future Rekor integration.

**Not its job:** the mTLS data path (node proxy); revocation infrastructure — short-lived 24h certs *are* the revocation strategy, no CRL/OCSP in v1; offline-root automation (operator runbook); multi-trust-domain federation (v2); workload attestation beyond node scoping + K8s identity.

## Interfaces

- **(A) SVID issuance gRPC** — consumer: agent, over node-cert mTLS. `FetchSVID(CSRRequest{csr_der, spiffe_id}) → SVIDResponse{cert_chain_der[], intermediate_chain_der[], expires_at}`. One-shot signing; the agent schedules rotation pulls. Server validates CSR signature, single valid `spiffe://cluster.local/...` URI SAN, node-authorized-for-identity, key type/curve. Typed errors, fail closed.
- **(B) Trust bundle** — `FetchBundle() → {trust_domain, x509_authorities_der[]}` on the same channel (and/or as an xDS resource); agents cache and re-serve.
- **(C) Workload API Unix socket** — served by the agent; consumers: node proxy, workloads via `go-spiffe`. Standard SPIFFE protocol; this is what makes Meridian SVIDs SDK-compatible.
- **(D) Bootstrap provisioning** — see below.
- **(E) Audit log sink** — structured records backing `meridian cert inspect`.
- **(F) CLI surface (Phase 6)** — `meridian cert inspect / rotate / verify` read the registry + audit log; `rotate` triggers the issuance RPC.

## Bootstrap scheme

The PRD names the circularity (§4.7 step 3): the agent must present an identity to get its mTLS connection accepted, but the CA is what issues identities.

- **Two-tier credentials.** A **node identity** (longer-lived, e.g. 7d) is distinct from **workload SVIDs** (24h). The node identity authenticates the agent↔control channel (ADS + issuance + bundle); workload SVIDs are minted over it.
- **Standalone Linux mode:** operator provisions `bootstrap.crt`/`bootstrap.key` out-of-band (PRD §8 config), with node SPIFFE ID `spiffe://cluster.local/node/<node-id>`.
- **Kubernetes mode (Phase 7):** the agent presents its ServiceAccount **projected token** (bound audience = meridian-control); the control plane validates via `TokenReview` and issues the node cert over an initially token-authenticated bootstrap RPC. The *first* call is authenticated by the SA token, not a cert — breaking the circularity.
- **Node-identity rotation** happens over the established mTLS channel at 2/3 of its own lifetime, same mechanism as SVIDs.

This single bootstrap serves both the control-plane and SPIFFE subsystems (CC-4).

## Dependencies

- **Libraries:** `spiffe/go-spiffe/v2` (Workload API server/client, SVID types), stdlib `crypto/x509` + `crypto/ecdsa`, `grpc`. SPIRE is a **reference only** — no runtime dependency; implement the minimal CA directly.
- **Meridian subsystems:** identity registry (control plane) must exist before issuance authorization works; the node proxy is the first real Workload API consumer, but the socket is validated earlier with a `go-spiffe` fake-workload client.

## Risks (ranked)

| # | Risk | L / I | Mitigation |
|---|---|---|---|
| 1 | **Rotation failure → expiry → outage** (PRD: Critical); the inverse failure — silently accepting near-expired certs — is a security hole | Low / Critical | Rotate at 2/3 (8h safety window); agent retries with backoff across the window + critical alert near expiry; **near-expiry fails closed** (no valid SVID → new connections refused, per the PRD chaos test); `meridian cert rotate` emergency path; make-before-break swap; test control-plane-down-during-window |
| 2 | **Intermediate CA key compromise** = forge any identity | Low / Critical | Key never leaves the process; load from secret manager, never hardcode; prefer KMS/HSM-backed signing; root stays offline so the intermediate is replaceable without touching root; audit-log all signing ops; intermediate-rotation runbook |
| 3 | **Clock skew** — fresh certs appear not-yet-valid / already-expired to peers; 2/3 math drifts | Med / High | Backdate `notBefore` by ~5m; require NTP (`meridian doctor` checks clock sanity); agent cross-checks its schedule against the control plane's `expires_at` |
| 4 | **Issuance authorization bypass** — a compromised node minting SVIDs for workloads it doesn't run (lateral movement) | Med / Critical | Cross-check requested SPIFFE ID against the registry's workload→node binding; deny by default; log every denial; node principal strictly = bootstrap cert's node SPIFFE ID |
| 5 | **Control plane down during first issuance** — new workloads can't start | Med / High | Fail closed (no silent allow); existing SVIDs keep working through their own 2/3 window (8h buffer absorbs typical outages); document the bounded tolerance |
| 6 | **Workload API socket security** — anything reaching the socket can request SVIDs | Med / High | Scoped socket perms; `SO_PEERCRED` checks where possible; in K8s, mount the socket only into intended pods |
| 7 | **Bootstrap token replay/theft (K8s mode)** | Low / High | Bounded-audience short-TTL projected tokens; TokenReview; node-id-bound one-time enrollment; audit every enrollment |

## Implementation order (PRD Phase 4; bootstrap spans 3/7)

- **PKI-1: CA primitives.** Root generation (offline runbook), intermediate cross-sign, CSR validation + signing path. **Gate:** issued chains verify against root; malformed/wrong-curve CSRs rejected fail-closed.
- **PKI-2: node bootstrap.** Standalone static bootstrap flow + node principal extraction; (Phase 7) TokenReview enrollment. **Gate:** forged bootstrap rejected; node principal flows into ADS authz (closes CP-4).
- **PKI-3: issuance + authorization over mTLS.** `FetchSVID`/`FetchBundle`; registry cross-check; audit logging. **Gate:** a node cannot mint an identity for a workload not bound to it; every issuance audited.
- **PKI-4: rotation + Workload API socket.** Agent SVID lifecycle (keygen → CSR → store → rotate at 2/3, make-before-break); Workload API socket validated with a `go-spiffe` fake client. **Gate:** rotation completes before expiry under normal and control-plane-down conditions; near-expiry fails closed; fake client receives pushed rotations.
- **PKI-5: integration.** Node proxy consumes the socket; `meridian cert inspect/rotate/verify`. **Gate:** PRD Phase 4 test — A↔B mTLS established, unauthorized C rejected; expired cert refused within the rotation window.

PKI-1..PKI-4 are verifiable entirely against fakes (synthetic CSRs, fake workload client, the control-plane agent stub) before any eBPF or proxy code lands.
