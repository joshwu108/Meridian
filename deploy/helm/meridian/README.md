# Meridian Helm chart

Verified against a local **kind** cluster on 2026-10-23: kind v0.33.0,
`kindest/node:v1.37.0` (Kubernetes 1.37.0), Docker Desktop 29.1.3 on
darwin/arm64, node kernel `6.12.54-linuxkit (arm64)`, Helm v4.3.1.

eBPF works on that target because the linuxkit kernel ships
`CONFIG_DEBUG_INFO_BTF=y` and exposes `/sys/kernel/btf/vmlinux`, which CO-RE
relocation needs, plus `CONFIG_NET_CLS_BPF` / `CONFIG_NET_ACT_BPF` for the TC
hook. Check before assuming another local-cluster runtime will work:

```console
docker run --rm --privileged alpine ls -la /sys/kernel/btf/vmlinux
```

## Working values (kind, dev)

```console
# 1. Build images for the node's architecture.
docker build --platform linux/arm64 -f deploy/docker/Dockerfile.agent   -t meridian-agent:dev   .
docker build --platform linux/arm64 -f deploy/docker/Dockerfile.control -t meridian-control:dev .

# 2. Cluster, then load the images so no registry is involved.
kind create cluster --name meridian-test
kind load docker-image meridian-agent:dev meridian-control:dev --name meridian-test

# 3. Install. Every --set below is REQUIRED on kind; see the notes.
helm install meridian ./deploy/helm/meridian \
  --namespace meridian-system --create-namespace \
  --set agent.image.repository=meridian-agent     --set agent.image.tag=dev \
  --set control.image.repository=meridian-control --set control.image.tag=dev \
  --set control.standalone=true \
  --set agent.standalone=true \
  --set webhook.enabled=false \
  --set agent.iface=<host-side veth of the pod to enforce>
```

Why each override is needed:

| Override | Without it |
|---|---|
| `agent.image.repository`, `control.image.repository` | No longer required on kind: the defaults are now the bare `meridian-agent:dev` / `meridian-control:dev` that `kind load docker-image` puts on the node. They are **placeholders**, not published images — Meridian publishes none — so any cluster that actually pulls must override both to a reachable repository. (They previously defaulted to the private `ghcr.io/joshuawu/meridian-*`, which left both pods in `ImagePullBackOff` with `403 Forbidden`.) |
| `--namespace meridian-system --create-namespace` | The chart has no namespace of its own, so it installs into whatever is current — usually `default`. `kubectl get pods -n meridian-system` then shows nothing. |
| `control.standalone=true` | No CA. It is already the chart and binary default; harmless to state. |
| `agent.standalone=true` | The agent runs without an SVID and logs why. With neither flag the message is still `neither --standalone nor --control-addr given`; with `--control-addr` but no credential it now names the address and the missing `--token-path` / `--bootstrap-cert`, instead of claiming `--control-addr` was never passed. |
| `webhook.enabled=false` | Rendering fails without `webhook.certSecret`. |
| `agent.iface` | See **Fail-closed and the attach scope** — this is the important one. |

## Fail-closed and the attach scope

Enforcement is fail-closed: a flow whose source or destination identity is not
in `identity_map` is dropped. `agent.vethPrefix` starts a watcher that attaches
the TC program to **every** matching pod veth as it appears, so on a cluster
with no seeded identities the agent drops all pod traffic on the node.

That is not hypothetical. With `agent.vethPrefix=veth` (the correct prefix for
kindnet) and empty maps, both CoreDNS replicas went `1/1 -> 0/1` within
seconds, with flow events showing `verdict=1` on CoreDNS → kube-apiserver.

`agent.policyFallopen=true` (agent flag `--policy-fallopen`) is the escape
hatch for that first boot. It sets `MERIDIAN_CFG_FALLOPEN_UNKNOWN` in
`runtime_config_map`, which `tc_ingress.c` and `tc_egress.c` read per packet,
so a flow with an unknown identity is allowed instead of dropped. The agent
writes the posture **before** it attaches anything — the supervisor attaches
inside `Startup()`, so a later write would still leave a drop window — and the
word is written on every boot, so clearing the value turns the posture back
off across a restart rather than inheriting the surviving pin.

Three consequences:

- For a demo or incremental rollout use `agent.iface=<one veth>`.
- Before using `agent.vethPrefix` on a real cluster, either seed identities for
  everything on the node **first** or start with
  `agent.policyFallopen=true`, then turn it off once identities are in place.
- `policyFallopen=true` is not a production posture: while it is set, anything
  Meridian does not recognise is permitted.

Also note the TC filters **outlive the pod**: after the agent DaemonSet was
rolled, `tc filter show dev <veth> ingress` still listed the BPF filter on six
veths, and CoreDNS only recovered once they were deleted by hand. Teardown
leaves the data plane attached.

### Which veth to pick

TC **ingress** on a host-side veth sees packets *leaving* that pod. To gate
`curl -> nginx`, attach to **curl's** veth, not nginx's — that is where the
client SYN is evaluated. Find it by matching the pod's `eth0` peer index:

```console
IFLINK=$(kubectl exec curlpod -- cat /sys/class/net/eth0/iflink)
docker exec meridian-test-control-plane sh -c \
  "for i in \$(ls /sys/class/net|grep '^veth'); do \
     [ \"\$(cat /sys/class/net/\$i/ifindex)\" = \"$IFLINK\" ] && echo \$i; done"
```

`agent.iface` is therefore tied to one pod sandbox and changes whenever that
pod is recreated. It is a demo/rollout tool, not a value for a real cluster.

## Driving policy

**`MeridianPolicy` CRDs do nothing.** The CRD installs, the OpenAPI schema
validates (`action` and `protocols` are lowercase — `deny`, `tcp`), the object
is accepted and stored, and then nothing happens: the ADS version does not
bump, the control-plane store stays empty, and traffic is unaffected.
`internal/control/k8s/policy_informer.go` defines `PolicyWatcher` but it is
referenced nowhere outside its own file — `cmd/meridian-control` only mounts
the validating webhook. The RBAC in this chart has no `meridian.io` rules and
the control-plane Deployment sets no `serviceAccountName`, both consistent with
the informer never running.

Until that is wired, policy goes through the control-plane REST API. Identity
IDs are allocated server-side, so create the services first and use the IDs
they return:

```console
kubectl port-forward -n meridian-system svc/meridian-meridian-control 18080:8080 &

curl -X POST localhost:18080/services -H 'Content-Type: application/json' \
  -d '{"name":"curlpod","spiffeId":"spiffe://cluster.local/ns/default/sa/curlpod","namespace":"default","podIpv4":"10.244.0.8"}'
curl -X POST localhost:18080/services -H 'Content-Type: application/json' \
  -d '{"name":"nginx","spiffeId":"spiffe://cluster.local/ns/default/sa/nginx","namespace":"default","podIpv4":"10.244.0.7"}'

# ALLOW curlpod(1) -> nginx(2) tcp/80 ingress. Action: 0=ALLOW 1=DENY 2=REDIRECT.
# Field names are Go-cased and the decoder rejects unknown fields.
curl -X POST localhost:18080/policies -H 'Content-Type: application/json' \
  -d '{"Key":{"SrcIdentity":1,"DstIdentity":2,"DstPort":80,"Protocol":6,"Direction":0},"Verdict":{"Action":0,"Flags":0}}'
```

Re-POSTing the same key with `"Action":1` flips it to DENY; the agent ACKs a
new ADS version within a few seconds.

Observed, on the clean install above:

```text
ALLOW  curl->nginx:80  HTTP=200  time=0.000548s
DENY   curl->nginx:80  HTTP=000  time=8.003182s   (curl: (28) timed out)
ALLOW  curl->nginx:80  HTTP=200  time=0.000580s
```

with the matching flow events from the agent:

```text
06:48:46.552880  10.244.0.8:52300 -> 10.244.0.7:80  proto=6 verdict=0 bytes=74
06:48:50.667916  10.244.0.8:39022 -> 10.244.0.7:80  proto=6 verdict=1 bytes=74
06:48:51.712809  10.244.0.8:39022 -> 10.244.0.7:80  proto=6 verdict=1 bytes=74
...                                                             (SYN retries, all dropped)
06:49:02.802312  10.244.0.8:58886 -> 10.244.0.7:80  proto=6 verdict=0 bytes=74
```

Flow events print `verdict=` as the **numeric** `enum flow_verdict`
(`0`=ALLOW, `1`=DENY, `2`=REDIRECT), not `verdict=ALLOW` / `verdict=DENY`.

## Chart fixes made while verifying this

- `dnsPolicy: ClusterFirstWithHostNet` on the agent DaemonSet. With
  `hostNetwork: true` the kubelet downgrades `ClusterFirst` to `Default`, so
  the agent got the **node's** `resolv.conf`, could not resolve
  `meridian-meridian-control`, and the ADS client failed in a reconnect loop:
  `name resolver error: produced zero addresses`. No policy could ever reach
  the agent.
- `--ads-addr` is now passed, defaulting to the in-cluster control service.
  The template previously passed only `--control-addr` (REST), so the agent
  never opened an ADS stream and its maps stayed empty — the chart could not
  enforce policy at all.
- `agent.mountBpffs` initContainer (default on, idempotent) plus
  `mountPropagation: Bidirectional` on the `/sys/fs/bpf` mount. kind nodes do
  not pre-mount bpffs, and the `hostPath: DirectoryOrCreate` quietly created a
  plain directory instead, which cannot hold map pins. The agent image is
  distroless and has no `mount(8)`, hence the separate `busybox` initContainer.
- **`MeridianPolicy` now reaches the agents.** `cmd/meridian-control` never
  started `PolicyWatcher`, so CRDs were admitted, validated and stored by the
  apiserver and then ignored: ADS only ever shipped what the REST API had been
  told. The control plane now takes `--kubeconfig` (empty = in-cluster) and
  starts the pod and MeridianPolicy informers whenever it has a cluster to
  talk to. Both are needed — the policy compiler resolves a CRD's SPIFFE
  sources and namespace/label selector through an `IdentityResolver` backed by
  the pod informer's cache, so starting the policy informer alone would skip
  every object with "no registered identity".
- **Control-plane RBAC and ServiceAccount** (`control.rbac.enabled`,
  `control.serviceAccount`, both on by default). The Deployment previously ran
  as `default` with no permissions, so the informers above would have failed
  their list/watch with `Forbidden`. The ClusterRole is read-only: `get`,
  `list`, `watch` on `pods` and `meridian.io/meridianpolicies`.
- `agent.policyFallopen` to choose the startup enforcement posture; see
  **Fail-closed and the attach scope**.
- `agent.cleanStaleSocket` initContainer (default on) removes a leftover
  `/run/meridian/workload.sock` before the agent starts. The socket lives on a
  `hostPath` and outlives the pod, so after an ungraceful stop the next agent
  died with `bind: address already in use`. Only the socket is removed — the
  node bootstrap cert/key sit in the same directory and are reused by design.
- **Clearer credential diagnostic.** `phase4_linux.go` logged `neither
  --standalone nor --control-addr given` even when `--control-addr` *was*
  given and only the bootstrap credential was missing, which sent people
  looking at the wrong flag. The message now distinguishes the two.
- `agent.image.repository` / `control.image.repository` now default to bare
  placeholder names rather than a private `ghcr.io` repository.
- `agent.iface` for single-interface attach, and a danger note on
  `agent.vethPrefix`.

## Known gaps (not fixed here)

1. **No agent metrics endpoint.** `values.yaml` sets `agent.metricsPort: 9901`
   and the DaemonSet declares a `metrics` containerPort, but
   `cmd/meridian-agent` contains no reference to `9901`, no `--metrics-addr`
   flag and no Prometheus handler. The node listens only on `9902` (admin,
   `127.0.0.1`), `15001` and `15008`. `docs/subsystems/06-observability.md`
   specifies `:9901`, so the chart advertises a port nothing serves.
2. **TPROXY/proxy redirect cannot work in this image.**
   `phase4: TPROXY install failed ...: iptables: executable file not found in
   $PATH` — the distroless agent image has no `iptables`, so the L7/redirect
   path is unavailable. L4 TC enforcement is unaffected.
3. **Agent RBAC is unused but broad.** The agent ClusterRole grants
   `pods`/`services`/`endpoints` watch and `tokenreviews` create, but the
   agent is driven entirely by ADS in this configuration. (The control plane
   now has its own ServiceAccount and ClusterRole — see below.)
