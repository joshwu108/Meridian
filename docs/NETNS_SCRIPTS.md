# Netns Fixture Scripts (P0-003)

Phase 0 integration tests already manage network namespaces programmatically in
Go (`test/harness/netns.go`). Ticket `P0-003` adds shell helpers so developers
can reproduce the same topology manually during debugging.

## Scripts

All scripts live in `scripts/netns/`:

- `setup_netns.sh <namespace>`
  - creates the namespace (if missing)
  - brings loopback up inside it
- `create_veth_pair.sh <namespace> <host_veth> <peer_veth> <host_cidr> <peer_cidr> [--no-clsact]`
  - creates and wires a veth pair
  - assigns addresses
  - brings interfaces up
  - installs `clsact` on the host veth unless `--no-clsact` is passed
- `cleanup_netns.sh <namespace> [host_veth]`
  - best-effort cleanup of qdisc, host link, and namespace

## Dry-run mode

Each script supports:

```bash
DRY_RUN=1 scripts/netns/<script>.sh ...
```

Dry-run prints the commands that would run and performs no changes. This is
what the unit tests assert on.

## Example session

```bash
sudo scripts/netns/setup_netns.sh mrdn-debug
sudo scripts/netns/create_veth_pair.sh mrdn-debug mh-debug mp-debug 169.254.20.1/30 169.254.20.2/30

# optional: attach a pinned BPF program with tc, then generate traffic
sudo ip netns exec mrdn-debug ping -c 3 169.254.20.1

sudo scripts/netns/cleanup_netns.sh mrdn-debug mh-debug
```

## Test coverage

`test/harness/netns_scripts_test.go` validates:

- command sequencing for setup / veth creation / cleanup in dry-run mode
- argument validation and usage output for each script
