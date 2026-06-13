# MER-25 Attach Flow

```mermaid
flowchart TD
    A["CLI start: meridian-agent --pin-dir --iface"] --> B["LoadCounter(pinDir)"]
    B --> C{"iface provided?"}
    C -- "no" --> Z["Run telemetry consumer only"]
    C -- "yes" --> D["attach.NewManager(program, pinDir/counter_prog)"]
    D --> E["EnsureAttached(iface)"]
    E --> F["replacePinnedProgram()"]
    F --> F1{"Pin returns EEXIST?"}
    F1 -- "yes" --> F2["Remove stale pin path"]
    F2 --> F3["Re-pin program"]
    F1 -- "no" --> G["ensureClsact(link) via QdiscReplace"]
    F3 --> G
    G --> H["replaceFilter(link) via BpfFilter + DirectAction + FilterReplace"]
    H --> I["Attached and idempotent on reruns"]
    I --> J["Run telemetry consumer"]
    J --> K["Shutdown signal"]
    K --> L["Best-effort Detach(iface)"]
    L --> M["Delete managed ingress filter(s)"]
    M --> N["Delete clsact qdisc"]
```

Notes:

- `EnsureAttached` is idempotent by design (`QdiscReplace` + `FilterReplace`), so repeated attach calls keep one managed ingress filter.
- Restart safety is handled by unpin-or-replace when pinning program paths (`EEXIST` triggers remove + re-pin).
- `ReplaceProgram` validates inputs and then reuses the same attach path for atomic program swap.
- `Detach` is idempotent, removes only manager-owned ingress BPF filters by name, and treats missing links/resources as success.
- `EnsureAttached`/`Detach` honor canceled contexts before netlink operations begin.
